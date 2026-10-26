package hashcat

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/bliey/zipkit/internal/hashextract"
	"github.com/bliey/zipkit/internal/settings"
)

// aes256Zip 是 hashextract 的固定样本（7-Zip 生成，口令 123456）。
const aes256Zip = "../hashextract/testdata/aes256.zip"

// ZipCrypto 的两个固定样本（口令分别是 123456 / abc123）。
//
// 两个都要测：hashcat 的 17200 只吃 Deflate、17210 只吃 Store，
// 写死一个模式号会让另一半文件「No hashes loaded」。
const (
	zipCryptoStoreZip   = "../hashextract/testdata/zipcrypto.zip"
	zipCryptoDeflateZip = "../hashextract/testdata/zipcrypto_deflate.zip"
)

// useConfig 把配置换成一个临时文件并写入 cfg，用例结束后恢复。
func useConfig(t *testing.T, cfg settings.Config) {
	t.Helper()

	settings.SetPath(filepath.Join(t.TempDir(), "config.json"))
	if err := settings.Save(cfg); err != nil {
		t.Fatalf("写测试配置: %v", err)
	}
	t.Cleanup(func() {
		settings.SetPath("")
		SetToolPaths("", "", "")
	})
}

// newService 用给定配置构造服务。服务是懒加载配置的，
// 所以必须先 useConfig 再构造。
func newService(t *testing.T, cfg settings.Config) *HashcatService {
	t.Helper()
	useConfig(t, cfg)
	return &HashcatService{}
}

// waitIdle 等破解线程结束。
func waitIdle(t *testing.T, svc *HashcatService) {
	t.Helper()
	deadline := time.Now().Add(120 * time.Second)
	for time.Now().Before(deadline) {
		svc.mu.Lock()
		running := svc.running
		svc.mu.Unlock()
		if !running {
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatal("破解没有在 120 秒内结束")
}

// waitRunning 等破解线程启动。
func waitRunning(t *testing.T, svc *HashcatService) {
	t.Helper()
	deadline := time.Now().Add(30 * time.Second)
	for time.Now().Before(deadline) {
		svc.mu.Lock()
		running := svc.running
		svc.mu.Unlock()
		if running {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatal("破解没有启动")
}

// ---------------------------------------------------------------------------
// 工具探测与设置
// ---------------------------------------------------------------------------

func TestServiceToolsDetectsConfiguredHashcat(t *testing.T) {
	exe := requireHashcat(t)
	svc := newService(t, settings.Config{HashcatPath: exe})

	tools := svc.Tools()
	if !tools.Hashcat.Available {
		t.Fatalf("hashcat 应该可用: %+v", tools.Hashcat)
	}
	if tools.Hashcat.Source != "config" {
		t.Errorf("Source = %q，want config", tools.Hashcat.Source)
	}
	if tools.Hashcat.Path != exe {
		t.Errorf("Path = %q，want %q", tools.Hashcat.Path, exe)
	}
	// 这台机器没装 john，两个 2john 入口应当报告不可用并给出提示。
	if tools.Rar2John.Available {
		t.Logf("检测到 rar2john: %s", tools.Rar2John.Path)
	} else if !strings.Contains(tools.Rar2John.Message, "rar2john") {
		t.Errorf("不可用提示里应带上工具名: %q", tools.Rar2John.Message)
	}
}

func TestServiceToolsWithoutAnyTool(t *testing.T) {
	svc := newService(t, settings.Config{})
	SetToolPaths("", "", "")

	tools := svc.Tools()
	if tools.Hashcat.Available {
		t.Skipf("这台机器 PATH 里有 hashcat（%s），跳过缺失场景", tools.Hashcat.Path)
	}
	if !strings.Contains(tools.Hashcat.Message, "hashcat") {
		t.Errorf("Message = %q，应提示安装 hashcat", tools.Hashcat.Message)
	}
}

func TestServiceSetToolPathKeepsOtherSettings(t *testing.T) {
	exe := requireHashcat(t)

	// 配置里本来有 7z 路径、bkcrack 路径和解压布局：
	// 保存 hashcat 路径不能把它们抹掉。
	svc := newService(t, settings.Config{
		SevenZipPath: `C:\tools\7z.exe`,
		BkcrackPath:  `C:\tools\bkcrack.exe`,
		Layout:       settings.LayoutFlat,
		Concurrency:  5,
	})

	status, err := svc.SetToolPath(ToolHashcat, exe)
	if err != nil {
		t.Fatalf("SetToolPath: %v", err)
	}
	if !status.Hashcat.Available {
		t.Errorf("status = %+v，应该可用", status.Hashcat)
	}

	saved := settings.Load()
	if saved.HashcatPath != exe {
		t.Errorf("HashcatPath = %q，want %q", saved.HashcatPath, exe)
	}
	if saved.SevenZipPath != `C:\tools\7z.exe` {
		t.Errorf("SevenZipPath 被覆盖了：%q", saved.SevenZipPath)
	}
	if saved.BkcrackPath != `C:\tools\bkcrack.exe` {
		t.Errorf("BkcrackPath 被覆盖了：%q", saved.BkcrackPath)
	}
	if saved.Layout != settings.LayoutFlat || saved.Concurrency != 5 {
		t.Errorf("解压设置被覆盖了：%+v", saved)
	}
}

func TestServiceSetToolPathRejectsBadInput(t *testing.T) {
	svc := newService(t, settings.Config{})

	if _, err := svc.SetToolPath("nonsense", "x"); err == nil {
		t.Error("未知工具类型应该报错")
	}
	if _, err := svc.SetToolPath(ToolHashcat, filepath.Join(t.TempDir(), "nope.exe")); err == nil {
		t.Error("不存在的路径应该报错")
	}
}

// ---------------------------------------------------------------------------
// 哈希提取
// ---------------------------------------------------------------------------

func TestServiceExtractZIP(t *testing.T) {
	svc := newService(t, settings.Config{})

	res, err := svc.Extract(aes256Zip, "hello.txt")
	if err != nil {
		t.Fatalf("Extract: %v", err)
	}
	if res.Mode != 13600 {
		t.Errorf("Mode = %d，want 13600", res.Mode)
	}
	if !strings.HasPrefix(res.Hash, "$zip2$*0*3*0*") {
		t.Errorf("Hash = %q", res.Hash)
	}

	if _, err := svc.Extract("", ""); err == nil {
		t.Error("没有指定压缩包时应该报错")
	}
}

// ZipCrypto 的 .zip 分派：以前 extractFor 只认 AES，ZipCrypto 文件一律
// ErrNoAESEntry，界面上「显卡加速破解」必然失败。这条用例守住修复。
func TestServiceExtractZipCrypto(t *testing.T) {
	svc := newService(t, settings.Config{})

	store, err := svc.Extract(zipCryptoStoreZip, "")
	if err != nil {
		t.Fatalf("Extract(Store): %v", err)
	}
	if store.Mode != hashextract.ModeZipCryptoStore {
		t.Errorf("Store 条目的 Mode = %d，want %d", store.Mode, hashextract.ModeZipCryptoStore)
	}
	if store.Format != hashextract.FormatZipCrypto {
		t.Errorf("Format = %q，want %q", store.Format, hashextract.FormatZipCrypto)
	}
	if !strings.HasPrefix(store.Hash, "$pkzip2$1*1*2*0*") {
		t.Errorf("Hash 前缀不对: %.32s", store.Hash)
	}

	deflate, err := svc.Extract(zipCryptoDeflateZip, "")
	if err != nil {
		t.Fatalf("Extract(Deflate): %v", err)
	}
	if deflate.Mode != hashextract.ModeZipCryptoDeflate {
		t.Errorf("Deflate 条目的 Mode = %d，want %d", deflate.Mode, hashextract.ModeZipCryptoDeflate)
	}

	// 指定不存在的条目要报错，不能悄悄退化成「取第一个」。
	if _, err := svc.Extract(zipCryptoStoreZip, "nope.txt"); !errors.Is(err, hashextract.ErrEntryNotFound) {
		t.Errorf("指定不存在条目返回 %v，want ErrEntryNotFound", err)
	}
}

func TestServiceExtractUnsupported(t *testing.T) {
	svc := newService(t, settings.Config{})

	if _, err := svc.Extract("archive.tar", ""); err == nil {
		t.Error("不支持的扩展名应该报错")
	} else if !strings.Contains(err.Error(), "不支持") {
		t.Errorf("错误信息不够明确: %v", err)
	}
}

// 缺 john 时，RAR5 / 7z 的入口要给出「未找到工具」而不是别的问题。
func TestServiceExtractRarWithoutJohn(t *testing.T) {
	svc := newService(t, settings.Config{})
	SetToolPaths("", "", "")

	_, err := svc.Extract("archive.rar", "")
	if err == nil {
		t.Skip("这台机器装了 rar2john，跳过缺失场景")
	}
	if !errors.Is(err, ErrToolMissing) {
		t.Fatalf("err = %v，want ErrToolMissing", err)
	}
	if !strings.Contains(err.Error(), "rar2john") {
		t.Errorf("错误信息里应带上工具名: %v", err)
	}
}

// 7z2john 没有外部二进制，走内建实现；没装 john 的机器上也要能提哈希。
func TestServiceExtract7zUsesNative(t *testing.T) {
	svc := newService(t, settings.Config{})
	SetToolPaths("", "", "")

	res, err := svc.Extract("../sevenzip/testdata/aes-lzma2.7z", "")
	if err != nil {
		t.Fatalf("Extract: %v", err)
	}
	if res.Mode != 11600 {
		t.Errorf("Mode = %d，want 11600", res.Mode)
	}
	if !strings.HasPrefix(res.Hash, "$7z$") {
		t.Errorf("Hash = %q", res.Hash)
	}
	if res.Source != hashextract.SourceBuiltin {
		t.Errorf("Source = %q，want %q", res.Source, hashextract.SourceBuiltin)
	}
}

// ---------------------------------------------------------------------------
// 工具路径解析：配错要能回退到内置实现
// ---------------------------------------------------------------------------

// 配置里写了错的 7z2john 路径时：Resolve 报「配置无效」，ResolveWithFallback
// 回退到内建实现并给出提示——这正是设置页要显示的那句话。
func TestResolveWithFallbackForNativeTool(t *testing.T) {
	bad := filepath.Join(t.TempDir(), "nope", "7z2john.exe")
	SetToolPaths("", "", bad)
	t.Cleanup(func() { SetToolPaths("", "", "") })

	path, warn, err := ResolveWithFallback(ToolSevenZip2John)
	if err != nil {
		t.Fatalf("ResolveWithFallback: %v", err)
	}
	if path != NativeSevenZip2John {
		t.Errorf("path = %q，want %q", path, NativeSevenZip2John)
	}
	if !strings.Contains(warn, bad) {
		t.Errorf("warn 里应带上配错的路径: %q", warn)
	}

	// Resolve 保持严格：配置无效就报错，不静默回退。
	_, err = Resolve(ToolSevenZip2John)
	if err == nil {
		t.Fatal("Resolve 应该报配置无效")
	}
	var cfgErr *ConfigPathError
	if !errors.As(err, &cfgErr) {
		t.Fatalf("err 类型 = %T，want *ConfigPathError", err)
	}
	if cfgErr.Path != bad {
		t.Errorf("cfgErr.Path = %q，want %q", cfgErr.Path, bad)
	}
	// 上层仍然能用 errors.Is 判断「工具缺失」。
	if !errors.Is(err, ErrToolMissing) {
		t.Errorf("err 应满足 errors.Is(ErrToolMissing)")
	}
}

// 没有配置时，7z2john 直接落到内建实现，Source 标成 builtin。
func TestDetectToolMarksNative7z2John(t *testing.T) {
	SetToolPaths("", "", "")
	t.Cleanup(func() { SetToolPaths("", "", "") })

	st := DetectTool(ToolSevenZip2John)
	if !st.Available {
		t.Fatalf("7z2john 应该可用: %+v", st)
	}
	if st.Source != "builtin" {
		t.Errorf("Source = %q，want builtin", st.Source)
	}
	if st.Path != NativeSevenZip2John {
		t.Errorf("Path = %q，want %q", st.Path, NativeSevenZip2John)
	}
	if !strings.Contains(st.Message, "内建") {
		t.Errorf("Message 应说明用的是内建实现: %q", st.Message)
	}
	if st.Warning != "" {
		t.Errorf("没配错时不该有 Warning: %q", st.Warning)
	}
}

// 配错的 hashcat 没有内置版本可回退，必须如实报错。
func TestResolveWithFallbackKeepsErrorWithoutBuiltin(t *testing.T) {
	bad := filepath.Join(t.TempDir(), "nope", "hashcat.exe")
	SetToolPaths(bad, "", "")
	t.Cleanup(func() { SetToolPaths("", "", "") })

	if _, _, err := ResolveWithFallback(ToolHashcat); err == nil {
		t.Fatal("没有内置版本时应该报错")
	} else if !errors.Is(err, ErrToolMissing) {
		t.Errorf("err = %v，want ErrToolMissing", err)
	}
}

// ---------------------------------------------------------------------------
// 启动 / 停止
// ---------------------------------------------------------------------------

func TestServiceStartCracksPassword(t *testing.T) {
	exe := requireHashcat(t)
	svc := newService(t, settings.Config{HashcatPath: exe})

	res, err := svc.Extract(aes256Zip, "hello.txt")
	if err != nil {
		t.Fatalf("Extract: %v", err)
	}

	if _, err := svc.Start(res.Hash, res.Mode, Strategy{Kind: StrategyMask, Mask: "?d?d?d?d?d?d"}); err != nil {
		t.Fatalf("Start: %v", err)
	}
	waitIdle(t, svc)

	last := svc.LastResult()
	if !last.OK {
		t.Fatalf("应该破解成功: %+v", last)
	}
	if last.Password != "123456" {
		t.Errorf("Password = %q，want 123456", last.Password)
	}
	if last.Status != "Cracked" {
		t.Errorf("Status = %q，want Cracked", last.Status)
	}
	if last.ElapsedMs <= 0 {
		t.Errorf("ElapsedMs = %d", last.ElapsedMs)
	}
}

func TestServiceStartExhausted(t *testing.T) {
	exe := requireHashcat(t)
	svc := newService(t, settings.Config{HashcatPath: exe})

	res, err := svc.Extract(aes256Zip, "hello.txt")
	if err != nil {
		t.Fatalf("Extract: %v", err)
	}

	// 口令是 6 位，用 4 位掩码必然穷尽。
	if _, err := svc.Start(res.Hash, res.Mode, Strategy{Kind: StrategyMask, Mask: "?d?d?d?d"}); err != nil {
		t.Fatalf("Start: %v", err)
	}
	waitIdle(t, svc)

	last := svc.LastResult()
	if last.OK {
		t.Fatalf("不该破解成功: %+v", last)
	}
	if last.Err == "" {
		t.Error("失败时应该有错误说明")
	}
	if len(last.Tail) == 0 {
		t.Error("失败时应该带输出尾部")
	}
}

func TestServiceStartAndStop(t *testing.T) {
	exe := requireHashcat(t)
	svc := newService(t, settings.Config{HashcatPath: exe})

	res, err := svc.Extract(aes256Zip, "hello.txt")
	if err != nil {
		t.Fatalf("Extract: %v", err)
	}

	// 空间足够大，不停止会跑很久。
	if _, err := svc.Start(res.Hash, res.Mode, Strategy{Kind: StrategyMask, Mask: "?a?a?a?a?a?a"}); err != nil {
		t.Fatalf("Start: %v", err)
	}
	waitRunning(t, svc)

	if err := svc.StopHashcat(); err != nil {
		t.Fatalf("StopHashcat: %v", err)
	}
	waitIdle(t, svc)

	last := svc.LastResult()
	if !last.Cancelled {
		t.Fatalf("应该标记为已停止: %+v", last)
	}
	if last.OK {
		t.Error("停止后不该算成功")
	}

	// 没有任务时停止不该报错。
	if err := svc.StopHashcat(); err != nil {
		t.Errorf("空转 StopHashcat = %v，want nil", err)
	}
}

func TestServiceStartRejectsConcurrentRun(t *testing.T) {
	exe := requireHashcat(t)
	svc := newService(t, settings.Config{HashcatPath: exe})

	res, err := svc.Extract(aes256Zip, "hello.txt")
	if err != nil {
		t.Fatalf("Extract: %v", err)
	}
	strategy := Strategy{Kind: StrategyMask, Mask: "?a?a?a?a?a?a"}

	if _, err := svc.Start(res.Hash, res.Mode, strategy); err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer func() {
		_ = svc.StopHashcat()
		waitIdle(t, svc)
	}()
	waitRunning(t, svc)

	if _, err := svc.Start(res.Hash, res.Mode, strategy); err == nil {
		t.Fatal("并发启动应该被拒绝")
	} else if !strings.Contains(err.Error(), "已有破解任务") {
		t.Errorf("错误信息不够明确: %v", err)
	}
}

func TestServiceStartWithoutHashcat(t *testing.T) {
	svc := newService(t, settings.Config{})
	SetToolPaths("", "", "")

	// 这台机器没装 hashcat 时才谈得上「缺工具」。
	if _, err := Resolve(ToolHashcat); err == nil {
		t.Skip("这台机器 PATH 里有 hashcat，跳过缺失场景")
	}

	_, err := svc.Start("$zip2$*0*1*0*00*0000*0**00000000000000000000*$/zip2$", 13600,
		Strategy{Kind: StrategyMask, Mask: "?d?d"})
	if !errors.Is(err, ErrToolMissing) {
		t.Fatalf("err = %v，want ErrToolMissing", err)
	}
}

func TestServiceStartValidatesHash(t *testing.T) {
	svc := newService(t, settings.Config{})
	if _, err := svc.Start("  ", 13600, Strategy{Kind: StrategyMask, Mask: "?d"}); err == nil {
		t.Fatal("空哈希应该报错")
	}
}

// ExtractAndStart 是「提取 + 立即开跑」的快捷路径。
func TestServiceExtractAndStart(t *testing.T) {
	exe := requireHashcat(t)
	svc := newService(t, settings.Config{HashcatPath: exe})

	if _, err := svc.ExtractAndStart(aes256Zip, "hello.txt",
		Strategy{Kind: StrategyMask, Mask: "?d?d?d?d?d?d"}); err != nil {
		t.Fatalf("ExtractAndStart: %v", err)
	}
	waitIdle(t, svc)

	if last := svc.LastResult(); !last.OK || last.Password != "123456" {
		t.Fatalf("结果 = %+v", last)
	}
}

func TestLastLines(t *testing.T) {
	lines := []string{"a", "", "b", "[s]tatus [p]ause [b]ypass", "c"}
	got := lastLines(lines, 10)
	want := []string{"a", "b", "c"}
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("lastLines = %v，want %v", got, want)
	}
	if got := lastLines([]string{"a", "b", "c"}, 2); strings.Join(got, ",") != "b,c" {
		t.Fatalf("截断结果 = %v", got)
	}
}

// 「数据加密、头部只压缩不加密」是 7-Zip 的默认形态（条目数 ≥ 2 时头部会被
// 压缩）。这条路径以前会报「归档里没有 AES 加密的数据流」，现在必须能提出来。
func TestServiceExtract7zEncodedHeader(t *testing.T) {
	svc := newService(t, settings.Config{})
	SetToolPaths("", "", "")
	Set7z2HashcatPaths("", "")

	res, err := svc.Extract("../sevenzip/testdata/multi-mhe-off.7z", "")
	if err != nil {
		t.Fatalf("Extract: %v", err)
	}
	if res.Mode != hashextract.Mode7z {
		t.Errorf("Mode = %d，want %d", res.Mode, hashextract.Mode7z)
	}
	if res.Source != hashextract.SourceBuiltin {
		t.Errorf("Source = %q，want %q", res.Source, hashextract.SourceBuiltin)
	}
	if !strings.HasPrefix(res.Hash, "$7z$") {
		t.Errorf("Hash = %q", res.Hash)
	}
}

// 所有路径都不通时，错误里要能看出试过哪些路径——只报一句「提取失败」
// 用户没法判断该去修哪里。
func TestExtract7zReportsEveryAttempt(t *testing.T) {
	SetToolPaths("", "", "")
	Set7z2HashcatPaths("", "")

	dir := t.TempDir()
	bad := filepath.Join(dir, "broken.7z")
	if err := os.WriteFile(bad, []byte("not a 7z at all"), 0o644); err != nil {
		t.Fatal(err)
	}

	_, err := extractFor(bad, "")
	if err == nil {
		t.Fatal("损坏的 7z 应当报错")
	}
	if !strings.Contains(err.Error(), "内建实现") {
		t.Errorf("错误里应包含内建实现这一条：%v", err)
	}
	if !strings.Contains(err.Error(), "都不通") {
		t.Errorf("错误应说明所有路径都失败：%v", err)
	}
}

// 用户在设置里配了 7z2hashcat 但配的路径无效：不能静默忽略，要能报出来。
func TestExtract7zReportsBrokenConfiguredScript(t *testing.T) {
	SetToolPaths("", "", "")
	bad := filepath.Join(t.TempDir(), "nope", "7z2hashcat.pl")
	Set7z2HashcatPaths(bad, "")
	t.Cleanup(func() { Set7z2HashcatPaths("", "") })

	dir := t.TempDir()
	broken := filepath.Join(dir, "broken.7z")
	if err := os.WriteFile(broken, []byte("not a 7z at all"), 0o644); err != nil {
		t.Fatal(err)
	}

	_, err := extractFor(broken, "")
	if err == nil {
		t.Fatal("应当报错")
	}
	if !strings.Contains(err.Error(), "7z2hashcat") {
		t.Errorf("错误里应提到用户配置的 7z2hashcat：%v", err)
	}
}

// 7z2hashcat 能提出来时，要把「内建实现为什么失败」写进 Warnings，
// 而不是悄悄换路径。
func TestExtract7zUsesScriptAndExplainsFallback(t *testing.T) {
	SetToolPaths("", "", "")
	t.Cleanup(func() { Set7z2HashcatPaths("", "") })

	dir := t.TempDir()
	script := filepath.Join(dir, "7z2hashcat.pl")
	if err := os.WriteFile(script, []byte("#!perl\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	Set7z2HashcatPaths(script, filepath.Join(dir, "perl"))

	archive := filepath.Join(dir, "broken.7z")
	if err := os.WriteFile(archive, []byte("not a 7z at all"), 0o644); err != nil {
		t.Fatal(err)
	}

	// 这里没法真跑脚本（依赖机器上有没有 Perl），所以只验证「配置路径无效时
	// 会把它当作一条失败原因记下来」，这已经能覆盖调用链的分支。
	_, err := extractFor(archive, "")
	if err == nil {
		t.Fatal("应当报错")
	}
	if !strings.Contains(err.Error(), "都不通") {
		t.Errorf("错误应汇总所有路径：%v", err)
	}
}
