package attack

import (
	"archive/zip"
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/bliey/zipkit/internal/settings"
	"github.com/bliey/zipkit/internal/zipservice"
)

// sampleText 必须与 zcrack 测试样本里的明文完全一致：store6.zip / num6.zip
// 的 hello.txt 就是这段文字加密后的结果，改一个字 CRC 就对不上了。
const sampleText = "The quick brown fox jumps over the lazy dog.\n" +
	"Pack my box with five dozen liquor jugs.\n" +
	"How vexingly quick daft zebras jump!\n" +
	"Sphinx of black quartz, judge my vow.\n" +
	"0123456789 abcdefghijklmnopqrstuvwxyz\n"

// 密码 123456 对应的内部密钥（ZipCrypto 的密钥只由密码决定，与文件无关），
// 用它可以直接测解密链路，不必每次先跑一遍攻击。
const testKeys = "8879dfed 14335b6b 8dc58b53"

// testConfigPath 是 TestMain 分配的临时配置路径，用例结束后要恢复回来。
var testConfigPath string

func TestMain(m *testing.M) {
	// 配置写到临时目录，避免测试动到用户真实的 config.json。
	dir, err := os.MkdirTemp("", "zipkit-attack-test-*")
	if err != nil {
		panic(err)
	}
	testConfigPath = filepath.Join(dir, "config.json")
	settings.SetPath(testConfigPath)
	code := m.Run()
	os.RemoveAll(dir)
	os.Exit(code)
}

// testdata 返回 zcrack 固定样本的绝对路径。
func testdata(t *testing.T, name string) string {
	t.Helper()
	abs, err := filepath.Abs(filepath.Join("..", "zcrack", "testdata", name))
	if err != nil {
		t.Fatalf("解析测试样本路径: %v", err)
	}
	if _, err := os.Stat(abs); err != nil {
		t.Fatalf("测试样本不存在: %v", err)
	}
	return abs
}

// requireBkcrack 找到可用的 bkcrack，找不到就跳过。
//
// 除了正常探测，还认 ZIPKIT_BKCRACK 环境变量：本机把 bkcrack 放在某个角落
// 时，不必为了跑测试去改 PATH 或用户配置。注意要把路径写进配置文件——服务
// 首次使用时会用配置里的值覆盖进程内设置，只调 SetBkcrackPath 会被抹掉。
func requireBkcrack(t *testing.T) string {
	t.Helper()

	if exe, err := ResolveBkcrack(); err == nil {
		return exe
	}
	env := strings.TrimSpace(os.Getenv("ZIPKIT_BKCRACK"))
	if env == "" {
		t.Skip("没有可用的 bkcrack，跳过（设置 ZIPKIT_BKCRACK 或把 bkcrack 放进 PATH）")
	}

	cfg := settings.Load()
	cfg.BkcrackPath = env
	if err := settings.Save(cfg); err != nil {
		t.Fatalf("写测试配置: %v", err)
	}
	SetBkcrackPath(env)
	t.Cleanup(func() { SetBkcrackPath("") })

	exe, err := ResolveBkcrack()
	if err != nil {
		t.Fatalf("ZIPKIT_BKCRACK=%q 不可用: %v", env, err)
	}
	return exe
}

// writePlain 把明文写到临时文件，返回路径。
func writePlain(t *testing.T, content []byte) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "known_plain.txt")
	if err := os.WriteFile(path, content, 0o644); err != nil {
		t.Fatalf("写明文文件: %v", err)
	}
	return path
}

// writePlainZip 造一个不加密的明文 ZIP，method 决定压缩方式。
func writePlainZip(t *testing.T, content []byte, method uint16, entryName string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "plain.zip")
	f, err := os.Create(path)
	if err != nil {
		t.Fatalf("创建明文 ZIP: %v", err)
	}
	zw := zip.NewWriter(f)
	w, err := zw.CreateHeader(&zip.FileHeader{Name: entryName, Method: method})
	if err != nil {
		t.Fatalf("写明文条目: %v", err)
	}
	if _, err := w.Write(content); err != nil {
		t.Fatalf("写明文内容: %v", err)
	}
	if err := zw.Close(); err != nil {
		t.Fatalf("收尾明文 ZIP: %v", err)
	}
	if err := f.Close(); err != nil {
		t.Fatalf("关闭明文 ZIP: %v", err)
	}
	return path
}

// ------------------------------------------------------------------ Precheck

func TestPrecheckExactMatch(t *testing.T) {
	// store6.zip 里的 hello.txt 是 Store + ZipCrypto；明文 ZIP 用同样的
	// 压缩方式和内容，三项（压缩方式 / CRC32 / 原始大小）全部一致。
	plainZip := writePlainZip(t, []byte(sampleText), zip.Store, "hello.txt")

	res := PrecheckForm(testdata(t, "store6.zip"), "hello.txt", plainZip, "hello.txt", true)
	if !res.OK {
		t.Fatalf("应该通过预检，Issues = %v", res.Issues)
	}
	if res.CipherCompression != "Store" || res.PlainCompression != "Store" {
		t.Errorf("压缩方式 = %q / %q, want Store / Store", res.CipherCompression, res.PlainCompression)
	}
	if res.CipherCRC32 != res.PlainCRC32 {
		t.Errorf("CRC32 应该一致：%08x vs %08x", res.CipherCRC32, res.PlainCRC32)
	}
	if res.CipherSize != res.PlainSize || res.CipherSize != uint64(len(sampleText)) {
		t.Errorf("大小 = %d / %d, want %d", res.CipherSize, res.PlainSize, len(sampleText))
	}
}

func TestPrecheckCompressionMismatch(t *testing.T) {
	// 明文 ZIP 用 Deflate，加密条目是 Store：CRC 和大小都一样，但压缩方式
	// 不同，bkcrack 拿到的字节流对不上。
	plainZip := writePlainZip(t, []byte(sampleText), zip.Deflate, "hello.txt")

	res := PrecheckForm(testdata(t, "store6.zip"), "hello.txt", plainZip, "hello.txt", true)
	if res.OK {
		t.Fatal("压缩方式不一致时不应该通过预检")
	}
	if res.CipherCRC32 != res.PlainCRC32 {
		t.Fatalf("这个用例的 CRC 应该一致，实际 %08x vs %08x", res.CipherCRC32, res.PlainCRC32)
	}
	if !containsIssue(res.Issues, "加密条目为 Store，明文条目为 Deflate") {
		t.Errorf("Issues = %v, 应该指出压缩方式不一致", res.Issues)
	}
}

func TestPrecheckCRCMismatch(t *testing.T) {
	// 长度相同、内容不同：大小一致但 CRC 不一致。
	other := []byte(strings.Repeat("x", len(sampleText)))
	plainZip := writePlainZip(t, other, zip.Store, "hello.txt")

	res := PrecheckForm(testdata(t, "store6.zip"), "hello.txt", plainZip, "hello.txt", true)
	if res.OK {
		t.Fatal("CRC 不一致时不应该通过预检")
	}
	if res.CipherSize != res.PlainSize {
		t.Fatalf("这个用例的大小应该一致：%d vs %d", res.CipherSize, res.PlainSize)
	}
	if !containsIssue(res.Issues, "CRC32 不一致") {
		t.Errorf("Issues = %v, 应该指出 CRC32 不一致", res.Issues)
	}
}

func TestPrecheckStandaloneFile(t *testing.T) {
	plain := writePlain(t, []byte(sampleText))

	res := PrecheckForm(testdata(t, "store6.zip"), "hello.txt", plain, "", false)
	if !res.OK {
		t.Fatalf("独立文件大小一致时应该通过，Issues = %v", res.Issues)
	}
	if res.PlainSize != uint64(len(sampleText)) {
		t.Errorf("PlainSize = %d, want %d", res.PlainSize, len(sampleText))
	}

	// 截断的文件：大小对不上，但可能是「只提供前一部分明文」，所以只提示。
	short := writePlain(t, []byte(sampleText)[:64])
	res = PrecheckForm(testdata(t, "store6.zip"), "hello.txt", short, "", false)
	if res.OK {
		t.Error("大小不一致时不应该通过预检")
	}
	if !containsIssue(res.Issues, "不一致") {
		t.Errorf("Issues = %v, 应该提示大小不一致", res.Issues)
	}
}

func TestPrecheckStandaloneDeflateCipher(t *testing.T) {
	// num6.zip 的条目是 Deflate：拿原始文件当明文一定对不上，必须直接拦住
	// 并说明原因，而不是让用户白跑一遍攻击。
	plain := writePlain(t, []byte(sampleText))

	res := PrecheckForm(testdata(t, "num6.zip"), "hello.txt", plain, "", false)
	if res.OK {
		t.Fatal("Deflate 条目配独立文件不应该通过预检")
	}
	if !containsIssue(res.Issues, "明文必须提供压缩后的字节流") {
		t.Errorf("Issues = %v, 应该说明需要压缩后的字节流", res.Issues)
	}
	if res.CipherCompression != "Deflate" {
		t.Errorf("CipherCompression = %q, want Deflate", res.CipherCompression)
	}
}

func TestPrecheckMissingEntry(t *testing.T) {
	plain := writePlain(t, []byte(sampleText))

	res := PrecheckForm(testdata(t, "store6.zip"), "nope.txt", plain, "", false)
	if res.OK {
		t.Fatal("条目不存在时不应该通过预检")
	}
	if !containsIssue(res.Issues, "没有条目") {
		t.Errorf("Issues = %v, 应该提示条目不存在", res.Issues)
	}
}

func TestPrecheckEmptyPlainEntryUsesFirst(t *testing.T) {
	// 明文 ZIP 的条目名留空时取第一个条目。
	plainZip := writePlainZip(t, []byte(sampleText), zip.Store, "whatever.txt")

	res := PrecheckForm(testdata(t, "store6.zip"), "hello.txt", plainZip, "", true)
	if !res.OK {
		t.Fatalf("留空条目名时应该取第一个条目并通过，Issues = %v", res.Issues)
	}
}

func containsIssue(issues []string, want string) bool {
	for _, issue := range issues {
		if strings.Contains(issue, want) {
			return true
		}
	}
	return false
}

// ----------------------------------------------------------------- 参数与解析

func TestAttackArgs(t *testing.T) {
	// 明文 ZIP：-C <zip> -c <entry> -P <plainZip> -p <plainEntry>
	args := attackArgs(AttackOptions{
		EncryptedZip: `C:\微信 账单\加密 包.zip`,
		CipherEntry:  "账单 2025.txt",
		PlainPath:    `C:\tmp\明文 包.zip`,
		PlainIsZip:   true,
		PlainEntry:   "账单 2025.txt",
	})
	want := []string{
		"-C", `C:\微信 账单\加密 包.zip`,
		"-c", "账单 2025.txt",
		"-P", `C:\tmp\明文 包.zip`,
		"-p", "账单 2025.txt",
	}
	if len(args) != len(want) {
		t.Fatalf("参数个数 = %d, want %d：%v", len(args), len(want), args)
	}
	for i := range want {
		if args[i] != want[i] {
			t.Errorf("args[%d] = %q, want %q", i, args[i], want[i])
		}
	}

	// 独立文件：没有 -P，明文直接跟在 -p 后面。
	args = attackArgs(AttackOptions{EncryptedZip: "a.zip", CipherEntry: "x", PlainPath: "plain.bin"})
	want = []string{"-C", "a.zip", "-c", "x", "-p", "plain.bin"}
	if strings.Join(args, "|") != strings.Join(want, "|") {
		t.Errorf("独立文件参数 = %v, want %v", args, want)
	}
}

func TestParseKeys(t *testing.T) {
	cases := []struct {
		name  string
		line  string
		want  [3]string
		found bool
	}{
		{"收尾单独一行", "8879dfed 14335b6b 8dc58b53", [3]string{"8879dfed", "14335b6b", "8dc58b53"}, true},
		{"带 Keys 前缀", "Keys: 8879dfed 14335b6b 8dc58b53", [3]string{"8879dfed", "14335b6b", "8dc58b53"}, true},
		{"大写也认", "8879DFED 14335B6B 8DC58B53", [3]string{"8879dfed", "14335b6b", "8dc58b53"}, true},
		{"进度行", "84.9 % (36488 / 42995)", [3]string{}, false},
		{"失败信息", "[13:28:48] Could not find the keys.", [3]string{}, false},
		{"两段不算", "8879dfed 14335b6b", [3]string{}, false},
		{"七位不算", "8879dfe 14335b6b 8dc58b53", [3]string{}, false},
	}
	for _, c := range cases {
		got, ok := parseKeys(c.line)
		if ok != c.found {
			t.Errorf("%s：parseKeys = %v, want found=%v", c.name, ok, c.found)
			continue
		}
		if ok && got != c.want {
			t.Errorf("%s：parseKeys = %v, want %v", c.name, got, c.want)
		}
	}
}

func TestSplitKeys(t *testing.T) {
	got, err := splitKeys(" 8879dfed  14335b6b 8dc58b53 ")
	if err != nil {
		t.Fatalf("splitKeys: %v", err)
	}
	if len(got) != 3 || got[0] != "8879dfed" || got[2] != "8dc58b53" {
		t.Errorf("splitKeys = %v", got)
	}

	// 整串当成一个参数是典型错误，这里必须拒绝而不是原样传下去。
	for _, bad := range []string{"8879dfed 14335b6b", "8879dfed 14335b6b 8dc58b53 1", "zzzzzzzz 14335b6b 8dc58b53", "8879dfe 14335b6b 8dc58b53"} {
		if _, err := splitKeys(bad); err == nil {
			t.Errorf("splitKeys(%q) 应该报错", bad)
		}
	}
}

func TestLastLinesFiltersProgress(t *testing.T) {
	raw := strings.Join([]string{
		"bkcrack 1.7.1 - 2024-12-21",
		"[13:27:55] Z reduction using 103458 bytes of known plaintext",
		"0.0 % (0 / 103458)",
		"50.0 % (1 / 2)",
		"[13:27:55] Attack on 2 Z values at index 96436",
		"[13:27:55] Could not find the keys.",
	}, "\n")

	lines := lastLines(raw, 20)
	for _, line := range lines {
		if strings.Contains(line, "% (") {
			t.Errorf("进度行应该被过滤：%q", line)
		}
	}
	if len(lines) != 4 {
		t.Fatalf("lines = %v, want 4 行", lines)
	}
	if lines[len(lines)-1] != "[13:27:55] Could not find the keys." {
		t.Errorf("最后一行 = %q", lines[len(lines)-1])
	}

	// 超过上限时只保留尾部。
	many := strings.Repeat("line\n", 40)
	if got := lastLines(many, 5); len(got) != 5 {
		t.Errorf("lastLines 应该只留 5 行，得到 %d", len(got))
	}
}

// -------------------------------------------------------------------- 真跑

func TestRunFindsKeys(t *testing.T) {
	if testing.Short() {
		t.Skip("-short 跳过真实攻击")
	}
	requireBkcrack(t)

	plain := writePlain(t, []byte(sampleText))
	var logs []string

	res := Run(context.Background(), AttackOptions{
		EncryptedZip: testdata(t, "store6.zip"),
		CipherEntry:  "hello.txt",
		PlainPath:    plain,
	}, func(line string) { logs = append(logs, line) })

	if res.Err != nil {
		t.Fatalf("攻击失败: %v\n输出：\n%s", res.Err, res.Raw)
	}
	if res.Keys != ([3]string{"8879dfed", "14335b6b", "8dc58b53"}) {
		t.Errorf("Keys = %v, want 8879dfed 14335b6b 8dc58b53", res.Keys)
	}
	if len(logs) == 0 {
		t.Error("onLog 没有收到任何输出")
	}
	if !strings.Contains(res.Raw, "Keys") {
		t.Errorf("Raw 应该保留原始输出，实际：%q", res.Raw[:min(len(res.Raw), 200)])
	}
}

func TestRunWrongPlaintext(t *testing.T) {
	if testing.Short() {
		t.Skip("-short 跳过真实攻击")
	}
	requireBkcrack(t)

	// 比密文还长的明文：bkcrack 会直接报错退出，退出码非 0。这条路径要保证
	// 把 bkcrack 自己那句错误带出来，而不是只显示「exit status 1」。
	plain := writePlain(t, []byte(strings.Repeat("not the plaintext\n", 40)))

	res := Run(context.Background(), AttackOptions{
		EncryptedZip: testdata(t, "store6.zip"),
		CipherEntry:  "hello.txt",
		PlainPath:    plain,
	}, nil)

	if res.Err == nil {
		t.Fatal("明文比密文长时应该报错")
	}
	if !strings.Contains(res.Err.Error(), "ciphertext is smaller than plaintext") {
		t.Errorf("Err = %v, 应该带上 bkcrack 自己的错误信息", res.Err)
	}
}

func TestClassifyRun(t *testing.T) {
	// bkcrack 找不到密钥时是「正常退出 + 一句话」，不能当成功。
	if err := classifyRun("[13:28:48] Could not find the keys.\n", [3]string{}, nil); !errors.Is(err, ErrKeysNotFound) {
		t.Errorf("Err = %v, want ErrKeysNotFound", err)
	}
	// 拿到密钥就无视退出码。
	if err := classifyRun("Keys\n8879dfed 14335b6b 8dc58b53\n",
		[3]string{"8879dfed", "14335b6b", "8dc58b53"}, errors.New("exit status 1")); err != nil {
		t.Errorf("Err = %v, want nil", err)
	}
	// 取消优先于一切。
	if err := classifyRun("Could not find the keys.", [3]string{}, ErrCancelled); !errors.Is(err, ErrCancelled) {
		t.Errorf("Err = %v, want ErrCancelled", err)
	}
	// 其它错误原样传出去，不要伪装成「找不到密钥」。
	boom := errors.New("attack: bkcrack 报错：Data error")
	if err := classifyRun("Data error", [3]string{}, boom); !errors.Is(err, boom) {
		t.Errorf("Err = %v, want %v", err, boom)
	}
}

func TestRunCancelled(t *testing.T) {
	if testing.Short() {
		t.Skip("-short 跳过真实攻击")
	}
	requireBkcrack(t)

	plain := writePlain(t, []byte(sampleText))
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	done := make(chan AttackResult, 1)
	start := time.Now()
	go func() {
		done <- Run(ctx, AttackOptions{
			EncryptedZip: testdata(t, "store6.zip"),
			CipherEntry:  "hello.txt",
			PlainPath:    plain,
		}, nil)
	}()

	time.Sleep(300 * time.Millisecond)
	cancel()

	select {
	case res := <-done:
		if !errors.Is(res.Err, ErrCancelled) {
			t.Fatalf("Err = %v, want ErrCancelled", res.Err)
		}
		if elapsed := time.Since(start); elapsed > 5*time.Second {
			t.Errorf("取消后 %v 才返回", elapsed)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("取消后攻击没有退出")
	}
}

func TestKillTerminatesProcess(t *testing.T) {
	if testing.Short() {
		t.Skip("-short 跳过真实攻击")
	}
	requireBkcrack(t)

	plain := writePlain(t, []byte(sampleText))
	done := make(chan AttackResult, 1)
	started := make(chan struct{})
	var once = make(chan struct{})

	go func() {
		done <- Run(context.Background(), AttackOptions{
			EncryptedZip: testdata(t, "store6.zip"),
			CipherEntry:  "hello.txt",
			PlainPath:    plain,
		}, func(line string) {
			// 第一行是 zipkit 自己回显的命令，等 bkcrack 真的开口了再动手。
			if strings.HasPrefix(line, "$ ") {
				return
			}
			select {
			case <-once:
			default:
				close(once)
				close(started)
			}
		})
	}()

	select {
	case <-started:
	case <-time.After(10 * time.Second):
		t.Fatal("攻击没有开始")
	}

	start := time.Now()
	if n := Kill(); n != 1 {
		t.Fatalf("Kill = %d, want 1", n)
	}

	select {
	case res := <-done:
		if !errors.Is(res.Err, ErrCancelled) {
			t.Fatalf("Err = %v, want ErrCancelled", res.Err)
		}
		if elapsed := time.Since(start); elapsed > 5*time.Second {
			t.Errorf("Kill 之后 %v 才返回", elapsed)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("Kill 之后攻击没有退出")
	}
}

func TestKillWithoutRunIsNoop(t *testing.T) {
	if n := Kill(); n != 0 {
		t.Errorf("没有在跑的任务时 Kill = %d, want 0", n)
	}
}

// -------------------------------------------------------------------- 解密

func TestDecryptWholeToPlainZip(t *testing.T) {
	requireBkcrack(t)

	out := filepath.Join(t.TempDir(), "解锁 后的.zip")
	if err := Decrypt(context.Background(), testdata(t, "store6.zip"), testKeys, out, "", nil); err != nil {
		t.Fatalf("Decrypt: %v", err)
	}

	// 无密码包应该能直接用标准库读出来，内容和明文一致。
	r, err := zip.OpenReader(out)
	if err != nil {
		t.Fatalf("打开解密结果: %v", err)
	}
	defer r.Close()

	if len(r.File) != 1 || r.File[0].Name != "hello.txt" {
		t.Fatalf("条目 = %v", r.File)
	}
	rc, err := r.File[0].Open()
	if err != nil {
		t.Fatalf("打开条目: %v", err)
	}
	defer rc.Close()

	data := make([]byte, 4096)
	n, _ := rc.Read(data)
	if string(data[:n]) != sampleText {
		t.Errorf("解出的内容不对：%q", string(data[:n]))
	}
}

func TestDecryptWithNewPassword(t *testing.T) {
	requireBkcrack(t)

	out := filepath.Join(t.TempDir(), "换密码.zip")
	if err := Decrypt(context.Background(), testdata(t, "store6.zip"), testKeys, out, "newpass123", nil); err != nil {
		t.Fatalf("Decrypt: %v", err)
	}

	// 换了密码的包仍然是加密的：文件存在、条目还在、加密标记没被去掉。
	info, err := zipservice.Inspect(out)
	if err != nil {
		t.Fatalf("解析解密结果: %v", err)
	}
	if info.EntryCount != 1 {
		t.Errorf("条目数 = %d, want 1", info.EntryCount)
	}
	if !info.Entries[0].IsEncrypted {
		t.Error("换密码后的包应该仍然是加密的")
	}
}

func TestDecryptEntryStore(t *testing.T) {
	requireBkcrack(t)

	out := filepath.Join(t.TempDir(), "hello.txt")
	if err := DecryptEntry(context.Background(), testdata(t, "store6.zip"), testKeys, "hello.txt", out, nil); err != nil {
		t.Fatalf("DecryptEntry: %v", err)
	}
	assertFileEquals(t, out, sampleText)
}

func TestDecryptEntryDeflateIsDecompressed(t *testing.T) {
	requireBkcrack(t)

	// num6.zip 的条目是 Deflate：bkcrack -d 写出的是压缩流，必须再解一层
	// 才能得到原始文件。
	out := filepath.Join(t.TempDir(), "hello.txt")
	var logs []string
	err := DecryptEntry(context.Background(), testdata(t, "num6.zip"), testKeys, "hello.txt", out,
		func(line string) { logs = append(logs, line) })
	if err != nil {
		t.Fatalf("DecryptEntry: %v", err)
	}
	assertFileEquals(t, out, sampleText)

	if !containsIssue(logs, "已解压为原始文件") {
		t.Errorf("日志应该说明做了 Deflate 解压：%v", logs)
	}
}

func TestDecryptInvalidKeys(t *testing.T) {
	err := Decrypt(context.Background(), testdata(t, "store6.zip"), "8879dfed 14335b6b", "out.zip", "", nil)
	if err == nil || !strings.Contains(err.Error(), "三组") {
		t.Errorf("Err = %v, 应该提示密钥组数不对", err)
	}
}

func TestDecryptEmptyOutputRejected(t *testing.T) {
	err := Decrypt(context.Background(), testdata(t, "store6.zip"), testKeys, "  ", "", nil)
	if err == nil || !strings.Contains(err.Error(), "输出路径") {
		t.Errorf("Err = %v, 应该提示输出路径为空", err)
	}
}

func assertFileEquals(t *testing.T, path, want string) {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("读输出文件: %v", err)
	}
	if string(data) != want {
		t.Errorf("输出内容不对：%q", string(data))
	}
}

// ------------------------------------------------------- 十六进制明文（-x）

func TestNormalizeHex(t *testing.T) {
	cases := []struct {
		in   string
		want string
		bad  bool
	}{
		{"89504E470D0A1A0A", "89504e470d0a1a0a", false},
		{"89 50 4E 47 0D 0A 1A 0A", "89504e470d0a1a0a", false},
		{"  0x89504e47  ", "89504e47", false},
		{"89:50:4e:47", "89504e47", false},
		{"89504E470D0A1A0", "", true},   // 奇数个字符
		{"89504E470D0A1A0AZ", "", true}, // 非法字符
		{"", "", true},
		{"   ", "", true},
	}
	for _, c := range cases {
		got, err := NormalizeHex(c.in)
		if c.bad {
			if err == nil {
				t.Errorf("NormalizeHex(%q) 应该报错，实际得到 %q", c.in, got)
			}
			continue
		}
		if err != nil {
			t.Errorf("NormalizeHex(%q): %v", c.in, err)
			continue
		}
		if got != c.want {
			t.Errorf("NormalizeHex(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

// -x 模式下参数是 -C <zip> -c <entry> -x <offset> <hex>，不能出现 -p。
// 带空格的十六进制必须被清掉：bkcrack 不接受 "89 50 4E 47"。
func TestAttackArgsHex(t *testing.T) {
	args := attackArgs(AttackOptions{
		EncryptedZip: `C:/微信 账单\加密 包.zip`,
		CipherEntry:  "账单 2025.png",
		HexPlaintext: "89 50 4E 47 0D 0A 1A 0A",
		HexOffset:    0,
	})
	want := []string{
		"-C", `C:/微信 账单\加密 包.zip`,
		"-c", "账单 2025.png",
		"-x", "0", "89504e470d0a1a0a",
	}
	if strings.Join(args, "|") != strings.Join(want, "|") {
		t.Fatalf("参数 = %v\nwant %v", args, want)
	}
	for _, a := range args {
		if a == "-p" || a == "-P" {
			t.Fatalf("十六进制模式不应该出现 %s：%v", a, args)
		}
	}

	// 非零偏移原样传成十进制。
	args = attackArgs(AttackOptions{
		EncryptedZip: "a.zip", CipherEntry: "x",
		HexPlaintext: "deadbeef", HexOffset: 4096,
	})
	if got := strings.Join(args[5:], " "); got != "4096 deadbeef" {
		t.Errorf("偏移参数 = %q, want %q", got, "4096 deadbeef")
	}
}

func TestValidateOptionsHex(t *testing.T) {
	base := AttackOptions{EncryptedZip: "a.zip", CipherEntry: "x"}

	// 只给十六进制明文就够了，不需要 PlainPath。
	ok := base
	ok.HexPlaintext = "89504e47"
	if err := validateOptions(ok); err != nil {
		t.Errorf("合法输入被拒: %v", err)
	}

	// 两种明文形式同时给 → 拒绝。
	both := base
	both.HexPlaintext = "89504e47"
	both.PlainPath = "plain.bin"
	if err := validateOptions(both); err == nil {
		t.Error("十六进制与明文文件同时填写应该被拒绝")
	}

	// 奇数长度、负偏移都要拦住。
	odd := base
	odd.HexPlaintext = "895"
	if err := validateOptions(odd); err == nil {
		t.Error("奇数长度应该被拒绝")
	}
	neg := base
	neg.HexPlaintext = "8950"
	neg.HexOffset = -1
	if err := validateOptions(neg); err == nil {
		t.Error("负偏移应该被拒绝")
	}
}

func TestPrecheckHexSkipsAlignment(t *testing.T) {
	res, err := PrecheckHex(testdata(t, "store6.zip"), "hello.txt", "89 50 4E 47", 0)
	if err != nil {
		t.Fatalf("PrecheckHex: %v", err)
	}
	if !res.OK {
		t.Error("十六进制模式应该直接放行")
	}
	if !res.HexMode {
		t.Error("HexMode 应该是 true")
	}
	if len(res.Notes) == 0 {
		t.Fatal("应该带上「无法预检对齐」的提醒")
	}
	if !strings.Contains(strings.Join(res.Notes, " "), "无法预检对齐") {
		t.Errorf("Notes = %v", res.Notes)
	}
	// 4 字节小于 12 字节，应该额外提醒一句。
	if !strings.Contains(strings.Join(res.Notes, " "), "至少 12 字节") {
		t.Errorf("短明文应该有提示，Notes = %v", res.Notes)
	}

	if _, err := PrecheckHex(testdata(t, "store6.zip"), "hello.txt", "", 0); err == nil {
		t.Error("空明文应该报错")
	}
}

// 真实跑一次 -x：把已知明文的开头转成十六进制，偏移 0。
func TestRunHexPlaintext(t *testing.T) {
	if testing.Short() {
		t.Skip("-short 跳过真实攻击")
	}
	requireBkcrack(t)

	head := []byte(sampleText)[:24]
	hex := fmt.Sprintf("%x", head)

	var logs []string
	res := Run(context.Background(), AttackOptions{
		EncryptedZip: testdata(t, "store6.zip"),
		CipherEntry:  "hello.txt",
		HexPlaintext: hex,
		HexOffset:    0,
	}, func(line string) { logs = append(logs, line) })

	if res.Err != nil {
		t.Fatalf("十六进制攻击失败: %v\n输出：\n%s", res.Err, res.Raw)
	}
	if res.Keys != ([3]string{"8879dfed", "14335b6b", "8dc58b53"}) {
		t.Errorf("Keys = %v, want 8879dfed 14335b6b 8dc58b53", res.Keys)
	}
	if len(logs) == 0 {
		t.Error("onLog 没有收到任何输出")
	}
	// 日志里的命令行必须显示 -x，而不是 -p。
	if joined := strings.Join(logs, "\n"); !strings.Contains(joined, "-x 0 "+hex) {
		t.Errorf("日志里应该有 -x 参数，实际：\n%s", joined[:min(len(joined), 400)])
	}
}
