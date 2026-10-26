package embedded

import (
	"os"
	"path/filepath"
	"testing"
)

// withCache 把释放目录指到临时目录，测试结束自动还原。
func withCache(t *testing.T, version string) string {
	t.Helper()
	dir := t.TempDir()
	SetCacheRoot(dir)
	SetVersion(version)
	Reset()
	t.Cleanup(func() {
		Reset()
		SetCacheRoot("")
		SetVersion("")
	})
	return dir
}

func TestReleaseWritesToolsIntoVersionDir(t *testing.T) {
	dir := withCache(t, "1.0.0-test")

	if err := Release(); err != nil {
		t.Fatalf("Release: %v", err)
	}

	want := filepath.Join(dir, "zipkit", "tools", "1.0.0-test")
	if got := Root(); got != want {
		t.Fatalf("Root = %q，want %q", got, want)
	}
	if info, err := os.Stat(want); err != nil || !info.IsDir() {
		t.Fatalf("释放目录不存在：%v", err)
	}

	// 仓库里至少带了 bkcrack 与 7z；其它平台（没放二进制）允许为空。
	infos := Infos()
	released := 0
	for _, info := range infos {
		// 内建实现没有文件，自然没有路径可查。
		if !info.Builtin || info.Native {
			continue
		}
		released++
		if _, err := os.Stat(info.Path); err != nil {
			t.Errorf("%s 报告已释放，但文件不在：%v", info.Kind, err)
		}
		if filepath.Dir(info.Path) != want {
			t.Errorf("%s 释放到了错误的目录：%s", info.Kind, info.Path)
		}
	}
	if released == 0 {
		t.Skip("internal/embedded/tools 里没有二进制，跳过释放校验")
	}
}

// 第二次调用不应该重复写盘：文件内容一样时直接跳过。
func TestReleaseIsIdempotent(t *testing.T) {
	withCache(t, "1.0.0")
	if err := Release(); err != nil {
		t.Fatalf("第一次 Release: %v", err)
	}

	path := Path(KindBkcrack)
	if path == "" {
		t.Skip("没有内置 bkcrack，跳过")
	}
	before, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}

	Reset()
	if err := Release(); err != nil {
		t.Fatalf("第二次 Release: %v", err)
	}
	after, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if !before.ModTime().Equal(after.ModTime()) {
		t.Errorf("文件被重复写入：%v → %v", before.ModTime(), after.ModTime())
	}
}

// 升级到新版本后，旧版本目录应该在下次启动时被清掉。
func TestReleaseRemovesOldVersionDirs(t *testing.T) {
	dir := withCache(t, "2.0.0")

	old := filepath.Join(dir, "zipkit", "tools", "1.0.0")
	if err := os.MkdirAll(old, 0o755); err != nil {
		t.Fatalf("准备旧目录: %v", err)
	}
	if err := os.WriteFile(filepath.Join(old, "stale.txt"), []byte("x"), 0o644); err != nil {
		t.Fatalf("写入旧文件: %v", err)
	}

	if err := Release(); err != nil {
		t.Fatalf("Release: %v", err)
	}
	if _, err := os.Stat(old); !os.IsNotExist(err) {
		t.Errorf("旧版本目录没有被清理：%v", err)
	}
}

// 损坏或被改动的文件要重新写回嵌入版本。
func TestReleaseRepairsTamperedFile(t *testing.T) {
	withCache(t, "1.0.0")
	if err := Release(); err != nil {
		t.Fatalf("Release: %v", err)
	}

	path := Path(KindBkcrack)
	if path == "" {
		t.Skip("没有内置 bkcrack，跳过")
	}
	if err := os.WriteFile(path, []byte("broken"), 0o644); err != nil {
		t.Fatalf("破坏文件: %v", err)
	}

	Reset()
	if err := Release(); err != nil {
		t.Fatalf("重新 Release: %v", err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if info.Size() <= int64(len("broken")) {
		t.Errorf("文件没有被修复，大小 %d", info.Size())
	}
}

func TestSanitizeVersion(t *testing.T) {
	cases := map[string]string{
		"":           "dev",
		"1.2.3":      "1.2.3",
		"1.2.3-beta": "1.2.3-beta",
		"a/b":        "a_b",
		"..":         "_",
		"with space": "with_space",
		"v1\\2:3":    "v1_2_3",
	}
	for in, want := range cases {
		if got := sanitizeVersion(in); got != want {
			t.Errorf("sanitizeVersion(%q) = %q，want %q", in, got, want)
		}
	}
}

func TestVersionDefaultsToDev(t *testing.T) {
	SetVersion("")
	if got := Version(); got != "dev" {
		t.Errorf("Version() = %q，want dev", got)
	}
}

// ---------------------------------------------------------------------------
// 三层自检
// ---------------------------------------------------------------------------

// 7z2john 没有外部二进制，必须被标成 Native，否则设置页只能显示「未内置」。
func TestSevenZip2JohnIsNative(t *testing.T) {
	if !IsNative(KindSevenZip2John) {
		t.Fatal("7z2john 应该是内建实现")
	}
	if IsNative(KindBkcrack) || IsNative(KindSevenZip) || IsNative(KindRar2John) {
		t.Error("有外部二进制的工具不该被标成 Native")
	}
	if IsNative("nonsense") {
		t.Error("未知工具应返回 false")
	}
}

// 还没 Release 时：有嵌入文件的工具是「未内置」，内建实现是「正常」。
func TestInfosBeforeRelease(t *testing.T) {
	withCache(t, "1.0.0")

	info, ok := InfoOf(KindSevenZip2John)
	if !ok {
		t.Fatal("InfoOf 找不到 7z2john")
	}
	if !info.Native || !info.Builtin || !info.Runnable {
		t.Errorf("7z2john 应该直接可用: %+v", info)
	}
	if info.Status != StatusOK {
		t.Errorf("Status = %q，want %q", info.Status, StatusOK)
	}
	if info.Path != "" {
		t.Errorf("内建实现不该有路径: %q", info.Path)
	}

	// 没 Release 就没有释放文件，应当如实报「未内置」而不是「无法执行」。
	if info, ok := InfoOf(KindBkcrack); ok && info.Status != StatusNotEmbedded {
		t.Errorf("bkcrack Status = %q，want %q", info.Status, StatusNotEmbedded)
	}
}

// 释放出来的文件起不来时，自检必须报 not-runnable 并给出原因。
// 光看「文件存在」是发现不了的：缺 DLL 的 john 会以 0xC0000135 静默退出。
func TestVerifyFlagsBrokenBinary(t *testing.T) {
	dir := withCache(t, "1.0.0")
	if err := Release(); err != nil {
		t.Fatalf("Release: %v", err)
	}
	if Path(KindBkcrack) == "" {
		t.Skip("没有内置 bkcrack，跳过")
	}

	// 换成一个内容不是可执行文件的假 bkcrack。
	broken := filepath.Join(dir, "broken", "bkcrack.exe")
	if err := os.MkdirAll(filepath.Dir(broken), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(broken, []byte("not a real executable"), 0o755); err != nil {
		t.Fatal(err)
	}
	mu.Lock()
	released[KindBkcrack] = broken
	mu.Unlock()

	ResetVerify()
	Verify()

	info, ok := InfoOf(KindBkcrack)
	if !ok {
		t.Fatal("InfoOf 找不到 bkcrack")
	}
	if info.Status != StatusNotRunnable {
		t.Fatalf("Status = %q，want %q", info.Status, StatusNotRunnable)
	}
	if info.Builtin {
		t.Error("起不来的版本不该算作可用")
	}
	if info.Runnable {
		t.Error("Runnable 应为 false")
	}
	if info.Detail == "" {
		t.Error("失败时必须给出具体原因")
	}
}

func TestProbeExecutableMissingFile(t *testing.T) {
	res := probeExecutable(filepath.Join(t.TempDir(), "nope.exe"))
	if res.ok {
		t.Fatal("不存在的文件不该探测通过")
	}
	if res.err == "" {
		t.Error("失败时要带上原因")
	}
}

func TestParseVersion(t *testing.T) {
	cases := map[string]string{
		"7-Zip 25.01 (x64)":             "25.01",
		"bkcrack 1.7.1 - 2024-01-31":    "1.7.1",
		"John the Ripper 1.9.0-jumbo-1": "1.9.0",
		"no version here":               "",
		"":                              "",
	}
	for in, want := range cases {
		if got := parseVersion(in); got != want {
			t.Errorf("parseVersion(%q) = %q，want %q", in, got, want)
		}
	}
}
