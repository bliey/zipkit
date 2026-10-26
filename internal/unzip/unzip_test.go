package unzip

import (
	"archive/zip"
	"context"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

// testdataZip 是 zcrack 的固定样本：单个 hello.txt，ZipCrypto 加密，密码 123456。
func testdataZip(t *testing.T, name string) string {
	t.Helper()
	path := filepath.Join("..", "zcrack", "testdata", name)
	abs, err := filepath.Abs(path)
	if err != nil {
		t.Fatalf("解析测试样本路径: %v", err)
	}
	if _, err := os.Stat(abs); err != nil {
		t.Fatalf("测试样本不存在 %s: %v", abs, err)
	}
	return abs
}

// requireSevenZip 让解压用例在没有 7z 的机器上跳过，而不是红一片。
func requireSevenZip(t *testing.T) {
	t.Helper()
	if _, err := ResolveSevenZip(); err != nil {
		t.Skipf("跳过：本机没有可用的 7z（%v）", err)
	}
}

type testFile struct {
	name    string
	content string
}

func writeTestZip(t *testing.T, path string, files []testFile) {
	t.Helper()

	f, err := os.Create(path)
	if err != nil {
		t.Fatalf("创建测试 ZIP: %v", err)
	}
	zw := zip.NewWriter(f)
	for _, file := range files {
		w, err := zw.Create(file.name)
		if err != nil {
			t.Fatalf("写入条目 %s: %v", file.name, err)
		}
		if _, err := w.Write([]byte(file.content)); err != nil {
			t.Fatalf("写入内容 %s: %v", file.name, err)
		}
	}
	if err := zw.Close(); err != nil {
		t.Fatalf("关闭 ZIP: %v", err)
	}
	if err := f.Close(); err != nil {
		t.Fatalf("关闭文件: %v", err)
	}
}

func TestExtractAllUnencrypted(t *testing.T) {
	requireSevenZip(t)

	dir := t.TempDir()
	zipPath := filepath.Join(dir, "账单_2024.zip")
	writeTestZip(t, zipPath, []testFile{
		{"a.txt", "alpha"},
		{"sub/b.txt", "beta"},
	})

	out := filepath.Join(dir, "out")
	res := ExtractAll(Job{ZipPath: zipPath, OutputDir: out})

	if res.Err != nil {
		t.Fatalf("ExtractAll 失败: %v", res.Err)
	}
	if res.Extracted != 2 {
		t.Errorf("Extracted = %d, want 2", res.Extracted)
	}
	if res.Skipped != 0 {
		t.Errorf("Skipped = %d, want 0", res.Skipped)
	}

	for _, name := range []string{"a.txt", "sub/b.txt"} {
		if _, err := os.Stat(filepath.Join(out, name)); err != nil {
			t.Errorf("缺少解压出来的 %s: %v", name, err)
		}
	}
	got, err := os.ReadFile(filepath.Join(out, "a.txt"))
	if err != nil {
		t.Fatalf("读取 a.txt: %v", err)
	}
	if string(got) != "alpha" {
		t.Errorf("a.txt = %q, want %q", got, "alpha")
	}
}

func TestExtractAllZipCryptoWithPassword(t *testing.T) {
	requireSevenZip(t)

	dir := t.TempDir()
	out := filepath.Join(dir, "out")
	res := ExtractAll(Job{
		ZipPath:   testdataZip(t, "real_zipcrypto.zip"),
		Password:  "123456",
		OutputDir: out,
	})

	if res.Err != nil {
		t.Fatalf("ExtractAll 失败: %v", res.Err)
	}
	if res.Extracted != 1 {
		t.Errorf("Extracted = %d, want 1", res.Extracted)
	}
	if _, err := os.Stat(filepath.Join(out, "hello.txt")); err != nil {
		t.Errorf("hello.txt 没有解出来: %v", err)
	}
}

func TestExtractAllWrongPassword(t *testing.T) {
	requireSevenZip(t)

	dir := t.TempDir()
	res := ExtractAll(Job{
		ZipPath:   testdataZip(t, "real_zipcrypto.zip"),
		Password:  "999999",
		OutputDir: filepath.Join(dir, "out"),
	})

	if res.Err == nil {
		t.Fatal("密码错误时应该返回 Err")
	}
	if !strings.Contains(res.Err.Error(), "密码错误") {
		t.Errorf("Err = %q, want 含「密码错误」", res.Err)
	}
	if res.Extracted != 0 {
		t.Errorf("Extracted = %d, want 0", res.Extracted)
	}
	if _, err := os.Stat(filepath.Join(dir, "out", "hello.txt")); err == nil {
		t.Error("密码错误却解出了 hello.txt")
	}
}

func TestExtractAllSkipsExistingFiles(t *testing.T) {
	requireSevenZip(t)

	dir := t.TempDir()
	zipPath := filepath.Join(dir, "dup.zip")
	writeTestZip(t, zipPath, []testFile{{"a.txt", "alpha"}, {"b.txt", "beta"}})

	out := filepath.Join(dir, "out")
	if res := ExtractAll(Job{ZipPath: zipPath, OutputDir: out}); res.Err != nil {
		t.Fatalf("第一次解压失败: %v", res.Err)
	}

	// 改一下磁盘上的内容，确认第二次没有覆盖。
	if err := os.WriteFile(filepath.Join(out, "a.txt"), []byte("keep-me"), 0o644); err != nil {
		t.Fatalf("改写 a.txt: %v", err)
	}

	res := ExtractAll(Job{ZipPath: zipPath, OutputDir: out})
	if res.Err != nil {
		t.Fatalf("第二次解压失败: %v", res.Err)
	}
	if res.Skipped != 2 {
		t.Errorf("Skipped = %d, want 2", res.Skipped)
	}
	if res.Extracted != 0 {
		t.Errorf("Extracted = %d, want 0", res.Extracted)
	}

	got, err := os.ReadFile(filepath.Join(out, "a.txt"))
	if err != nil {
		t.Fatalf("读取 a.txt: %v", err)
	}
	if string(got) != "keep-me" {
		t.Errorf("a.txt = %q, 已存在的文件被覆盖了", got)
	}
}

func TestExtractAllRenameExisting(t *testing.T) {
	requireSevenZip(t)

	dir := t.TempDir()
	zipPath := filepath.Join(dir, "dup.zip")
	writeTestZip(t, zipPath, []testFile{{"a.txt", "alpha"}})

	out := filepath.Join(dir, "out")
	if res := ExtractAll(Job{ZipPath: zipPath, OutputDir: out}); res.Err != nil {
		t.Fatalf("第一次解压失败: %v", res.Err)
	}

	res := ExtractAll(Job{ZipPath: zipPath, OutputDir: out, RenameExisting: true})
	if res.Err != nil {
		t.Fatalf("第二次解压失败: %v", res.Err)
	}
	if res.Skipped != 0 {
		t.Errorf("RenameExisting 模式下 Skipped = %d, want 0", res.Skipped)
	}

	// 7z -aou 的规则是给新解出来的文件加序号：a.txt → a_1.txt。
	if _, err := os.Stat(filepath.Join(out, "a_1.txt")); err != nil {
		t.Errorf("重名文件没有加 _1 后缀: %v", err)
	}
}

func TestExtractAllCreatesOutputDir(t *testing.T) {
	requireSevenZip(t)

	dir := t.TempDir()
	zipPath := filepath.Join(dir, "one.zip")
	writeTestZip(t, zipPath, []testFile{{"a.txt", "alpha"}})

	out := filepath.Join(dir, "deep", "nested", "out")
	res := ExtractAll(Job{ZipPath: zipPath, OutputDir: out})
	if res.Err != nil {
		t.Fatalf("ExtractAll 失败: %v", res.Err)
	}
	if info, err := os.Stat(out); err != nil || !info.IsDir() {
		t.Fatalf("输出目录没有创建: %v", err)
	}
}

func TestExtractAllMissingSevenZip(t *testing.T) {
	restore := SetSevenZipPathForTest(filepath.Join(t.TempDir(), "no-such-7z"))
	defer restore()

	dir := t.TempDir()
	zipPath := filepath.Join(dir, "one.zip")
	writeTestZip(t, zipPath, []testFile{{"a.txt", "alpha"}})

	res := ExtractAll(Job{ZipPath: zipPath, OutputDir: filepath.Join(dir, "out")})
	if res.Err == nil {
		t.Fatal("7z 不存在时应该报错")
	}
	if !errors.Is(res.Err, ErrSevenZipMissing) {
		t.Errorf("Err = %v, want ErrSevenZipMissing", res.Err)
	}
	if !strings.Contains(res.Err.Error(), "7z") {
		t.Errorf("错误提示里应该提到 7z：%v", res.Err)
	}
}

func TestExtractAllMissingZip(t *testing.T) {
	requireSevenZip(t)

	res := ExtractAll(Job{ZipPath: filepath.Join(t.TempDir(), "nope.zip"), OutputDir: t.TempDir()})
	if res.Err == nil || !strings.Contains(res.Err.Error(), "打开") {
		t.Fatalf("不存在的压缩包应该报错，得到 %v", res.Err)
	}
}

func TestExtractAllEmptyOutputDir(t *testing.T) {
	res := ExtractAll(Job{ZipPath: "whatever.zip"})
	if res.Err == nil || !strings.Contains(res.Err.Error(), "输出目录") {
		t.Fatalf("空输出目录应该报错，得到 %v", res.Err)
	}
}

func TestExtractContextCancelled(t *testing.T) {
	requireSevenZip(t)

	dir := t.TempDir()
	zipPath := filepath.Join(dir, "one.zip")
	writeTestZip(t, zipPath, []testFile{{"a.txt", strings.Repeat("x", 1024)}})

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // 一开始就取消

	res := ExtractContext(ctx, Job{ZipPath: zipPath, OutputDir: filepath.Join(dir, "out")})
	if res.Err == nil {
		t.Fatal("ctx 已取消时应该返回错误")
	}
	if !errors.Is(res.Err, context.Canceled) {
		t.Errorf("Err = %v, want context.Canceled", res.Err)
	}
}

// ---------------------------------------------------------------------------
// 参数拼装：AI 最容易在这里加空格或者拼字符串
// ---------------------------------------------------------------------------

func TestSevenZipArgs(t *testing.T) {
	args := sevenZipArgs(Job{
		ZipPath:   `C:\账单\微信.zip`,
		Password:  `a b&c|d"e`,
		OutputDir: `C:\导出\微信`,
	})

	joined := strings.Join(args, " ")
	if strings.Contains(joined, "-o ") || strings.Contains(joined, "-p ") {
		t.Fatalf("-o / -p 后面不能有空格：%v", args)
	}

	want := []string{
		"x", "-y", "-aos",
		`-pa b&c|d"e`,
		`-oC:\导出\微信`,
		`C:\账单\微信.zip`,
	}
	if len(args) != len(want) {
		t.Fatalf("args = %v, want %v", args, want)
	}
	for i := range want {
		if args[i] != want[i] {
			t.Errorf("args[%d] = %q, want %q", i, args[i], want[i])
		}
	}
}

func TestSevenZipArgsFlatAndEntry(t *testing.T) {
	args := sevenZipArgs(Job{ZipPath: "a.zip", OutputDir: "out", RenameExisting: true, EntryName: "x.txt"})

	if args[2] != "-aou" {
		t.Errorf("RenameExisting 时应该用 -aou，得到 %q", args[2])
	}
	if args[len(args)-1] != "x.txt" {
		t.Errorf("EntryName 应该作为最后一个参数，得到 %v", args)
	}
	for _, arg := range args {
		if strings.HasPrefix(arg, "-p") {
			t.Error("密码为空时不应该传 -p，否则 7z 会向终端要密码")
		}
	}
}

// ---------------------------------------------------------------------------
// 输出目录规则
// ---------------------------------------------------------------------------

func TestOutputDirFor(t *testing.T) {
	cases := []struct {
		zip  string
		want string
	}{
		{filepath.Join("d", "微信账单_2024.zip"), "微信账单_2024"},
		{filepath.Join("d", "备份.ZIP"), "备份"},
		{filepath.Join("d", "no-ext"), "no-ext"},
		{filepath.Join("d", "a:b*c.zip"), "a_b_c"},
	}
	for _, c := range cases {
		got := filepath.Base(OutputDirFor(filepath.Join("root"), c.zip))
		if got != c.want {
			t.Errorf("OutputDirFor(%q) = %q, want %q", c.zip, got, c.want)
		}
	}
}

func TestSanitizeDirName(t *testing.T) {
	cases := map[string]string{
		`  hello  `:              "hello",
		`a/b\c`:                  "a_b_c",
		`con<>|?*`:               "con_____",
		".":                      "",
		"  . .  ":                "",
		strings.Repeat("长", 200): strings.Repeat("长", 100),
	}
	for in, want := range cases {
		if got := sanitizeDirName(in); got != want {
			t.Errorf("sanitizeDirName(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestUniqueDirName(t *testing.T) {
	used := map[string]struct{}{}
	root := t.TempDir()

	first := uniqueDirName(root, "账单", used)
	second := uniqueDirName(root, "账单", used)
	third := uniqueDirName(root, "账单", used)

	if first != "账单" || second != "账单_1" || third != "账单_2" {
		t.Errorf("重名目录 = %q, %q, %q, want 账单 / 账单_1 / 账单_2", first, second, third)
	}
}

func TestPrepareJobsPerZip(t *testing.T) {
	root := t.TempDir()
	jobs := prepareJobs([]Job{
		{ZipPath: filepath.Join("x", "a.zip")},
		{ZipPath: filepath.Join("y", "a.zip")},
		{ZipPath: filepath.Join("z", "b.zip")},
	}, root, LayoutPerZip)

	if jobs[0].OutputDir != filepath.Join(root, "a") {
		t.Errorf("jobs[0].OutputDir = %q", jobs[0].OutputDir)
	}
	if jobs[1].OutputDir != filepath.Join(root, "a_1") {
		t.Errorf("同名压缩包应该加 _1，得到 %q", jobs[1].OutputDir)
	}
	if jobs[2].OutputDir != filepath.Join(root, "b") {
		t.Errorf("jobs[2].OutputDir = %q", jobs[2].OutputDir)
	}
}

func TestPrepareJobsFlat(t *testing.T) {
	root := t.TempDir()
	jobs := prepareJobs([]Job{
		{ZipPath: filepath.Join("x", "a.zip")},
		{ZipPath: filepath.Join("y", "b.zip")},
	}, root, LayoutFlat)

	for i, job := range jobs {
		if job.OutputDir != root {
			t.Errorf("jobs[%d].OutputDir = %q, want %q", i, job.OutputDir, root)
		}
		if !job.RenameExisting {
			t.Errorf("jobs[%d] 应该开启 RenameExisting", i)
		}
	}
}

// ---------------------------------------------------------------------------
// 输出解析
// ---------------------------------------------------------------------------

func TestSevenZipSummaryScan(t *testing.T) {
	output := strings.Join([]string{
		"",
		"7-Zip 25.01 (x64) : Copyright (c) 1999-2025 Igor Pavlov : 2025-08-03",
		"Scanning the drive for archives:",
		"Everything is Ok",
		"Files: 12",
		"Size:       20480",
		"Compressed: 4096",
		"",
	}, "\n")

	var summary sevenZipSummary
	summary.scan(strings.NewReader(output))

	if summary.files != 12 {
		t.Errorf("files = %d, want 12", summary.files)
	}
	if summary.subErrors != 0 {
		t.Errorf("subErrors = %d, want 0", summary.subErrors)
	}
}

func TestDescribeFailure(t *testing.T) {
	cases := []struct {
		name   string
		stdout string
		stderr string
		want   string
	}{
		{"密码错误", "", "ERROR: Wrong password : hello.txt", "密码错误"},
		{"数据错误", "Data Error in encrypted file. Wrong password?", "", "密码错误"},
		{"无权限", "", "ERROR: Access is denied.", "输出目录无写权限"},
		{"其他", "", "ERROR: Can not open file as archive", "解压失败"},
	}
	for _, c := range cases {
		err := describeFailure(2, c.stdout, c.stderr)
		if !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: err = %q, want 含 %q", c.name, err, c.want)
		}
		if !strings.Contains(err.Error(), "2") {
			t.Errorf("%s: 错误消息里应该带退出码：%q", c.name, err)
		}
	}
}

// SetSevenZipPathForTest 设置 7z 路径并返回恢复函数，避免用例之间互相污染。
func SetSevenZipPathForTest(path string) func() {
	previous := ConfiguredSevenZipPath()
	SetSevenZipPath(path)
	return func() { SetSevenZipPath(previous) }
}

// testConfigPath 是 TestMain 指定的配置文件位置，用例切换路径后要能切回来。
var testConfigPath string

func TestMain(m *testing.M) {
	// 配置文件写到临时目录，别污染真实的用户配置。
	dir, err := os.MkdirTemp("", "zipkit-unzip-test")
	if err == nil {
		testConfigPath = filepath.Join(dir, "config.json")
		SetConfigPath(testConfigPath)
	}
	code := m.Run()
	if err == nil {
		_ = os.RemoveAll(dir)
	}
	os.Exit(code)
}

func TestKillAllNoop(t *testing.T) {
	if runtime.GOOS == "js" {
		t.Skip("不支持")
	}
	if n := KillAll(); n != 0 {
		t.Errorf("没有在跑的任务时 KillAll = %d, want 0", n)
	}
}

// TestKillAllTerminatesProcess 验证 StopUnzip 依赖的进程终止真的有效：
// 光取消 context 的话 7z 可能还在往磁盘里写，界面会以为已经停了。
func TestKillAllTerminatesProcess(t *testing.T) {
	var cmd *exec.Cmd
	if runtime.GOOS == "windows" {
		cmd = exec.Command("ping", "-n", "10", "127.0.0.1")
	} else {
		cmd = exec.Command("sleep", "10")
	}
	cmd.Stdout = io.Discard

	if err := cmd.Start(); err != nil {
		t.Skipf("启动测试进程失败: %v", err)
	}
	untrack := trackCommand(cmd)
	defer untrack()

	start := time.Now()
	if n := KillAll(); n != 1 {
		t.Fatalf("KillAll = %d, want 1", n)
	}
	if err := cmd.Wait(); err == nil {
		t.Error("被 kill 的进程 Wait 应该返回错误")
	}
	if elapsed := time.Since(start); elapsed > 5*time.Second {
		t.Errorf("KillAll 之后进程没有及时退出：%v", elapsed)
	}
}
