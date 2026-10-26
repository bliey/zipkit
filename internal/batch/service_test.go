package batch

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// ---------------------------------------------------------------------------
// 适用性判定
// ---------------------------------------------------------------------------

func TestClassifyZipCrypto(t *testing.T) {
	cases := []struct {
		path  string
		entry string
	}{
		{"../zcrack/testdata/num6.zip", "hello.txt"},
		{"../zcrack/testdata/store6.zip", "hello.txt"},
		{"../zcrack/testdata/descriptor6.zip", "hello.txt"},
		{"../zcrack/testdata/multi.zip", "secret.txt"},
		{"../zcrack/testdata/leadingzero_desc6.zip", "hello.txt"},
	}
	for _, c := range cases {
		fi := classify(c.path)
		if fi.Err != "" {
			t.Fatalf("%s: 不应有解析错误: %s", c.path, fi.Err)
		}
		if !fi.Applicable {
			t.Fatalf("%s: 应判定为可破解，实际跳过原因 %q", c.path, fi.SkipReason)
		}
		if fi.EntryName != c.entry {
			t.Fatalf("%s: 选中条目应为 %q，实际 %q", c.path, c.entry, fi.EntryName)
		}
		if fi.EncryptionType != "ZipCrypto" && fi.EncryptionType != "Mixed" {
			t.Fatalf("%s: 加密类型异常 %q", c.path, fi.EncryptionType)
		}
	}
}

func TestClassifySkips(t *testing.T) {
	cases := []struct {
		path   string
		reason string
	}{
		{"../zcrack/testdata/aes.zip", SkipAES},
		{"../zcrack/testdata/real_aes.zip", SkipAES},
	}
	for _, c := range cases {
		fi := classify(c.path)
		if fi.Applicable {
			t.Fatalf("%s: AES 归档不应进入破解队列", c.path)
		}
		if fi.SkipReason != c.reason {
			t.Fatalf("%s: 跳过原因应为 %q，实际 %q", c.path, c.reason, fi.SkipReason)
		}
	}
}

func TestClassifyNotAZip(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "note.txt")
	if err := os.WriteFile(p, []byte("这不是压缩包\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	fi := classify(p)
	if fi.Applicable {
		t.Fatal("普通文本文件不应进入破解队列")
	}
	if fi.Err != "" {
		t.Fatalf("非 ZIP 不应算解析失败: %s", fi.Err)
	}
	if fi.SkipReason != SkipUnsupported {
		t.Fatalf("跳过原因应为 %q，实际 %q", SkipUnsupported, fi.SkipReason)
	}
}

func TestClassifyMissingFile(t *testing.T) {
	fi := classify(filepath.Join(t.TempDir(), "nope.zip"))
	if fi.Applicable {
		t.Fatal("不存在的文件不应进入破解队列")
	}
	if fi.Err == "" {
		t.Fatal("打开失败应记录错误")
	}
}

// ---------------------------------------------------------------------------
// 回归：前导零密码走完整批量链路
//
// 用户反馈的真实 bug：微信账单 ZIP（ZipCrypto + 数据描述符 + Deflate，密码
// 052092）在批量模式解不出来，hashcat 能解。根因是 zcrack.buildUnits 的首位
// 只枚举 '1'..'9'，0 开头的候选全部被跳过。这里从 classify 一路测到
// BatchRunner，确保整条链路都能拿到这个密码。
// ---------------------------------------------------------------------------

const leadingZeroDescZip = "../zcrack/testdata/leadingzero_desc6.zip"

func TestClassifyLeadingZeroEntry(t *testing.T) {
	fi := classify(leadingZeroDescZip)
	if fi.Err != "" {
		t.Fatalf("不应有解析错误: %s", fi.Err)
	}
	if !fi.Applicable {
		t.Fatalf("应判定为可破解，实际跳过原因 %q", fi.SkipReason)
	}
	if fi.EntryName != "hello.txt" {
		t.Fatalf("选中条目应为 hello.txt，实际 %q", fi.EntryName)
	}
}

func TestCrackOneLeadingZeroPassword(t *testing.T) {
	svc := &BatchService{}
	got, err := svc.CrackOne(leadingZeroDescZip, 6, 6)
	if err != nil {
		t.Fatalf("CrackOne 返回错误: %v", err)
	}
	if got.Err != "" {
		t.Fatalf("不应有内部错误: %s", got.Err)
	}
	if !got.Found || got.Password != "052092" {
		t.Fatalf("期望找到 052092，实际 Found=%v Password=%q", got.Found, got.Password)
	}
}

func TestBatchRunnerLeadingZeroPassword(t *testing.T) {
	runner := NewBatchRunner(1)
	defer runner.Stop()

	tasks := []FileTask{{Path: leadingZeroDescZip, EntryName: "hello.txt", MinLen: 6, MaxLen: 6}}
	var results []FileResult
	for res := range runner.Run(context.Background(), tasks) {
		results = append(results, res)
	}

	if len(results) != 1 {
		t.Fatalf("应收到 1 条结果，实际 %d 条", len(results))
	}
	r := results[0]
	if r.Err != nil {
		t.Fatalf("意外错误: %v", r.Err)
	}
	if !r.Found || r.Password != "052092" {
		t.Fatalf("期望找到 052092，实际 Found=%v Password=%q", r.Found, r.Password)
	}
}

// ---------------------------------------------------------------------------
// CSV 导出
// ---------------------------------------------------------------------------

func TestExportCSVHasBOMAndRows(t *testing.T) {
	target := filepath.Join(t.TempDir(), "batch.csv")
	rows := []ExportRow{
		{Name: "微信账单_2024.zip", Status: "已找到", Detail: "123456"},
		{Name: "某备份.zip", Status: "跳过", Detail: "AES 加密"},
		{Name: "某文档.zip", Status: "未找到", Detail: "6–8 位纯数字内无匹配"},
	}

	svc := &BatchService{}
	if err := svc.ExportCSV(target, rows); err != nil {
		t.Fatal(err)
	}

	raw, err := os.ReadFile(target)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.HasPrefix(raw, []byte{0xEF, 0xBB, 0xBF}) {
		t.Fatal("CSV 缺少 UTF-8 BOM，Excel 会把中文显示成乱码")
	}

	text := string(raw[3:])
	if !strings.HasPrefix(text, "文件名,状态,密码/原因\r\n") {
		t.Fatalf("表头不正确: %q", strings.SplitN(text, "\r\n", 2)[0])
	}
	for _, want := range []string{
		"微信账单_2024.zip,已找到,123456",
		"某备份.zip,跳过,AES 加密",
		"某文档.zip,未找到,6–8 位纯数字内无匹配",
	} {
		if !strings.Contains(text, want) {
			t.Fatalf("CSV 缺少行 %q，实际内容：\n%s", want, text)
		}
	}
}

func TestExportCSVRejectsEmpty(t *testing.T) {
	svc := &BatchService{}
	if err := svc.ExportCSV("", []ExportRow{{Name: "a"}}); err == nil {
		t.Fatal("空路径应报错")
	}
	if err := svc.ExportCSV(filepath.Join(t.TempDir(), "x.csv"), nil); err == nil {
		t.Fatal("空结果应报错")
	}
}

// ---------------------------------------------------------------------------
// 并发数
// ---------------------------------------------------------------------------

func TestSetConcurrencyRange(t *testing.T) {
	svc := &BatchService{}
	if _, err := svc.SetConcurrency(0); err == nil {
		t.Fatal("并发数 0 应被拒绝")
	}
	if _, err := svc.SetConcurrency(-1); err == nil {
		t.Fatal("负数应被拒绝")
	}
	if _, err := svc.SetConcurrency(9999); err == nil {
		t.Fatal("超过 NumCPU 应被拒绝")
	}
	got, err := svc.SetConcurrency(1)
	if err != nil || got != 1 {
		t.Fatalf("设置并发数 1 失败: %d %v", got, err)
	}
	if d := svc.Defaults(); d.Concurrency != 1 {
		t.Fatalf("Defaults 应返回刚设置的值，实际 %d", d.Concurrency)
	}
}

func TestDefaultConcurrencyLeavesOneCore(t *testing.T) {
	n := runtime.NumCPU()
	d := defaultConcurrency()
	if d < 1 || d > n {
		t.Fatalf("默认并发数 %d 越界（NumCPU=%d）", d, n)
	}
	if n >= 3 && d != n-1 {
		t.Fatalf("多核机器默认并发数应为 NumCPU-1=%d，实际 %d", n-1, d)
	}
	if n == 2 && d != 2 {
		t.Fatalf("双核机器默认并发数不应小于 2，实际 %d", d)
	}
}

// ---------------------------------------------------------------------------
// 拖放目录展开用的 ListDir（阶段 9）
// ---------------------------------------------------------------------------

func TestListDirSeparatesFilesAndDirs(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "a.zip"), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(root, "sub"), 0o755); err != nil {
		t.Fatal(err)
	}
	// 资源管理器生成的垃圾文件不该出现在批量列表里。
	if err := os.WriteFile(filepath.Join(root, "Thumbs.db"), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}

	s := &BatchService{}
	got := s.ListDir(root)

	if !got.IsDir {
		t.Fatalf("IsDir = false, want true")
	}
	if got.Err != "" {
		t.Fatalf("Err = %q, want empty", got.Err)
	}
	if len(got.Files) != 1 || filepath.Base(got.Files[0]) != "a.zip" {
		t.Fatalf("Files = %v, want [a.zip]", got.Files)
	}
	if len(got.Dirs) != 1 || filepath.Base(got.Dirs[0]) != "sub" {
		t.Fatalf("Dirs = %v, want [sub]", got.Dirs)
	}
}

func TestListDirOnPlainFileReportsNotDir(t *testing.T) {
	root := t.TempDir()
	file := filepath.Join(root, "a.zip")
	if err := os.WriteFile(file, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}

	got := (&BatchService{}).ListDir(file)
	if got.IsDir {
		t.Fatalf("普通文件的 IsDir 应为 false")
	}
	if got.Err != "" {
		t.Fatalf("普通文件不算错误，Err = %q", got.Err)
	}
	if got.Files == nil || got.Dirs == nil {
		t.Fatalf("两个切片都要是非 nil，方便前端直接用")
	}
}

func TestListDirOnMissingPathReportsErr(t *testing.T) {
	got := (&BatchService{}).ListDir(filepath.Join(t.TempDir(), "nope"))
	if got.Err == "" {
		t.Fatalf("不存在的路径要带上 Err")
	}
}
