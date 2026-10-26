package settingservice

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/bliey/zipkit/internal/embedded"
	"github.com/bliey/zipkit/internal/settings"
)

// useConfig 把配置文件指到临时目录，避免动到用户真实的设置。
func useConfig(t *testing.T) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "config.json")
	settings.SetPath(path)
	t.Cleanup(func() {
		settings.SetPath("")
		os.Remove(path)
	})
	return path
}

// fakeTool 造一个名字像可执行文件的空文件，用来测试「填了一个路径」这条分支。
func fakeTool(t *testing.T, dir, name string) string {
	t.Helper()
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, []byte("stub"), 0o755); err != nil {
		t.Fatalf("写临时工具: %v", err)
	}
	return path
}

func TestSnapshotListsAllTools(t *testing.T) {
	useConfig(t)

	snap := (&SettingsService{}).Snapshot()
	// 5 个必需工具：7z / bkcrack / hashcat / rar2john / 7z2john（内建）。
	if len(snap.Tools) != 5 {
		t.Fatalf("Tools = %d 个, want 5", len(snap.Tools))
	}

	kinds := make([]string, 0, len(snap.Tools))
	for _, tool := range snap.Tools {
		kinds = append(kinds, tool.Kind)
		if tool.Label == "" {
			t.Errorf("%s 没有 label", tool.Kind)
		}
		if tool.Hint == "" {
			t.Errorf("%s 没有 hint", tool.Kind)
		}
	}
	// 7z2hashcat 与脚本解释器不在列表里：它们是可选备用路径，没有内置副本，
	// 列出来只会在面板上多两行「未找到」。
	want := []string{KindSevenZip, KindBkcrack, KindHashcat, KindRar2John, KindSevenZip2John}
	if strings.Join(kinds, ",") != strings.Join(want, ",") {
		t.Errorf("工具顺序 = %v, want %v", kinds, want)
	}

	if snap.NumCPU != runtime.NumCPU() {
		t.Errorf("NumCPU = %d, want %d", snap.NumCPU, runtime.NumCPU())
	}
	if snap.UnzipConcurrency < 1 {
		t.Errorf("UnzipConcurrency = %d", snap.UnzipConcurrency)
	}
	if snap.BatchConcurrency < 1 || snap.BatchConcurrency > runtime.NumCPU() {
		t.Errorf("BatchConcurrency = %d 超出范围", snap.BatchConcurrency)
	}
	if snap.ConfigPath == "" {
		t.Error("ConfigPath 为空")
	}
}

func TestSetPathKeepsBadPathVisible(t *testing.T) {
	useConfig(t)
	svc := &SettingsService{}

	if _, err := svc.SetPath("nope", "x"); err == nil {
		t.Fatal("未知的工具名应该报错")
	}

	// 路径照原样保存：面板上会显示红色「未找到」，功能入口跟着禁用。
	// 这里不回滚，用户才能看清「是我填的这条路径不对」。
	missing := filepath.Join(t.TempDir(), "nope.exe")
	snap, err := svc.SetPath(KindBkcrack, missing)
	if err != nil {
		t.Fatalf("SetPath: %v", err)
	}

	cfg := settings.Load()
	if cfg.BkcrackPath != missing {
		t.Errorf("BkcrackPath = %q, want %q", cfg.BkcrackPath, missing)
	}

	tool := toolByKind(snap, KindBkcrack)
	if tool == nil {
		t.Fatal("快照里没有 bkcrack")
	}
	if tool.Available {
		t.Error("不存在的路径不该判定为可用")
	}
	if tool.Path != missing {
		t.Errorf("Path = %q, want %q", tool.Path, missing)
	}

	// 清空即恢复自动探测。
	snap, err = svc.SetPath(KindBkcrack, "")
	if err != nil {
		t.Fatalf("清空路径: %v", err)
	}
	if cfg := settings.Load(); cfg.BkcrackPath != "" {
		t.Errorf("清空后 BkcrackPath = %q", cfg.BkcrackPath)
	}
}

// toolByKind 从快照里按种类取工具。
func toolByKind(snap Snapshot, kind string) *Tool {
	for i := range snap.Tools {
		if snap.Tools[i].Kind == kind {
			return &snap.Tools[i]
		}
	}
	return nil
}

func TestSetPathAcceptsRealExecutable(t *testing.T) {
	useConfig(t)
	svc := &SettingsService{}

	// bin/bkcrack.exe 是仓库里自带的，用它当「一个真实存在的可执行文件」。
	exe, err := filepath.Abs(filepath.Join("..", "..", "bin", "bkcrack.exe"))
	if err != nil {
		t.Fatalf("解析路径: %v", err)
	}
	if _, statErr := os.Stat(exe); statErr != nil {
		t.Skipf("仓库里没有 bin/bkcrack.exe：%v", statErr)
	}

	snap, err := svc.SetPath(KindBkcrack, exe)
	if err != nil {
		t.Fatalf("SetPath: %v", err)
	}

	var got *Tool
	for i := range snap.Tools {
		if snap.Tools[i].Kind == KindBkcrack {
			got = &snap.Tools[i]
		}
	}
	if got == nil {
		t.Fatal("快照里没有 bkcrack")
	}
	if !got.Available {
		t.Fatalf("bkcrack 应该可用：%s", got.Message)
	}
	if got.Path != exe {
		t.Errorf("Path = %q, want %q", got.Path, exe)
	}

	// 配置里也要落下来。
	if cfg := settings.Load(); cfg.BkcrackPath != exe {
		t.Errorf("配置里的 BkcrackPath = %q", cfg.BkcrackPath)
	}

	// 清空即恢复自动探测。
	snap, err = svc.SetPath(KindBkcrack, "")
	if err != nil {
		t.Fatalf("清空路径: %v", err)
	}
	if cfg := settings.Load(); cfg.BkcrackPath != "" {
		t.Errorf("清空后 BkcrackPath = %q", cfg.BkcrackPath)
	}
	_ = snap
}

func TestSetConcurrencyValidates(t *testing.T) {
	useConfig(t)
	svc := &SettingsService{}

	if _, err := svc.SetBatchConcurrency(0); err == nil {
		t.Error("并发数 0 应该被拒绝")
	}
	if _, err := svc.SetBatchConcurrency(runtime.NumCPU() + 1); err == nil {
		t.Error("超过 CPU 核数应该被拒绝")
	}
	if _, err := svc.SetBatchConcurrency(2); err != nil {
		t.Fatalf("SetBatchConcurrency(2): %v", err)
	}
	if cfg := settings.Load(); cfg.BatchConcurrency != 2 {
		t.Errorf("BatchConcurrency = %d, want 2", cfg.BatchConcurrency)
	}

	if _, err := svc.SetUnzipConcurrency(0); err == nil {
		t.Error("解压并发数 0 应该被拒绝")
	}
	if _, err := svc.SetUnzipConcurrency(9); err == nil {
		t.Error("解压并发数 9 应该被拒绝")
	}
	if _, err := svc.SetUnzipConcurrency(4); err != nil {
		t.Fatalf("SetUnzipConcurrency(4): %v", err)
	}
	if cfg := settings.Load(); cfg.Concurrency != 4 {
		t.Errorf("Concurrency = %d, want 4", cfg.Concurrency)
	}
}

func TestSetDefaultExportDir(t *testing.T) {
	useConfig(t)
	svc := &SettingsService{}

	dir := t.TempDir()
	if _, err := svc.SetDefaultExportDir(dir); err != nil {
		t.Fatalf("SetDefaultExportDir: %v", err)
	}
	if cfg := settings.Load(); cfg.DefaultExportDir != dir {
		t.Errorf("DefaultExportDir = %q, want %q", cfg.DefaultExportDir, dir)
	}

	if _, err := svc.SetDefaultExportDir(filepath.Join(dir, "nope")); err == nil {
		t.Error("不存在的目录应该被拒绝")
	}
	file := filepath.Join(dir, "a.txt")
	if err := os.WriteFile(file, []byte("x"), 0o644); err != nil {
		t.Fatalf("写文件: %v", err)
	}
	if _, err := svc.SetDefaultExportDir(file); err == nil {
		t.Error("文件路径应该被拒绝")
	}

	if _, err := svc.SetDefaultExportDir(""); err != nil {
		t.Fatalf("清空默认导出目录: %v", err)
	}
}

// 保存配置会推进版本号，各 Service 靠它发现「配置变了」并重新加载。
func TestSaveBumpsRevision(t *testing.T) {
	useConfig(t)

	before := settings.Revision()
	if err := settings.Save(settings.Load()); err != nil {
		t.Fatalf("Save: %v", err)
	}
	if settings.Revision() <= before {
		t.Errorf("Revision 没有递增：%d -> %d", before, settings.Revision())
	}
}

// 设置页底部的「关于」要用到版本号与内置清单，这里把契约钉住。
func TestSnapshotCarriesVersionAndBuiltinInfo(t *testing.T) {
	useConfig(t)
	embedded.SetVersion("9.9.9-test")
	embedded.Reset()
	t.Cleanup(func() {
		embedded.SetVersion("")
		embedded.Reset()
	})

	snap := (&SettingsService{}).Snapshot()
	if snap.Version != "9.9.9-test" {
		t.Errorf("Version = %q，want 9.9.9-test", snap.Version)
	}
	if len(snap.Builtin) == 0 {
		t.Fatal("Builtin 清单为空")
	}

	byKind := map[string]Tool{}
	for _, tool := range snap.Tools {
		byKind[tool.Kind] = tool
	}

	bkcrack := byKind[KindBkcrack]
	if !bkcrack.Bundled {
		t.Error("bkcrack 应该在内置清单里")
	}
	if bkcrack.BuiltinVersion != "1.8.1" {
		t.Errorf("bkcrack 内置版本 = %q", bkcrack.BuiltinVersion)
	}
	// 状态必须是四态之一，前端只认这个字段（测试环境没释放内置工具，
	// 所以这里多半是 missing，不能写死成 builtin）。
	switch bkcrack.State {
	case StateBuiltin, StateConfig, StateAuto, StateMissing:
	default:
		t.Errorf("bkcrack 状态 = %q，want builtin/config/auto/missing", bkcrack.State)
	}

	// hashcat 刻意不内置，不能出现在清单里。
	if byKind[KindHashcat].Bundled {
		t.Error("hashcat 不应该被内置")
	}
	if byKind[KindHashcat].State == StateBuiltin {
		t.Error("hashcat 不该显示成已内置")
	}
}

// TestToolStateAndMessage 校验三态文案：已内置（版本）/ 用户配置：路径 / 未找到。
// 设置页直接显示这几个字符串，改文案要先过这里。
func TestToolStateAndMessage(t *testing.T) {
	cases := []struct {
		name string
		tool Tool
		info embedded.Info
		want string
		text string
	}{
		{
			name: "内置",
			tool: Tool{Available: true, Source: "builtin", Resolved: "/c/tools/7z.exe"},
			info: embedded.Info{Builtin: true, Version: "25.01", Path: "/c/tools/7z.exe"},
			want: StateBuiltin,
			text: "已内置（25.01）",
		},
		{
			name: "用户配置",
			tool: Tool{Available: true, Source: "config", Path: "D:/x/bkcrack.exe", Resolved: "D:/x/bkcrack.exe"},
			info: embedded.Info{Builtin: true, Version: "1.8.1", Path: "/c/tools/bkcrack.exe"},
			want: StateConfig,
			text: "用户配置：D:/x/bkcrack.exe",
		},
		{
			name: "系统路径",
			tool: Tool{Available: true, Source: "auto", Resolved: "/usr/bin/hashcat"},
			want: StateAuto,
			text: "系统路径：/usr/bin/hashcat",
		},
		{
			name: "未找到",
			tool: Tool{},
			want: StateMissing,
			text: "未找到，需要手动指定",
		},
		{
			name: "内建实现",
			tool: Tool{Available: true, Source: "builtin"},
			info: embedded.Info{Builtin: true, Native: true, Version: "1.9.0-jumbo-1"},
			want: StateBuiltin,
			text: "已内置（程序内建实现，无需外部文件）",
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := stateOf(c.tool, c.info); got != c.want {
				t.Errorf("stateOf = %q，want %q", got, c.want)
			}
			c.tool.State = c.want
			if got := messageOf(c.tool, c.info); got != c.text {
				t.Errorf("messageOf = %q，want %q", got, c.text)
			}
		})
	}
}

// TestRestoreBuiltinRejectsNonBundled 确认「恢复为内置版本」不会作用在不内置的工具上。
func TestRestoreBuiltinRejectsNonBundled(t *testing.T) {
	useConfig(t)
	if _, err := (&SettingsService{}).RestoreBuiltin(KindHashcat); err == nil {
		t.Fatal("hashcat 没有内置版本，应当报错")
	}
	if _, err := (&SettingsService{}).RestoreBuiltin("不存在的工具"); err == nil {
		t.Fatal("未知工具应当报错")
	}
}
