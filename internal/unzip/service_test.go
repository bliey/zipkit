package unzip

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// useConfig 把配置换成一个临时文件并写入 cfg，用例结束后恢复。
func useConfig(t *testing.T, cfg Config) {
	t.Helper()

	SetConfigPath(filepath.Join(t.TempDir(), "config.json"))
	if err := SaveConfig(cfg); err != nil {
		t.Fatalf("写测试配置: %v", err)
	}
	t.Cleanup(func() {
		SetConfigPath(testConfigPath)
		SetSevenZipPath("")
	})
}

func waitIdle(t *testing.T, svc *UnzipService) {
	t.Helper()
	deadline := time.Now().Add(30 * time.Second)
	for time.Now().Before(deadline) {
		svc.mu.Lock()
		running := svc.running
		svc.mu.Unlock()
		if !running {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatal("解压任务没有在 30 秒内结束")
}

func TestStartUnzipRejectsEmptyInput(t *testing.T) {
	svc := &UnzipService{}

	if _, err := svc.StartUnzip(nil, t.TempDir()); err == nil {
		t.Error("没有任务时应该报错")
	}
	if _, err := svc.StartUnzip([]Job{{ZipPath: "a.zip"}}, "  "); err == nil {
		t.Error("没有导出目录时应该报错")
	}
}

func TestStartUnzipWithoutSevenZip(t *testing.T) {
	// 走真实路径：配置里写一个不存在的 7z，服务首次使用时会把它读进来。
	useConfig(t, Config{
		SevenZipPath: filepath.Join(t.TempDir(), "no-such-7z"),
		Layout:       LayoutPerZip,
		Concurrency:  DefaultConcurrency,
	})

	svc := &UnzipService{}
	dir := t.TempDir()
	_, err := svc.StartUnzip([]Job{{ZipPath: filepath.Join(dir, "a.zip")}}, dir)
	if err == nil {
		t.Fatal("没有 7z 时应该直接报错，而不是启动一个注定失败的任务")
	}
	if !strings.Contains(err.Error(), "7z") {
		t.Errorf("Err = %q, 应该提示 7z 缺失", err)
	}
}

func TestStartUnzipExtractsAndFinishes(t *testing.T) {
	requireSevenZip(t)

	dir := t.TempDir()
	zipPath := filepath.Join(dir, "微信账单_2024.zip")
	writeTestZip(t, zipPath, []testFile{{"a.txt", "alpha"}})

	svc := &UnzipService{}
	out := filepath.Join(dir, "微信账单_2024")
	id, err := svc.StartUnzip([]Job{{ZipPath: zipPath, OutputDir: out}}, dir)
	if err != nil {
		t.Fatalf("StartUnzip: %v", err)
	}
	if !strings.HasPrefix(id, "unzip-") {
		t.Errorf("任务 ID = %q", id)
	}

	waitIdle(t, svc)

	if _, err := os.Stat(filepath.Join(out, "a.txt")); err != nil {
		t.Errorf("文件没有解出来: %v", err)
	}
}

func TestStartUnzipRejectsSecondRun(t *testing.T) {
	requireSevenZip(t)

	dir := t.TempDir()
	zipPath := filepath.Join(dir, "a.zip")
	writeTestZip(t, zipPath, []testFile{{"a.txt", "alpha"}})

	svc := &UnzipService{}
	if _, err := svc.StartUnzip([]Job{{ZipPath: zipPath}}, dir); err != nil {
		t.Fatalf("第一次 StartUnzip: %v", err)
	}
	defer func() {
		_ = svc.StopUnzip()
		waitIdle(t, svc)
	}()

	if _, err := svc.StartUnzip([]Job{{ZipPath: zipPath}}, dir); err == nil {
		t.Error("已有任务在跑时，第二次 StartUnzip 应该报错")
	}
}

func TestStopUnzipWaitsForWorkers(t *testing.T) {
	requireSevenZip(t)

	dir := t.TempDir()
	zipPath := filepath.Join(dir, "a.zip")
	writeTestZip(t, zipPath, []testFile{{"a.txt", "alpha"}})

	svc := &UnzipService{}
	if _, err := svc.StartUnzip([]Job{{ZipPath: zipPath}, {ZipPath: zipPath}}, dir); err != nil {
		t.Fatalf("StartUnzip: %v", err)
	}

	if err := svc.StopUnzip(); err != nil {
		t.Fatalf("StopUnzip: %v", err)
	}

	svc.mu.Lock()
	running := svc.running
	svc.mu.Unlock()
	if running {
		t.Error("StopUnzip 返回后不应该还有任务在跑")
	}
}

func TestStopUnzipWithoutRunIsNoop(t *testing.T) {
	svc := &UnzipService{}
	if err := svc.StopUnzip(); err != nil {
		t.Errorf("空跑一次 StopUnzip 不该报错: %v", err)
	}
}

func TestSetSevenZipPathValidates(t *testing.T) {
	svc := &UnzipService{}
	if _, err := svc.SetSevenZipPath(filepath.Join(t.TempDir(), "missing-7z")); err == nil {
		t.Error("指向不存在的文件时应该报错")
	}
}

func TestSetSevenZipPathSavesConfig(t *testing.T) {
	requireSevenZip(t)

	sevenZip, err := ResolveSevenZip()
	if err != nil {
		t.Skipf("本机没有 7z: %v", err)
	}
	defer SetSevenZipPathForTest("")()

	svc := &UnzipService{}
	status, err := svc.SetSevenZipPath(sevenZip)
	if err != nil {
		t.Fatalf("SetSevenZipPath: %v", err)
	}
	if !status.Available {
		t.Error("保存后应该检测到 7z 可用")
	}
	if status.Source != "config" {
		t.Errorf("Source = %q, want config", status.Source)
	}

	if cfg := LoadConfig(); cfg.SevenZipPath != sevenZip {
		t.Errorf("配置里的路径 = %q, want %q", cfg.SevenZipPath, sevenZip)
	}
}

func TestSetLayout(t *testing.T) {
	svc := &UnzipService{}
	if err := svc.SetLayout(LayoutFlat); err != nil {
		t.Fatalf("SetLayout: %v", err)
	}
	if cfg := LoadConfig(); cfg.Layout != LayoutFlat {
		t.Errorf("配置里的布局 = %q, want flat", cfg.Layout)
	}
	if err := svc.SetLayout("weird"); err == nil {
		t.Error("未知布局应该报错")
	}
}

func TestOpenOutputDirRejectsMissingDir(t *testing.T) {
	svc := &UnzipService{}
	if err := svc.OpenOutputDir(filepath.Join(t.TempDir(), "nope")); err == nil {
		t.Error("目录不存在时应该报错")
	}
	if err := svc.OpenOutputDir(""); err == nil {
		t.Error("空目录时应该报错")
	}
}

func TestSnapshotKeepsLatestResult(t *testing.T) {
	svc := &UnzipService{}
	if got := svc.Snapshot(); len(got) != 0 {
		t.Fatalf("还没跑过任务时 Snapshot 应该为空，得到 %d 条", len(got))
	}

	svc.recordResult(ResultEvent{Path: "a.zip", Extracted: 1})
	svc.recordResult(ResultEvent{Path: "b.zip", Extracted: 2})
	svc.recordResult(ResultEvent{Path: "a.zip", Extracted: 3})

	snap := svc.Snapshot()
	if len(snap) != 2 {
		t.Fatalf("Snapshot 长度 = %d, want 2", len(snap))
	}

	byPath := make(map[string]int, len(snap))
	for _, ev := range snap {
		byPath[ev.Path] = ev.Extracted
	}
	if byPath["a.zip"] != 3 {
		t.Errorf("a.zip 应该保留最新一条结果，得到 %d", byPath["a.zip"])
	}
	if byPath["b.zip"] != 2 {
		t.Errorf("b.zip = %d, want 2", byPath["b.zip"])
	}
}

func TestConfigRoundTrip(t *testing.T) {
	path := filepath.Join(t.TempDir(), "cfg", "config.json")
	SetConfigPath(path)
	defer SetConfigPath(testConfigPath)

	want := Config{SevenZipPath: `C:\tools\7z.exe`, Layout: LayoutFlat, Concurrency: 5}
	if err := SaveConfig(want); err != nil {
		t.Fatalf("SaveConfig: %v", err)
	}
	got := LoadConfig()
	if got != want {
		t.Errorf("LoadConfig = %+v, want %+v", got, want)
	}

	// 损坏的配置不应该让调用方崩掉。
	if err := os.WriteFile(path, []byte("{not json"), 0o644); err != nil {
		t.Fatalf("写坏配置: %v", err)
	}
	if got := LoadConfig(); got.Layout != LayoutPerZip || got.Concurrency != DefaultConcurrency {
		t.Errorf("坏配置应该回落到默认值，得到 %+v", got)
	}
}

func TestConfigNormalize(t *testing.T) {
	cfg := Config{Layout: "???", Concurrency: 99}.Normalize()
	if cfg.Layout != LayoutPerZip {
		t.Errorf("Layout = %q, want %q", cfg.Layout, LayoutPerZip)
	}
	if cfg.Concurrency != DefaultConcurrency {
		t.Errorf("Concurrency = %d, want %d", cfg.Concurrency, DefaultConcurrency)
	}
}
