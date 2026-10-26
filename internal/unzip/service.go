package unzip

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/wailsapp/wails/v3/pkg/application"

	"github.com/bliey/zipkit/internal/executil"
	"github.com/bliey/zipkit/internal/settings"
)

// 事件名。前端只认这三个，字段与下面的结构体一一对应。
const (
	EventStart  = "unzip-start"  // 某个文件开始解压，用于显示「当前：xxx.zip」
	EventResult = "unzip-result" // 某个文件解压完成
	EventDone   = "unzip-done"   // 整批结束（含取消）
)

// Defaults 是前端初始化需要的默认值。
type Defaults struct {
	Concurrency int            `json:"concurrency"`
	Layout      string         `json:"layout"`
	SevenZip    SevenZipStatus `json:"sevenZip"`
}

// StartEvent 是 unzip-start 的负载。
type StartEvent struct {
	Path string `json:"path"`
	Name string `json:"name"`
}

// ResultEvent 是 unzip-result 的负载。
//
// Result.Err 是 error 接口，直接序列化只会得到 {}，所以事件单独用一份可以
// 直接展示的字符串。
type ResultEvent struct {
	Path      string `json:"path"`
	Name      string `json:"name"`
	OutputDir string `json:"outputDir"`
	Extracted int    `json:"extracted"`
	Failed    int    `json:"failed"`
	Skipped   int    `json:"skipped"`
	Err       string `json:"err"`
	Cancelled bool   `json:"cancelled"`
}

// DoneEvent 是 unzip-done 的负载。
type DoneEvent struct {
	Cancelled bool  `json:"cancelled"`
	Completed int   `json:"completed"`
	Total     int   `json:"total"`
	Succeeded int   `json:"succeeded"`
	Failed    int   `json:"failed"`
	Skipped   int   `json:"skipped"`
	ElapsedMs int64 `json:"elapsedMs"`
}

// UnzipService 是绑定到前端的批量解压服务。
type UnzipService struct {
	startMu sync.Mutex // 串行化 StartUnzip

	mu      sync.Mutex
	cfg     Config
	loaded  bool
	rev     int64
	running bool
	cancel  context.CancelFunc
	done    chan struct{}

	// lastResults 保存最近一次运行里每个文件的最终结果。事件是异步送达的，
	// 前端收尾时用 Snapshot 对一次账，避免某条 unzip-result 掉队导致某一行
	// 一直停在「解压中…」。
	lastResults []ResultEvent
	lastIndex   map[string]int
}

// ensureConfigLocked 懒加载配置文件，调用方必须持有 s.mu。
//
// 配置被别处改过（设置面板保存）时靠 settings.Revision 发现并重新加载，
// 这样改完设置不用重启程序。
func (s *UnzipService) ensureConfigLocked() Config {
	rev := settings.Revision()
	if !s.loaded || s.rev != rev {
		s.cfg = LoadConfig()
		s.loaded = true
		s.rev = rev
		// 配置里的 7z 路径是持久的，进程内的解析器也要同步。
		SetSevenZipPath(s.cfg.SevenZipPath)
	}
	return s.cfg
}

// Defaults 返回并发数、布局和 7z 状态，前端初始化时调用一次。
func (s *UnzipService) Defaults() Defaults {
	s.mu.Lock()
	cfg := s.ensureConfigLocked()
	s.mu.Unlock()

	return Defaults{
		Concurrency: cfg.Concurrency,
		Layout:      cfg.Layout,
		SevenZip:    DetectSevenZip(),
	}
}

// SevenZip 重新检测 7z，供「重新检测」按钮使用。
//
// 先把配置读进来：配置文件里的 7z 路径是这个方法的唯一数据来源，没加载
// 配置就检测的话，用户指定过的路径会被当成「没设置」。
func (s *UnzipService) SevenZip() SevenZipStatus {
	s.mu.Lock()
	s.ensureConfigLocked()
	s.mu.Unlock()

	return DetectSevenZip()
}

// SetSevenZipPath 校验并保存用户手动指定的 7z 路径。传空字符串表示恢复自动探测。
func (s *UnzipService) SetSevenZipPath(path string) (SevenZipStatus, error) {
	path = strings.TrimSpace(path)
	if path != "" {
		if _, ok := lookExecutable(path); !ok {
			return DetectSevenZip(), fmt.Errorf("unzip: %q 不是一个可执行文件", path)
		}
	}

	s.mu.Lock()
	cfg := s.ensureConfigLocked()
	cfg.SevenZipPath = path
	s.cfg = cfg
	s.mu.Unlock()

	SetSevenZipPath(path)
	if err := SaveConfig(cfg); err != nil {
		return DetectSevenZip(), fmt.Errorf("unzip: 保存配置失败：%w", err)
	}
	return DetectSevenZip(), nil
}

// SetLayout 切换解压目录布局（per-zip / flat）。
func (s *UnzipService) SetLayout(layout string) error {
	if layout != LayoutPerZip && layout != LayoutFlat {
		return fmt.Errorf("unzip: 未知的目录布局 %q", layout)
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	cfg := s.ensureConfigLocked()
	if s.running {
		return errors.New("unzip: 解压进行中，不能修改目录布局")
	}
	cfg.Layout = layout
	s.cfg = cfg
	return SaveConfig(cfg)
}

// StartUnzip 启动一批解压任务，返回本次任务的 ID。
//
// 只有调用方传进来的 Job 才会被执行：密码没找到、AES 加密的文件在批量
// 破解阶段就已经被排除，这里不做二次判断，避免两边规则不一致。
func (s *UnzipService) StartUnzip(jobs []Job, rootDir string) (string, error) {
	s.startMu.Lock()
	defer s.startMu.Unlock()

	rootDir = strings.TrimSpace(rootDir)
	if rootDir == "" {
		return "", errors.New("unzip: 没有选择导出目录")
	}
	if len(jobs) == 0 {
		return "", errors.New("unzip: 没有需要解压的文件")
	}

	s.mu.Lock()
	cfg := s.ensureConfigLocked()
	s.mu.Unlock()

	// 配置加载完再解析 7z，否则用户手动指定的路径不会生效。
	if _, err := ResolveSevenZip(); err != nil {
		return "", err
	}

	s.mu.Lock()
	if s.running {
		s.mu.Unlock()
		return "", errors.New("unzip: 已有解压任务在运行")
	}
	s.running = true
	s.lastResults = make([]ResultEvent, 0, len(jobs))
	s.lastIndex = make(map[string]int, len(jobs))

	ctx, cancel := context.WithCancel(context.Background())
	s.cancel = cancel
	done := make(chan struct{})
	s.done = done
	s.mu.Unlock()

	prepared := prepareJobs(jobs, rootDir, cfg.Layout)

	concurrency := cfg.Concurrency
	if concurrency < 1 {
		concurrency = DefaultConcurrency
	}
	if concurrency > len(prepared) {
		concurrency = len(prepared)
	}

	go s.run(ctx, cancel, prepared, concurrency, done)
	return fmt.Sprintf("unzip-%d", time.Now().UnixNano()), nil
}

// StopUnzip 取消当前解压，杀掉还在跑的 7z，并等所有 goroutine 退出。
func (s *UnzipService) StopUnzip() error {
	s.mu.Lock()
	cancel, done := s.cancel, s.done
	s.mu.Unlock()

	if cancel == nil {
		return nil
	}
	cancel()
	// 只取消 context 不够：7z 可能正在写盘，进程要直接杀掉。
	KillAll()

	if done != nil {
		<-done
	}
	return nil
}

// OpenOutputDir 用系统文件管理器打开解压目录。
func (s *UnzipService) OpenOutputDir(dir string) error {
	dir = strings.TrimSpace(dir)
	if dir == "" {
		return errors.New("unzip: 目录为空")
	}
	info, err := os.Stat(dir)
	if err != nil {
		return fmt.Errorf("unzip: 目录不可用：%w", err)
	}
	if !info.IsDir() {
		return fmt.Errorf("unzip: %q 不是目录", dir)
	}

	var cmd *exec.Cmd
	switch runtime.GOOS {
	case "windows":
		cmd = executil.Command("explorer", dir)
	case "darwin":
		cmd = executil.Command("open", dir)
	default:
		cmd = executil.Command("xdg-open", dir)
	}
	if err := cmd.Start(); err != nil {
		return fmt.Errorf("unzip: 打开目录失败：%w", err)
	}
	// explorer 即使成功也常返回非 0，退出码不作为判断依据。
	go func() { _ = cmd.Wait() }()
	return nil
}

// run 是真正跑批的地方：信号量限流 + 事件推送 + 收尾。
//
// 所有事件都走同一个 channel、由同一个 goroutine 发出去。Wails 的 Emit 是
// 异步的，如果每个 worker 各自 emit，「unzip-done」有可能比某个「unzip-result」
// 先到前端，界面就会短暂显示「解压完成但某行还在解压中」。串行发送把顺序
// 钉死：start → result → … → done。
func (s *UnzipService) run(ctx context.Context, cancel context.CancelFunc, jobs []Job, concurrency int, done chan struct{}) {
	defer close(done)
	defer cancel()

	started := time.Now()
	sem := make(chan struct{}, concurrency)
	events := make(chan any, concurrency*2)

	var wg sync.WaitGroup
	wg.Add(len(jobs))

	for _, job := range jobs {
		go func(job Job) {
			defer wg.Done()

			// 信号量限流：拿不到槽位就等着，而不是一口气开一堆 7z。
			select {
			case sem <- struct{}{}:
				defer func() { <-sem }()
			case <-ctx.Done():
				return
			}

			select {
			case events <- StartEvent{Path: job.ZipPath, Name: filepath.Base(job.ZipPath)}:
			case <-ctx.Done():
				return
			}

			res := ExtractContext(ctx, job)

			ev := ResultEvent{
				Path:      job.ZipPath,
				Name:      filepath.Base(job.ZipPath),
				OutputDir: job.OutputDir,
				Extracted: res.Extracted,
				Failed:    res.Failed,
				Skipped:   res.Skipped,
			}
			switch {
			case errors.Is(res.Err, context.Canceled), errors.Is(res.Err, context.DeadlineExceeded):
				ev.Cancelled = true
				ev.Err = "已停止"
			case res.Err != nil:
				ev.Err = res.Err.Error()
			}

			select {
			case events <- ev:
			case <-ctx.Done():
			}
		}(job)
	}

	go func() {
		wg.Wait()
		close(events)
	}()

	app := application.Get()
	emit := func(name string, data any) {
		if app != nil {
			app.Event.Emit(name, data)
		}
	}

	var (
		completed int
		succeeded int
		failed    int
		skipped   int
	)
	for event := range events {
		switch ev := event.(type) {
		case StartEvent:
			emit(EventStart, ev)
		case ResultEvent:
			if !ev.Cancelled {
				completed++
			}
			switch {
			case ev.Cancelled:
			case ev.Err != "":
				failed++
			default:
				succeeded++
			}
			skipped += ev.Skipped
			s.recordResult(ev)
			emit(EventResult, ev)
		}
	}

	stats := DoneEvent{
		Cancelled: ctx.Err() != nil,
		Completed: completed,
		Total:     len(jobs),
		Succeeded: succeeded,
		Failed:    failed,
		Skipped:   skipped,
		ElapsedMs: time.Since(started).Milliseconds(),
	}

	s.mu.Lock()
	s.running = false
	s.cancel = nil
	s.done = nil
	s.mu.Unlock()

	emit(EventDone, stats)
}

// recordResult 把一条结果记进 lastResults（同一路径只保留最新一条）。
func (s *UnzipService) recordResult(ev ResultEvent) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.lastIndex == nil {
		s.lastIndex = make(map[string]int, 1)
	}
	if i, ok := s.lastIndex[ev.Path]; ok {
		s.lastResults[i] = ev
		return
	}
	s.lastIndex[ev.Path] = len(s.lastResults)
	s.lastResults = append(s.lastResults, ev)
}

// Snapshot 返回最近一次运行里每个文件的最终结果。
//
// 前端在收到 unzip-done 之后调用一次，用这份权威数据把列表对齐——事件是
// 异步送达的，不能保证「最后一条结果」一定在 done 之前到达。
func (s *UnzipService) Snapshot() []ResultEvent {
	s.mu.Lock()
	defer s.mu.Unlock()

	out := make([]ResultEvent, len(s.lastResults))
	copy(out, s.lastResults)
	return out
}

// prepareJobs 按布局给每个 Job 分配输出目录。
//
// per-zip：每个压缩包一个子目录，子目录名 = 文件名去掉扩展名。同一批里出现
// 同名压缩包时，后面的加 _1、_2——否则两个 7z 会往同一个目录里写。
// flat：全部落到根目录，重名文件交给 7z 的 -aou 自动改名。
func prepareJobs(jobs []Job, rootDir, layout string) []Job {
	out := make([]Job, 0, len(jobs))
	used := make(map[string]struct{}, len(jobs))

	for _, job := range jobs {
		prepared := job
		if layout == LayoutFlat {
			prepared.OutputDir = rootDir
			prepared.RenameExisting = true
			out = append(out, prepared)
			continue
		}

		if strings.TrimSpace(prepared.OutputDir) == "" {
			name := uniqueDirName(rootDir, dirNameFor(prepared.ZipPath), used)
			prepared.OutputDir = filepath.Join(rootDir, name)
		} else {
			used[entryKey(prepared.OutputDir)] = struct{}{}
		}
		out = append(out, prepared)
	}
	return out
}
