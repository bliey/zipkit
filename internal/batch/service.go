package batch

import (
	"context"
	"encoding/csv"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/wailsapp/wails/v3/pkg/application"

	"github.com/bliey/zipkit/internal/settings"
	"github.com/bliey/zipkit/internal/zcrack"
	"github.com/bliey/zipkit/internal/zipservice"
)

// maxPasswordLen 与 zcrack 内部的上限保持一致；超过这个长度的纯数字枚举
// 没有实际意义，前端也不会允许输入。
const maxPasswordLen = 20

// errBatchCancelled 表示侦察阶段就被 StopBatch 取消，批次没有真正启动。
var errBatchCancelled = errors.New("batch: 已取消")

// FileInfo 是批量视图里「文件列表」一行的数据。
//
// 判定逻辑全部放在 Go 侧，前端只负责展示：StartBatch 和 InspectFile 走的是
// 同一个 classify，因此列表里显示「等待」的文件一定会进破解队列。
type FileInfo struct {
	Path           string `json:"path"`
	Name           string `json:"name"`
	Size           int64  `json:"size"`
	Format         string `json:"format"`
	EncryptionType string `json:"encryptionType"`
	EntryCount     int    `json:"entryCount"`
	Applicable     bool   `json:"applicable"`
	SkipReason     string `json:"skipReason"`
	EntryName      string `json:"entryName"`
	Err            string `json:"err"`
}

// ResultEvent 是 batch-result 事件的负载。FileResult 里的 Err 是 error
// 接口，直接扔给 JSON 只会得到 {}，所以事件单独用一份可序列化的结构。
type ResultEvent struct {
	Path       string `json:"path"`
	Name       string `json:"name"`
	Password   string `json:"password"`
	Found      bool   `json:"found"`
	Skipped    bool   `json:"skipped"`
	SkipReason string `json:"skipReason"`
}

// ErrorEvent 是 batch-error 事件的负载。
type ErrorEvent struct {
	Path    string `json:"path"`
	Name    string `json:"name"`
	Message string `json:"message"`
}

// DoneEvent 是 batch-done 事件的负载。取消与正常完成都会发这个事件，
// Cancelled 用来区分两者。
type DoneEvent struct {
	Cancelled bool  `json:"cancelled"`
	Completed int   `json:"completed"`
	Total     int   `json:"total"`
	ElapsedMs int64 `json:"elapsedMs"`
}

// ExportRow 是导出 CSV 的一行：文件名、状态、密码/原因。
type ExportRow struct {
	Name   string `json:"name"`
	Status string `json:"status"`
	Detail string `json:"detail"`
}

// Defaults 是前端初始化控制条需要的默认值。
type Defaults struct {
	Concurrency    int `json:"concurrency"`
	NumCPU         int `json:"numCPU"`
	MinLen         int `json:"minLen"`
	MaxLen         int `json:"maxLen"`
	MaxPasswordLen int `json:"maxPasswordLen"`
}

// BatchService 是绑定到前端的批量破解服务。
type BatchService struct {
	startMu sync.Mutex // 串行化 StartBatch，避免两个批次同时启动

	mu          sync.Mutex
	concurrency int
	rev         int64
	running     bool
	runner      *BatchRunner
	cancel      context.CancelFunc
}

// defaultConcurrency 留一个核心给界面和系统，最少 2 个。
func defaultConcurrency() int {
	n := runtime.NumCPU() - 1
	if n < 2 {
		n = 2
	}
	if cores := runtime.NumCPU(); n > cores {
		n = cores
	}
	return n
}

func (s *BatchService) concurrencyValue() int {
	s.mu.Lock()
	defer s.mu.Unlock()

	// 设置面板改过并发数时以配置文件为准。用 Revision 判断，避免每次调用
	// 都去读文件，也避免把界面上临时调的值覆盖掉。
	if rev := settings.Revision(); s.rev != rev {
		if n := settings.Load().BatchConcurrency; n > 0 {
			s.concurrency = n
		}
		s.rev = rev
	}
	if s.concurrency == 0 {
		s.concurrency = defaultConcurrency()
	}
	return s.concurrency
}

// CrackOneResult 是单文件「快速弱密码检测」的结果。
type CrackOneResult struct {
	Password  string `json:"password"`
	Found     bool   `json:"found"`
	MinLen    int    `json:"minLen"`
	MaxLen    int    `json:"maxLen"`
	ElapsedMs int64  `json:"elapsedMs"`
	Skip      string `json:"skip"`
	Err       string `json:"err"`
}

// CrackOne 对单个文件跑一次纯数字弱密码检测，同步返回结果。
//
// 这是单文件视图里的「快速弱密码检测」按钮用的：范围默认 1–6 位，几秒钟
// 就能出结果，适合先排除「密码就是 123456」这类情况，再决定要不要上明文
// 攻击或 GPU。范围上限仍然是 maxPasswordLen。
func (s *BatchService) CrackOne(path string, minLen, maxLen int) (CrackOneResult, error) {
	if strings.TrimSpace(path) == "" {
		return CrackOneResult{}, errors.New("batch: 没有指定文件")
	}
	if minLen < 1 || maxLen < minLen || maxLen > maxPasswordLen {
		return CrackOneResult{}, fmt.Errorf("batch: 密码长度范围无效（%d–%d）", minLen, maxLen)
	}

	s.mu.Lock()
	running := s.running
	s.mu.Unlock()
	if running {
		return CrackOneResult{}, errors.New("batch: 批量任务进行中，先停止再做单文件检测")
	}

	fi := classify(path)
	if fi.Err != "" {
		return CrackOneResult{MinLen: minLen, MaxLen: maxLen, Err: fi.Err}, nil
	}
	if !fi.Applicable {
		return CrackOneResult{MinLen: minLen, MaxLen: maxLen, Skip: fi.SkipReason}, nil
	}

	started := time.Now()
	res := zcrack.Crack(context.Background(), path, fi.EntryName, minLen, maxLen)
	out := CrackOneResult{
		Found:     res.Found,
		Password:  res.Password,
		MinLen:    minLen,
		MaxLen:    maxLen,
		ElapsedMs: time.Since(started).Milliseconds(),
	}
	if res.Err != nil {
		out.Err = res.Err.Error()
	}
	return out, nil
}

// Defaults 返回并发数与密码长度范围的默认值。
func (s *BatchService) Defaults() Defaults {
	return Defaults{
		Concurrency:    s.concurrencyValue(),
		NumCPU:         runtime.NumCPU(),
		MinLen:         6,
		MaxLen:         8,
		MaxPasswordLen: maxPasswordLen,
	}
}

// SetConcurrency 调整并发数，返回实际生效的值。范围 1 到 NumCPU。
func (s *BatchService) SetConcurrency(n int) (int, error) {
	if n < 1 || n > runtime.NumCPU() {
		return 0, fmt.Errorf("batch: 并发数必须在 1 到 %d 之间", runtime.NumCPU())
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.running {
		return 0, errors.New("batch: 批量任务进行中，不能修改并发数")
	}
	s.concurrency = n
	return n, nil
}

// InspectFile 侦察单个文件，供前端在文件加入列表时逐行更新。
func (s *BatchService) InspectFile(path string) FileInfo {
	return classify(path)
}

// DirListing 是一次目录列举的结果，只读。
//
// 存在的唯一原因是拖入文件夹：Wails 的 files-dropped 事件给的是路径数组，
// 没有 DataTransfer，也就没有 webkitGetAsEntry() 可用，前端没法自己判断
// 一个路径是文件还是目录。递归与「最多两层」的深度控制放在前端
// （frontend/drop-rules.js 的 expandDropPaths），这里只负责列一层。
type DirListing struct {
	Path  string   `json:"path"`
	IsDir bool     `json:"isDir"`
	Dirs  []string `json:"dirs"`
	Files []string `json:"files"`
	Err   string   `json:"err"`
}

// ListDir 列一层目录内容。路径是普通文件时返回 IsDir=false，调用方按文件处理。
//
// 不递归、不读文件内容，也不改任何状态：纯粹给拖放展开用的辅助方法。
func (s *BatchService) ListDir(path string) DirListing {
	out := DirListing{Path: path, Dirs: []string{}, Files: []string{}}
	if strings.TrimSpace(path) == "" {
		out.Err = "路径为空"
		return out
	}

	info, err := os.Stat(path)
	if err != nil {
		out.Err = err.Error()
		return out
	}
	if !info.IsDir() {
		return out
	}
	out.IsDir = true

	entries, err := os.ReadDir(path)
	if err != nil {
		out.Err = err.Error()
		return out
	}
	for _, e := range entries {
		name := e.Name()
		// 隐藏项和系统垃圾文件不该出现在批量列表里。
		if strings.HasPrefix(name, ".") || skipDirEntry(name) {
			continue
		}
		full := filepath.Join(path, name)
		if e.IsDir() {
			out.Dirs = append(out.Dirs, full)
			continue
		}
		out.Files = append(out.Files, full)
	}
	return out
}

// skipDirEntry 过滤掉资源管理器随手生成的垃圾文件。
func skipDirEntry(name string) bool {
	switch strings.ToLower(name) {
	case "thumbs.db", "desktop.ini", "ehthumbs.db":
		return true
	}
	return false
}

// StartBatch 启动一批破解任务，返回本次批次的 ID。
//
// 流程：逐个 Inspect 判断是否适用 → 适用的进 FileTask，不适用的直接生成
// FileResult{Skipped:true} → BatchRunner 限流执行 → 一个 goroutine 消费
// 结果并通过 Wails 事件推给前端。
func (s *BatchService) StartBatch(paths []string, minLen, maxLen int) (string, error) {
	s.startMu.Lock()
	defer s.startMu.Unlock()

	if len(paths) == 0 {
		return "", errors.New("batch: 没有选择文件")
	}
	if minLen < 1 || maxLen < minLen || maxLen > maxPasswordLen {
		return "", fmt.Errorf("batch: 密码长度范围无效（%d–%d）", minLen, maxLen)
	}

	s.mu.Lock()
	if s.running {
		s.mu.Unlock()
		return "", errors.New("batch: 已有批量任务在运行")
	}
	if s.concurrency == 0 {
		s.concurrency = defaultConcurrency()
	}
	concurrency := s.concurrency
	s.running = true
	s.mu.Unlock()

	// 先建好可取消的 context，这样侦察阶段点「停止」也能立刻生效。
	ctx, cancel := context.WithCancel(context.Background())
	s.mu.Lock()
	s.cancel = cancel
	s.mu.Unlock()

	// 侦察阶段。这一步是同步的：文件数量在界面上有限，而且 Inspect 只读
	// 文件尾和中央目录，几百个文件也只是一瞬间。
	tasks := make([]FileTask, 0, len(paths))
	skipped := make([]FileResult, 0, len(paths))
	failed := make([]FileInfo, 0)
	for _, path := range paths {
		if ctx.Err() != nil {
			s.mu.Lock()
			s.running = false
			s.cancel = nil
			s.mu.Unlock()
			cancel()
			return "", errBatchCancelled
		}
		fi := classify(path)
		switch {
		case fi.Err != "":
			failed = append(failed, fi)
		case fi.Applicable:
			tasks = append(tasks, FileTask{
				Path:      fi.Path,
				EntryName: fi.EntryName,
				MinLen:    minLen,
				MaxLen:    maxLen,
			})
		default:
			skipped = append(skipped, FileResult{
				Path:       fi.Path,
				Skipped:    true,
				SkipReason: fi.SkipReason,
			})
		}
	}

	runner := NewBatchRunner(concurrency)
	ch := runner.Run(ctx, tasks)

	s.mu.Lock()
	s.runner = runner
	s.mu.Unlock()

	started := time.Now()
	id := fmt.Sprintf("batch-%d", started.UnixNano())
	go s.consume(ctx, ch, cancel, skipped, failed, len(paths), started)
	return id, nil
}

// StopBatch 取消当前批次，并等待所有 worker 真正退出。
func (s *BatchService) StopBatch() error {
	s.mu.Lock()
	runner, cancel := s.runner, s.cancel
	s.mu.Unlock()

	if cancel != nil {
		cancel()
	}
	if runner != nil {
		runner.Stop()
	}
	return nil
}

// consume 把 runner 的结果翻译成前端事件。
func (s *BatchService) consume(ctx context.Context, ch <-chan FileResult, cancel context.CancelFunc, skipped []FileResult, failed []FileInfo, total int, started time.Time) {
	defer cancel()

	app := application.Get()
	emit := func(name string, data any) {
		if app != nil {
			app.Event.Emit(name, data)
		}
	}

	completed := 0

	// 不适用的文件在侦察阶段就已有结论，先一次性推给前端。
	for _, res := range skipped {
		emit("batch-result", newResultEvent(res))
		completed++
	}
	for _, fi := range failed {
		emit("batch-error", ErrorEvent{Path: fi.Path, Name: fi.Name, Message: fi.Err})
		completed++
	}

	for res := range ch {
		if errors.Is(res.Err, context.Canceled) {
			// 取消导致的中断不是错误，也不占「已完成」的额度。
			continue
		}
		if res.Err != nil {
			emit("batch-error", ErrorEvent{
				Path:    res.Path,
				Name:    filepath.Base(res.Path),
				Message: res.Err.Error(),
			})
			completed++
			continue
		}
		emit("batch-result", newResultEvent(res))
		completed++
	}

	cancelled := ctx.Err() != nil

	s.mu.Lock()
	s.running = false
	s.runner = nil
	s.cancel = nil
	s.mu.Unlock()

	emit("batch-done", DoneEvent{
		Cancelled: cancelled,
		Completed: completed,
		Total:     total,
		ElapsedMs: time.Since(started).Milliseconds(),
	})
}

// ExportCSV 把结果写成 UTF-8 with BOM 的 CSV，Excel 打开中文不会乱码。
func (s *BatchService) ExportCSV(target string, rows []ExportRow) error {
	if strings.TrimSpace(target) == "" {
		return errors.New("batch: 导出路径为空")
	}
	if len(rows) == 0 {
		return errors.New("batch: 没有可导出的结果")
	}

	f, err := os.Create(target)
	if err != nil {
		return fmt.Errorf("batch: 创建 %q: %w", target, err)
	}
	defer f.Close()

	// UTF-8 BOM：Excel 靠它识别编码，否则中文按 GBK 解释。
	if _, err := f.Write([]byte{0xEF, 0xBB, 0xBF}); err != nil {
		return fmt.Errorf("batch: 写入 BOM: %w", err)
	}

	w := csv.NewWriter(f)
	w.UseCRLF = true
	if err := w.Write([]string{"文件名", "状态", "密码/原因"}); err != nil {
		return fmt.Errorf("batch: 写入表头: %w", err)
	}
	for _, row := range rows {
		if err := w.Write([]string{row.Name, row.Status, row.Detail}); err != nil {
			return fmt.Errorf("batch: 写入 %q: %w", row.Name, err)
		}
	}
	w.Flush()
	if err := w.Error(); err != nil {
		return fmt.Errorf("batch: 写入 CSV: %w", err)
	}
	return f.Close()
}

// ---------------------------------------------------------------------------
// 适用性判定
// ---------------------------------------------------------------------------

// classify 判断一个文件能不能走快速破解，并给出原因。
func classify(path string) FileInfo {
	fi := FileInfo{Path: path, Name: filepath.Base(path)}
	if strings.TrimSpace(path) == "" {
		fi.Err = "路径为空"
		return fi
	}

	info, err := zipservice.Inspect(path)
	if err != nil {
		if errors.Is(err, zipservice.ErrNotZip) {
			// 不是 ZIP 的文件不算「解析失败」，只是不适用。
			fi.SkipReason = SkipUnsupported
		} else {
			fi.Err = err.Error()
		}
		return fi
	}

	fi.Size = info.FileSize
	fi.Format = info.Format
	fi.EncryptionType = info.EncryptionType
	fi.EntryCount = info.EntryCount

	switch {
	case info.IsFakeEncrypted:
		fi.SkipReason = SkipFakeEncrypt
		return fi
	case info.EncryptionType == "None":
		fi.SkipReason = SkipNotEncrypted
		return fi
	case info.Format == "ZIP64":
		// zcrack 只解析经典 EOCD，ZIP64 归档会被直接拒绝。
		fi.SkipReason = SkipUnsupported
		return fi
	}

	// 找一个 ZipCrypto 加密、压缩方法受支持的条目。
	// GPBF bit 6 是「强加密」，ZipCrypto 破解引擎不支持，直接算作不适用。
	const flagStrongEncryption = 0x0040

	zipCryptoSeen := false
	strongSeen := false
	for _, e := range info.Entries {
		if !e.IsEncrypted || e.EncryptionType != "ZipCrypto" {
			continue
		}
		if e.GPFlags&flagStrongEncryption != 0 {
			strongSeen = true
			continue
		}
		zipCryptoSeen = true
		if e.Compression == "Store" || e.Compression == "Deflate" {
			fi.Applicable = true
			fi.EntryName = e.Name
			return fi
		}
	}

	switch {
	case zipCryptoSeen, strongSeen:
		fi.SkipReason = SkipUnsupported
	case strings.HasPrefix(info.EncryptionType, "AES") || info.EncryptionType == "Mixed":
		fi.SkipReason = SkipAES
	case info.EncryptionType == "Unknown":
		fi.SkipReason = SkipUnsupported
	default:
		fi.SkipReason = SkipNoEntry
	}
	return fi
}

func newResultEvent(res FileResult) ResultEvent {
	return ResultEvent{
		Path:       res.Path,
		Name:       filepath.Base(res.Path),
		Password:   res.Password,
		Found:      res.Found,
		Skipped:    res.Skipped,
		SkipReason: res.SkipReason,
	}
}
