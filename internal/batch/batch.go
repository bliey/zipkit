// Package batch 把 zcrack 的单文件破解能力组织成受控并发的批处理。
//
// 这一层只负责「怎么跑」：限流、取消、结果汇聚。判断某个文件适不适合
// 快速破解属于服务层的职责，不适用的文件在进入本包之前就已经变成
// FileResult{Skipped: true}，所以 Run 收到的任务都是可以直接跑的。
package batch

import (
	"context"
	"sync"

	"github.com/bliey/zipkit/internal/zcrack"
)

// FileTask 是批量队列里的一个文件。
//
// EntryName 由调用方从 ZipService.Inspect 的结果里挑出，必须是中央目录里
// 实际存在的 ZipCrypto 条目名；MinLen / MaxLen 是纯数字密码长度范围。
type FileTask struct {
	Path      string
	EntryName string
	MinLen    int
	MaxLen    int
}

// FileResult 是一个文件跑完（或跳过）之后的汇总。
type FileResult struct {
	Path       string
	Password   string
	Found      bool
	Skipped    bool
	SkipReason string // "AES 加密" / "未加密" / "不支持的格式" / ...
	Err        error
}

// 跳过原因。服务层与前端共用这几条文案，避免两边各写一套。
const (
	SkipAES          = "AES 加密"
	SkipNotEncrypted = "未加密"
	SkipUnsupported  = "不支持的格式"
	SkipNoEntry      = "找不到 ZipCrypto 条目"
	SkipFakeEncrypt  = "疑似伪加密（无需密码）"
)

// crackFile 是 zcrack.Crack 的间接层。测试替换它就能在不碰真实 ZIP 的
// 情况下观察并发上限与取消行为。
var crackFile = zcrack.Crack

// BatchRunner 执行一批 FileTask，同时最多跑 concurrency 个。
//
// 一个 BatchRunner 可以反复 Run；每次 Run 会先终止上一次尚未结束的运行。
type BatchRunner struct {
	concurrency int

	mu     sync.Mutex
	cancel context.CancelFunc
	done   chan struct{} // 当前这次 Run 的所有 goroutine 退出后关闭
}

// NewBatchRunner 创建 runner。concurrency 小于 1 时按 1 处理。
func NewBatchRunner(concurrency int) *BatchRunner {
	if concurrency < 1 {
		concurrency = 1
	}
	return &BatchRunner{concurrency: concurrency}
}

// Concurrency 返回同时运行的任务上限。
func (r *BatchRunner) Concurrency() int { return r.concurrency }

// Run 启动一批任务，返回结果 channel。
//
// 每个 FileTask 对应一个 goroutine：goroutine 先从容量为 concurrency 的
// 信号量 channel 里拿一个槽位，跑完 zcrack.Crack 后释放。所有 goroutine
// 退出后结果 channel 被关闭，调用方可以安全地用 range 消费。
//
// ctx 取消后 goroutine 会尽快退出：已经写进 channel 的结果保留，还没写出去
// 的直接丢弃。写结果用 select 同时等 ctx，因此调用方即使停止消费也不会
// 把 goroutine 卡死。
func (r *BatchRunner) Run(ctx context.Context, tasks []FileTask) <-chan FileResult {
	// 结果 channel 带一点缓冲，减少 worker 在发送处等待的次数。
	out := make(chan FileResult, r.concurrency)

	runCtx, cancel := context.WithCancel(ctx)
	done := make(chan struct{})

	// 上一次运行如果还没结束，先把它停干净，避免两次运行的 cancel/done
	// 互相覆盖。
	r.stopCurrent()

	r.mu.Lock()
	r.cancel, r.done = cancel, done
	r.mu.Unlock()

	go func() {
		defer cancel()

		sem := make(chan struct{}, r.concurrency)
		var wg sync.WaitGroup
		wg.Add(len(tasks))

		for _, task := range tasks {
			go func(t FileTask) {
				defer wg.Done()

				// 信号量限流：拿不到槽位就在这里等，而不是真的开跑。
				select {
				case sem <- struct{}{}:
					defer func() { <-sem }()
				case <-runCtx.Done():
					return
				}

				res := crackFile(runCtx, t.Path, t.EntryName, t.MinLen, t.MaxLen)
				fr := FileResult{
					Path:     t.Path,
					Password: res.Password,
					Found:    res.Found,
					Err:      res.Err,
				}

				select {
				case out <- fr:
				case <-runCtx.Done():
				}
			}(task)
		}

		wg.Wait()
		close(out)
		close(done)
	}()

	return out
}

// Stop 取消当前运行，并阻塞到所有 goroutine 真正退出。
//
// 阻塞是刻意的：调用方在 Stop 返回后立刻重新开始一批时，不会出现两批
// 任务共用 CPU、进度互相干扰的情况。
func (r *BatchRunner) Stop() {
	r.mu.Lock()
	cancel, done := r.cancel, r.done
	r.cancel, r.done = nil, nil
	r.mu.Unlock()

	if cancel == nil {
		return
	}
	cancel()
	if done != nil {
		<-done
	}
}

// stopCurrent 终止并等待上一次运行，供 Run 复用 runner 时调用。
func (r *BatchRunner) stopCurrent() {
	r.mu.Lock()
	cancel, done := r.cancel, r.done
	r.mu.Unlock()

	if cancel == nil {
		return
	}
	cancel()
	if done != nil {
		<-done
	}
}
