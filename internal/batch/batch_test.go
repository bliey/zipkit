package batch

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"

	"github.com/bliey/zipkit/internal/zcrack"
)

// ---------------------------------------------------------------------------
// 辅助
// ---------------------------------------------------------------------------

// fakeCrack 临时替换 crackFile，测试结束后自动还原。
func fakeCrack(t *testing.T, fn func(ctx context.Context, path, entry string, minLen, maxLen int) zcrack.Result) {
	t.Helper()
	old := crackFile
	crackFile = fn
	t.Cleanup(func() { crackFile = old })
}

func tasks(n int) []FileTask {
	out := make([]FileTask, n)
	for i := range out {
		out[i] = FileTask{Path: "file.zip", EntryName: "hello.txt", MinLen: 6, MaxLen: 8}
	}
	return out
}

// collect 读完 channel，并断言它会在 timeout 内关闭。
func collect(t *testing.T, ch <-chan FileResult, timeout time.Duration) []FileResult {
	t.Helper()
	var out []FileResult
	deadline := time.After(timeout)
	for {
		select {
		case r, ok := <-ch:
			if !ok {
				return out
			}
			out = append(out, r)
		case <-deadline:
			t.Fatalf("结果 channel 在 %v 内没有关闭（已收到 %d 条）", timeout, len(out))
		}
	}
}

// ---------------------------------------------------------------------------
// channel 关闭
// ---------------------------------------------------------------------------

func TestRunClosesChannelWithoutTasks(t *testing.T) {
	r := NewBatchRunner(2)
	got := collect(t, r.Run(context.Background(), nil), 2*time.Second)
	if len(got) != 0 {
		t.Fatalf("空任务不应产生结果，实际 %d 条", len(got))
	}
}

func TestRunClosesChannelAfterAllResults(t *testing.T) {
	fakeCrack(t, func(ctx context.Context, path, entry string, minLen, maxLen int) zcrack.Result {
		return zcrack.Result{Found: true, Password: "123456"}
	})

	r := NewBatchRunner(3)
	got := collect(t, r.Run(context.Background(), tasks(9)), 3*time.Second)
	if len(got) != 9 {
		t.Fatalf("期望 9 条结果，实际 %d 条", len(got))
	}
	for i, res := range got {
		if !res.Found || res.Password != "123456" {
			t.Fatalf("第 %d 条结果不正确: %+v", i, res)
		}
		if res.Err != nil || res.Skipped {
			t.Fatalf("第 %d 条结果不应带错误或跳过标记: %+v", i, res)
		}
	}
}

func TestRunPassesTaskFieldsThrough(t *testing.T) {
	type call struct {
		path, entry    string
		minLen, maxLen int
	}
	var got atomic.Value
	fakeCrack(t, func(ctx context.Context, path, entry string, minLen, maxLen int) zcrack.Result {
		got.Store(call{path, entry, minLen, maxLen})
		return zcrack.Result{}
	})

	r := NewBatchRunner(1)
	ch := r.Run(context.Background(), []FileTask{{Path: "a.zip", EntryName: "x.txt", MinLen: 4, MaxLen: 7}})
	collect(t, ch, time.Second)

	c, ok := got.Load().(call)
	if !ok {
		t.Fatal("crackFile 没有被调用")
	}
	if c.path != "a.zip" || c.entry != "x.txt" || c.minLen != 4 || c.maxLen != 7 {
		t.Fatalf("任务字段没有原样传入: %+v", c)
	}
}

func TestRunCarriesError(t *testing.T) {
	wantErr := errors.New("boom")
	fakeCrack(t, func(ctx context.Context, path, entry string, minLen, maxLen int) zcrack.Result {
		return zcrack.Result{Err: wantErr}
	})

	got := collect(t, NewBatchRunner(2).Run(context.Background(), tasks(2)), time.Second)
	if len(got) != 2 {
		t.Fatalf("期望 2 条结果，实际 %d", len(got))
	}
	for _, res := range got {
		if !errors.Is(res.Err, wantErr) {
			t.Fatalf("错误没有透传: %v", res.Err)
		}
	}
}

// ---------------------------------------------------------------------------
// 限流
// ---------------------------------------------------------------------------

// TestRunLimitsConcurrency 是这一层最关键的断言：100 个任务同时提交，
// 真正在跑的不能超过 concurrency 个。
func TestRunLimitsConcurrency(t *testing.T) {
	const limit = 3
	var inflight, peak int32

	fakeCrack(t, func(ctx context.Context, path, entry string, minLen, maxLen int) zcrack.Result {
		n := atomic.AddInt32(&inflight, 1)
		for {
			p := atomic.LoadInt32(&peak)
			if n <= p || atomic.CompareAndSwapInt32(&peak, p, n) {
				break
			}
		}
		time.Sleep(15 * time.Millisecond)
		atomic.AddInt32(&inflight, -1)
		return zcrack.Result{}
	})

	r := NewBatchRunner(limit)
	got := collect(t, r.Run(context.Background(), tasks(40)), 5*time.Second)
	if len(got) != 40 {
		t.Fatalf("期望 40 条结果，实际 %d", len(got))
	}
	if p := atomic.LoadInt32(&peak); p > limit {
		t.Fatalf("并发峰值 %d 超过上限 %d", p, limit)
	} else if p < 2 {
		t.Fatalf("并发峰值只有 %d，信号量把任务串行化了", p)
	}
}

func TestRunConcurrencyOneIsSerial(t *testing.T) {
	var inflight, peak int32
	fakeCrack(t, func(ctx context.Context, path, entry string, minLen, maxLen int) zcrack.Result {
		n := atomic.AddInt32(&inflight, 1)
		if p := atomic.LoadInt32(&peak); n > p {
			atomic.StoreInt32(&peak, n)
		}
		time.Sleep(5 * time.Millisecond)
		atomic.AddInt32(&inflight, -1)
		return zcrack.Result{}
	})

	got := collect(t, NewBatchRunner(1).Run(context.Background(), tasks(5)), 3*time.Second)
	if len(got) != 5 {
		t.Fatalf("期望 5 条结果，实际 %d", len(got))
	}
	if p := atomic.LoadInt32(&peak); p != 1 {
		t.Fatalf("concurrency=1 时并发峰值应为 1，实际 %d", p)
	}
}

func TestNewBatchRunnerClampsConcurrency(t *testing.T) {
	for _, tc := range []struct{ in, want int }{{0, 1}, {-5, 1}, {1, 1}, {8, 8}} {
		if got := NewBatchRunner(tc.in).Concurrency(); got != tc.want {
			t.Fatalf("NewBatchRunner(%d).Concurrency() = %d，期望 %d", tc.in, got, tc.want)
		}
	}
}

// ---------------------------------------------------------------------------
// 取消
// ---------------------------------------------------------------------------

// TestStopWaitsForWorkers 验证 Stop 不是「发个取消就返回」，而是真的等
// 所有 goroutine 退出——否则下一次批量启动时会和上一批抢 CPU。
func TestStopWaitsForWorkers(t *testing.T) {
	var finished atomic.Bool
	started := make(chan struct{}, 8)

	fakeCrack(t, func(ctx context.Context, path, entry string, minLen, maxLen int) zcrack.Result {
		select {
		case started <- struct{}{}:
		default:
		}
		<-ctx.Done()
		time.Sleep(40 * time.Millisecond)
		finished.Store(true)
		return zcrack.Result{Err: ctx.Err()}
	})

	r := NewBatchRunner(4)
	ch := r.Run(context.Background(), tasks(8))

	select {
	case <-started:
	case <-time.After(time.Second):
		t.Fatal("worker 没有启动")
	}

	r.Stop()

	if !finished.Load() {
		t.Fatal("Stop 返回时仍有 worker 在运行")
	}
	if got := collect(t, ch, time.Second); len(got) != 0 {
		// 取消后 worker 返回的 context.Canceled 结果允许被丢弃，也允许已经写进
		// channel；这里只要求 channel 能正常关闭。
		for _, res := range got {
			if !errors.Is(res.Err, context.Canceled) {
				t.Fatalf("取消后不应产生非取消错误: %v", res.Err)
			}
		}
	}
}

func TestStopDropsUnsentResultsButKeepsSent(t *testing.T) {
	// release 里有令牌的调用立即命中；没有令牌的调用一直等到 ctx 取消。
	release := make(chan struct{}, 4)
	fakeCrack(t, func(ctx context.Context, path, entry string, minLen, maxLen int) zcrack.Result {
		select {
		case <-release:
			return zcrack.Result{Found: true, Password: "123456"}
		case <-ctx.Done():
			return zcrack.Result{Err: ctx.Err()}
		}
	})

	r := NewBatchRunner(2)
	ch := r.Run(context.Background(), tasks(4))

	// 放行两个候选，确保前两条结果已经发出去。
	release <- struct{}{}
	release <- struct{}{}

	var sent []FileResult
	for len(sent) < 2 {
		select {
		case res := <-ch:
			sent = append(sent, res)
		case <-time.After(2 * time.Second):
			t.Fatalf("只收到 %d 条已完成结果", len(sent))
		}
	}
	for _, res := range sent {
		if !res.Found || res.Password != "123456" {
			t.Fatalf("已发送结果被破坏: %+v", res)
		}
	}

	// 剩下的两个任务还卡在等待令牌，取消后它们的结果不允许再冒出来。
	r.Stop()

	rest := collect(t, ch, 2*time.Second)
	for _, res := range rest {
		if res.Found {
			t.Fatalf("取消后不应再收到命中结果: %+v", res)
		}
	}
}

// TestContextCancelClosesChannel 验证调用方自己取消 ctx 时，channel 也会关闭。
func TestContextCancelClosesChannel(t *testing.T) {
	fakeCrack(t, func(ctx context.Context, path, entry string, minLen, maxLen int) zcrack.Result {
		<-ctx.Done()
		return zcrack.Result{Err: ctx.Err()}
	})

	ctx, cancel := context.WithCancel(context.Background())
	ch := NewBatchRunner(2).Run(ctx, tasks(4))

	cancel()
	collect(t, ch, 2*time.Second)
}

func TestStopWithoutRunIsNoop(t *testing.T) {
	done := make(chan struct{})
	go func() {
		NewBatchRunner(2).Stop()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("没有运行时 Stop 不应阻塞")
	}
}

// TestRunTwice 验证 runner 可以复用：第二次 Run 会先把第一次收尾。
func TestRunTwice(t *testing.T) {
	var calls int32
	fakeCrack(t, func(ctx context.Context, path, entry string, minLen, maxLen int) zcrack.Result {
		atomic.AddInt32(&calls, 1)
		select {
		case <-ctx.Done():
			return zcrack.Result{Err: ctx.Err()}
		case <-time.After(20 * time.Millisecond):
			return zcrack.Result{}
		}
	})

	r := NewBatchRunner(2)
	first := r.Run(context.Background(), tasks(10))
	// 不等第一批结束就直接开第二批。
	second := collect(t, r.Run(context.Background(), tasks(3)), 3*time.Second)
	if len(second) != 3 {
		t.Fatalf("第二次运行期望 3 条结果，实际 %d", len(second))
	}
	collect(t, first, 3*time.Second)
}

// ---------------------------------------------------------------------------
// 与真实 ZIP 的集成
// ---------------------------------------------------------------------------

func TestRunAgainstRealArchives(t *testing.T) {
	cases := []struct {
		path     string
		entry    string
		password string
	}{
		{"../zcrack/testdata/num6.zip", "hello.txt", "123456"},
		{"../zcrack/testdata/num7.zip", "hello.txt", "7654321"},
		{"../zcrack/testdata/store6.zip", "hello.txt", "123456"},
		{"../zcrack/testdata/multi.zip", "secret.txt", "123456"},
	}
	tasks := make([]FileTask, len(cases))
	for i, c := range cases {
		tasks[i] = FileTask{Path: c.path, EntryName: c.entry, MinLen: len(c.password), MaxLen: len(c.password)}
	}

	got := collect(t, NewBatchRunner(2).Run(context.Background(), tasks), 30*time.Second)
	if len(got) != len(cases) {
		t.Fatalf("期望 %d 条结果，实际 %d", len(cases), len(got))
	}
	byPath := make(map[string]FileResult, len(got))
	for _, res := range got {
		byPath[res.Path] = res
	}
	for _, c := range cases {
		res, ok := byPath[c.path]
		if !ok {
			t.Fatalf("%s 没有结果", c.path)
		}
		if res.Err != nil {
			t.Fatalf("%s: %v", c.path, res.Err)
		}
		if !res.Found || res.Password != c.password {
			t.Fatalf("%s: 期望 %s，实际 Found=%v Password=%q", c.path, c.password, res.Found, res.Password)
		}
	}
}
