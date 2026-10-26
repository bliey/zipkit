package attack

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/wailsapp/wails/v3/pkg/application"

	"github.com/bliey/zipkit/internal/settings"
)

// 事件名。前端只认这两个。
const (
	EventLog  = "attack-log"  // bkcrack 的一行输出
	EventDone = "attack-done" // 攻击结束（成功 / 失败 / 取消）
)

// LogEvent 是 attack-log 的负载。
type LogEvent struct {
	Line string `json:"line"`
}

// DoneEvent 是 attack-done 的负载。
//
// AttackResult.Err 是 error 接口，直接序列化只会得到 {}，所以事件里用
// 可以直接展示的字符串，另外带一份输出尾部方便排查。
type DoneEvent struct {
	OK        bool     `json:"ok"`
	Keys      string   `json:"keys"`
	Err       string   `json:"err"`
	Cancelled bool     `json:"cancelled"`
	ElapsedMs int64    `json:"elapsedMs"`
	Tail      []string `json:"tail"`
}

// AttackService 是绑定到前端的明文攻击服务。
type AttackService struct {
	startMu sync.Mutex // 串行化 StartAttack

	mu      sync.Mutex
	cfg     settings.Config
	loaded  bool
	rev     int64
	running bool
	cancel  context.CancelFunc
	done    chan struct{}

	last DoneEvent
}

// ensureConfigLocked 懒加载配置文件，调用方必须持有 s.mu。
//
// 设置面板改了路径后靠 settings.Revision 发现并重新加载，不用重启。
func (s *AttackService) ensureConfigLocked() settings.Config {
	rev := settings.Revision()
	if !s.loaded || s.rev != rev {
		s.cfg = settings.Load()
		s.loaded = true
		s.rev = rev
		// 配置里的 bkcrack 路径是持久的，进程内的解析器也要同步。
		SetBkcrackPath(s.cfg.BkcrackPath)
	}
	return s.cfg
}

// Bkcrack 重新检测 bkcrack，供初始化与「重新检测」按钮使用。
//
// 先读配置再检测：配置文件里的路径是唯一数据来源，没加载配置就检测的话，
// 用户指定过的路径会被当成「没设置」。
func (s *AttackService) Bkcrack() BkcrackStatus {
	s.mu.Lock()
	s.ensureConfigLocked()
	s.mu.Unlock()

	return DetectBkcrack()
}

// SetBkcrackPath 校验并保存用户手动指定的 bkcrack 路径。传空字符串表示
// 恢复自动探测。
func (s *AttackService) SetBkcrackPath(path string) (BkcrackStatus, error) {
	path = strings.TrimSpace(path)
	if path != "" {
		if _, ok := lookExecutable(path); !ok {
			return DetectBkcrack(), fmt.Errorf("attack: %q 不是一个可执行文件", path)
		}
	}

	s.mu.Lock()
	cfg := s.ensureConfigLocked()
	cfg.BkcrackPath = path
	s.cfg = cfg
	s.mu.Unlock()

	SetBkcrackPath(path)
	if err := settings.Save(cfg); err != nil {
		return DetectBkcrack(), fmt.Errorf("attack: 保存配置失败：%w", err)
	}
	return DetectBkcrack(), nil
}

// Precheck 在真正攻击之前检查加密条目与明文是否对得上。
//
// 它不阻止用户继续：结果里的 Issues 只是提示，前端照常可以点「开始攻击」。
func (s *AttackService) Precheck(encryptedZip, cipherEntry, plainPath, plainEntry string, plainIsZip bool) (PrecheckResult, error) {
	if strings.TrimSpace(encryptedZip) == "" {
		return PrecheckResult{}, errors.New("attack: 没有指定加密压缩包")
	}
	if strings.TrimSpace(cipherEntry) == "" {
		return PrecheckResult{}, errors.New("attack: 没有指定目标条目")
	}
	if strings.TrimSpace(plainPath) == "" {
		return PrecheckResult{}, errors.New("attack: 没有选择明文")
	}
	return PrecheckForm(encryptedZip, cipherEntry, plainPath, plainEntry, plainIsZip), nil
}

// PrecheckHex 是十六进制明文模式下的预检：三项比对不适用，直接放行并附提醒。
func (s *AttackService) PrecheckHex(encryptedZip, cipherEntry, hexPlaintext string, offset int64) (PrecheckResult, error) {
	return PrecheckHex(encryptedZip, cipherEntry, hexPlaintext, offset)
}

// DetectCreators 识别加密包与明文 ZIP 各自由什么软件创建，并给出一致性结论。
//
// 只在「明文 ZIP」模式下调用：独立文件与十六进制模式没有第二个 ZIP，
// 比来源没有意义。结论纯属辅助信息，不影响 Precheck，也不阻止开始攻击。
func (s *AttackService) DetectCreators(encryptedZip, plainZip string) (CreatorPair, error) {
	return DetectCreators(encryptedZip, plainZip)
}

// StartAttack 启动一次明文攻击。攻击在 goroutine 里跑，日志通过 attack-log
// 事件实时推送，结束时发 attack-done。
func (s *AttackService) StartAttack(opts AttackOptions) (string, error) {
	s.startMu.Lock()
	defer s.startMu.Unlock()

	if err := validateOptions(opts); err != nil {
		return "", err
	}

	s.mu.Lock()
	s.ensureConfigLocked()
	s.mu.Unlock()

	// 配置加载完再解析 bkcrack，否则用户手动指定的路径不会生效。
	if _, err := ResolveBkcrack(); err != nil {
		return "", err
	}

	s.mu.Lock()
	if s.running {
		s.mu.Unlock()
		return "", errors.New("attack: 已有攻击在进行")
	}
	s.running = true
	ctx, cancel := context.WithCancel(context.Background())
	s.cancel = cancel
	done := make(chan struct{})
	s.done = done
	s.mu.Unlock()

	go s.run(ctx, cancel, opts, done)
	return fmt.Sprintf("attack-%d", time.Now().UnixNano()), nil
}

// StopAttack 立刻终止 bkcrack 进程，并等 goroutine 收尾。
func (s *AttackService) StopAttack() error {
	s.mu.Lock()
	cancel, done := s.cancel, s.done
	s.mu.Unlock()

	if cancel == nil {
		return nil
	}
	cancel()
	// 只取消 context 不够：bkcrack 在 Z 值搜索里可能长时间不看 context，
	// 用户点「停止」必须当场把进程杀掉。
	Kill()

	if done != nil {
		<-done
	}
	return nil
}

// DecryptWithKeys 用恢复出的密钥解密整个包，newPassword 为空时生成无密码包。
func (s *AttackService) DecryptWithKeys(encryptedZip, keys, outputZip, newPassword string) error {
	s.mu.Lock()
	running := s.running
	s.mu.Unlock()
	if running {
		return errors.New("attack: 攻击进行中，先停止再解密")
	}

	emit := s.logEmitter()
	if err := Decrypt(context.Background(), encryptedZip, keys, outputZip, newPassword, emit); err != nil {
		return err
	}
	emit(fmt.Sprintf("[zipkit] 已生成 %s", filepath.Base(outputZip)))
	return nil
}

// DecryptEntryWithKeys 用恢复出的密钥只解出目标条目。
func (s *AttackService) DecryptEntryWithKeys(encryptedZip, keys, entryName, outputPath string) error {
	s.mu.Lock()
	running := s.running
	s.mu.Unlock()
	if running {
		return errors.New("attack: 攻击进行中，先停止再解密")
	}

	emit := s.logEmitter()
	if err := DecryptEntry(context.Background(), encryptedZip, keys, entryName, outputPath, emit); err != nil {
		return err
	}
	emit(fmt.Sprintf("[zipkit] 已生成 %s", filepath.Base(outputPath)))
	return nil
}

// LastResult 返回最近一次攻击的结果，前端刷新后可以据此恢复界面。
func (s *AttackService) LastResult() DoneEvent {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.last
}

// logEmitter 返回一个把日志推给前端的回调。
func (s *AttackService) logEmitter() func(string) {
	app := application.Get()
	var mu sync.Mutex
	return func(line string) {
		if app == nil {
			return
		}
		mu.Lock()
		defer mu.Unlock()
		app.Event.Emit(EventLog, LogEvent{Line: line})
	}
}

// run 是攻击线程：跑 Run、发日志、收尾发 attack-done。
func (s *AttackService) run(ctx context.Context, cancel context.CancelFunc, opts AttackOptions, done chan struct{}) {
	defer close(done)
	defer cancel()

	started := time.Now()
	app := application.Get()
	emitLog := func(line string) {
		if app != nil {
			app.Event.Emit(EventLog, LogEvent{Line: line})
		}
	}

	res := Run(ctx, opts, emitLog)

	ev := DoneEvent{ElapsedMs: time.Since(started).Milliseconds()}
	switch {
	case errors.Is(res.Err, ErrCancelled):
		ev.Cancelled = true
		ev.Err = "已停止"
	case res.Err != nil:
		ev.Err = res.Err.Error()
		ev.Tail = lastLines(res.Raw, 20)
	case res.Keys == ([3]string{}):
		ev.Err = ErrKeysNotFound.Error()
		ev.Tail = lastLines(res.Raw, 20)
	default:
		ev.OK = true
		ev.Keys = strings.Join(res.Keys[:], " ")
	}

	s.mu.Lock()
	s.running = false
	s.cancel = nil
	s.done = nil
	s.last = ev
	s.mu.Unlock()

	if app != nil {
		app.Event.Emit(EventDone, ev)
	}
}

// progressRe 匹配 bkcrack 的进度行（`42.3 % (18160 / 42995)`）。
var progressRe = regexp.MustCompile(`^\d+(\.\d+)? %( \(\d+ / \d+\))?$`)

// lastLines 取输出的最后 n 行，用来在失败时给用户看现场。
//
// 进度行会被过滤掉：几万条进度对判断原因没有任何帮助，真正有用的是
// 「Could not find the keys」前后的那几行。
func lastLines(raw string, n int) []string {
	if strings.TrimSpace(raw) == "" {
		return nil
	}
	all := strings.Split(strings.TrimRight(raw, "\n"), "\n")
	kept := make([]string, 0, len(all))
	for _, line := range all {
		line = strings.TrimSpace(line)
		if line == "" || progressRe.MatchString(line) {
			continue
		}
		kept = append(kept, line)
	}
	if len(kept) > n {
		kept = kept[len(kept)-n:]
	}
	return kept
}
