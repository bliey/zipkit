package hashcat

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/wailsapp/wails/v3/pkg/application"

	"github.com/bliey/zipkit/internal/hashextract"
	"github.com/bliey/zipkit/internal/settings"
	"github.com/bliey/zipkit/internal/unzip"
)

// 事件名。前端只认这两个。
const (
	EventProgress = "hashcat-progress" // 一行原始输出，或一份结构化进度
	EventDone     = "hashcat-done"     // 本次运行结束
)

// ProgressEvent 是 hashcat-progress 的负载。
//
// 两种用途合在一个事件里：
//   - Line 非空 → 前端把这一行追加到等宽日志区；
//   - Status 等字段非空 → 前端更新上方的结构化进度条。
//
// 这样前端只需要订阅一个事件，日志与进度条天然对齐。
type ProgressEvent struct {
	Line      string `json:"line"`
	Status    string `json:"status"`
	Speed     string `json:"speed"`
	Progress  string `json:"progress"`
	Recovered string `json:"recovered"`
	ETA       string `json:"eta"`
}

// DoneEvent 是 hashcat-done 的负载。
//
// error 接口直接序列化只会得到 {}，所以这里用可以直接展示的字符串，
// 另外带一份输出尾部，失败时用户能看到 hashcat 到底说了什么。
type DoneEvent struct {
	OK        bool     `json:"ok"`
	Password  string   `json:"password"`
	Status    string   `json:"status"`
	Err       string   `json:"err"`
	Cancelled bool     `json:"cancelled"`
	ElapsedMs int64    `json:"elapsedMs"`
	Tail      []string `json:"tail"`
}

// HashcatService 是绑定到前端的 GPU 恢复服务。
type HashcatService struct {
	startMu sync.Mutex // 串行化 Start / ExtractAndStart

	mu      sync.Mutex
	cfg     settings.Config
	loaded  bool
	rev     int64
	running bool
	session string // 当前运行的 hashcat 会话名
	cancel  context.CancelFunc
	done    chan struct{}

	last DoneEvent
}

// ensureConfigLocked 懒加载配置，调用方必须持有 s.mu。
//
// 设置面板改了路径后靠 settings.Revision 发现并重新加载，不用重启。
func (s *HashcatService) ensureConfigLocked() settings.Config {
	rev := settings.Revision()
	if !s.loaded || s.rev != rev {
		s.cfg = settings.Load()
		s.loaded = true
		s.rev = rev
		// 配置里的路径是持久的，进程内的解析器也要同步。
		SetToolPaths(s.cfg.HashcatPath, s.cfg.Rar2JohnPath, s.cfg.SevenZip2JohnPath)
		Set7z2HashcatPaths(s.cfg.SevenZip2HashcatPath, s.cfg.InterpreterPath)
	}
	return s.cfg
}

// Tools 重新检测三个外部工具，供初始化与「重新检测」按钮使用。
func (s *HashcatService) Tools() ToolsStatus {
	s.mu.Lock()
	s.ensureConfigLocked()
	s.mu.Unlock()
	return DetectTools()
}

// SetToolPath 校验并保存某个工具的路径。kind 取 hashcat / rar2john / 7z2john /
// 7z2hashcat / interpreter。传空字符串表示恢复自动探测。
func (s *HashcatService) SetToolPath(kind, path string) (ToolsStatus, error) {
	kind = strings.TrimSpace(kind)
	switch kind {
	case ToolHashcat, ToolRar2John, ToolSevenZip2John, ToolSevenZip2Hashcat, ToolInterpreter:
	default:
		return DetectTools(), fmt.Errorf("hashcat: 未知的工具 %q", kind)
	}

	path = strings.TrimSpace(path)
	if path != "" {
		// 7z2john / 7z2hashcat 可能是 .pl 脚本，所以只要求文件存在，不要求可执行位。
		if _, ok := lookExecutable(path); !ok {
			return DetectTools(), fmt.Errorf("hashcat: %q 不是一个可用的文件", path)
		}
	}

	s.mu.Lock()
	cfg := s.ensureConfigLocked()
	switch kind {
	case ToolHashcat:
		cfg.HashcatPath = path
	case ToolRar2John:
		cfg.Rar2JohnPath = path
	case ToolSevenZip2John:
		cfg.SevenZip2JohnPath = path
	case ToolSevenZip2Hashcat:
		cfg.SevenZip2HashcatPath = path
	case ToolInterpreter:
		cfg.InterpreterPath = path
	}
	s.cfg = cfg
	s.mu.Unlock()

	SetToolPaths(cfg.HashcatPath, cfg.Rar2JohnPath, cfg.SevenZip2JohnPath)
	Set7z2HashcatPaths(cfg.SevenZip2HashcatPath, cfg.InterpreterPath)
	if err := settings.Save(cfg); err != nil {
		return DetectTools(), fmt.Errorf("hashcat: 保存配置失败：%w", err)
	}
	return DetectTools(), nil
}

// Extract 提取哈希但不启动破解。前端用它填充攻击面板里的哈希预览。
func (s *HashcatService) Extract(archivePath, entryName string) (hashextract.HashResult, error) {
	if strings.TrimSpace(archivePath) == "" {
		return hashextract.HashResult{}, errors.New("hashcat: 没有指定压缩包")
	}

	s.mu.Lock()
	s.ensureConfigLocked()
	s.mu.Unlock()

	return extractFor(archivePath, entryName)
}

// extractFor 按归档类型选择提取方式：ZIP 自己解析，RAR5 走 john 的 rar2john，
// 7z 走内建实现（用户配了外部 7z2john 就用外部的）。
func extractFor(archivePath, entryName string) (hashextract.HashResult, error) {
	switch strings.ToLower(filepath.Ext(archivePath)) {
	case ".zip":
		// ZIP 里可能同时有 AES 和 ZipCrypto 条目，具体走哪条路由
		// hashextract.ExtractZIP 按条目实际的加密类型决定。
		return hashextract.ExtractZIP(archivePath, entryName)
	case ".rar":
		tool, _, err := ResolveWithFallback(ToolRar2John)
		if err != nil {
			return hashextract.HashResult{}, err
		}
		return hashextract.ExtractViaJohn(tool, archivePath)
	case ".7z":
		return extract7z(archivePath)
	}
	return hashextract.HashResult{}, fmt.Errorf(
		"hashcat: 不支持的归档类型 %q（只支持 .zip / .rar / .7z）",
		filepath.Ext(archivePath))
}

// extract7z 按固定顺序尝试多条 7z 提哈希路径，全部失败时把所有原因都报出来。
//
// 顺序的取舍：
//
//  1. 用户显式配置的 7z2hashcat —— 他既然配了就是想用它；
//  2. 内建实现 —— 不需要任何外部依赖，覆盖常见结构（含「数据加密、头部
//     只压缩不加密」这种 7-Zip 默认形态）；
//  3. 自动探测到的 7z2hashcat —— 内建不支持时（BCJ2 / PPMd 等）由它兜底；
//  4. 7z2john —— 老路径，保留。
//
// 任何一步成功都会把前面失败的原因写进 Warnings：既不让用户被卡住，也不
// 把「你配的那条路走不通」藏起来。
func extract7z(archivePath string) (hashextract.HashResult, error) {
	var reasons []string
	record := func(label string, err error) {
		if err != nil {
			reasons = append(reasons, label+"："+err.Error())
		}
	}

	// 1. 用户配置的 7z2hashcat。
	if configured := configuredPath(ToolSevenZip2Hashcat); configured != "" {
		script, _, resolveErr := ResolveWithFallback(ToolSevenZip2Hashcat)
		if resolveErr == nil {
			res, err := hashextract.ExtractVia7z2Hashcat(archivePath, script, configuredPath(ToolInterpreter))
			if err == nil {
				return res, nil
			}
			record("7z2hashcat（设置里指定的）", err)
		} else {
			record("7z2hashcat（设置里指定的）", resolveErr)
		}
	}

	// 2. 内建实现。
	res, nativeErr := hashextract.Extract7zNative(archivePath)
	if nativeErr == nil {
		if len(reasons) > 0 {
			res.Warnings = append(res.Warnings,
				"以下路径没能提取哈希，已改用内建实现："+strings.Join(reasons, "；"))
		}
		return res, nil
	}
	record("内建实现", nativeErr)

	// 3. 自动探测到的 7z2hashcat（用户没配，但机器上有）。
	if configuredPath(ToolSevenZip2Hashcat) == "" {
		if script, err := Resolve(ToolSevenZip2Hashcat); err == nil {
			scriptRes, scriptErr := hashextract.ExtractVia7z2Hashcat(
				archivePath, script, configuredPath(ToolInterpreter))
			if scriptErr == nil {
				scriptRes.Warnings = append(scriptRes.Warnings,
					"内建实现没能提取哈希，已改用 7z2hashcat："+nativeErr.Error())
				return scriptRes, nil
			}
			record("7z2hashcat（自动探测）", scriptErr)
		} else if !errors.Is(err, ErrToolMissing) {
			record("7z2hashcat（自动探测）", err)
		}
	}

	// 4. 7z2john。
	if tool, _, err := ResolveWithFallback(ToolSevenZip2John); err == nil && tool != NativeSevenZip2John {
		johnRes, johnErr := hashextract.ExtractViaJohn(tool, archivePath)
		if johnErr == nil {
			johnRes.Warnings = append(johnRes.Warnings,
				"内建实现没能提取哈希，已改用 7z2john："+nativeErr.Error())
			return johnRes, nil
		}
		record("7z2john", johnErr)
	}

	return hashextract.HashResult{}, fmt.Errorf(
		"hashcat: 7z 提哈希失败，以下 %d 条路径都不通：\n- %s",
		len(reasons), strings.Join(reasons, "\n- "))
}

// ExtractAndStart 一步到位：提取哈希后立刻用给定策略开跑。
// 返回会话名，前端可以用它取消。
func (s *HashcatService) ExtractAndStart(archivePath, entryName string, strategy Strategy) (string, error) {
	res, err := s.Extract(archivePath, entryName)
	if err != nil {
		return "", err
	}
	return s.Start(res.Hash, res.Mode, strategy)
}

// Start 用给定的哈希与策略启动一次破解。
func (s *HashcatService) Start(hash string, mode int, strategy Strategy) (string, error) {
	s.startMu.Lock()
	defer s.startMu.Unlock()

	if strings.TrimSpace(hash) == "" {
		return "", fmt.Errorf("%w: 哈希为空", ErrBadStrategy)
	}

	s.mu.Lock()
	s.ensureConfigLocked()
	running := s.running
	s.mu.Unlock()
	if running {
		return "", errors.New("hashcat: 已有破解任务在进行")
	}

	// 配置加载完再解析，否则用户手动指定的路径不会生效。
	hcPath, err := Resolve(ToolHashcat)
	if err != nil {
		return "", err
	}

	sessionID := fmt.Sprintf("zipkit-%d", time.Now().UnixNano())

	s.mu.Lock()
	s.running = true
	s.session = sessionID
	ctx, cancel := context.WithCancel(context.Background())
	s.cancel = cancel
	done := make(chan struct{})
	s.done = done
	s.mu.Unlock()

	opts := RunOptions{
		Hash:      hash,
		Mode:      mode,
		Strategy:  strategy,
		SessionID: sessionID,
	}
	go s.run(ctx, cancel, hcPath, opts, done)
	return sessionID, nil
}

// StopHashcat 立刻终止 hashcat 进程，并等 goroutine 收尾。
func (s *HashcatService) StopHashcat() error {
	s.mu.Lock()
	session, cancel, done := s.session, s.cancel, s.done
	s.mu.Unlock()

	if cancel == nil {
		return nil
	}
	cancel()
	// 只取消 context 不够快：hashcat 在内核里跑时不会看 context，
	// 用户点「停止」必须当场把进程杀掉。
	if session != "" {
		_ = Stop(session)
	}
	if done != nil {
		<-done
	}
	return nil
}

// LastResult 返回最近一次运行的结果，前端刷新后可以据此恢复界面。
func (s *HashcatService) LastResult() DoneEvent {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.last
}

// DecryptResult 是「用恢复出的密码解压」的结果。
type DecryptResult struct {
	Extracted int `json:"extracted"`
	Skipped   int `json:"skipped"`
	Failed    int `json:"failed"`
}

// DecryptFile 用恢复出的密码把整个压缩包解到 outputDir。
//
// 直接复用批量解压那套（7z + Job），这样密码正确性、编码处理、错误文案
// 都和别处一致，不需要为 GPU 这条链路再写一份解压逻辑。
func (s *HashcatService) DecryptFile(archivePath, password, outputDir string) (DecryptResult, error) {
	if strings.TrimSpace(archivePath) == "" {
		return DecryptResult{}, errors.New("hashcat: 没有指定压缩包")
	}
	if strings.TrimSpace(outputDir) == "" {
		return DecryptResult{}, errors.New("hashcat: 没有选择导出目录")
	}

	res := unzip.ExtractAll(unzip.Job{
		ZipPath:   archivePath,
		Password:  password,
		OutputDir: outputDir,
	})
	if res.Err != nil {
		return DecryptResult{}, res.Err
	}
	return DecryptResult{
		Extracted: res.Extracted,
		Skipped:   res.Skipped,
		Failed:    res.Failed,
	}, nil
}

// emitter 返回一个把原始输出行推给前端的回调。
func (s *HashcatService) emitter() func(string) {
	app := application.Get()
	if app == nil {
		return nil
	}
	var mu sync.Mutex
	return func(line string) {
		mu.Lock()
		defer mu.Unlock()
		app.Event.Emit(EventProgress, ProgressEvent{Line: line})
	}
}

// progressEmitter 返回一个把结构化进度推给前端的回调。
func (s *HashcatService) progressEmitter() func(Progress) {
	app := application.Get()
	if app == nil {
		return nil
	}
	var mu sync.Mutex
	return func(p Progress) {
		mu.Lock()
		defer mu.Unlock()
		app.Event.Emit(EventProgress, ProgressEvent{
			Status:    p.Status,
			Speed:     p.Speed,
			Progress:  p.Progress,
			Recovered: p.Recovered,
			ETA:       p.ETA,
		})
	}
}

// run 是破解线程：跑 Run、发进度、收尾发 hashcat-done。
func (s *HashcatService) run(ctx context.Context, cancel context.CancelFunc, hcPath string, opts RunOptions, done chan struct{}) {
	defer close(done)
	defer cancel()

	started := time.Now()
	app := application.Get()

	// 边推日志边留一份，失败时从尾部挑几行塞进 done 事件。
	var (
		rawMu sync.Mutex
		raw   []string
	)
	emitLine := s.emitter()
	opts.OnLine = func(line string) {
		rawMu.Lock()
		raw = append(raw, line)
		if len(raw) > tailLimit*5 {
			raw = raw[len(raw)-tailLimit*5:]
		}
		rawMu.Unlock()
		if emitLine != nil {
			emitLine(line)
		}
	}

	res, err := Run(ctx, hcPath, opts, s.progressEmitter())

	ev := DoneEvent{ElapsedMs: time.Since(started).Milliseconds(), Status: res.Status}
	switch {
	case errors.Is(err, ErrCancelled):
		ev.Cancelled = true
		ev.Err = "已停止"
	case err != nil:
		ev.Err = err.Error()
	case res.Password != "":
		ev.OK = true
		ev.Password = res.Password
	default:
		ev.Err = ErrExhausted.Error()
	}
	if !ev.OK {
		rawMu.Lock()
		// 回传给前端的是「挑过的」几行：原始输出里混着一堆初始化噪声，
		// 整段贴到失败卡片上用户根本找不到重点。
		ev.Tail = pickFailureLines(lastLines(raw, tailLimit), 8)
		rawMu.Unlock()
	}

	s.mu.Lock()
	s.running = false
	s.session = ""
	s.cancel = nil
	s.done = nil
	s.last = ev
	s.mu.Unlock()

	if app != nil {
		app.Event.Emit(EventDone, ev)
	}
}

// tailLimit 是失败时先留住的原始输出行数；回传给前端的还要经过
// pickFailureLines 再挑一遍，最终只有几行。
const tailLimit = 20

// lastLines 取最后 n 行，并去掉纯空行与进度条提示行。
func lastLines(lines []string, n int) []string {
	kept := make([]string, 0, len(lines))
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		// 交互提示符对判断原因没有帮助。
		if strings.HasPrefix(line, "[s]tatus [p]ause") {
			continue
		}
		kept = append(kept, line)
	}
	if len(kept) > n {
		kept = kept[len(kept)-n:]
	}
	return kept
}
