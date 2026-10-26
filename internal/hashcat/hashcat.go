// Package hashcat 负责驱动外部 hashcat 进程做密码恢复。
//
// 本包不关心哈希是怎么来的，只接收一个 hashcat 可识别的哈希字符串、
// 一个模式号与一份攻击策略，然后把 hashcat 的标准输出逐行解析成结构化进度。
//
// 几个容易踩的坑，这里都做了处理：
//
//   - 哈希走临时文件而不是命令行：$zip2$/$rar5$/$7z$ 里全是 '$' 与 '*'，
//     直接拼进命令行会被 shell 或 Windows 参数解析吃掉。
//   - 用 os.Pipe 把 stdout 与 stderr 合并成一条流：只读 stdout 时，
//     stderr 写满管道缓冲区会让 hashcat 卡死。
//   - 进度行可能以 '\r' 结尾（覆盖式刷新），所以按 '\r' 与 '\n' 双分隔。
//   - 破解成功后明文只在 potfile 里，必须用 --potfile-path 指定临时文件再读回来。
//   - 每次运行用独立的 session 与 potfile，避免多实例互相干扰。
package hashcat

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"math"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/bliey/zipkit/internal/executil"
)

// 攻击策略类型。
const (
	// StrategyDictionary 字典攻击（-a 0）。
	StrategyDictionary = "dictionary"
	// StrategyMask 掩码攻击（-a 3，直接用 ?d?d... 形式的掩码）。
	StrategyMask = "mask"
	// StrategyBruteforce 暴力攻击（-a 3 + 自定义字符集 ?1?1...）。
	StrategyBruteforce = "bruteforce"
)

// hashcat 的退出码含义。
const (
	exitCracked   = 0
	exitExhausted = 1
	exitAborted   = 2
)

// 运行过程中可能返回的错误。
var (
	// ErrExhausted 表示候选空间已穷尽，仍未找到密码。这不算异常。
	ErrExhausted = errors.New("hashcat: 未恢复密码（候选已穷尽）")
	// ErrCancelled 表示调用方主动取消。
	ErrCancelled = errors.New("hashcat: 已取消")
	// ErrFailed 表示 hashcat 以非预期状态退出。
	// 消息里不再重复工具名：包装它的地方已经写成 "hashcat 退出码 N"。
	ErrFailed = errors.New("运行失败")
	// ErrBadStrategy 表示攻击策略参数不合法。
	ErrBadStrategy = errors.New("hashcat: 攻击策略无效")
	// ErrNoPassword 表示 hashcat 报告破解成功，但 potfile 里读不到明文。
	ErrNoPassword = errors.New("hashcat: 破解成功但未读到明文")
)

// 暴力攻击的长度范围限制。前端两个输入框（最小/最大）都用这个区间，
// 后端再校验一次：光靠前端钳制，改个请求就能把长度提到天文数字。
const (
	minBruteforceLength = 1
	maxBruteforceLength = 12
)

// Strategy 描述一次攻击怎么跑。
type Strategy struct {
	// Kind 是 StrategyDictionary / StrategyMask / StrategyBruteforce 之一。
	Kind string
	// Wordlist 是字典文件路径（Kind 为 dictionary 时必填）。
	Wordlist string
	// Mask 是掩码，例如 ?d?d?d?d?d?d（Kind 为 mask 时必填）。
	// 掩码策略的密码长度由掩码本身决定，不需要再给长度范围。
	Mask string
	// Charset 是自定义字符集（Kind 为 bruteforce 时必填），会映射为 -1。
	Charset string
	// MinLen / MaxLen 是暴力攻击的密码长度范围（Kind 为 bruteforce 时必填），
	// 必须满足 1 ≤ MinLen ≤ MaxLen ≤ 12。
	//
	// 用 --increment 让 hashcat 在一次运行里从 MinLen 试到 MaxLen：每次启动
	// hashcat 都要重载内核、重建字典缓存，8 次独立启动的开销远大于一次
	// 带 --increment 的运行。
	MinLen int `json:"minLen"`
	MaxLen int `json:"maxLen"`
}

// Progress 是一份结构化进度。
type Progress struct {
	Status    string // Running / Cracked / Exhausted / Aborted ...
	Speed     string // 例如 "1234.5 kH/s"
	Progress  string // 例如 "12.34%"
	Recovered string // 例如 "1/1 (100.00%)"
	ETA       string // 例如 "1 min, 2 secs"
	Password  string // 仅破解成功时有值
}

// RunOptions 是一次运行的输入。
type RunOptions struct {
	Hash      string // hashcat 可识别的哈希字符串
	Mode      int    // hashcat 模式号，例如 13600
	Strategy  Strategy
	SessionID string // 会话名；为空时自动生成
	// ExtraArgs 追加到命令行的额外参数，主要给测试与排障用。
	ExtraArgs []string
	// OnLine 会收到 hashcat 的每一行原始输出（已去掉颜色控制符）。
	// 界面上那块等宽日志就是靠它填的；为 nil 时不回调。
	OnLine func(string)
}

// session 记录一个正在运行的 hashcat 进程。
type session struct {
	cmd      *exec.Cmd
	potfile  string
	tempDir  string
	killed   atomic.Bool
	done     chan struct{}
	mu       sync.Mutex
	password string
}

var (
	sessionsMu sync.Mutex
	sessions   = map[string]*session{}
)

// sessionCounter 保证同一毫秒内多次运行也能拿到不同的会话名。
var sessionCounter atomic.Uint64

// Run 启动 hashcat 并阻塞到进程结束。onProgress 为 nil 时忽略进度回调。
//
// 返回值的 Password 在破解成功时非空。密码未恢复时返回 ErrExhausted；
// ctx 被取消时返回 ErrCancelled。
func Run(ctx context.Context, hashcatPath string, opts RunOptions, onProgress func(Progress)) (Progress, error) {
	if strings.TrimSpace(opts.Hash) == "" {
		return Progress{}, fmt.Errorf("%w: 哈希为空", ErrBadStrategy)
	}
	if opts.Mode <= 0 {
		return Progress{}, fmt.Errorf("%w: 模式号 %d 非法", ErrBadStrategy, opts.Mode)
	}
	attackMode, flags, target, err := buildArgs(opts)
	if err != nil {
		return Progress{}, err
	}

	sessionID := opts.SessionID
	if sessionID == "" {
		sessionID = fmt.Sprintf("zipkit-%d-%d", time.Now().UnixNano(), sessionCounter.Add(1))
	}

	tempDir, err := os.MkdirTemp("", "zipkit-hashcat-")
	if err != nil {
		return Progress{}, fmt.Errorf("%w: 创建临时目录失败: %v", ErrFailed, err)
	}
	cleanupTemp := true
	defer func() {
		if cleanupTemp {
			os.RemoveAll(tempDir)
		}
	}()

	hashFile := filepath.Join(tempDir, "target.hash")
	// 末尾必须有换行，否则 hashcat 会把最后一行当成被截断的内容。
	if err := os.WriteFile(hashFile, []byte(opts.Hash+"\n"), 0o600); err != nil {
		return Progress{}, fmt.Errorf("%w: 写入哈希文件失败: %v", ErrFailed, err)
	}
	potfile := filepath.Join(tempDir, "hashcat.potfile")

	// hashcat 的位置参数顺序固定为：<哈希文件> <词表或掩码>，
	// 目标不能跑到哈希文件前面，否则它会把掩码当成哈希去解析。
	full := commandArgs(opts, attackMode, flags, target, hashFile, potfile, sessionID)

	cmd := executil.Command(hashcatPath, full...)
	// hashcat 会相对当前工作目录去找 OpenCL/ 与 modules/，在别的目录下启动
	// 会直接报 "./OpenCL/: No such file or directory"。所以切到它自己的目录。
	if abs, err := filepath.Abs(hashcatPath); err == nil {
		cmd.Dir = filepath.Dir(abs)
	}

	// stdout 与 stderr 合并到同一个管道：hashcat 的告警走 stderr，
	// 只读 stdout 会让它因为管道写满而阻塞。
	pr, pw, err := os.Pipe()
	if err != nil {
		return Progress{}, fmt.Errorf("%w: 创建管道失败: %v", ErrFailed, err)
	}
	cmd.Stdout = pw
	cmd.Stderr = pw
	cmd.Stdin = nil

	s := &session{cmd: cmd, potfile: potfile, tempDir: tempDir, done: make(chan struct{})}
	sessionsMu.Lock()
	sessions[sessionID] = s
	sessionsMu.Unlock()
	defer func() {
		sessionsMu.Lock()
		delete(sessions, sessionID)
		sessionsMu.Unlock()
	}()

	if err := cmd.Start(); err != nil {
		pw.Close()
		pr.Close()
		return Progress{}, fmt.Errorf("%w: 启动 %s 失败: %v", ErrFailed,
			filepath.Base(hashcatPath), err)
	}
	// 父进程必须关掉写端，否则读端永远等不到 EOF。
	pw.Close()

	// ctx 取消时杀掉进程，避免 Run 永久挂住。
	watchDone := make(chan struct{})
	go func() {
		select {
		case <-ctx.Done():
			s.kill()
		case <-watchDone:
		}
	}()

	collector := &progressCollector{emit: onProgress, onLine: opts.OnLine}
	scanErr := scanMerged(pr, collector.feed)
	pr.Close()
	collector.flush()

	waitErr := cmd.Wait()
	close(watchDone)
	close(s.done)

	if s.killed.Load() || ctx.Err() != nil {
		return collector.last, ErrCancelled
	}

	final := collector.last
	if pwd, ok := readPassword(potfile, opts.Hash); ok {
		final.Password = pwd
		if final.Status == "" {
			final.Status = "Cracked"
		}
		return final, nil
	}

	code := exitCode(waitErr)
	switch {
	case final.Status == "Cracked":
		// hashcat 说破解了，但 potfile 里没有——多半是 potfile 路径被外部改动。
		return final, fmt.Errorf("%w: %s", ErrNoPassword, potfile)
	case code == exitExhausted || final.Status == "Exhausted":
		return final, ErrExhausted
	case code == exitAborted:
		return final, ErrCancelled
	case code == exitCracked:
		// 退出码 0 却没有明文，按未恢复处理，避免界面误报成功。
		return final, ErrExhausted
	case scanErr != nil:
		return final, newRunError(failureDetail(code, collector.tail(5), scanErr))
	}
	if waitErr != nil {
		return final, newRunError(failureDetail(code, collector.tail(5), waitErr))
	}
	return final, ErrExhausted
}

// RunError 是 hashcat 以非预期状态退出的错误。
//
// 消息本身就是给用户看的（工具名 + 退出码 + 关键输出行），所以不再套一层
// 「运行失败: 」前缀；errors.Is(err, ErrFailed) 通过 Unwrap 仍然成立。
type RunError struct{ detail string }

func (e *RunError) Error() string { return e.detail }

func (e *RunError) Unwrap() error { return ErrFailed }

func newRunError(detail string) error { return &RunError{detail: detail} }

// failureDetail 统一失败信息：工具名 + 退出码 + 输出的前 5 行。
//
// hashcat 的真实原因（缺 OpenCL、需要 --force、掩码写错）只出现在输出里，
// 光给一个 "exit status 1" 对用户没有任何帮助。
func failureDetail(code int, lines []string, cause error) string {
	var b strings.Builder
	fmt.Fprintf(&b, "hashcat 退出码 %d", normalizeExitCode(code))
	if cause != nil {
		fmt.Fprintf(&b, "（%v）", cause)
	}
	for _, line := range pickFailureLines(lines, 5) {
		b.WriteString("\n  ")
		b.WriteString(line)
	}
	return b.String()
}

// normalizeExitCode 把 Windows 上的无符号退出码折成有符号数。
//
// 进程以 0xFFFFFFFF 退出时 Go 会给出 4294967295，直接打给用户没人看得懂；
// 折成 -1 至少和 "exit status -1" 对得上。
func normalizeExitCode(code int) int {
	if code > math.MaxInt32 {
		return code - (1 << 32)
	}
	return code
}

// errorKeywords 用来在失败输出里挑出真正有用的行。
var errorKeywords = []string{
	"error", "failed", "failure", "cannot", "can't", "unable",
	"no such", "not found", "invalid", "unsupported", "syntax",
	"exception", "denied", "missing", "no hashes", "requires",
	"token length", "exceeded", "out of memory", "not installed",
}

// pickFailureLines 从原始输出里挑出最多 max 行「有用」的内容。
//
// hashcat 把一堆 "Initializing ... Please be patient...Initialized ..." 连着
// 写在同一行里（管道里没有换行），照原样贴给用户就是一堵墙。这里先按换行
// 拆散、丢掉空行，优先挑带错误关键词的行，不够再补尾部。
func pickFailureLines(lines []string, max int) []string {
	var all []string
	for _, line := range lines {
		// hashcat 写这些固定短语时不带前导换行，整段会粘成一行，
		// 比如 "Finished self-testSyntax error in mask: ?x?x?x?x"。
		line = splitGlued(line)
		for _, part := range strings.FieldsFunc(line, func(r rune) bool {
			return r == '\r' || r == '\n'
		}) {
			part = strings.TrimSpace(part)
			if part == "" {
				continue
			}
			all = append(all, truncateRunes(part, 220))
		}
	}
	if len(all) == 0 {
		return nil
	}

	picked := make([]string, 0, max)
	seen := make(map[string]bool, len(all))
	for _, line := range all {
		if len(picked) == max {
			return picked
		}
		if seen[line] || !containsAny(strings.ToLower(line), errorKeywords) {
			continue
		}
		seen[line] = true
		picked = append(picked, line)
	}
	if len(picked) > 0 {
		return picked
	}

	// 一行都没命中关键词：退回最后几行，尾部通常才是真正失败的地方。
	for i := len(all) - 1; i >= 0 && len(picked) < max; i-- {
		if seen[all[i]] {
			continue
		}
		seen[all[i]] = true
		picked = append([]string{all[i]}, picked...)
	}
	return picked
}

// glueStarts 是 hashcat 写在一行里、但其实是新句子开头的短语。
//
// 管道模式下 hashcat 经常不打换行：「Finished self-test」后面直接接
// 「Syntax error in mask: ...」，贴到失败卡片上就是一句看不懂的连体话。
var glueStarts = []string{
	"Syntax error",
	"No devices found",
	"Failed to",
	"ERROR:",
	"Warning:",
}

// splitGlued 把粘连在一行里的多句 hashcat 输出拆开。
//
// 两种断点：一是固定的 "Please be patient..."（初始化提示的收尾），
// 二是上面列出的句首短语。已经在行首的不再重复插换行。
func splitGlued(line string) string {
	line = strings.ReplaceAll(line, "Please be patient...", "Please be patient...\n")
	for _, phrase := range glueStarts {
		var b strings.Builder
		rest := line
		for {
			idx := strings.Index(rest, phrase)
			if idx < 0 {
				b.WriteString(rest)
				break
			}
			if idx > 0 && rest[idx-1] != '\n' {
				b.WriteString(rest[:idx])
				b.WriteString("\n")
			} else {
				b.WriteString(rest[:idx])
			}
			b.WriteString(phrase)
			rest = rest[idx+len(phrase):]
		}
		line = b.String()
	}
	return line
}

// containsAny 判断 s 是否包含任意一个关键词。
func containsAny(s string, keywords []string) bool {
	for _, k := range keywords {
		if strings.Contains(s, k) {
			return true
		}
	}
	return false
}

// truncateRunes 按字符截断，避免把中文切成半个字节。
func truncateRunes(s string, max int) string {
	runes := []rune(s)
	if len(runes) <= max {
		return s
	}
	return string(runes[:max]) + "…"
}

// Stop 终止指定会话的 hashcat 进程并清理临时文件。
// 会话不存在时返回 nil——停止一个已经结束的任务不该报错。
func Stop(sessionID string) error {
	sessionsMu.Lock()
	s := sessions[sessionID]
	sessionsMu.Unlock()
	if s == nil {
		return nil
	}
	s.kill()
	return nil
}

// kill 杀掉进程并等待它退出，只生效一次。
func (s *session) kill() {
	if s.killed.Swap(true) {
		return
	}
	if s.cmd.Process != nil {
		_ = s.cmd.Process.Kill()
	}
	// 等 Run 里的 cmd.Wait 收尾，避免临时目录被提前删掉。
	select {
	case <-s.done:
	case <-time.After(5 * time.Second):
	}
}

// commandArgs 拼出完整的 hashcat 参数列表。
//
// 单独抽出来是为了能被测试直接断言：位置参数顺序一旦写错（例如把掩码放到
// 哈希文件前面），hashcat 会报 "Separator unmatched / No hashes loaded"，
// 而且现象很难和哈希格式错误区分开。
func commandArgs(opts RunOptions, attackMode string, flags []string, target, hashFile, potfile, sessionID string) []string {
	out := []string{"-m", strconv.Itoa(opts.Mode), "-a", attackMode}
	out = append(out, flags...)
	out = append(out, hashFile, target)
	out = append(out,
		"--status",
		"--status-timer=1",
		"--session="+sessionID,
		"--potfile-path="+potfile,
		// 不写 restore 文件，避免污染用户主目录（也不支持断点续跑）。
		"--restore-disable",
	)
	out = append(out, opts.ExtraArgs...)
	return out
}

// buildArgs 把策略翻译成 hashcat 参数。
//
// 返回攻击模式（-a 的值）、附加选项（如 -1 自定义字符集）与目标（词表或掩码）。
// 目标必须紧跟在哈希文件之后，所以不能直接拼进完整命令行，要分开返回。
func buildArgs(opts RunOptions) (attackMode string, flags []string, target string, err error) {
	st := opts.Strategy
	switch st.Kind {
	case StrategyDictionary:
		wordlist := strings.TrimSpace(st.Wordlist)
		if wordlist == "" {
			return "", nil, "", fmt.Errorf("%w: 字典攻击需要词表路径", ErrBadStrategy)
		}
		// hashcat 在它自己的目录下运行，相对路径会指错地方，统一转绝对路径。
		if abs, err := filepath.Abs(wordlist); err == nil {
			wordlist = abs
		}
		if info, err := os.Stat(wordlist); err != nil || info.IsDir() {
			return "", nil, "", fmt.Errorf("%w: 词表不可用: %s", ErrBadStrategy, st.Wordlist)
		}
		return "0", nil, wordlist, nil

	case StrategyMask:
		mask := strings.TrimSpace(st.Mask)
		if mask == "" {
			return "", nil, "", fmt.Errorf("%w: 掩码攻击需要掩码", ErrBadStrategy)
		}
		return "3", nil, mask, nil

	case StrategyBruteforce:
		charset := strings.TrimSpace(st.Charset)
		if charset == "" {
			return "", nil, "", fmt.Errorf("%w: 暴力攻击需要字符集", ErrBadStrategy)
		}
		minLen, maxLen, err := bruteforceRange(st)
		if err != nil {
			return "", nil, "", err
		}
		// 掩码按最大长度写满，再用 --increment 让 hashcat 自己从 minLen
		// 递增到 maxLen：一次启动试完整个范围，不必为每个长度重载内核。
		flags := []string{
			"-1", charset,
			"--increment",
			fmt.Sprintf("--increment-min=%d", minLen),
			fmt.Sprintf("--increment-max=%d", maxLen),
		}
		return "3", flags, strings.Repeat("?1", maxLen), nil
	}
	return "", nil, "", fmt.Errorf("%w: 未知类型 %q", ErrBadStrategy, st.Kind)
}

// bruteforceRange 校验暴力攻击的长度范围。
//
// 后端必须自己校验一次：前端已经把两个输入框钳在 1..12，但请求不一定来自
// 前端（脚本可以直接调绑定方法），长度写到 30 位就是跑不完的活儿。
func bruteforceRange(st Strategy) (int, int, error) {
	minLen, maxLen := st.MinLen, st.MaxLen
	if minLen < minBruteforceLength || minLen > maxBruteforceLength ||
		maxLen < minBruteforceLength || maxLen > maxBruteforceLength {
		return 0, 0, fmt.Errorf("%w: 密码长度范围 %d-%d 超出 %d..%d", ErrBadStrategy,
			minLen, maxLen, minBruteforceLength, maxBruteforceLength)
	}
	if minLen > maxLen {
		return 0, 0, fmt.Errorf("%w: 最小长度 %d 大于最大长度 %d", ErrBadStrategy, minLen, maxLen)
	}
	return minLen, maxLen, nil
}

// exitCode 从 Wait 错误里取进程退出码，取不到时返回 -1。
func exitCode(err error) int {
	if err == nil {
		return 0
	}
	var ee *exec.ExitError
	if errors.As(err, &ee) {
		return ee.ExitCode()
	}
	return -1
}

// readPassword 从 potfile 里读出明文。potfile 每行是 "hash:password"，
// 哈希部分不含 ':'，所以按第一个冒号切分即可（明文里可以有冒号）。
func readPassword(potfile, hash string) (string, bool) {
	data, err := os.ReadFile(potfile)
	if err != nil {
		return "", false
	}
	want := strings.TrimSpace(hash)
	var last string
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimRight(line, "\r")
		if line == "" {
			continue
		}
		parts := strings.SplitN(line, ":", 2)
		if len(parts) != 2 {
			continue
		}
		last = parts[1]
		if strings.TrimSpace(parts[0]) == want {
			return parts[1], true
		}
	}
	// 本次运行的 potfile 是全新的，里面只可能有我们这一条哈希，
	// 因此格式对不上时退回最后一条，避免因为 hashcat 重编码哈希而漏掉明文。
	if last != "" {
		return last, true
	}
	return "", false
}

// ---------------------------------------------------------------------------
// 输出解析
// ---------------------------------------------------------------------------

// ansiRe 匹配终端颜色控制序列，hashcat 偶尔会输出。
var ansiRe = regexp.MustCompile("\x1b\\[[0-9;]*[A-Za-z]")

// splitFunc 同时按 '\r' 与 '\n' 切行：hashcat 的进度行以 '\r' 刷新。
func splitFunc(data []byte, atEOF bool) (int, []byte, error) {
	if i := bytes.IndexAny(data, "\r\n"); i >= 0 {
		return i + 1, data[:i], nil
	}
	if atEOF && len(data) > 0 {
		return len(data), data, nil
	}
	return 0, nil, nil
}

// scanMerged 逐行读取管道内容并回调。
func scanMerged(r *os.File, fn func(string)) error {
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 64*1024), 4*1024*1024)
	sc.Split(splitFunc)
	for sc.Scan() {
		fn(sc.Text())
	}
	return sc.Err()
}

// progressCollector 把 hashcat 的输出块解析成 Progress。
type progressCollector struct {
	emit   func(Progress)
	onLine func(string)
	cur    Progress
	last   Progress
	has    bool
	// raw 保留最近若干行原始输出，用于失败时给出上下文。
	raw []string
}

// rawLimit 是保留的原始输出行数。
const rawLimit = 40

// feed 处理一行。字段按 "名字....: 值" 的形式解析，靠完整字段名判断，
// 不用子串匹配，避免 "Candidates.#1" 之类被误当成 "Progress"。
func (c *progressCollector) feed(line string) {
	clean := strings.TrimSpace(ansiRe.ReplaceAllString(line, ""))
	if clean == "" {
		return
	}
	c.raw = append(c.raw, clean)
	if c.onLine != nil {
		c.onLine(clean)
	}
	if len(c.raw) > rawLimit {
		c.raw = c.raw[len(c.raw)-rawLimit:]
	}

	idx := strings.Index(clean, ":")
	if idx <= 0 {
		return
	}
	field := strings.TrimRight(strings.TrimSpace(clean[:idx]), ".")
	value := strings.TrimSpace(clean[idx+1:])
	if field == "" || value == "" {
		return
	}

	// hashcat 6.x 打印 "Speed.#1"，7.x 起把设备号补零成 "Speed.#01"，
	// 多设备时还有 "Speed.Dev.#1"。按前缀识别，别让版本差异把速度吞掉。
	if isSpeedField(field) {
		// "247.4 kH/s (10.22ms) @ Accel:4 Loops:999 ..." 只留速度本身。
		c.cur.Speed = cutAt(value, " (")
		c.has = true
		return
	}

	switch field {
	case "Session":
		// 每个状态块以 Session 开头，看到它就说明上一块已经完整。
		c.flush()
	case "Status":
		if c.cur.Status != "" {
			c.flush()
		}
		c.cur.Status = value
		c.has = true
	case "Progress":
		// "262144/1000000 (26.21%)" 只保留百分比，界面上更好排。
		if i := strings.LastIndex(value, "("); i >= 0 {
			c.cur.Progress = strings.TrimSuffix(value[i+1:], ")")
		} else {
			c.cur.Progress = value
		}
		c.has = true
	case "Recovered":
		// "1/1 (100.00%) Digests (total), 1/1 (100.00%) Digests (new)"
		c.cur.Recovered = cutAt(value, " Digests")
		c.has = true
	case "Time.Estimated":
		c.cur.ETA = value
		c.has = true
	}
}

// isSpeedField 判断字段名是不是速度行。
//
// 覆盖 "Speed.#1"、"Speed.#01"、"Speed.#*"（多设备汇总）以及
// "Speed.Dev.#1" 这几种写法。
func isSpeedField(field string) bool {
	rest, ok := strings.CutPrefix(field, "Speed.")
	if !ok {
		return false
	}
	rest = strings.TrimPrefix(rest, "Dev.")
	return strings.HasPrefix(rest, "#")
}

// cutAt 在 sep 第一次出现处截断，用于去掉 hashcat 附带的统计细节。
func cutAt(s, sep string) string {
	if i := strings.Index(s, sep); i >= 0 {
		return strings.TrimSpace(s[:i])
	}
	return s
}

// tail 返回最后 n 行原始输出。
func (c *progressCollector) tail(n int) []string {
	if len(c.raw) == 0 {
		return nil
	}
	start := len(c.raw) - n
	if start < 0 {
		start = 0
	}
	return c.raw[start:]
}

// flush 把当前块交给回调，然后清空。
func (c *progressCollector) flush() {
	if !c.has {
		c.cur = Progress{}
		return
	}
	snapshot := c.cur
	c.last = snapshot
	if c.emit != nil {
		c.emit(snapshot)
	}
	c.cur = Progress{}
	c.has = false
}
