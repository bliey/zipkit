// Package unzip 用系统 7-Zip 把 ZIP 解压到指定目录。
//
// 为什么不自己解：archive/zip 能读中央目录，但 f.Open() 遇到 ZipCrypto / AES
// 加密条目会直接报「zip: unsupported compression algorithm」之类的错误——
// 标准库根本不实现传统加密和 AES 解密。7z 能一次覆盖 ZipCrypto、AES、
// Store、Deflate、ZIP64 全部情况，所以这一层只做三件事：拼参数、跑进程、
// 把退出码和输出翻译成 Result。
package unzip

import (
	"archive/zip"
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"sync"

	"github.com/bliey/zipkit/internal/executil"
	"github.com/bliey/zipkit/internal/settings"
)

// DefaultConcurrency 是解压的默认并发数。
//
// 解压是 IO 密集型，再多的并发只会让多个 7z 抢同一块盘；3 个已经能打满
// 普通机械盘的顺序写带宽。真正的值放在 settings 包里（配置文件共享），
// 这里只是给调用方一个短名字。
const DefaultConcurrency = settings.DefaultConcurrency

// Job 是一次解压任务。
type Job struct {
	ZipPath   string
	Password  string
	OutputDir string // 该压缩包解压的目标目录
	EntryName string // 可选：只解压某个条目；为空时解压全部

	// RenameExisting 为 true 时，目标目录里的同名文件不跳过，而是让 7z 给
	// 新解出来的文件加 _1、_2 后缀（-aou）。「全部解压到同一目录」用这个
	// 模式，避免不同压缩包里的同名文件互相覆盖。
	RenameExisting bool
}

// Result 是一次解压的结果。
//
// Extracted 是成功解出的文件数，Skipped 是因为目标文件已存在而跳过的条目数
// （RenameExisting 模式下恒为 0），Failed 是 7z 报告的失败条目数。Err 非空
// 表示整体失败（打不开、密码错误、没有写权限……），此时前面几个计数没有
// 参考价值。
type Result struct {
	ZipPath   string
	OutputDir string
	Extracted int
	Failed    int
	Skipped   int
	Err       error
}

// ExtractAll 解压一个 Job，等价于用 background context 调用 ExtractContext。
func ExtractAll(job Job) Result {
	return ExtractContext(context.Background(), job)
}

// ExtractContext 解压一个 Job，ctx 取消时会杀掉正在跑的 7z 进程。
//
// 返回的 Err 在取消场景下是 context.Canceled，调用方可以据此把这次解压
// 当作「被打断」而不是「失败」。
func ExtractContext(ctx context.Context, job Job) Result {
	res := Result{ZipPath: job.ZipPath, OutputDir: job.OutputDir}

	if strings.TrimSpace(job.ZipPath) == "" {
		res.Err = errors.New("unzip: 压缩包路径为空")
		return res
	}
	if strings.TrimSpace(job.OutputDir) == "" {
		res.Err = errors.New("unzip: 输出目录为空")
		return res
	}

	info, err := os.Stat(job.ZipPath)
	if err != nil {
		res.Err = fmt.Errorf("unzip: 打开 %q：%w", job.ZipPath, err)
		return res
	}
	if info.IsDir() {
		res.Err = fmt.Errorf("unzip: %q 是目录", job.ZipPath)
		return res
	}

	sevenZip, err := ResolveSevenZip()
	if err != nil {
		res.Err = err
		return res
	}

	if err := os.MkdirAll(job.OutputDir, 0o755); err != nil {
		res.Err = fmt.Errorf("unzip: 创建输出目录 %q：%w", job.OutputDir, err)
		return res
	}

	// 先把归档里的条目名读出来（archive/zip 只读中央目录，不需要密码），
	// 再和目标目录里已有的文件对比。这样「跳过 N 个已存在文件」是算出来的，
	// 而不是从 7z 的屏幕输出里猜的。
	entries, listErr := listEntries(job.ZipPath, job.EntryName)
	existing := existingFiles(job.OutputDir)
	skipped := 0
	if listErr == nil && !job.RenameExisting {
		for _, name := range entries {
			if _, ok := existing[entryKey(name)]; ok {
				skipped++
			}
		}
	}

	cmd := executil.CommandContext(ctx, sevenZip, sevenZipArgs(job)...)
	untrack := trackCommand(cmd)
	defer untrack()

	stdoutPipe, err := cmd.StdoutPipe()
	if err != nil {
		res.Err = fmt.Errorf("unzip: 接管 7z 输出失败：%w", err)
		return res
	}
	stderrPipe, err := cmd.StderrPipe()
	if err != nil {
		res.Err = fmt.Errorf("unzip: 接管 7z 错误输出失败：%w", err)
		return res
	}

	if err := cmd.Start(); err != nil {
		if ctxErr := ctx.Err(); ctxErr != nil {
			res.Err = ctxErr
			return res
		}
		res.Err = fmt.Errorf("unzip: 启动 7z 失败：%w", err)
		return res
	}

	// 两个管道必须同时读，否则 7z 写满其中一个的缓冲区就会卡住。
	var wg sync.WaitGroup
	wg.Add(2)

	var summary sevenZipSummary
	go func() {
		defer wg.Done()
		summary.scan(stdoutPipe)
	}()

	var stderrBuf tailBuffer
	go func() {
		defer wg.Done()
		_, _ = io.Copy(&stderrBuf, stderrPipe)
	}()

	// 先把管道读干净再 Wait：os/exec 在 Wait 里关闭管道，先 Wait 会丢尾部输出。
	wg.Wait()
	waitErr := cmd.Wait()

	if ctxErr := ctx.Err(); ctxErr != nil {
		res.Err = ctxErr
		return res
	}

	code := 0
	if waitErr != nil {
		var exitErr *exec.ExitError
		if !errors.As(waitErr, &exitErr) {
			res.Err = fmt.Errorf("unzip: 7z 运行失败：%w", waitErr)
			return res
		}
		code = exitErr.ExitCode()
	}

	res.Skipped = skipped
	switch code {
	case 0:
		res.Extracted = countExtracted(entries, listErr, skipped, &summary)
	case 1:
		// 1 = 有警告但解压完成，比如部分条目被跳过。
		res.Extracted = countExtracted(entries, listErr, skipped, &summary)
		res.Failed = summary.subErrors
	default:
		res.Failed = summary.subErrors
		if res.Failed == 0 {
			res.Failed = 1
		}
		res.Err = describeFailure(code, summary.text, stderrBuf.String())
		// 密码错误时 7z 会先建出文件、读到 CRC 才发现不对，留下一个 0 字节
		// 的同名文件。不清掉的话用户会以为「报错了但文件解出来了」。
		removeEmptyNewFiles(job.OutputDir, existing)
	}
	return res
}

// removeEmptyNewFiles 删掉本次运行新产生、且大小为 0 的文件。
//
// 只动「运行前不存在 + 0 字节」这两个条件同时满足的文件，不会碰到用户
// 原有的任何东西。
func removeEmptyNewFiles(dir string, before map[string]struct{}) {
	_ = filepath.WalkDir(dir, func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return nil
		}
		rel, relErr := filepath.Rel(dir, path)
		if relErr != nil {
			return nil
		}
		if _, ok := before[entryKey(rel)]; ok {
			return nil
		}
		info, infoErr := d.Info()
		if infoErr != nil || info.Size() != 0 {
			return nil
		}
		_ = os.Remove(path)
		return nil
	})
}

// sevenZipArgs 拼 7z 的参数。全程用参数数组，不经过 shell，密码里带空格、
// 引号、&、| 都不会被解释。
func sevenZipArgs(job Job) []string {
	args := []string{"x", "-y"}
	if job.RenameExisting {
		args = append(args, "-aou") // 重名时给解出来的文件加序号
	} else {
		args = append(args, "-aos") // 已存在的文件跳过，不覆盖
	}
	if job.Password != "" {
		// -p 和密码之间不能有空格；密码为空时干脆不传，交给 7z 直接报错，
		// 传一个空的 -p 会让它转而向终端要密码，把进程挂住。
		args = append(args, "-p"+job.Password)
	}
	// -o 和目录之间同样不能有空格，否则 7z 会把目录当成另一个参数。
	args = append(args, "-o"+job.OutputDir, job.ZipPath)
	if job.EntryName != "" {
		args = append(args, job.EntryName)
	}
	return args
}

// countExtracted 优先用我们自己数的条目数（总数 - 已跳过），拿不到中央目录
// 时退回 7z 自己报的 Files: N。
func countExtracted(entries []string, listErr error, skipped int, summary *sevenZipSummary) int {
	if listErr == nil {
		n := len(entries) - skipped
		if n < 0 {
			n = 0
		}
		return n
	}
	return summary.files
}

// listEntries 读出归档里的文件条目（跳过目录条目）。
func listEntries(zipPath, only string) ([]string, error) {
	r, err := zip.OpenReader(zipPath)
	if err != nil {
		return nil, err
	}
	defer r.Close()

	names := make([]string, 0, len(r.File))
	for _, f := range r.File {
		if f.FileInfo().IsDir() {
			continue
		}
		if only != "" && f.Name != only {
			continue
		}
		names = append(names, f.Name)
	}
	return names, nil
}

// existingFiles 递归收集目标目录里已有的文件，键是归一化后的相对路径。
func existingFiles(dir string) map[string]struct{} {
	out := make(map[string]struct{})
	_ = filepath.WalkDir(dir, func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return nil
		}
		rel, relErr := filepath.Rel(dir, path)
		if relErr != nil {
			return nil
		}
		out[entryKey(rel)] = struct{}{}
		return nil
	})
	return out
}

// entryKey 把路径归一化成可以比较的键：统一用 /，Windows / macOS 上再折叠
// 大小写（这两个文件系统默认不区分）。
func entryKey(name string) string {
	key := filepath.ToSlash(strings.TrimPrefix(name, "./"))
	if runtime.GOOS == "windows" || runtime.GOOS == "darwin" {
		key = strings.ToLower(key)
	}
	return key
}

// ---------------------------------------------------------------------------
// 7z 输出解析
// ---------------------------------------------------------------------------

var (
	reFilesLine     = regexp.MustCompile(`(?i)^Files:\s*(\d+)\s*$`)
	reSubErrorLine  = regexp.MustCompile(`(?i)^Sub items Errors:\s*(\d+)\s*$`)
	reArchiveErrors = regexp.MustCompile(`(?i)^Archives with Errors:\s*(\d+)\s*$`)
)

// sevenZipSummary 是 7z 标准输出里我们关心的几行。
type sevenZipSummary struct {
	files     int
	subErrors int
	text      string // 带 error 字样的行，拼起来给错误消息用
}

func (s *sevenZipSummary) scan(r io.Reader) {
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)

	var notes []string
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" {
			continue
		}
		if m := reFilesLine.FindStringSubmatch(line); m != nil {
			if n, err := strconv.Atoi(m[1]); err == nil {
				s.files = n
			}
			continue
		}
		if m := reSubErrorLine.FindStringSubmatch(line); m != nil {
			if n, err := strconv.Atoi(m[1]); err == nil {
				s.subErrors = n
			}
			continue
		}
		if m := reArchiveErrors.FindStringSubmatch(line); m != nil {
			if n, err := strconv.Atoi(m[1]); err == nil && s.subErrors == 0 {
				s.subErrors = n
			}
			continue
		}
		if strings.Contains(strings.ToLower(line), "error") {
			notes = append(notes, line)
		}
	}
	s.text = strings.Join(notes, "\n")
}

// tailBuffer 只保留最后 max 字节，避免 7z 刷屏把内存吃光。
type tailBuffer struct {
	buf []byte
	max int
}

func (b *tailBuffer) Write(p []byte) (int, error) {
	if b.max <= 0 {
		b.max = 8 << 10
	}
	b.buf = append(b.buf, p...)
	if len(b.buf) > b.max {
		b.buf = b.buf[len(b.buf)-b.max:]
	}
	return len(p), nil
}

func (b *tailBuffer) String() string { return string(b.buf) }

// describeFailure 把 7z 的退出码 + 输出翻译成用户能看懂的一句话。
//
// 统一的错误格式：工具名 + 退出码 + 输出的前 5 行。前两条是「一眼就知道
// 怎么回事」的常见原因，其余情况把 7z 自己说的话原样带出来。
func describeFailure(code int, stdout, stderr string) error {
	combined := strings.ToLower(stdout + "\n" + stderr)
	tail := firstLines(stderr, 5)
	if tail == "" {
		tail = firstLines(stdout, 5)
	}

	wrap := func(msg string) error {
		if tail == "" {
			return fmt.Errorf("%s（7z 退出码 %d）", msg, code)
		}
		return fmt.Errorf("%s（7z 退出码 %d）\n%s", msg, code, tail)
	}

	switch {
	case strings.Contains(combined, "wrong password"),
		strings.Contains(combined, "can not open encrypted archive"),
		strings.Contains(combined, "cannot open encrypted archive"),
		strings.Contains(combined, "data error in encrypted file"):
		return wrap("密码错误")

	case strings.Contains(combined, "access is denied"),
		strings.Contains(combined, "permission denied"),
		strings.Contains(combined, "cannot open output file"):
		return wrap("输出目录无写权限")
	}

	return wrap("解压失败")
}

// firstLines 取输出的前 n 行非空内容，缩进两格方便贴在错误里阅读。
func firstLines(text string, n int) string {
	var out []string
	for _, line := range strings.Split(text, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		out = append(out, "  "+line)
		if len(out) >= n {
			break
		}
	}
	return strings.Join(out, "\n")
}

// firstErrorLine 优先挑带 ERROR 的那一行，没有就取第一行非空内容。
func firstErrorLine(text string) string {
	var first string
	for _, line := range strings.Split(text, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		if strings.Contains(strings.ToLower(line), "error") {
			return line
		}
		if first == "" {
			first = line
		}
	}
	return first
}

// ---------------------------------------------------------------------------
// 进程登记：StopUnzip 靠它把还在跑的 7z 直接杀掉
// ---------------------------------------------------------------------------

var (
	cmdMu       sync.Mutex
	runningCmds = map[*exec.Cmd]struct{}{}
)

func trackCommand(cmd *exec.Cmd) func() {
	cmdMu.Lock()
	runningCmds[cmd] = struct{}{}
	cmdMu.Unlock()

	return func() {
		cmdMu.Lock()
		delete(runningCmds, cmd)
		cmdMu.Unlock()
	}
}

// KillAll 杀掉当前所有在跑的 7z 进程，返回成功杀掉的个数。
//
// 光取消 context 不够：exec.CommandContext 的 Kill 是异步的，用户点了
// 「停止」之后 7z 可能还在往磁盘里写。这里直接对进程下手，界面才能立刻
// 回到可操作状态。
func KillAll() int {
	cmdMu.Lock()
	defer cmdMu.Unlock()

	killed := 0
	for cmd := range runningCmds {
		if cmd.Process == nil {
			continue
		}
		if err := cmd.Process.Kill(); err == nil {
			killed++
		}
	}
	return killed
}

// ---------------------------------------------------------------------------
// 输出目录规则
// ---------------------------------------------------------------------------

// OutputDirFor 返回 <rootDir>/<压缩包文件名去掉扩展名>。
func OutputDirFor(rootDir, zipPath string) string {
	return filepath.Join(rootDir, dirNameFor(zipPath))
}

// dirNameFor 把压缩包文件名变成安全的目录名。
func dirNameFor(zipPath string) string {
	base := filepath.Base(zipPath)
	name := strings.TrimSuffix(base, filepath.Ext(base))
	name = sanitizeDirName(name)
	if name == "" {
		name = "zip"
	}
	return name
}

var windowsInvalidChars = regexp.MustCompile(`[<>:"/\\|?*\x00-\x1f]`)

// sanitizeDirName 去掉文件名里不能出现在目录名中的字符。
func sanitizeDirName(name string) string {
	name = windowsInvalidChars.ReplaceAllString(name, "_")
	name = strings.Trim(name, " .")

	const limit = 100
	if runes := []rune(name); len(runes) > limit {
		name = string(runes[:limit])
	}
	return name
}

// uniqueDirName 处理同一批里两个压缩包重名的情况：第二个开始加 _1、_2。
func uniqueDirName(rootDir, name string, used map[string]struct{}) string {
	candidate := name
	for i := 1; ; i++ {
		key := entryKey(filepath.Join(rootDir, candidate))
		if _, taken := used[key]; !taken {
			used[key] = struct{}{}
			return candidate
		}
		candidate = fmt.Sprintf("%s_%d", name, i)
	}
}
