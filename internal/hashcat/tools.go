package hashcat

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"

	"github.com/bliey/zipkit/internal/embedded"
)

// 外部工具的种类标识，前端用同一套字符串。
const (
	ToolHashcat       = "hashcat"
	ToolRar2John      = "rar2john"
	ToolSevenZip2John = "7z2john"
	// ToolSevenZip2Hashcat 是 philsmd 的 7z2hashcat，7z 提哈希的备用路径。
	ToolSevenZip2Hashcat = "7z2hashcat"
	// ToolInterpreter 是运行 .pl / .py 脚本的解释器。
	ToolInterpreter = "interpreter"
)

// ErrToolMissing 表示找不到指定的外部工具。调用方用 errors.Is 区分
// 「没装工具」和「运行失败」：前者要引导用户去设置路径。
var ErrToolMissing = errors.New("hashcat: 未找到外部工具")

// ToolStatus 是单个工具的可用性。
type ToolStatus struct {
	Name      string `json:"name"`
	Available bool   `json:"available"`
	Path      string `json:"path"`
	// Source 说明路径是怎么来的：config | builtin | auto。
	Source string `json:"source"`
	// Warning 是非致命提示，例如「配置的路径无效，已回退到内置版本」。
	Warning string `json:"warning"`
	Message string `json:"message"`
}

// ToolsStatus 是三个外部工具的可用性汇总。
type ToolsStatus struct {
	Hashcat       ToolStatus `json:"hashcat"`
	Rar2John      ToolStatus `json:"rar2john"`
	SevenZip2John ToolStatus `json:"sevenZip2John"`
}

// HasHashcat 报告 GPU 破解入口是否可用。
func (t ToolsStatus) HasHashcat() bool { return t.Hashcat.Available }

var (
	toolsMu     sync.RWMutex
	hashcatPath string // 用户手动指定；空表示自动探测
	rar2John    string
	sevenZip2   string
	sevenZip2HC string
	interpreter string
)

// SetToolPaths 设置三个工具的手动路径，空字符串表示回到自动探测。
func SetToolPaths(hashcat, rar2john, sevenZip2john string) {
	toolsMu.Lock()
	hashcatPath = strings.TrimSpace(hashcat)
	rar2John = strings.TrimSpace(rar2john)
	sevenZip2 = strings.TrimSpace(sevenZip2john)
	toolsMu.Unlock()
}

// Set7z2HashcatPaths 设置 7z 提哈希备用路径的两个路径：脚本（或 .exe）本身，
// 以及运行脚本用的解释器。两者都可以留空。
//
// 单独开一个函数而不是给 SetToolPaths 加参数：那个函数在测试和调用点里已经
// 铺开，改签名会把无关的调用全部拖下水。
func Set7z2HashcatPaths(scriptPath, interpreterPath string) {
	toolsMu.Lock()
	sevenZip2HC = strings.TrimSpace(scriptPath)
	interpreter = strings.TrimSpace(interpreterPath)
	toolsMu.Unlock()
}

// configuredPath 返回某工具的手动路径。
func configuredPath(kind string) string {
	toolsMu.RLock()
	defer toolsMu.RUnlock()
	switch kind {
	case ToolHashcat:
		return hashcatPath
	case ToolRar2John:
		return rar2John
	case ToolSevenZip2John:
		return sevenZip2
	case ToolSevenZip2Hashcat:
		return sevenZip2HC
	case ToolInterpreter:
		return interpreter
	}
	return ""
}

// NativeSevenZip2John 是一个哨兵路径：表示 7z2john 由程序内建实现提供，
// 没有对应的外部可执行文件。调用方看到这个值就该走内建提取器。
const NativeSevenZip2John = "builtin:7z2john"

// ConfigPathError 表示用户手动配置的路径不可用。
//
// 单独定义成类型是为了让上层能区分「没装」和「配错了」：配错时如果存在内置
// 版本，可以回退过去并在界面上提示，而不是让功能直接不可用。
type ConfigPathError struct {
	Kind string
	Path string
}

func (e *ConfigPathError) Error() string {
	// 用「」而不是 %q：路径里的反斜杠被 %q 转义成 \\，直接显示在设置页很难看。
	return fmt.Sprintf("%s：配置的路径「%s」不可用，请在设置里重新指定", e.Kind, e.Path)
}

// Unwrap 让 errors.Is(err, ErrToolMissing) 继续成立。
func (e *ConfigPathError) Unwrap() error { return ErrToolMissing }

// Resolve 返回某工具的可执行文件路径。
//
// 顺序：用户配置 → 随程序内置并释放出来的版本 → PATH → 各平台常见安装位置。
// 配置了却不可用时直接报错，不静默回退——用户明确指定过路径，写错了要让他看见。
func Resolve(kind string) (string, error) {
	if configured := configuredPath(kind); configured != "" {
		if resolved, ok := lookExecutable(configured); ok {
			return resolved, nil
		}
		return "", &ConfigPathError{Kind: kind, Path: configured}
	}

	// 内置版本排在 PATH 前面；hashcat 本身不在内置清单里。
	if resolved, ok := builtinPath(kind); ok {
		return resolved, nil
	}

	names := commandNames(kind)
	for _, name := range names {
		if p, err := exec.LookPath(name); err == nil {
			return p, nil
		}
	}
	for _, candidate := range toolCandidates(kind) {
		if resolved, ok := lookExecutable(candidate); ok {
			return resolved, nil
		}
	}
	return "", fmt.Errorf("%w：%s", ErrToolMissing, missingHint(kind))
}

// builtinPath 返回随程序分发的实现：释放出来的文件，或者内建实现。
func builtinPath(kind string) (string, bool) {
	if p := embedded.Path(kind); p != "" {
		if resolved, ok := lookExecutable(p); ok {
			return resolved, true
		}
	}
	if embedded.IsNative(kind) {
		return NativeSevenZip2John, true
	}
	return "", false
}

// ResolveWithFallback 在 Resolve 的基础上多做一件事：用户配错了路径、但这个
// 工具有内置版本时，回退到内置版本，并把「配错了」作为提示返回（err 为 nil）。
func ResolveWithFallback(kind string) (path string, warn string, err error) {
	path, err = Resolve(kind)
	if err == nil {
		return path, "", nil
	}
	var cfgErr *ConfigPathError
	if errors.As(err, &cfgErr) {
		if fallback, ok := builtinPath(kind); ok {
			return fallback, cfgErr.Error(), nil
		}
	}
	return "", "", err
}

// commandNames 返回在 PATH 里查找时依次尝试的命令名。
func commandNames(kind string) []string {
	switch kind {
	case ToolHashcat:
		return []string{"hashcat"}
	case ToolRar2John:
		return []string{"rar2john"}
	case ToolSevenZip2John:
		// john jumbo 的 7z2john 常以脚本形式发布，PATH 里可能只有 .pl。
		return []string{"7z2john", "7z2john.pl", "7z2john.py"}
	case ToolSevenZip2Hashcat:
		// 上游发布的是 7z2hashcat.pl；Windows 另有一份自带依赖的 .exe。
		return []string{"7z2hashcat", "7z2hashcat.pl", "7z2hashcat.exe"}
	case ToolInterpreter:
		// 7z2hashcat 是 Perl 脚本，所以 perl 排在最前面；python 留给 .py 脚本。
		return []string{"perl", "python3", "python"}
	}
	return nil
}

// missingHint 是找不到工具时给用户的话，直接显示在界面上。
func missingHint(kind string) string {
	switch kind {
	case ToolHashcat:
		return "请安装 hashcat，或在设置里指定 hashcat 路径"
	case ToolRar2John:
		return "请安装 john（jumbo 版），或在设置里指定 rar2john 路径"
	case ToolSevenZip2John:
		return "7z 提哈希的内建实现不可用，请在设置里指定 7z2john 路径"
	case ToolSevenZip2Hashcat:
		return "未找到 7z2hashcat。7z 提哈希已由内建实现覆盖，只有遇到 BCJ2 / PPMd 这类结构才需要它；" +
			"可下载 7z2hashcat.pl（或官方 .exe）后在设置里指定"
	case ToolInterpreter:
		return "未检测到 Perl / Python 解释器；运行 7z2hashcat.pl 需要 Perl，运行 .py 脚本需要 Python 3"
	}
	return "请安装该工具，或在设置里指定路径"
}

// toolCandidates 是自动探测时依次尝试的路径。
func toolCandidates(kind string) []string {
	var out []string

	// 随程序分发的版本优先于系统安装的版本。
	if exe, err := os.Executable(); err == nil {
		dir := filepath.Dir(exe)
		for _, name := range commandNames(kind) {
			out = append(out,
				filepath.Join(dir, "tools", name),
				filepath.Join(dir, "tools", name+".exe"),
			)
		}
	}

	switch runtime.GOOS {
	case "windows":
		var bases []string
		for _, env := range []string{"ProgramW6432", "ProgramFiles", "ProgramFiles(x86)"} {
			if v := os.Getenv(env); v != "" {
				bases = append(bases, v)
			}
		}
		for _, base := range bases {
			out = append(out,
				filepath.Join(base, "hashcat", "hashcat.exe"),
				filepath.Join(base, "John the Ripper", "run", "rar2john.exe"),
				filepath.Join(base, "John the Ripper", "rar2john.exe"),
				filepath.Join(base, "John the Ripper", "run", "7z2john.pl"),
				filepath.Join(base, "John the Ripper", "7z2john.pl"),
			)
		}
		out = append(out,
			`C:\hashcat\hashcat.exe`,
			`C:\Tools\hashcat\hashcat.exe`,
			`C:\john\run\rar2john.exe`,
			`C:\john\run\7z2john.pl`,
		)
	case "darwin":
		out = append(out,
			"/opt/homebrew/bin/hashcat",
			"/usr/local/bin/hashcat",
			"/usr/local/share/john/rar2john",
			"/usr/local/share/john/7z2john.pl",
		)
	default:
		out = append(out,
			"/usr/bin/hashcat",
			"/usr/local/bin/hashcat",
			"/usr/share/john/rar2john",
			"/usr/lib/john/rar2john",
			"/usr/share/john/7z2john.pl",
		)
	}
	if kind == ToolInterpreter {
		out = append(out, interpreterCandidates()...)
	}
	return out
}

// lookExecutable 判断路径或命令名是否可用。
func lookExecutable(path string) (string, bool) {
	path = strings.TrimSpace(path)
	if path == "" {
		return "", false
	}
	if filepath.IsAbs(path) || strings.ContainsAny(path, `/\`) {
		info, err := os.Stat(path)
		if err != nil || info.IsDir() {
			return "", false
		}
		return path, true
	}
	if resolved, err := exec.LookPath(path); err == nil {
		return resolved, true
	}
	return "", false
}

// DetectTool 返回单个工具的可用性。
//
// 用户配错了路径但有内置版本时会回退到内置版本，并把问题放进 Warning，
// 让设置页能同时显示「能用」和「你配的那条不对」。
func DetectTool(kind string) ToolStatus {
	path, warn, err := ResolveWithFallback(kind)
	if err != nil {
		return ToolStatus{
			Name:      kind,
			Available: false,
			Message:   missingHint(kind),
		}
	}
	source := "auto"
	message := kind + " 已就绪：" + path
	switch {
	case warn != "":
		// 配置的路径不可用、已经回退到内置版本：这时候说「用你配的那个」是错的，
		// 状态要按内置版本报，配错这件事单独走 Warning。
		source = "builtin"
	case configuredPath(kind) != "":
		source = "config"
	case path == NativeSevenZip2John:
		source = "builtin"
		message = "7z2john 使用内建实现（不需要 Perl）"
	case path == embedded.Path(kind):
		source = "builtin"
	}
	return ToolStatus{
		Name:      kind,
		Available: true,
		Path:      path,
		Source:    source,
		Message:   message,
		Warning:   warn,
	}
}

// DetectTools 返回三个工具的可用性汇总。
func DetectTools() ToolsStatus {
	return ToolsStatus{
		Hashcat:       DetectTool(ToolHashcat),
		Rar2John:      DetectTool(ToolRar2John),
		SevenZip2John: DetectTool(ToolSevenZip2John),
	}
}

// ResolveInterpreter 为脚本挑一个解释器。
//
// 返回空字符串表示这个文件本身就能直接执行（.exe、或没有后缀的可执行文件），
// 调用方把它当命令直接跑即可。
//
// 之所以要按后缀分流：7z2hashcat 上游发布的是 **Perl** 脚本，不是 Python
// 脚本。硬编码 python 会让用户在「装了解释器」的情况下依然跑不起来。
func ResolveInterpreter(scriptPath string) (string, error) {
	ext := strings.ToLower(filepath.Ext(scriptPath))
	if ext != ".pl" && ext != ".py" {
		return "", nil
	}

	// 用户显式配了解释器就用它，不做语言猜测——配错了让脚本自己报错，
	// 报错信息（stderr）会原样给到用户，比我们猜更准。
	if configured := configuredPath(ToolInterpreter); configured != "" {
		if resolved, ok := lookExecutable(configured); ok {
			return resolved, nil
		}
		return "", &ConfigPathError{Kind: ToolInterpreter, Path: configured}
	}

	names := []string{"perl"}
	if ext == ".py" {
		names = []string{"python3", "python"}
	}
	for _, name := range names {
		if p, err := exec.LookPath(name); err == nil {
			return p, nil
		}
	}
	for _, candidate := range interpreterCandidates() {
		if resolved, ok := lookExecutable(candidate); ok {
			return resolved, nil
		}
	}
	return "", fmt.Errorf("%w：%s", ErrToolMissing, missingHint(ToolInterpreter))
}

// interpreterCandidates 是自动探测解释器时依次尝试的固定路径。
func interpreterCandidates() []string {
	switch runtime.GOOS {
	case "windows":
		return []string{
			`C:\Strawberry\perl\bin\perl.exe`,
			`C:\Perl64\bin\perl.exe`,
			`C:\Perl\bin\perl.exe`,
		}
	case "darwin":
		return []string{"/opt/homebrew/bin/perl", "/usr/local/bin/perl", "/usr/bin/perl"}
	}
	return []string{"/usr/bin/perl", "/usr/local/bin/perl"}
}
