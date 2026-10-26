package attack

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

// ErrBkcrackMissing 表示找不到可用的 bkcrack。调用方用 errors.Is 判断，
// 好把「没装 bkcrack」和「攻击本身失败」区分开：前者要引导用户去设置路径，
// 后者是这个文件或明文的问题。
var ErrBkcrackMissing = errors.New("attack: 未找到 bkcrack")

// BkcrackStatus 是 bkcrack 可用性检测的结果，前端用它决定明文攻击入口
// 是可用还是禁用。
type BkcrackStatus struct {
	Available bool   `json:"available"`
	Path      string `json:"path"`
	Source    string `json:"source"` // config | auto | ""
	Message   string `json:"message"`
}

var (
	bkcrackMu   sync.RWMutex
	bkcrackPath string // 用户手动指定的路径；空表示自动探测
)

// SetBkcrackPath 设置 bkcrack 路径。传空字符串表示回到自动探测。
func SetBkcrackPath(path string) {
	bkcrackMu.Lock()
	bkcrackPath = strings.TrimSpace(path)
	bkcrackMu.Unlock()
}

// ConfiguredBkcrackPath 返回用户手动指定的 bkcrack 路径（可能为空）。
func ConfiguredBkcrackPath() string {
	bkcrackMu.RLock()
	defer bkcrackMu.RUnlock()
	return bkcrackPath
}

// ResolveBkcrack 返回一个可用的 bkcrack 可执行文件路径。
//
// 顺序：用户配置 → 随程序内置并释放出来的版本 → PATH 里的 bkcrack →
// 各平台常见位置。配置了但不可用时直接报错，不静默回退：用户明确指定过
// 路径却写错了，应该让他看见，而不是悄悄换成另一个版本。
func ResolveBkcrack() (string, error) {
	if configured := ConfiguredBkcrackPath(); configured != "" {
		if resolved, ok := lookExecutable(configured); ok {
			return resolved, nil
		}
		return "", fmt.Errorf("%w：配置的路径 %q 不可用，请在设置里重新指定", ErrBkcrackMissing, configured)
	}

	// 内置版本排在 PATH 前面：用户下载即用，装了别的版本也不影响。
	if p := embedded.Path(embedded.KindBkcrack); p != "" {
		if resolved, ok := lookExecutable(p); ok {
			return resolved, nil
		}
	}

	if p, err := exec.LookPath("bkcrack"); err == nil {
		return p, nil
	}
	for _, candidate := range bkcrackCandidates() {
		if resolved, ok := lookExecutable(candidate); ok {
			return resolved, nil
		}
	}
	return "", fmt.Errorf("%w：请安装 bkcrack，或在设置里指定 bkcrack 路径", ErrBkcrackMissing)
}

// DetectBkcrack 返回 bkcrack 的可用性，供界面上的提示条与入口按钮使用。
func DetectBkcrack() BkcrackStatus {
	path, err := ResolveBkcrack()
	if err != nil {
		return BkcrackStatus{
			Available: false,
			Message:   "未找到 bkcrack，请在设置中指定路径",
		}
	}

	source := "auto"
	if ConfiguredBkcrackPath() != "" {
		source = "config"
	} else if path == embedded.Path(embedded.KindBkcrack) {
		source = "builtin"
	}
	return BkcrackStatus{
		Available: true,
		Path:      path,
		Source:    source,
		Message:   "bkcrack 已就绪：" + path,
	}
}

// bkcrackCandidates 是自动探测时依次尝试的路径。
func bkcrackCandidates() []string {
	var out []string

	// 随程序分发的版本优先于系统安装的版本。
	if exe, err := os.Executable(); err == nil {
		dir := filepath.Dir(exe)
		out = append(out,
			filepath.Join(dir, "tools", "bkcrack.exe"),
			filepath.Join(dir, "tools", "bkcrack"),
			filepath.Join(dir, "bkcrack.exe"),
			filepath.Join(dir, "bkcrack"),
		)
	}

	switch runtime.GOOS {
	case "windows":
		for _, root := range []string{
			os.Getenv("ProgramW6432"),
			os.Getenv("ProgramFiles"),
			os.Getenv("ProgramFiles(x86)"),
		} {
			if root != "" {
				out = append(out,
					filepath.Join(root, "bkcrack", "bkcrack.exe"),
					filepath.Join(root, "bkcrack", "bin", "bkcrack.exe"),
				)
			}
		}
		out = append(out, `C:\bkcrack\bkcrack.exe`)
	case "darwin":
		out = append(out,
			"/opt/homebrew/bin/bkcrack",
			"/usr/local/bin/bkcrack",
		)
	default:
		out = append(out, "/usr/bin/bkcrack", "/usr/local/bin/bkcrack")
	}
	return out
}

// lookExecutable 判断一个路径/命令名是否真的能执行。
func lookExecutable(path string) (string, bool) {
	path = strings.TrimSpace(path)
	if path == "" {
		return "", false
	}

	// 带分隔符的按路径处理，否则当成 PATH 里的命令名。
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
