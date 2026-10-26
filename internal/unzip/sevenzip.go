package unzip

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

// ErrSevenZipMissing 表示找不到可用的 7z。调用方用 errors.Is 判断，好把
// 「没装 7z」和「解压失败」区分开——前者应该引导用户去设置路径，后者是
// 这个文件本身的问题。
var ErrSevenZipMissing = errors.New("unzip: 未找到 7z")

// SevenZipStatus 是 7z 可用性检测的结果，前端用它决定是否显示提示条。
type SevenZipStatus struct {
	Available bool   `json:"available"`
	Path      string `json:"path"`
	Source    string `json:"source"` // config | auto | ""
	Message   string `json:"message"`
}

var (
	sevenZipMu   sync.RWMutex
	sevenZipPath string // 用户手动指定的路径；空表示自动探测
)

// SetSevenZipPath 设置 7z 路径。传空字符串表示回到自动探测。
func SetSevenZipPath(path string) {
	sevenZipMu.Lock()
	sevenZipPath = strings.TrimSpace(path)
	sevenZipMu.Unlock()
}

// ConfiguredSevenZipPath 返回用户手动指定的 7z 路径（可能为空）。
func ConfiguredSevenZipPath() string {
	sevenZipMu.RLock()
	defer sevenZipMu.RUnlock()
	return sevenZipPath
}

// ResolveSevenZip 返回一个可用的 7z 可执行文件路径。
//
// 顺序：用户配置 → 随程序内置并释放出来的版本 → PATH 里的 7z/7za/7zr →
// 各平台常见安装位置。配置了但不可用时直接报错，不静默回退：用户明确指定
// 过路径却装错了，应该让他看见，而不是悄悄换成另一个版本。
func ResolveSevenZip() (string, error) {
	if configured := ConfiguredSevenZipPath(); configured != "" {
		if resolved, ok := lookExecutable(configured); ok {
			return resolved, nil
		}
		return "", fmt.Errorf("%w：配置的路径 %q 不可用，请在设置里重新指定", ErrSevenZipMissing, configured)
	}

	// 内置版本排在 PATH 前面：这样即使用户机器上装着别的版本，
	// 行为也和「下载即用」的预期一致。
	if p := embedded.Path(embedded.KindSevenZip); p != "" {
		if resolved, ok := lookExecutable(p); ok {
			return resolved, nil
		}
	}

	for _, name := range []string{"7z", "7za", "7zr"} {
		if p, err := exec.LookPath(name); err == nil {
			return p, nil
		}
	}
	for _, candidate := range sevenZipCandidates() {
		if resolved, ok := lookExecutable(candidate); ok {
			return resolved, nil
		}
	}
	return "", fmt.Errorf("%w：请安装 7-Zip，或在设置里指定 7z 路径", ErrSevenZipMissing)
}

// DetectSevenZip 返回 7z 的可用性，供界面上的提示条使用。
func DetectSevenZip() SevenZipStatus {
	path, err := ResolveSevenZip()
	if err != nil {
		return SevenZipStatus{
			Available: false,
			Message:   "未检测到 7z，批量解压功能不可用。请安装 7-Zip，或在下方指定 7z 路径。",
		}
	}

	source := "auto"
	if ConfiguredSevenZipPath() != "" {
		source = "config"
	} else if path == embedded.Path(embedded.KindSevenZip) {
		source = "builtin"
	}
	return SevenZipStatus{
		Available: true,
		Path:      path,
		Source:    source,
		Message:   "7z 已就绪：" + path,
	}
}

// sevenZipCandidates 是自动探测时依次尝试的路径。
func sevenZipCandidates() []string {
	var out []string

	// 随程序分发的版本优先于系统安装的版本。
	if exe, err := os.Executable(); err == nil {
		dir := filepath.Dir(exe)
		out = append(out,
			filepath.Join(dir, "tools", "7z.exe"),
			filepath.Join(dir, "tools", "7z"),
			filepath.Join(dir, "7z.exe"),
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
				out = append(out, filepath.Join(root, "7-Zip", "7z.exe"))
			}
		}
	case "darwin":
		out = append(out,
			"/opt/homebrew/bin/7z",
			"/usr/local/bin/7z",
			"/Applications/7z.app/Contents/MacOS/7z",
		)
	default:
		out = append(out, "/usr/bin/7z", "/usr/local/bin/7z", "/usr/bin/7zz")
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
