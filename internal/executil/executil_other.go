//go:build !windows

package executil

import "os/exec"

// prepare 在非 Windows 平台上什么都不做：macOS / Linux 没有「控制台窗口」
// 这个概念，直接沿用 os/exec 的默认行为。
func prepare(cmd *exec.Cmd) {}
