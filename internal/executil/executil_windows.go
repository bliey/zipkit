//go:build windows

package executil

import (
	"os/exec"
	"syscall"
)

// createNoWindow 是 Windows 的 CREATE_NO_WINDOW 进程创建标志。
//
// 只设 HideWindow 是不够的：那个字段管的是窗口显示方式，控制台程序照样会
// 分配一个新控制台（屏幕上一闪的黑框就是这么来的）。两个一起设，子进程才
// 真正没有控制台。
const createNoWindow = 0x08000000

func prepare(cmd *exec.Cmd) {
	cmd.SysProcAttr = &syscall.SysProcAttr{
		HideWindow:    true,
		CreationFlags: createNoWindow,
	}
}
