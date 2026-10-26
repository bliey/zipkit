// Package executil 统一外部命令的启动方式。
//
// 唯一的目的：Windows 上不要弹黑色控制台窗口。
//
// Windows 的 GUI 进程（zipkit 就是）自己不带控制台，调用控制台程序时系统会
// 给子进程新开一个控制台窗口——这就是 7z / bkcrack / hashcat 一闪而过的黑框。
// 批量解压时并发起多个 7z，屏幕上会连续闪很多次，很难看。
//
// 解决办法是给子进程设上 SysProcAttr{HideWindow: true, CreationFlags:
// CREATE_NO_WINDOW}。其它平台没有这个概念，prepare 是空实现，行为与直接调用
// os/exec 完全一致。
//
// 这个包只碰 SysProcAttr，不动调用方的 Stdin / StdoutPipe / Wait 用法：
// 换进来之后原来的管道、取消、超时逻辑一个字都不用改。
package executil

import (
	"context"
	"os/exec"
)

// Option 是给单个调用点用的额外调整。默认没有任何 Option，行为不变。
type Option func(*exec.Cmd)

// CommandContext 等价于 exec.CommandContext，额外做平台相关的启动设置。
//
// 所有需要随 context 取消的外部命令都应该走这里，而不是直接用 os/exec。
func CommandContext(ctx context.Context, name string, args ...string) *exec.Cmd {
	cmd := exec.CommandContext(ctx, name, args...)
	prepare(cmd)
	return cmd
}

// Command 等价于 exec.Command，额外做平台相关的启动设置。
func Command(name string, args ...string) *exec.Cmd {
	cmd := exec.Command(name, args...)
	prepare(cmd)
	return cmd
}

// WithOptions 在 CommandContext 之上再应用几个 Option。
//
// args 单独传一个切片：这样 opts 才能接在参数后面，不与命令参数混在一起。
// 目前没有调用点需要它，留着是为了以后某个工具要单独设环境变量或工作目录时
// 不用再改签名。
func WithOptions(ctx context.Context, name string, args []string, opts ...Option) *exec.Cmd {
	cmd := CommandContext(ctx, name, args...)
	for _, opt := range opts {
		if opt != nil {
			opt(cmd)
		}
	}
	return cmd
}
