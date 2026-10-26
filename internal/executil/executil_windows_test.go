//go:build windows

package executil

import "testing"

// Windows 上必须同时设 HideWindow 与 CREATE_NO_WINDOW：只设前者，
// 控制台程序照样会分配一个新控制台，屏幕上就是一闪的黑框。
func TestPrepareHidesConsoleWindow(t *testing.T) {
	cmd := Command("7z")
	if cmd.SysProcAttr == nil {
		t.Fatal("SysProcAttr 为空，子进程会弹控制台窗口")
	}
	if !cmd.SysProcAttr.HideWindow {
		t.Error("HideWindow 没有设置")
	}
	if cmd.SysProcAttr.CreationFlags&createNoWindow == 0 {
		t.Errorf("CreationFlags = %#x，缺少 CREATE_NO_WINDOW", cmd.SysProcAttr.CreationFlags)
	}
}
