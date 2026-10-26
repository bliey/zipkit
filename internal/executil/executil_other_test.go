//go:build !windows

package executil

import "testing"

// 非 Windows 平台没有控制台窗口的概念，prepare 必须是空操作。
func TestPrepareIsNoop(t *testing.T) {
	cmd := Command("7z")
	if cmd.SysProcAttr != nil {
		t.Errorf("SysProcAttr = %+v，非 Windows 平台不应该设置", cmd.SysProcAttr)
	}
}
