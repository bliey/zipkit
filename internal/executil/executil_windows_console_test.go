//go:build windows

package executil_test

import (
	"os"
	"os/exec"
	"strings"
	"syscall"
	"testing"

	"github.com/bliey/zipkit/internal/executil"
)

// 「黑窗口闪一下」的本质是控制台窗口有没有被创建出来，而不是进程有没有控制台：
// CREATE_NO_WINDOW 给的是一个**没有窗口**的控制台（conhost 在后台跑），所以用
// AttachConsole 区分不出来——两种方式都能附加成功。只有 GetConsoleWindow 才能
// 区分：没有窗口时返回 NULL。
var (
	kernel32          = syscall.NewLazyDLL("kernel32.dll")
	procGetConsoleWin = kernel32.NewProc("GetConsoleWindow")
)

const consoleProbeEnv = "ZIPKIT_EXECUTIL_CONSOLE_PROBE"

// TestConsoleProbe 不是真的测试，只是给主用例当探针：报告自己有没有控制台窗口。
func TestConsoleProbe(t *testing.T) {
	if os.Getenv(consoleProbeEnv) != "1" {
		t.Skip("仅作为子进程探针使用")
	}
	if hwnd, _, _ := procGetConsoleWin.Call(); hwnd != 0 {
		os.Stdout.WriteString("CONSOLE=window\n")
		return
	}
	os.Stdout.WriteString("CONSOLE=none\n")
}

// TestChildProcessHasNoConsoleWindow 验证 executil 启动的控制台程序不会创建控制台窗口。
//
// 这就是「批量解压时黑窗口一闪」的根因：只设 HideWindow 时子进程会先创建窗口再
// 隐藏，肉眼能看到闪一下；同时加 CREATE_NO_WINDOW 才是压根不创建窗口。
//
// 探针跑两遍做对照：普通 exec.Command 启动的应当有窗口，executil 启动的不该有。
//
// 对照组拿不到窗口时直接跳过：ConPTY（Windows Terminal、CI、无桌面会话）下控制台
// 根本没有窗口句柄，GetConsoleWindow 一律返回 NULL，这时测不出区别。在真实桌面上
// 会正常执行。
func TestChildProcessHasNoConsoleWindow(t *testing.T) {
	plain := runProbe(t, exec.Command(os.Args[0], "-test.run=^TestConsoleProbe$", "-test.timeout=30s"))
	if plain != "window" {
		t.Skip("当前会话没有真实控制台窗口（ConPTY / 无桌面），无法区分，跳过")
	}

	wrapped := runProbe(t, executil.Command(os.Args[0], "-test.run=^TestConsoleProbe$", "-test.timeout=30s"))
	if wrapped != "none" {
		t.Fatalf("executil 启动的子进程仍有控制台窗口（%q），黑窗口会闪现", wrapped)
	}
}

func runProbe(t *testing.T, cmd *exec.Cmd) string {
	t.Helper()

	cmd.Env = append(os.Environ(), consoleProbeEnv+"=1")
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("探针执行失败：%v（输出 %q）", err, string(out))
	}

	switch {
	case strings.Contains(string(out), "CONSOLE=window"):
		return "window"
	case strings.Contains(string(out), "CONSOLE=none"):
		return "none"
	default:
		t.Fatalf("探针没有给出结论：%q", string(out))
		return ""
	}
}
