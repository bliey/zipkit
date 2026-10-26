package executil

import (
	"context"
	"os/exec"
	"testing"
)

// Option 必须真的作用到 *exec.Cmd 上，否则以后加环境变量之类的调整会静默失效。
func TestOptionsAreApplied(t *testing.T) {
	called := false
	cmd := WithOptions(context.Background(), "echo", []string{"hi"}, func(c *exec.Cmd) {
		called = true
		c.Dir = "/tmp"
	})
	if cmd == nil {
		t.Fatal("WithOptions 返回 nil")
	}
	if !called {
		t.Error("Option 没有被调用")
	}
	if cmd.Dir != "/tmp" {
		t.Errorf("Option 的修改没生效：Dir = %q", cmd.Dir)
	}
}

func TestNilOptionIsIgnored(t *testing.T) {
	cmd := WithOptions(context.Background(), "echo", nil, nil)
	if cmd == nil {
		t.Fatal("WithOptions 返回 nil")
	}
}

// 封装不能改变参数传递方式：name + args 原样进到 cmd.Args。
func TestArgsArePassedThrough(t *testing.T) {
	cmd := Command("7z", "x", "-y", "a b.zip")
	want := []string{"7z", "x", "-y", "a b.zip"}
	if len(cmd.Args) != len(want) {
		t.Fatalf("Args = %v，want %v", cmd.Args, want)
	}
	for i := range want {
		if cmd.Args[i] != want[i] {
			t.Errorf("Args[%d] = %q，want %q", i, cmd.Args[i], want[i])
		}
	}
}
