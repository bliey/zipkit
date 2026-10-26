package attack

import (
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/bliey/zipkit/internal/settings"
)

// useConfig 把配置换成一个临时文件并写入 cfg，用例结束后恢复。
func useConfig(t *testing.T, cfg settings.Config) {
	t.Helper()

	settings.SetPath(filepath.Join(t.TempDir(), "config.json"))
	if err := settings.Save(cfg); err != nil {
		t.Fatalf("写测试配置: %v", err)
	}
	t.Cleanup(func() {
		settings.SetPath(testConfigPath)
		SetBkcrackPath("")
	})
}

// waitIdle 等攻击线程结束。
func waitIdle(t *testing.T, svc *AttackService) {
	t.Helper()
	deadline := time.Now().Add(30 * time.Second)
	for time.Now().Before(deadline) {
		svc.mu.Lock()
		running := svc.running
		svc.mu.Unlock()
		if !running {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatal("攻击没有在 30 秒内结束")
}

func TestServicePrecheck(t *testing.T) {
	svc := &AttackService{}
	plain := writePlain(t, []byte(sampleText))

	res, err := svc.Precheck(testdata(t, "store6.zip"), "hello.txt", plain, "", false)
	if err != nil {
		t.Fatalf("Precheck: %v", err)
	}
	if !res.OK {
		t.Errorf("应该通过预检，Issues = %v", res.Issues)
	}

	if _, err := svc.Precheck("", "hello.txt", plain, "", false); err == nil {
		t.Error("没有加密包时应该报错")
	}
	if _, err := svc.Precheck(testdata(t, "store6.zip"), "", plain, "", false); err == nil {
		t.Error("没有目标条目时应该报错")
	}
	if _, err := svc.Precheck(testdata(t, "store6.zip"), "hello.txt", "", "", false); err == nil {
		t.Error("没有明文时应该报错")
	}
}

func TestServiceStartRejectsEmptyInput(t *testing.T) {
	svc := &AttackService{}

	if _, err := svc.StartAttack(AttackOptions{}); err == nil {
		t.Error("空参数应该报错")
	}
	if _, err := svc.StartAttack(AttackOptions{EncryptedZip: "a.zip", CipherEntry: "x"}); err == nil {
		t.Error("没有明文时应该报错")
	}
	if _, err := svc.StartAttack(AttackOptions{
		EncryptedZip: "a.zip", CipherEntry: "x", PlainPath: "p.zip", PlainIsZip: true,
	}); err == nil {
		t.Error("明文 ZIP 模式下没给条目名应该报错")
	}
}

func TestServiceStartWithoutBkcrack(t *testing.T) {
	// 走真实配置路径：配置里写一个不存在的 bkcrack，服务首次使用时会读进来。
	useConfig(t, settings.Config{BkcrackPath: filepath.Join(t.TempDir(), "no-such-bkcrack")})

	svc := &AttackService{}
	plain := writePlain(t, []byte(sampleText))
	_, err := svc.StartAttack(AttackOptions{
		EncryptedZip: testdata(t, "store6.zip"),
		CipherEntry:  "hello.txt",
		PlainPath:    plain,
	})
	if err == nil {
		t.Fatal("没有 bkcrack 时应该直接报错，而不是启动一个注定失败的任务")
	}
	if !strings.Contains(err.Error(), "bkcrack") {
		t.Errorf("Err = %q, 应该提示 bkcrack 缺失", err)
	}
}

func TestServiceAttackAndStop(t *testing.T) {
	requireBkcrack(t)

	svc := &AttackService{}
	plain := writePlain(t, []byte(sampleText))

	if _, err := svc.StartAttack(AttackOptions{
		EncryptedZip: testdata(t, "store6.zip"),
		CipherEntry:  "hello.txt",
		PlainPath:    plain,
	}); err != nil {
		t.Fatalf("StartAttack: %v", err)
	}

	// 同一时间只能跑一个攻击。
	if _, err := svc.StartAttack(AttackOptions{
		EncryptedZip: testdata(t, "store6.zip"),
		CipherEntry:  "hello.txt",
		PlainPath:    plain,
	}); err == nil {
		t.Error("重复启动应该被拒绝")
	}

	// 等 bkcrack 真的开始跑再停，否则测不到「杀进程」这条路。
	time.Sleep(400 * time.Millisecond)
	if err := svc.StopAttack(); err != nil {
		t.Fatalf("StopAttack: %v", err)
	}
	waitIdle(t, svc)

	last := svc.LastResult()
	if !last.Cancelled {
		t.Errorf("LastResult = %+v, 应该是已取消", last)
	}
	if last.Err != "已停止" {
		t.Errorf("Err = %q, want 已停止", last.Err)
	}
}

func TestServiceAttackFailureResult(t *testing.T) {
	requireBkcrack(t)

	svc := &AttackService{}
	// 明文比密文长：bkcrack 立刻报错，用例跑得很快。
	plain := writePlain(t, []byte(strings.Repeat("not the plaintext\n", 40)))

	if _, err := svc.StartAttack(AttackOptions{
		EncryptedZip: testdata(t, "store6.zip"),
		CipherEntry:  "hello.txt",
		PlainPath:    plain,
	}); err != nil {
		t.Fatalf("StartAttack: %v", err)
	}
	waitIdle(t, svc)

	last := svc.LastResult()
	if last.OK || last.Cancelled {
		t.Fatalf("LastResult = %+v, 应该是失败", last)
	}
	if !strings.Contains(last.Err, "ciphertext is smaller than plaintext") {
		t.Errorf("Err = %q, 应该带上 bkcrack 的错误信息", last.Err)
	}
	if len(last.Tail) == 0 {
		t.Error("失败时应该带回输出的尾部，方便排查")
	}
}

func TestServiceStopWithoutRunIsNoop(t *testing.T) {
	svc := &AttackService{}
	if err := svc.StopAttack(); err != nil {
		t.Errorf("StopAttack = %v, want nil", err)
	}
}

func TestServiceSetBkcrackPathKeepsOtherSettings(t *testing.T) {
	exe := requireBkcrack(t)

	// 配置里本来有 7z 路径和解压布局：保存 bkcrack 路径不能把它们抹掉。
	useConfig(t, settings.Config{
		SevenZipPath: `C:\tools\7z.exe`,
		Layout:       settings.LayoutFlat,
		Concurrency:  5,
	})

	svc := &AttackService{}
	status, err := svc.SetBkcrackPath(exe)
	if err != nil {
		t.Fatalf("SetBkcrackPath: %v", err)
	}
	if !status.Available {
		t.Errorf("status = %+v, 应该可用", status)
	}

	saved := settings.Load()
	if saved.BkcrackPath != exe {
		t.Errorf("BkcrackPath = %q, want %q", saved.BkcrackPath, exe)
	}
	if saved.SevenZipPath != `C:\tools\7z.exe` {
		t.Errorf("SevenZipPath 被覆盖了：%q", saved.SevenZipPath)
	}
	if saved.Layout != settings.LayoutFlat || saved.Concurrency != 5 {
		t.Errorf("解压设置被覆盖了：%+v", saved)
	}
}

func TestServiceSetBkcrackPathRejectsMissing(t *testing.T) {
	useConfig(t, settings.Config{})

	svc := &AttackService{}
	if _, err := svc.SetBkcrackPath(filepath.Join(t.TempDir(), "nope.exe")); err == nil {
		t.Error("不存在的路径应该报错")
	}
	// 报错之后不应该把坏路径写进配置。
	if saved := settings.Load(); saved.BkcrackPath != "" {
		t.Errorf("BkcrackPath = %q, want 空", saved.BkcrackPath)
	}
}

func TestServiceBkcrackStatus(t *testing.T) {
	exe := requireBkcrack(t)
	useConfig(t, settings.Config{BkcrackPath: exe})

	svc := &AttackService{}
	status := svc.Bkcrack()
	if !status.Available {
		t.Fatalf("status = %+v, 应该可用", status)
	}
	if status.Source != "config" {
		t.Errorf("Source = %q, want config", status.Source)
	}
	if status.Path != exe {
		t.Errorf("Path = %q, want %q", status.Path, exe)
	}
}

func TestServiceDecryptWhileAttackingIsRejected(t *testing.T) {
	requireBkcrack(t)

	svc := &AttackService{}
	plain := writePlain(t, []byte(sampleText))
	if _, err := svc.StartAttack(AttackOptions{
		EncryptedZip: testdata(t, "store6.zip"),
		CipherEntry:  "hello.txt",
		PlainPath:    plain,
	}); err != nil {
		t.Fatalf("StartAttack: %v", err)
	}
	t.Cleanup(func() { _ = svc.StopAttack() })

	if err := svc.DecryptWithKeys(testdata(t, "store6.zip"), testKeys, filepath.Join(t.TempDir(), "o.zip"), ""); err == nil {
		t.Error("攻击进行中调用解密应该被拒绝")
	}
	if err := svc.DecryptEntryWithKeys(testdata(t, "store6.zip"), testKeys, "hello.txt", filepath.Join(t.TempDir(), "o.txt")); err == nil {
		t.Error("攻击进行中调用解密应该被拒绝")
	}
}
