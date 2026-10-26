package hashcat

import (
	"bufio"
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

// aes256Hash 是 hashextract 从 internal/hashextract/testdata/aes256.zip
// 提取出的哈希（口令 123456）。样本文件固定，所以哈希也固定。
const aes256Hash = "$zip2$*0*3*0*17aa55eb2f1d5b1cf9e3dc74e2ddd922*bea3*2d*be911222d950d52c41bb463aa7e1f54d9cbdc87ce93b8b46aa91ce29f43981e533a83394b29a2b9fb90fb7930d*5a58aa32435b81a618ec*$/zip2$"

const zip2Mode = 13600

// requireHashcat 返回 hashcat 路径，找不到时跳过测试。
// 通过环境变量 ZIPKIT_HASHCAT 指定，例如：
//
//	ZIPKIT_HASHCAT=C:\tools\hashcat-6.2.6\hashcat.exe go test ./internal/hashcat/
func requireHashcat(t *testing.T) string {
	t.Helper()
	path := strings.TrimSpace(os.Getenv("ZIPKIT_HASHCAT"))
	if path == "" {
		t.Skip("未设置 ZIPKIT_HASHCAT，跳过需要 hashcat 的用例")
	}
	if _, err := os.Stat(path); err != nil {
		t.Skipf("ZIPKIT_HASHCAT=%s 不可用: %v", path, err)
	}
	return path
}

// ---------------------------------------------------------------------------
// 纯逻辑用例
// ---------------------------------------------------------------------------

func TestBuildArgs(t *testing.T) {
	dir := t.TempDir()
	wordlist := filepath.Join(dir, "rockyou.txt")
	if err := os.WriteFile(wordlist, []byte("123456\npassword\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	cases := []struct {
		name       string
		st         Strategy
		wantMode   string
		wantFlags  []string
		wantTarget string
	}{
		{
			name:       "字典",
			st:         Strategy{Kind: StrategyDictionary, Wordlist: wordlist},
			wantMode:   "0",
			wantTarget: wordlist,
		},
		{
			name:       "掩码",
			st:         Strategy{Kind: StrategyMask, Mask: "?d?d?d?d?d?d"},
			wantMode:   "3",
			wantTarget: "?d?d?d?d?d?d",
		},
		{
			name:       "暴力单点",
			st:         Strategy{Kind: StrategyBruteforce, Charset: "0123456789", MinLen: 4, MaxLen: 4},
			wantMode:   "3",
			wantFlags:  []string{"-1", "0123456789", "--increment", "--increment-min=4", "--increment-max=4"},
			wantTarget: "?1?1?1?1",
		},
		{
			// 范围攻击：掩码按最大长度写满，靠 --increment 让 hashcat 自己
			// 从 6 递增到 8，避免为每个长度各启动一次。
			name:       "暴力范围",
			st:         Strategy{Kind: StrategyBruteforce, Charset: "0123456789", MinLen: 6, MaxLen: 8},
			wantMode:   "3",
			wantFlags:  []string{"-1", "0123456789", "--increment", "--increment-min=6", "--increment-max=8"},
			wantTarget: "?1?1?1?1?1?1?1?1",
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			mode, flags, target, err := buildArgs(RunOptions{Hash: aes256Hash, Mode: zip2Mode, Strategy: c.st})
			if err != nil {
				t.Fatalf("buildArgs: %v", err)
			}
			if mode != c.wantMode {
				t.Errorf("attackMode = %q，want %q", mode, c.wantMode)
			}
			if strings.Join(flags, " ") != strings.Join(c.wantFlags, " ") {
				t.Errorf("flags = %v，want %v", flags, c.wantFlags)
			}
			if target != c.wantTarget {
				t.Errorf("target = %q，want %q", target, c.wantTarget)
			}
		})
	}
}

// 位置参数顺序：<哈希文件> 必须紧挨着在目标（词表/掩码）前面。
func TestCommandArgsOrder(t *testing.T) {
	opts := RunOptions{Hash: aes256Hash, Mode: zip2Mode,
		Strategy: Strategy{Kind: StrategyMask, Mask: "?d?d"}}

	args := commandArgs(opts, "3", nil, "?d?d", "/tmp/target.hash", "/tmp/x.pot", "s1")
	joined := strings.Join(args, " ")

	wantHead := "-m 13600 -a 3 /tmp/target.hash ?d?d"
	if !strings.HasPrefix(joined, wantHead) {
		t.Fatalf("参数开头 = %q，want %q", joined, wantHead)
	}
	for _, must := range []string{"--status", "--status-timer=1", "--session=s1", "--potfile-path=/tmp/x.pot"} {
		if !strings.Contains(joined, must) {
			t.Errorf("缺少 %q: %q", must, joined)
		}
	}
	if strings.Contains(joined, "--potfile-disable") {
		t.Error("不能用 --potfile-disable，否则读不到明文")
	}
}

func TestBuildArgsRejectsBadInput(t *testing.T) {
	cases := []struct {
		name string
		st   Strategy
	}{
		{"空字典路径", Strategy{Kind: StrategyDictionary}},
		{"字典不存在", Strategy{Kind: StrategyDictionary, Wordlist: "no-such-file.txt"}},
		{"空掩码", Strategy{Kind: StrategyMask}},
		{"空字符集", Strategy{Kind: StrategyBruteforce, MinLen: 4, MaxLen: 4}},
		{"长度为零", Strategy{Kind: StrategyBruteforce, Charset: "01"}},
		{"长度过大", Strategy{Kind: StrategyBruteforce, Charset: "01", MinLen: 13, MaxLen: 13}},
		{"最大长度过大", Strategy{Kind: StrategyBruteforce, Charset: "01", MinLen: 1, MaxLen: 99}},
		{"最小大于最大", Strategy{Kind: StrategyBruteforce, Charset: "01", MinLen: 8, MaxLen: 6}},
		{"未知类型", Strategy{Kind: "rainbow"}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if _, _, _, err := buildArgs(RunOptions{Hash: aes256Hash, Mode: zip2Mode, Strategy: c.st}); err == nil {
				t.Fatal("应当报错")
			} else if !errors.Is(err, ErrBadStrategy) {
				t.Fatalf("err = %v，want ErrBadStrategy", err)
			}
		})
	}
}

func TestRunValidatesInput(t *testing.T) {
	if _, err := Run(context.Background(), "hashcat", RunOptions{Hash: "  ", Mode: zip2Mode}, nil); !errors.Is(err, ErrBadStrategy) {
		t.Errorf("空哈希: err = %v", err)
	}
	if _, err := Run(context.Background(), "hashcat", RunOptions{Hash: aes256Hash, Mode: 0}, nil); !errors.Is(err, ErrBadStrategy) {
		t.Errorf("模式号 0: err = %v", err)
	}
}

func TestReadPassword(t *testing.T) {
	dir := t.TempDir()
	pot := filepath.Join(dir, "hashcat.potfile")

	// 明文里可以有冒号，只按第一个冒号切分。
	content := aes256Hash + ":12:34\n"
	if err := os.WriteFile(pot, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	if pwd, ok := readPassword(pot, aes256Hash); !ok || pwd != "12:34" {
		t.Fatalf("readPassword = %q, %v，want \"12:34\", true", pwd, ok)
	}

	// hashcat 可能重编码哈希：格式对不上时退回最后一条。
	if err := os.WriteFile(pot, []byte("something-else:abc\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if pwd, ok := readPassword(pot, aes256Hash); !ok || pwd != "abc" {
		t.Fatalf("重编码兜底: readPassword = %q, %v", pwd, ok)
	}

	// 空文件 / 文件不存在都算没读到。
	if err := os.WriteFile(pot, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, ok := readPassword(pot, aes256Hash); ok {
		t.Error("空 potfile 不该读到明文")
	}
	if _, ok := readPassword(filepath.Join(dir, "nope.pot"), aes256Hash); ok {
		t.Error("不存在的 potfile 不该读到明文")
	}
}

func TestSplitFunc(t *testing.T) {
	// hashcat 的进度行用 '\r' 刷新，普通行用 '\n'，两种都要能切。
	input := "Session..........: t\rStatus...........: Running\nProgress.........: 10/100 (10.00%)\r"
	var lines []string
	sc := newTestScanner(input)
	for sc.Scan() {
		lines = append(lines, sc.Text())
	}
	want := []string{"Session..........: t", "Status...........: Running", "Progress.........: 10/100 (10.00%)"}
	if strings.Join(lines, "|") != strings.Join(want, "|") {
		t.Fatalf("lines = %q，want %q", lines, want)
	}
}

// newTestScanner 用生产用的 splitFunc 构造扫描器。
func newTestScanner(input string) *bufio.Scanner {
	sc := bufio.NewScanner(strings.NewReader(input))
	sc.Split(splitFunc)
	return sc
}

func TestProgressCollector(t *testing.T) {
	// 真实输出片段（hashcat 6.2.6 破解 $zip2$ 时打印的状态块）。
	block := []string{
		"Session..........: zipkit-1",
		"Status...........: Running",
		"Hash.Mode........: 13600 (WinZip)",
		"Hash.Target......: $zip2$*0*3*0*17aa55eb*.../zip2$",
		"Time.Estimated...: Fri Oct 23 14:41:00 2026 (30 secs)",
		"Speed.#1.........:   247.4 kH/s (10.22ms) @ Accel:4 Loops:999 Thr:256 Vec:1",
		"Recovered........: 0/1 (0.00%) Digests (total), 0/1 (0.00%) Digests (new)",
		"Progress.........: 262144/1000000 (26.21%)",
		"Candidates.#1....: 123456 -> 192145",
	}

	var got []Progress
	c := &progressCollector{emit: func(p Progress) { got = append(got, p) }}
	for _, line := range block {
		c.feed(line)
	}
	c.flush()

	if len(got) != 1 {
		t.Fatalf("回调次数 = %d，want 1", len(got))
	}
	p := got[0]
	if p.Status != "Running" {
		t.Errorf("Status = %q", p.Status)
	}
	if p.Speed != "247.4 kH/s" {
		t.Errorf("Speed = %q，want \"247.4 kH/s\"", p.Speed)
	}
	if p.Progress != "26.21%" {
		t.Errorf("Progress = %q，want \"26.21%%\"", p.Progress)
	}
	if p.Recovered != "0/1 (0.00%)" {
		t.Errorf("Recovered = %q，want \"0/1 (0.00%%)\"", p.Recovered)
	}
	if !strings.Contains(p.ETA, "30 secs") {
		t.Errorf("ETA = %q", p.ETA)
	}
}

// hashcat 7.x 把设备号补零成 "Speed.#01"，多设备还有 "Speed.Dev.#1"。
// 这两种写法都必须能解析出速度，否则界面上永远是空的。
func TestProgressCollectorSpeedVariants(t *testing.T) {
	cases := []struct {
		name string
		line string
		want string
	}{
		{"6.x 单设备", "Speed.#1.........:   247.4 kH/s (10.22ms) @ Accel:4", "247.4 kH/s"},
		{"7.x 补零", "Speed.#01........:   862.4 kH/s (9.38ms) @ Accel:3", "862.4 kH/s"},
		{"多设备汇总", "Speed.#*.........:    1.2 MH/s (8.11ms) @ Accel:2", "1.2 MH/s"},
		{"多设备分列", "Speed.Dev.#1.....:   431.2 kH/s (9.38ms) @ Accel:3", "431.2 kH/s"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var got []Progress
			c := &progressCollector{emit: func(p Progress) { got = append(got, p) }}
			c.feed("Status...........: Running")
			c.feed(tc.line)
			c.flush()

			if len(got) != 1 {
				t.Fatalf("回调次数 = %d，want 1", len(got))
			}
			if got[0].Speed != tc.want {
				t.Errorf("Speed = %q，want %q", got[0].Speed, tc.want)
			}
		})
	}
}

// 连续两个状态块应该回调两次，且不会把上一块的值带进下一块。
func TestProgressCollectorTwoBlocks(t *testing.T) {
	var got []Progress
	c := &progressCollector{emit: func(p Progress) { got = append(got, p) }}
	for _, line := range []string{
		"Session..........: a",
		"Status...........: Running",
		"Progress.........: 10/100 (10.00%)",
		"Session..........: a",
		"Status...........: Cracked",
		"Progress.........: 100/100 (100.00%)",
	} {
		c.feed(line)
	}
	c.flush()

	if len(got) != 2 {
		t.Fatalf("回调次数 = %d，want 2（%+v）", len(got), got)
	}
	if got[0].Status != "Running" || got[0].Progress != "10.00%" {
		t.Errorf("第一块 = %+v", got[0])
	}
	if got[1].Status != "Cracked" || got[1].Progress != "100.00%" {
		t.Errorf("第二块 = %+v", got[1])
	}
}

// 无关行（破解结果行、空行、提示符）不应影响解析。
func TestProgressCollectorIgnoresNoise(t *testing.T) {
	var got []Progress
	c := &progressCollector{emit: func(p Progress) { got = append(got, p) }}
	for _, line := range []string{
		aes256Hash + ":123456",
		"",
		"[s]tatus [p]ause [b]ypass [c]heckpoint [f]inish [q]uit =>",
		"Session..........: a",
		"Status...........: Cracked",
	} {
		c.feed(line)
	}
	c.flush()
	if len(got) != 1 || got[0].Status != "Cracked" {
		t.Fatalf("got = %+v", got)
	}
}

// ---------------------------------------------------------------------------
// 需要真实 hashcat 的用例
// ---------------------------------------------------------------------------

func TestRunCracksMask(t *testing.T) {
	hc := requireHashcat(t)

	var mu sync.Mutex
	var progress []Progress
	res, err := Run(context.Background(), hc, RunOptions{
		Hash:     aes256Hash,
		Mode:     zip2Mode,
		Strategy: Strategy{Kind: StrategyMask, Mask: "?d?d?d?d?d?d"},
	}, func(p Progress) {
		mu.Lock()
		progress = append(progress, p)
		mu.Unlock()
	})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if res.Password != "123456" {
		t.Fatalf("Password = %q，want 123456", res.Password)
	}
	if res.Status != "Cracked" {
		t.Errorf("Status = %q，want Cracked", res.Status)
	}

	mu.Lock()
	defer mu.Unlock()
	if len(progress) == 0 {
		t.Fatal("没有收到任何进度回调")
	}
	// 至少要有一份带状态与速度的进度，证明解析没跑偏。
	var sawSpeed bool
	for _, p := range progress {
		if p.Speed != "" && p.Status != "" {
			sawSpeed = true
		}
	}
	if !sawSpeed {
		t.Errorf("进度里没有同时带状态与速度的条目: %+v", progress)
	}
}

func TestRunExhausted(t *testing.T) {
	hc := requireHashcat(t)

	// 口令是 6 位数字，用 4 位掩码必然穷尽。
	_, err := Run(context.Background(), hc, RunOptions{
		Hash:     aes256Hash,
		Mode:     zip2Mode,
		Strategy: Strategy{Kind: StrategyMask, Mask: "?d?d?d?d"},
	}, nil)
	if !errors.Is(err, ErrExhausted) {
		t.Fatalf("err = %v，want ErrExhausted", err)
	}
}

func TestRunCancelledByContext(t *testing.T) {
	hc := requireHashcat(t)

	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		time.Sleep(4 * time.Second)
		cancel()
	}()

	start := time.Now()
	_, err := Run(ctx, hc, RunOptions{
		Hash: aes256Hash,
		Mode: zip2Mode,
		// 掩码长度必须大于口令长度：hashcat 7 的 Device Generator 会从
		// 数字开头枚举，"123456" 在 6 位 ?a 掩码里两秒就命中，根本等不到取消。
		Strategy: Strategy{Kind: StrategyMask, Mask: "?a?a?a?a?a?a?a"},
	}, nil)
	if !errors.Is(err, ErrCancelled) {
		t.Fatalf("err = %v，want ErrCancelled", err)
	}
	if elapsed := time.Since(start); elapsed > 90*time.Second {
		t.Fatalf("取消后仍然跑了 %v，进程可能没被杀死", elapsed)
	}
}

func TestStopTerminatesProcess(t *testing.T) {
	hc := requireHashcat(t)

	const sessionID = "zipkit-test-stop"
	done := make(chan error, 1)
	go func() {
		_, err := Run(context.Background(), hc, RunOptions{
			Hash:      aes256Hash,
			Mode:      zip2Mode,
			Strategy:  Strategy{Kind: StrategyMask, Mask: "?a?a?a?a?a?a"},
			SessionID: sessionID,
		}, nil)
		done <- err
	}()

	// 等会话登记完成再停，否则 Stop 会因为找不到会话而空转。
	deadline := time.Now().Add(30 * time.Second)
	for {
		sessionsMu.Lock()
		_, ok := sessions[sessionID]
		sessionsMu.Unlock()
		if ok {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("会话没有登记")
		}
		time.Sleep(100 * time.Millisecond)
	}

	if err := Stop(sessionID); err != nil {
		t.Fatalf("Stop: %v", err)
	}
	select {
	case err := <-done:
		if !errors.Is(err, ErrCancelled) {
			t.Fatalf("err = %v，want ErrCancelled", err)
		}
	case <-time.After(60 * time.Second):
		t.Fatal("Stop 之后 Run 没有返回")
	}

	// 停止一个不存在的会话不该报错。
	if err := Stop("no-such-session"); err != nil {
		t.Errorf("Stop(未知会话) = %v，want nil", err)
	}
}

func TestRunMissingBinary(t *testing.T) {
	_, err := Run(context.Background(), "definitely-not-hashcat", RunOptions{
		Hash:     aes256Hash,
		Mode:     zip2Mode,
		Strategy: Strategy{Kind: StrategyMask, Mask: "?d"},
	}, nil)
	if !errors.Is(err, ErrFailed) {
		t.Fatalf("err = %v，want ErrFailed", err)
	}
}

// hashcat 把初始化信息连着写在同一行里，失败卡片上直接贴出来就是一堵墙。
// pickFailureLines 负责把这些粘在一起的片段拆开、挑出带错误关键词的几行。
func TestPickFailureLines(t *testing.T) {
	glued := "Initializing bridges. Please be patient...Initialized bridges" +
		"Initializing backend runtimes. Please be patient...Initialized backend runtimes" +
		"Failed to initialize NVIDIA RTC library."
	lines := []string{
		"hashcat (v7.1.2) starting - session [zipkit-1]",
		glued,
		"* Device #1: CUDA SDK Toolkit not installed or incorrectly installed.",
		"",
		"Syntax error in mask: ?x?x?x?x",
	}

	got := pickFailureLines(lines, 5)
	if len(got) != 3 {
		t.Fatalf("挑出 %d 行，want 3：%v", len(got), got)
	}
	if !strings.Contains(got[0], "Failed to initialize NVIDIA RTC library") {
		t.Errorf("第一行 = %q", got[0])
	}
	if !strings.Contains(got[2], "Syntax error in mask") {
		t.Errorf("最后一行 = %q", got[2])
	}
	// 纯初始化提示不该出现在结果里。
	for _, line := range got {
		if strings.HasPrefix(line, "Initializing") {
			t.Errorf("混进了初始化提示：%q", line)
		}
	}

	// 没有任何关键词时退回最后几行，而不是返回空。
	plain := pickFailureLines([]string{"alpha", "beta", "gamma"}, 2)
	if len(plain) != 2 || plain[1] != "gamma" {
		t.Errorf("退回尾部失败：%v", plain)
	}

	if got := pickFailureLines(nil, 5); got != nil {
		t.Errorf("空输入 = %v，want nil", got)
	}
}

// 掩码写错时 hashcat 会输出 "Finished self-testSyntax error in mask: ..."，
// 两句粘成一行，卡片上看着像乱码。
func TestPickFailureLinesSplitsGluedSentences(t *testing.T) {
	glued := "Finished self-testSyntax error in mask: ?x?x?x?x"
	if got := splitGlued(glued); got != "Finished self-test\nSyntax error in mask: ?x?x?x?x" {
		t.Errorf("拆分结果 = %q", got)
	}

	got := pickFailureLines([]string{glued}, 5)
	if len(got) != 1 || !strings.Contains(got[0], "Syntax error in mask") {
		t.Fatalf("挑出 %v，want 只留错误原因", got)
	}

	// 已经在行首的短语不能再插一个空行。
	if s := splitGlued("Syntax error in mask: ?x"); s != "Syntax error in mask: ?x" {
		t.Errorf("行首短语被误拆：%q", s)
	}
	if s := splitGlued("no devices found"); s != "no devices found" {
		t.Errorf("小写短语被误拆：%q", s)
	}
}

func TestNormalizeExitCode(t *testing.T) {
	cases := map[int]int{
		0:          0,
		1:          1,
		2:          2,
		-1:         -1,
		4294967295: -1, // Windows 上进程以 0xFFFFFFFF 退出时 Go 给出的值
	}
	for in, want := range cases {
		if got := normalizeExitCode(in); got != want {
			t.Errorf("normalizeExitCode(%d) = %d，want %d", in, got, want)
		}
	}
}
