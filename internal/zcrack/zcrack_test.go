package zcrack

import (
	"archive/zip"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// testdata 下的固定样本，均由 testdata/generate.go 生成，
// 其中 real_zipcrypto.zip / real_aes.zip 由 7-Zip 25.01 实际产出。
const (
	zipNum6        = "testdata/num6.zip"               // hello.txt, ZipCrypto, Deflate, 密码 123456
	zipNum7        = "testdata/num7.zip"               // hello.txt, ZipCrypto, Deflate, 密码 7654321
	zipNum8        = "testdata/num8.zip"               // hello.txt, ZipCrypto, Deflate, 密码 88888888
	zipBig         = "testdata/num6_big.zip"           // big.log（170KB 原文 / 34KB 压缩），密码 123456
	zipStore6      = "testdata/store6.zip"             // hello.txt, ZipCrypto, Store,   密码 123456
	zipDescriptor6 = "testdata/descriptor6.zip"        // hello.txt, GPBF bit 3（数据描述符），密码 123456
	zipAlpha6      = "testdata/alpha6.zip"             // hello.txt, ZipCrypto, 密码 abc123
	zipFive6       = "testdata/five6.zip"              // hello.txt, ZipCrypto, 密码 12345
	zipLeadZero6   = "testdata/leadingzero6.zip"       // hello.txt, ZipCrypto, Deflate, 密码 052092（前导零）
	zipLeadZeroDes = "testdata/leadingzero_desc6.zip"  // 同上 + GPBF bit 3（复刻真实微信账单结构）
	zipLeadZeroSt  = "testdata/leadingzero_store6.zip" // hello.txt, ZipCrypto, Store, 密码 012345（前导零）
	zipAllZero6    = "testdata/allzero6.zip"           // hello.txt, ZipCrypto, Deflate, 密码 000000
	zipAES         = "testdata/aes.zip"                // hello.txt, method 99（AES 头部字段）
	zipMulti       = "testdata/multi.zip"              // readme.txt（明文）+ secret.txt（密码 123456）
	zipReal7z      = "testdata/real_zipcrypto.zip"     // 7-Zip 产出的真实 ZipCrypto 归档
	zipRealAES     = "testdata/real_aes.zip"           // 7-Zip 产出的真实 AES-256 归档
)

func mustExist(t *testing.T, paths ...string) {
	t.Helper()
	for _, p := range paths {
		if _, err := os.Stat(p); err != nil {
			t.Fatalf("缺少测试样本 %s（运行 `go run testdata/generate.go` 重新生成）: %v", p, err)
		}
	}
}

// firstEntryName 返回 ZIP 中第一个条目的名称，避免测试里硬编码路径分隔符。
func firstEntryName(t *testing.T, zipPath string) string {
	t.Helper()
	entries, err := ListEntries(zipPath)
	if err != nil {
		t.Fatalf("ListEntries(%s): %v", zipPath, err)
	}
	if len(entries) == 0 {
		t.Fatalf("%s 中没有条目", zipPath)
	}
	return entries[0].Name
}

// --- 用例 1：6 位密码，1 秒内命中 ------------------------------------------

func TestCrackSixDigits(t *testing.T) {
	mustExist(t, zipNum6)
	start := time.Now()
	res := Crack(context.Background(), zipNum6, "hello.txt", 6, 6)
	elapsed := time.Since(start)

	if res.Err != nil {
		t.Fatalf("意外错误: %v", res.Err)
	}
	if !res.Found || res.Password != "123456" {
		t.Fatalf("期望找到 123456，实际 Found=%v Password=%q", res.Found, res.Password)
	}
	if elapsed > time.Second {
		t.Fatalf("6 位破解耗时 %v，超过 1 秒", elapsed)
	}
	t.Logf("6 位命中耗时 %v", elapsed)
}

// --- 用例 2：8 位密码，10 秒内命中 ----------------------------------------

func TestCrackEightDigits(t *testing.T) {
	if testing.Short() {
		t.Skip("short 模式跳过 8 位全量枚举")
	}
	mustExist(t, zipNum8)
	start := time.Now()
	res := Crack(context.Background(), zipNum8, "hello.txt", 8, 8)
	elapsed := time.Since(start)

	if res.Err != nil {
		t.Fatalf("意外错误: %v", res.Err)
	}
	if !res.Found || res.Password != "88888888" {
		t.Fatalf("期望找到 88888888，实际 Found=%v Password=%q", res.Found, res.Password)
	}
	if elapsed > 10*time.Second {
		t.Fatalf("8 位破解耗时 %v，超过 10 秒", elapsed)
	}
	t.Logf("8 位命中耗时 %v", elapsed)
}

// TestLargeEntry 确认大条目不会因为"每次误报都要解密整段数据"而退化。
func TestLargeEntry(t *testing.T) {
	mustExist(t, zipBig)
	start := time.Now()
	res := Crack(context.Background(), zipBig, "big.log", 6, 6)
	elapsed := time.Since(start)
	if res.Err != nil {
		t.Fatalf("意外错误: %v", res.Err)
	}
	if !res.Found || res.Password != "123456" {
		t.Fatalf("期望 123456，实际 Found=%v Password=%q", res.Found, res.Password)
	}
	if elapsed > 2*time.Second {
		t.Fatalf("34KB 压缩数据的 6 位破解耗时 %v，超出预期", elapsed)
	}
	t.Logf("34KB 条目 6 位命中耗时 %v", elapsed)
}

// --- 用例 3：密码短于 minLen，返回未找到 -----------------------------------

func TestBelowMinLen(t *testing.T) {
	mustExist(t, zipFive6)
	start := time.Now()
	res := Crack(context.Background(), zipFive6, "hello.txt", 6, 6)
	if res.Err != nil {
		t.Fatalf("意外错误: %v", res.Err)
	}
	if res.Found {
		t.Fatalf("密码 12345 只有 5 位，不应在 6 位范围内被找到，却返回 %q", res.Password)
	}
	if elapsed := time.Since(start); elapsed > 3*time.Second {
		t.Fatalf("未命中的全量枚举耗时过长: %v", elapsed)
	}
}

// --- 用例 4：含字母的密码不会被误判为纯数字密码 ---------------------------

func TestNonNumericPasswordNotMatched(t *testing.T) {
	mustExist(t, zipAlpha6)
	res := Crack(context.Background(), zipAlpha6, "hello.txt", 6, 6)
	if res.Err != nil {
		t.Fatalf("意外错误: %v", res.Err)
	}
	if res.Found {
		t.Fatalf("密码 abc123 不是纯数字，却返回 %q", res.Password)
	}
}

// --- 用例 5：AES 加密直接报“不适用”，不进入破解循环 -----------------------

func TestAESRejected(t *testing.T) {
	mustExist(t, zipAES, zipRealAES)
	for _, path := range []string{zipAES, zipRealAES} {
		name := firstEntryName(t, path)
		start := time.Now()
		res := Crack(context.Background(), path, name, 1, 8)
		elapsed := time.Since(start)

		if res.Found {
			t.Fatalf("%s: AES 条目不应被破解", path)
		}
		if !errors.Is(res.Err, ErrNotZipCrypto) {
			t.Fatalf("%s: 期望 ErrNotZipCrypto，实际 %v", path, res.Err)
		}
		if !strings.Contains(res.Err.Error(), "不适用") {
			t.Fatalf("%s: 错误信息应说明不适用，实际 %q", path, res.Err.Error())
		}
		if elapsed > 100*time.Millisecond {
			t.Fatalf("%s: 应在解析阶段立即返回，实际耗时 %v", path, elapsed)
		}
	}
}

// --- 用例 6：ctx 取消后立即返回 context.Canceled --------------------------

func TestContextCancel(t *testing.T) {
	mustExist(t, zipNum8)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	cancelledAt := make(chan time.Time, 1)
	start := time.Now()
	time.AfterFunc(100*time.Millisecond, func() {
		cancelledAt <- time.Now()
		cancel()
	})

	res := Crack(ctx, zipNum8, "hello.txt", 8, 8)
	end := time.Now()
	at := <-cancelledAt

	if !errors.Is(res.Err, context.Canceled) {
		t.Fatalf("期望 context.Canceled，实际 %v", res.Err)
	}
	if res.Found {
		t.Fatal("取消后不应返回密码")
	}

	// Windows 的定时器精度只有 ~15ms，且 16 个 worker 满载时还会被调度推迟几十毫秒，
	// 所以真正能衡量"取消是否被及时响应"的是 cancel() 到 Crack 返回的间隔。
	resp := end.Sub(at)
	if resp > 50*time.Millisecond {
		t.Fatalf("取消后响应耗时 %v，超过 50ms", resp)
	}
	// 总耗时只做一个宽松的兜底：定时器本身可能迟到，这部分不计入实现的响应能力。
	if total := end.Sub(start); total > 300*time.Millisecond {
		t.Fatalf("总耗时 %v 明显异常（取消→返回仅 %v）", total, resp)
	}
	t.Logf("取消→返回 %v（总耗时 %v，含定时器迟到 %v）", resp, end.Sub(start), at.Sub(start)-100*time.Millisecond)
}

// --- 用例 7：误报率验证（校验字节 1/256 命中，CRC 二级校验全部拒绝）-------

func TestCRCSecondStageRejectsFalsePositives(t *testing.T) {
	mustExist(t, zipNum6)
	f, err := os.Open(zipNum6)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil {
		t.Fatal(err)
	}
	e, err := findEntry(f, st.Size(), "hello.txt")
	if err != nil {
		t.Fatal(err)
	}
	c, err := newCracker(f, e)
	if err != nil {
		t.Fatal(err)
	}
	w := c.newWorker()

	const n = 200000
	passes := 0
	for i := 0; i < n; i++ {
		pw := fmt.Sprintf("%06d", i)
		if pw == "123456" {
			continue
		}
		// 用候选密码初始化密钥并解密 12 字节头，统计通过第一级校验的比例。
		k := initKeys
		for j := 0; j < len(pw); j++ {
			k = k.update(pw[j] - '0')
		}
		k0, k1, k2 := k.k0, k.k1, k.k2
		var last byte
		for j := 0; j < 12; j++ {
			last = w.hdr[j] ^ decryptByte(k2)
			k0, k1, k2 = updateKeys(k0, k1, k2, last)
		}
		if last != w.check && last != w.check2 {
			continue
		}
		passes++
		ok, err := w.verify(k0, k1, k2)
		if err != nil {
			t.Fatalf("校验 %s 时出错: %v", pw, err)
		}
		if ok {
			t.Fatalf("误报：错误密码 %s 通过了 CRC 二级校验", pw)
		}
	}

	// 期望约 n/256 ≈ 781 次命中；给一倍余量，防止实现被"优化"掉第一级校验。
	if passes < n/256/2 || passes > n/256*2 {
		t.Fatalf("校验字节通过率异常：%d/%d（期望约 %d）", passes, n, n/256)
	}
	t.Logf("%d 个错误候选中 %d 个通过校验字节，全部被 CRC 二级校验拒绝", n, passes)
}

// --- 结构相关的分支：数据描述符 / Store / 多条目 / 真实 7-Zip 归档 -------

func TestDataDescriptorEntry(t *testing.T) {
	mustExist(t, zipDescriptor6)
	// GPBF bit 3 置位时，本地文件头里的 CRC32 为 0，真实 CRC 只在中央目录里。
	e, err := InspectEntry(zipDescriptor6, "hello.txt")
	if err != nil {
		t.Fatal(err)
	}
	if e.GPFlags&0x0008 == 0 {
		t.Fatal("样本应置位 GPBF bit 3")
	}
	res := Crack(context.Background(), zipDescriptor6, "hello.txt", 6, 6)
	if res.Err != nil {
		t.Fatalf("意外错误: %v", res.Err)
	}
	if !res.Found || res.Password != "123456" {
		t.Fatalf("期望 123456，实际 Found=%v Password=%q", res.Found, res.Password)
	}
}

func TestStoreMethod(t *testing.T) {
	mustExist(t, zipStore6)
	res := Crack(context.Background(), zipStore6, "hello.txt", 6, 6)
	if res.Err != nil {
		t.Fatalf("意外错误: %v", res.Err)
	}
	if !res.Found || res.Password != "123456" {
		t.Fatalf("期望 123456，实际 Found=%v Password=%q", res.Found, res.Password)
	}
}

// --- 回归：前导零密码 -------------------------------------------------------
//
// 用户反馈的真实 bug：微信账单 ZIP（ZipCrypto + 数据描述符，6 位纯数字）在
// 批量模式下解不出来，但 hashcat 能解。真实密码是 052092，而 buildUnits 的
// 首位只枚举 '1'..'9'，0 开头的 10 万个候选从未被尝试。
// 这三条用例分别覆盖 Deflate / Deflate+数据描述符 / Store 三种结构。

func TestCrackLeadingZeroDeflate(t *testing.T) {
	mustExist(t, zipLeadZero6)
	res := Crack(context.Background(), zipLeadZero6, "hello.txt", 6, 6)
	if res.Err != nil {
		t.Fatalf("意外错误: %v", res.Err)
	}
	if !res.Found || res.Password != "052092" {
		t.Fatalf("期望找到 052092（前导零），实际 Found=%v Password=%q", res.Found, res.Password)
	}
}

// TestCrackLeadingZeroWithDescriptor 完全复刻用户提供的真实文件结构：
// GPBF = 0x0809（加密 + 数据描述符 + UTF-8 名），加密头第 12 字节写的是
// DOS 修改时间高字节而不是 CRC 高字节。
func TestCrackLeadingZeroWithDescriptor(t *testing.T) {
	mustExist(t, zipLeadZeroDes)
	e, err := InspectEntry(zipLeadZeroDes, "hello.txt")
	if err != nil {
		t.Fatal(err)
	}
	if e.GPFlags&0x0008 == 0 {
		t.Fatal("样本应置位 GPBF bit 3")
	}
	res := Crack(context.Background(), zipLeadZeroDes, "hello.txt", 6, 6)
	if res.Err != nil {
		t.Fatalf("意外错误: %v", res.Err)
	}
	if !res.Found || res.Password != "052092" {
		t.Fatalf("期望找到 052092，实际 Found=%v Password=%q", res.Found, res.Password)
	}
}

func TestCrackLeadingZeroStore(t *testing.T) {
	mustExist(t, zipLeadZeroSt)
	res := Crack(context.Background(), zipLeadZeroSt, "hello.txt", 6, 6)
	if res.Err != nil {
		t.Fatalf("意外错误: %v", res.Err)
	}
	if !res.Found || res.Password != "012345" {
		t.Fatalf("期望找到 012345，实际 Found=%v Password=%q", res.Found, res.Password)
	}
}

// TestCrackAllZeroPassword 覆盖搜索空间的起点：6 位全零。
// 任何「首位从 1 开始」的写法都会连第一个候选都漏掉。
func TestCrackAllZeroPassword(t *testing.T) {
	mustExist(t, zipAllZero6)
	res := Crack(context.Background(), zipAllZero6, "hello.txt", 6, 6)
	if res.Err != nil {
		t.Fatalf("意外错误: %v", res.Err)
	}
	if !res.Found || res.Password != "000000" {
		t.Fatalf("期望找到 000000，实际 Found=%v Password=%q", res.Found, res.Password)
	}
}

func TestMultiEntryArchive(t *testing.T) {
	mustExist(t, zipMulti)
	res := Crack(context.Background(), zipMulti, "secret.txt", 6, 6)
	if res.Err != nil {
		t.Fatalf("意外错误: %v", res.Err)
	}
	if !res.Found || res.Password != "123456" {
		t.Fatalf("期望 123456，实际 Found=%v Password=%q", res.Found, res.Password)
	}
}

func TestRealSevenZipArchive(t *testing.T) {
	mustExist(t, zipReal7z)
	name := firstEntryName(t, zipReal7z)
	start := time.Now()
	res := Crack(context.Background(), zipReal7z, name, 6, 6)
	if res.Err != nil {
		t.Fatalf("意外错误: %v", res.Err)
	}
	if !res.Found || res.Password != "123456" {
		t.Fatalf("期望 123456，实际 Found=%v Password=%q", res.Found, res.Password)
	}
	t.Logf("7-Zip 真实归档（条目 %q）命中耗时 %v", name, time.Since(start))
}

// --- 参数与错误路径 -------------------------------------------------------

func TestEntryNotFound(t *testing.T) {
	mustExist(t, zipNum6)
	res := Crack(context.Background(), zipNum6, "nope.txt", 6, 6)
	if !errors.Is(res.Err, ErrEntryNotFound) {
		t.Fatalf("期望 ErrEntryNotFound，实际 %v", res.Err)
	}
}

func TestNotEncrypted(t *testing.T) {
	mustExist(t, zipMulti)
	res := Crack(context.Background(), zipMulti, "readme.txt", 6, 6)
	if !errors.Is(res.Err, ErrNotEncrypted) {
		t.Fatalf("期望 ErrNotEncrypted，实际 %v", res.Err)
	}
}

func TestInvalidRange(t *testing.T) {
	mustExist(t, zipNum6)
	for _, tc := range [][2]int{{7, 6}, {-1, 6}, {1, maxPWLen + 1}} {
		res := Crack(context.Background(), zipNum6, "hello.txt", tc[0], tc[1])
		if !errors.Is(res.Err, ErrInvalidRange) {
			t.Fatalf("范围 %v 期望 ErrInvalidRange，实际 %v", tc, res.Err)
		}
	}
}

func TestMissingFile(t *testing.T) {
	res := Crack(context.Background(), "testdata/does-not-exist.zip", "x", 6, 6)
	if res.Err == nil || res.Found {
		t.Fatalf("期望文件错误，实际 %+v", res)
	}
}

func TestCrackEntryAPI(t *testing.T) {
	mustExist(t, zipNum7)
	e, err := InspectEntry(zipNum7, "hello.txt")
	if err != nil {
		t.Fatal(err)
	}
	res := CrackEntry(context.Background(), zipNum7, e, 7, 7)
	if res.Err != nil {
		t.Fatalf("意外错误: %v", res.Err)
	}
	if !res.Found || res.Password != "7654321" {
		t.Fatalf("期望 7654321，实际 Found=%v Password=%q", res.Found, res.Password)
	}
}

func TestListEntries(t *testing.T) {
	mustExist(t, zipMulti)
	entries, err := ListEntries(zipMulti)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 2 {
		t.Fatalf("期望 2 个条目，实际 %d", len(entries))
	}
	if entries[0].Name != "readme.txt" || entries[0].GPFlags&1 != 0 {
		t.Fatalf("第一个条目应是不加密的 readme.txt，实际 %+v", entries[0])
	}
	if entries[1].Name != "secret.txt" || entries[1].GPFlags&1 == 0 {
		t.Fatalf("第二个条目应是加密的 secret.txt，实际 %+v", entries[1])
	}
}

// TestStandardLibraryReadsFixture 用 archive/zip 打开自己生成的样本，
// 确认容器结构合法（加密条目本身无法被标准库读取，所以只读明文条目）。
func TestStandardLibraryReadsFixture(t *testing.T) {
	mustExist(t, zipMulti)
	r, err := zip.OpenReader(zipMulti)
	if err != nil {
		t.Fatalf("标准库无法打开样本: %v", err)
	}
	defer r.Close()
	for _, f := range r.File {
		if f.Name != "readme.txt" {
			continue
		}
		rc, err := f.Open()
		if err != nil {
			t.Fatal(err)
		}
		defer rc.Close()
		data, err := io.ReadAll(rc)
		if err != nil {
			t.Fatal(err)
		}
		if string(data) != "not encrypted\n" {
			t.Fatalf("内容不符: %q", data)
		}
		return
	}
	t.Fatal("未找到 readme.txt")
}

func TestBuildUnits(t *testing.T) {
	// 6 位：10*10 个工作块；1 位：10 个；0 位：1 个。
	if got := len(buildUnits(6, 6)); got != 100 {
		t.Fatalf("6 位工作块数量应为 100，实际 %d", got)
	}
	if got := len(buildUnits(1, 1)); got != 10 {
		t.Fatalf("1 位工作块数量应为 10，实际 %d", got)
	}
	if got := len(buildUnits(0, 0)); got != 1 {
		t.Fatalf("0 位工作块数量应为 1，实际 %d", got)
	}
	for _, u := range buildUnits(6, 8) {
		if u.length < 6 || u.length > 8 {
			t.Fatalf("长度越界: %d", u.length)
		}
	}
}

// TestBuildUnitsCoversWholeSpace 保证每一位都枚举 '0'..'9'，特别是首位。
// 曾经的实现让首位只从 '1' 开始，6 位密码少了 10 万个候选（0 开头的全部），
// 导致「hashcat 能解、本包解不出」。
func TestBuildUnitsCoversWholeSpace(t *testing.T) {
	for l := 0; l <= 8; l++ {
		units := buildUnits(l, l)

		// 工作块覆盖的候选数之和必须等于 10^l。
		total := 0
		for _, u := range units {
			n := 1
			for i := len(u.prefix); i < u.length; i++ {
				n *= 10
			}
			total += n
		}
		want := 1
		for i := 0; i < l; i++ {
			want *= 10
		}
		if total != want {
			t.Fatalf("%d 位覆盖候选数应为 %d，实际 %d（缺 %d）", l, want, total, want-total)
		}

		// 每一位的取值都必须出现，首位也不例外。
		if l > 0 {
			seen := make(map[byte]bool)
			for _, u := range units {
				seen[u.prefix[0]] = true
			}
			for c := byte('0'); c <= '9'; c++ {
				if !seen[c] {
					t.Fatalf("%d 位的工作块前缀缺少首位 %q", l, string(c))
				}
			}
		}
	}
}

// --- 基准测试：单核吞吐 ---------------------------------------------------

func benchCrack(b *testing.B, zipPath, entry, password string, minLen, maxLen int) {
	b.Helper()
	b.SetBytes(0)
	for i := 0; i < b.N; i++ {
		res := CrackWithOptions(context.Background(), zipPath, entry,
			Options{MinLen: minLen, MaxLen: maxLen, Workers: 1})
		if res.Err != nil {
			b.Fatal(res.Err)
		}
		if !res.Found || res.Password != password {
			b.Fatalf("期望 %s，实际 Found=%v Password=%q", password, res.Found, res.Password)
		}
	}
}

func BenchmarkCrack6DigitsSingleCore(b *testing.B) {
	benchCrack(b, zipNum6, "hello.txt", "123456", 6, 6)
}

func BenchmarkCrack7DigitsSingleCore(b *testing.B) {
	benchCrack(b, zipNum7, "hello.txt", "7654321", 7, 7)
}

func BenchmarkCrack8DigitsSingleCore(b *testing.B) {
	benchCrack(b, zipNum8, "hello.txt", "88888888", 8, 8)
}

func BenchmarkCrack8DigitsAllCores(b *testing.B) {
	for i := 0; i < b.N; i++ {
		res := Crack(context.Background(), zipNum8, "hello.txt", 8, 8)
		if !res.Found || res.Password != "88888888" {
			b.Fatalf("期望 88888888，实际 Found=%v Password=%q", res.Found, res.Password)
		}
	}
}

// BenchmarkHeaderCheckSingleCore 测量纯枚举吞吐：每次迭代枚举 100000 个候选
// （固定前缀 '1'、长度 6，全部不会命中），结果反映单核的候选/秒上限。
// 单候选耗时 = ns/op ÷ 100000。
func BenchmarkHeaderCheckSingleCore(b *testing.B) {
	mustExistB(b, zipNum6)
	f, err := os.Open(zipNum6)
	if err != nil {
		b.Fatal(err)
	}
	defer f.Close()
	st, _ := f.Stat()
	e, err := findEntry(f, st.Size(), "hello.txt")
	if err != nil {
		b.Fatal(err)
	}
	c, err := newCracker(f, e)
	if err != nil {
		b.Fatal(err)
	}
	w := c.newWorker()
	stop := new(atomic.Bool)
	prefix := []byte{'9'} // 9xxxxx 里没有正确密码 123456，保证跑满 100000 个候选
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, _, err := w.search(context.Background(), stop, prefix, 6); err != nil {
			b.Fatal(err)
		}
	}
}

// TestHotLoopDoesNotAllocate 验证枚举热循环零分配。
// 这是本包性能的关键：候选循环里一旦分配 []byte 或 string，GC 压力会让吞吐掉一个数量级。
func TestHotLoopDoesNotAllocate(t *testing.T) {
	mustExist(t, zipNum6)
	f, err := os.Open(zipNum6)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil {
		t.Fatal(err)
	}
	e, err := findEntry(f, st.Size(), "hello.txt")
	if err != nil {
		t.Fatal(err)
	}
	c, err := newCracker(f, e)
	if err != nil {
		t.Fatal(err)
	}
	w := c.newWorker()
	stop := new(atomic.Bool)
	ctx := context.Background()
	prefix := []byte{'9'} // 以 9 开头且长度 6 的候选里没有正确密码

	// 预热：第一次进入二级校验时会惰性分配数据缓冲区。
	if _, ok, err := w.search(ctx, stop, prefix, 6); err != nil || ok {
		t.Fatalf("预热失败: ok=%v err=%v", ok, err)
	}

	allocs := testing.AllocsPerRun(5, func() {
		if _, ok, err := w.search(ctx, stop, prefix, 6); err != nil || ok {
			t.Fatalf("意外命中或出错: ok=%v err=%v", ok, err)
		}
	})
	if allocs != 0 {
		t.Fatalf("枚举 100000 个候选分配了 %.1f 次，热循环必须零分配", allocs)
	}
}

// BenchmarkWorstCase6to8SingleCore 是规格里的验收场景：6~8 位纯数字全量枚举
// （900000 + 9000000 + 90000000 = 99900000 个候选），密码不在范围内，必须跑满。
func BenchmarkWorstCase6to8SingleCore(b *testing.B) {
	mustExistB(b, zipAlpha6) // 密码 abc123，纯数字范围内必然找不到
	for i := 0; i < b.N; i++ {
		res := CrackWithOptions(context.Background(), zipAlpha6, "hello.txt",
			Options{MinLen: 6, MaxLen: 8, Workers: 1})
		if res.Err != nil || res.Found {
			b.Fatalf("期望未找到，实际 Found=%v Err=%v", res.Found, res.Err)
		}
	}
}

func mustExistB(b *testing.B, p string) {
	b.Helper()
	if _, err := os.Stat(p); err != nil {
		b.Fatalf("缺少测试样本 %s（运行 `go run testdata/generate.go` 重新生成）: %v", p, err)
	}
}
