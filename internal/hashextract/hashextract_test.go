package hashextract

import (
	"crypto/hmac"
	"crypto/sha1"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

// testdata 下的样本由 7-Zip 25.01 生成，口令统一为 123456：
//
//	aes128.zip        AES-128，Deflate
//	aes192_store.zip  AES-192，Store（-mx0）
//	aes256.zip        AES-256，Deflate
//	zipcrypto.zip     ZipCrypto（负样本）
//	plain.zip         未加密（负样本）
const (
	zipAES128      = "testdata/aes128.zip"
	zipAES192Store = "testdata/aes192_store.zip"
	zipAES256      = "testdata/aes256.zip"
	zipZipCrypto   = "testdata/zipcrypto.zip"
	zipPlain       = "testdata/plain.zip"

	testPassword = "123456"
	testEntry    = "hello.txt"
)

// ---------------------------------------------------------------------------
// $zip2$ 解析与校验工具（仅测试使用，与 hashcat module_13600 的判定一致）
// ---------------------------------------------------------------------------

type zip2Fields struct {
	typ      int
	mode     int
	magic    int
	salt     []byte
	verifier []byte
	compLen  uint64
	data     []byte
	auth     []byte
}

// parseZip2 按 "$zip2$*Ty*Mo*Ma*Sa*Va*Le*DF*Au*$/zip2$" 拆字段。
func parseZip2(t *testing.T, hash string) zip2Fields {
	t.Helper()
	if !strings.HasPrefix(hash, "$zip2$*") || !strings.HasSuffix(hash, "*$/zip2$") {
		t.Fatalf("哈希首尾标记不对: %q", hash)
	}
	parts := strings.Split(hash, "*")
	if len(parts) != 10 {
		t.Fatalf("字段数 = %d，want 10（%q）", len(parts), hash)
	}
	atoi := func(s string) int {
		n, err := strconv.Atoi(s)
		if err != nil {
			t.Fatalf("字段 %q 不是十进制整数: %v", s, err)
		}
		return n
	}
	unhex := func(name, s string) []byte {
		b, err := hex.DecodeString(s)
		if err != nil {
			t.Fatalf("字段 %s 不是合法十六进制: %v", name, err)
		}
		return b
	}
	return zip2Fields{
		typ:      atoi(parts[1]),
		mode:     atoi(parts[2]),
		magic:    atoi(parts[3]),
		salt:     unhex("salt", parts[4]),
		verifier: unhex("verifier", parts[5]),
		compLen:  parseHexUint(t, parts[6]),
		data:     unhex("data", parts[7]),
		auth:     unhex("auth", parts[8]),
	}
}

func parseHexUint(t *testing.T, s string) uint64 {
	t.Helper()
	n, err := strconv.ParseUint(s, 16, 64)
	if err != nil {
		t.Fatalf("字段 %q 不是十六进制整数: %v", s, err)
	}
	return n
}

// pbkdf2SHA1 是 RFC 2898 的 PBKDF2-HMAC-SHA1，只用于校验提取出的哈希。
func pbkdf2SHA1(password, salt []byte, iter, keyLen int) []byte {
	prf := hmac.New(sha1.New, password)
	hashLen := prf.Size()
	blocks := (keyLen + hashLen - 1) / hashLen
	var dk []byte
	u := make([]byte, hashLen)
	var counter [4]byte
	for block := 1; block <= blocks; block++ {
		prf.Reset()
		prf.Write(salt)
		counter[0] = byte(block >> 24)
		counter[1] = byte(block >> 16)
		counter[2] = byte(block >> 8)
		counter[3] = byte(block)
		prf.Write(counter[:])
		u = prf.Sum(u[:0])
		t := append([]byte(nil), u...)
		for n := 2; n <= iter; n++ {
			prf.Reset()
			prf.Write(u)
			u = prf.Sum(u[:0])
			for i := range t {
				t[i] ^= u[i]
			}
		}
		dk = append(dk, t...)
	}
	return dk[:keyLen]
}

// verifyZip2 用已知口令复算密码校验值与 HMAC，等价于 hashcat 内核的判定：
// 两者都匹配时，hashcat 一定能用该口令破解这个哈希。
func verifyZip2(t *testing.T, f zip2Fields, password string) {
	t.Helper()
	// AES-128/192/256 的密钥长度是 16/24/32 字节，即 8*(strength+1)。
	keyLen := 8 * (f.mode + 1)
	if len(f.salt) != 4+4*f.mode {
		t.Fatalf("盐长度 = %d，mode %d 要求 %d", len(f.salt), f.mode, 4+4*f.mode)
	}
	// PBKDF2 派生 2*keyLen+2 字节：加密密钥 + 认证密钥 + 2 字节密码校验值。
	derived := pbkdf2SHA1([]byte(password), f.salt, 1000, 2*keyLen+2)
	authKey := derived[keyLen : 2*keyLen]
	verifier := derived[2*keyLen:]

	if !hmac.Equal(verifier, f.verifier) {
		t.Fatalf("密码校验值不匹配：派生 %x，哈希里是 %x（口令 %q）",
			verifier, f.verifier, password)
	}

	mac := hmac.New(sha1.New, authKey)
	mac.Write(f.data)
	if got := mac.Sum(nil)[:10]; !hmac.Equal(got, f.auth) {
		t.Fatalf("认证码不匹配：计算 %x，哈希里是 %x", got, f.auth)
	}

}

// ---------------------------------------------------------------------------
// ExtractZIPAES
// ---------------------------------------------------------------------------

func TestExtractZIPAESStrength(t *testing.T) {
	cases := []struct {
		name      string
		path      string
		mode      int
		saltBytes int
	}{
		{"AES-128", zipAES128, 1, 8},
		{"AES-192+Store", zipAES192Store, 2, 12},
		{"AES-256", zipAES256, 3, 16},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			res, err := ExtractZIPAES(c.path, testEntry)
			if err != nil {
				t.Fatalf("ExtractZIPAES: %v", err)
			}
			if res.Mode != ModeZip2 {
				t.Errorf("Mode = %d，want %d", res.Mode, ModeZip2)
			}
			if res.Format != FormatZIPAES {
				t.Errorf("Format = %q，want %q", res.Format, FormatZIPAES)
			}
			if res.Source != SourceBuiltin {
				t.Errorf("Source = %q，want %q", res.Source, SourceBuiltin)
			}

			f := parseZip2(t, res.Hash)
			if f.typ != 0 {
				t.Errorf("type = %d，hashcat 只接受 0", f.typ)
			}
			if f.magic != 0 {
				t.Errorf("magic = %d，hashcat 只接受 0", f.magic)
			}
			if f.mode != c.mode {
				t.Errorf("mode = %d，want %d", f.mode, c.mode)
			}
			if len(f.salt) != c.saltBytes {
				t.Errorf("盐长度 = %d，want %d", len(f.salt), c.saltBytes)
			}
			if len(f.verifier) != aesVerifierLength {
				t.Errorf("校验值长度 = %d，want %d", len(f.verifier), aesVerifierLength)
			}
			if len(f.auth) != aesAuthLength {
				t.Errorf("认证码长度 = %d，want %d", len(f.auth), aesAuthLength)
			}
			if f.compLen != uint64(len(f.data)) {
				t.Errorf("compress_length = %d，密文实际 %d 字节", f.compLen, len(f.data))
			}
			if len(f.data) == 0 {
				t.Error("密文为空，样本不应该是 0 字节明文")
			}
		})
	}
}

// 核心用例：用已知口令复算校验值与 HMAC，证明这份哈希足以让 hashcat 解出口令。
func TestExtractZIPAESMatchesPassword(t *testing.T) {
	for _, path := range []string{zipAES128, zipAES192Store, zipAES256} {
		t.Run(path, func(t *testing.T) {
			res, err := ExtractZIPAES(path, testEntry)
			if err != nil {
				t.Fatalf("ExtractZIPAES: %v", err)
			}
			verifyZip2(t, parseZip2(t, res.Hash), testPassword)
		})
	}
}

// 错误口令必须校验失败，否则上面的用例就没有证明力。
func TestExtractZIPAESRejectsWrongPassword(t *testing.T) {
	res, err := ExtractZIPAES(zipAES256, testEntry)
	if err != nil {
		t.Fatalf("ExtractZIPAES: %v", err)
	}
	f := parseZip2(t, res.Hash)
	keyLen := 8 * (f.mode + 1)
	derived := pbkdf2SHA1([]byte("123457"), f.salt, 1000, 2*keyLen+2)
	if hmac.Equal(derived[2*keyLen:], f.verifier) {
		t.Fatal("错误口令居然通过了校验，说明提取的字段有误")
	}
}

func TestExtractZIPAESNonAES(t *testing.T) {
	for _, path := range []string{zipZipCrypto, zipPlain} {
		t.Run(path, func(t *testing.T) {
			_, err := ExtractZIPAES(path, "")
			if !errors.Is(err, ErrNoAESEntry) {
				t.Fatalf("err = %v，want ErrNoAESEntry", err)
			}
		})
	}
}

func TestExtractZIPAESEntrySelection(t *testing.T) {
	if _, err := ExtractZIPAES(zipAES256, "nope.txt"); !errors.Is(err, ErrEntryNotFound) {
		t.Errorf("不存在的条目: err = %v，want ErrEntryNotFound", err)
	}
	if _, err := ExtractZIPAES(zipZipCrypto, testEntry); !errors.Is(err, ErrNotAESEntry) {
		t.Errorf("ZipCrypto 条目: err = %v，want ErrNotAESEntry", err)
	}
	// 不指定条目时取第一个 AES 条目。
	if _, err := ExtractZIPAES(zipAES256, ""); err != nil {
		t.Errorf("不指定条目: %v", err)
	}
}

// 前端按 hash/mode/format 取值，字段名一旦回退成 Go 的 PascalCase，
// 界面就会显示 undefined —— 这里把 JSON 契约钉住。
func TestHashResultJSONKeys(t *testing.T) {
	res, err := ExtractZIPAES(zipAES256, testEntry)
	if err != nil {
		t.Fatalf("ExtractZIPAES: %v", err)
	}
	data, err := json.Marshal(res)
	if err != nil {
		t.Fatal(err)
	}
	var decoded map[string]any
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatal(err)
	}
	for _, key := range []string{"hash", "mode", "format", "source"} {
		if _, ok := decoded[key]; !ok {
			t.Errorf("JSON 里缺少 %q 字段：%s", key, data)
		}
	}
	if decoded["mode"] != float64(ModeZip2) {
		t.Errorf("mode = %v，want %d", decoded["mode"], ModeZip2)
	}
}

func TestExtractZIPAESMissingFile(t *testing.T) {
	if _, err := ExtractZIPAES("testdata/nope.zip", ""); err == nil {
		t.Fatal("文件不存在时应当报错")
	}
}

// ---------------------------------------------------------------------------
// ExtractViaJohn
// ---------------------------------------------------------------------------

// 真实的 hashcat 测试向量（module_13600.c 的 ST_HASH，口令 "hashcat"），
// 用来验证 findHash 能正确处理 john 追加的 ":file:base:path" 后缀。
const zip2TestVector = "$zip2$*0*1*0*0675369741458183*5dc5*0**36b85538918416712640*$/zip2$"

func TestFindHash(t *testing.T) {
	cases := []struct {
		name   string
		out    string
		format string
		want   string
	}{
		{
			name:   "zip2 带 john 后缀",
			out:    "hello.txt:" + zip2TestVector + ":hello.txt:archive.zip:/tmp/archive.zip\n",
			format: FormatZIPAES,
			want:   zip2TestVector,
		},
		{
			name:   "rar5 整行即哈希",
			out:    "archive.rar:$rar5$16$abcdef$3$1122$deadbeef\n",
			format: FormatRAR5,
			want:   "$rar5$16$abcdef$3$1122$deadbeef",
		},
		{
			name:   "7z 前面有警告行",
			out:    "! warning: something\narchive.7z:$7z$0$19$0$$8$aaaa$bbbb$cccc\r\n",
			format: Format7z,
			want:   "$7z$0$19$0$$8$aaaa$bbbb$cccc",
		},
		{
			name:   "没有哈希",
			out:    "something went wrong\n",
			format: FormatRAR5,
			want:   "",
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, ok := findHash(c.out, c.format)
			if c.want == "" {
				if ok {
					t.Fatalf("应当找不到哈希，却得到 %q", got)
				}
				return
			}
			if !ok {
				t.Fatal("没有找到哈希")
			}
			if got != c.want {
				t.Errorf("hash = %q，want %q", got, c.want)
			}
		})
	}
}

// stubRunner 替换外部命令执行，返回固定输出。
func stubRunner(t *testing.T, out string, err error, captured *[]string) {
	t.Helper()
	orig := runCommand
	runCommand = func(name string, args ...string) ([]byte, error) {
		if captured != nil {
			*captured = append([]string{name}, args...)
		}
		return []byte(out), err
	}
	t.Cleanup(func() { runCommand = orig })
}

func TestExtractViaJohnRAR5(t *testing.T) {
	var argv []string
	stubRunner(t, "archive.rar:$rar5$16$abcdef$3$1122$deadbeef\n", nil, &argv)

	res, err := ExtractViaJohn(`C:\tools\rar2john.exe`, `C:\zips\archive.rar`)
	if err != nil {
		t.Fatalf("ExtractViaJohn: %v", err)
	}
	if res.Mode != ModeRAR5 {
		t.Errorf("Mode = %d，want %d", res.Mode, ModeRAR5)
	}
	if res.Format != FormatRAR5 {
		t.Errorf("Format = %q，want %q", res.Format, FormatRAR5)
	}
	if res.Source != SourceRar2 {
		t.Errorf("Source = %q，want %q", res.Source, SourceRar2)
	}
	if res.Hash != "$rar5$16$abcdef$3$1122$deadbeef" {
		t.Errorf("Hash = %q", res.Hash)
	}
	want := []string{`C:\tools\rar2john.exe`, `C:\zips\archive.rar`}
	if strings.Join(argv, "|") != strings.Join(want, "|") {
		t.Errorf("argv = %v，want %v", argv, want)
	}
}

func TestExtractViaJohn7z(t *testing.T) {
	stubRunner(t, "archive.7z:$7z$0$19$0$$8$aaaa$bbbb$cccc\n", nil, nil)

	res, err := ExtractViaJohn(`C:\tools\7z2john.exe`, `C:\zips\archive.7z`)
	if err != nil {
		t.Fatalf("ExtractViaJohn: %v", err)
	}
	if res.Mode != Mode7z {
		t.Errorf("Mode = %d，want %d", res.Mode, Mode7z)
	}
	if res.Format != Format7z {
		t.Errorf("Format = %q，want %q", res.Format, Format7z)
	}
	if res.Source != Source7z2 {
		t.Errorf("Source = %q，want %q", res.Source, Source7z2)
	}
}

func TestExtractViaJohnNoHash(t *testing.T) {
	stubRunner(t, "ERROR: unsupported archive\n", errors.New("exit status 1"), nil)

	_, err := ExtractViaJohn(`C:\tools\rar2john.exe`, `C:\zips\archive.rar`)
	if !errors.Is(err, ErrNoHash) {
		t.Fatalf("err = %v，want ErrNoHash", err)
	}
	if !strings.Contains(err.Error(), "rar2john.exe") {
		t.Errorf("错误信息里应带上工具名: %v", err)
	}
}

func TestExtractViaJohnUnknownTool(t *testing.T) {
	_, err := ExtractViaJohn(`C:\tools\mystery.exe`, `C:\zips\archive.bin`)
	if !errors.Is(err, ErrUnknownTool) {
		t.Fatalf("err = %v，want ErrUnknownTool", err)
	}
}

// 工具名认不出来时，退回看归档扩展名。
func TestJohnTargetForFallsBackToExtension(t *testing.T) {
	target, err := johnTargetFor(`C:\tools\mystery.exe`, `C:\zips\archive.rar`)
	if err != nil {
		t.Fatalf("johnTargetFor: %v", err)
	}
	if target.mode != ModeRAR5 {
		t.Errorf("mode = %d，want %d", target.mode, ModeRAR5)
	}
}

func TestJohnCommandInterpreter(t *testing.T) {
	cases := []struct {
		tool     string
		wantName string
		wantArgs int
	}{
		{`C:\tools\rar2john.exe`, `C:\tools\rar2john.exe`, 1},
		{`C:\tools\7z2john.pl`, "perl", 2},
		{`C:\tools\7z2john.py`, "python", 2},
	}
	for _, c := range cases {
		name, args := johnCommand(c.tool, "a.7z")
		if name != c.wantName {
			t.Errorf("%s: name = %q，want %q", c.tool, name, c.wantName)
		}
		if len(args) != c.wantArgs {
			t.Errorf("%s: args = %v，want %d 个", c.tool, args, c.wantArgs)
		}
	}
}

// 真实执行一次：工具不存在时应当返回可读的错误，而不是 panic。
func TestExtractViaJohnMissingTool(t *testing.T) {
	_, err := ExtractViaJohn("definitely-not-a-real-tool-rar2john", "a.rar")
	if err == nil {
		t.Fatal("工具不存在时应当报错")
	}
	if !errors.Is(err, ErrNoHash) {
		t.Fatalf("err = %v，want ErrNoHash", err)
	}
}

// ---------------------------------------------------------------------------
// 7z2hashcat（外部脚本）
// ---------------------------------------------------------------------------

// stubScript 在临时目录里放一个「像脚本」的空文件。
func stubScript(t *testing.T, name string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(path, []byte("#!/usr/bin/env perl\n"), 0o755); err != nil {
		t.Fatalf("写临时脚本: %v", err)
	}
	return path
}

// stubRun 替换真实的进程执行，并返回恢复函数。
func stubRun(t *testing.T, stdout, stderr string, runErr error) *[]string {
	t.Helper()
	var got []string
	old := runScriptOutput
	runScriptOutput = func(name string, args ...string) (string, string, error) {
		got = append([]string{name}, args...)
		return stdout, stderr, runErr
	}
	t.Cleanup(func() { runScriptOutput = old })
	return &got
}

// 7z2hashcat 的输出是「一行一条哈希、行首没有文件名前缀」，和 7z2john 不同。
func TestExtractVia7z2HashcatParsesBareHash(t *testing.T) {
	script := stubScript(t, "7z2hashcat.pl")
	const hash = "$7z$0$19$0$$16$00112233445566778899aabbccddeeff$123456789$48$48$aabb$13$00"

	got := stubRun(t, hash+"\n", "", nil)
	old := execLookPath
	execLookPath = func(string) (string, error) { return "/usr/bin/perl", nil }
	t.Cleanup(func() { execLookPath = old })

	res, err := ExtractVia7z2Hashcat("a.7z", script, "")
	if err != nil {
		t.Fatalf("ExtractVia7z2Hashcat: %v", err)
	}
	if res.Hash != hash {
		t.Errorf("Hash = %q，want %q", res.Hash, hash)
	}
	if res.Mode != Mode7z {
		t.Errorf("Mode = %d，want %d", res.Mode, Mode7z)
	}
	if res.Source != Source7z2Hashcat {
		t.Errorf("Source = %q，want %q", res.Source, Source7z2Hashcat)
	}
	// .pl 必须用 perl 起，而不是硬编码 python。
	if len(*got) == 0 || !strings.Contains((*got)[0], "perl") {
		t.Errorf("启动命令 = %v，期望用 perl", *got)
	}
	if (*got)[len(*got)-1] != "a.7z" {
		t.Errorf("最后一个参数应是归档路径，实际 %v", *got)
	}
}

// .py 脚本要按后缀改用 python3/python，不能一律 perl。
func TestSevenZip2HashcatCommandPicksInterpreterByExtension(t *testing.T) {
	old := execLookPath
	execLookPath = func(name string) (string, error) {
		if name == "python3" {
			return "/usr/bin/python3", nil
		}
		return "", errors.New("not found")
	}
	t.Cleanup(func() { execLookPath = old })

	name, args, err := sevenZip2HashcatCommand("/x/7z2hashcat.py", "", "a.7z")
	if err != nil {
		t.Fatalf("err = %v", err)
	}
	if name != "/usr/bin/python3" {
		t.Errorf("解释器 = %q，want /usr/bin/python3", name)
	}
	if len(args) != 2 || args[0] != "/x/7z2hashcat.py" {
		t.Errorf("args = %v", args)
	}
}

// .exe 直接执行，即使配了解释器也不能插进去。
func TestSevenZip2HashcatCommandRunsExeDirectly(t *testing.T) {
	name, args, err := sevenZip2HashcatCommand("/x/7z2hashcat.exe", "/usr/bin/perl", "a.7z")
	if err != nil {
		t.Fatalf("err = %v", err)
	}
	if name != "/x/7z2hashcat.exe" {
		t.Errorf("命令 = %q，应直接执行 .exe", name)
	}
	if len(args) != 1 || args[0] != "a.7z" {
		t.Errorf("args = %v，不应带脚本路径", args)
	}
}

func TestExtractVia7z2HashcatScriptMissing(t *testing.T) {
	_, err := ExtractVia7z2Hashcat("a.7z", "", "")
	if !errors.Is(err, ErrScriptMissing) {
		t.Fatalf("err = %v，want ErrScriptMissing", err)
	}
	_, err = ExtractVia7z2Hashcat("a.7z", filepath.Join(t.TempDir(), "nope.pl"), "")
	if !errors.Is(err, ErrScriptMissing) {
		t.Fatalf("err = %v，want ErrScriptMissing", err)
	}
}

// 没装解释器时要明确说是解释器的问题，而不是笼统的「执行失败」。
func TestExtractVia7z2HashcatInterpreterMissing(t *testing.T) {
	script := stubScript(t, "7z2hashcat.pl")
	old := execLookPath
	execLookPath = func(string) (string, error) { return "", errors.New("not found") }
	t.Cleanup(func() { execLookPath = old })

	_, err := ExtractVia7z2Hashcat("a.7z", script, "")
	if !errors.Is(err, ErrInterpreterMissing) {
		t.Fatalf("err = %v，want ErrInterpreterMissing", err)
	}
	if !strings.Contains(err.Error(), "Perl") {
		t.Errorf("提示里应说明 .pl 需要 Perl：%v", err)
	}
}

// 脚本失败时要把 stderr 原样带出来，用户才能看到 7z2hashcat 自己的诊断。
func TestExtractVia7z2HashcatSurfacesStderr(t *testing.T) {
	script := stubScript(t, "7z2hashcat.pl")
	stubRun(t, "", "WARNING: no AES data found in the 7z file 'a.7z'", errors.New("exit status 1"))

	_, err := ExtractVia7z2Hashcat("a.7z", script, "/usr/bin/perl")
	if err == nil {
		t.Fatal("期望报错")
	}
	if !errors.Is(err, ErrScriptFailed) {
		t.Fatalf("err = %v，want ErrScriptFailed", err)
	}
	if !strings.Contains(err.Error(), "no AES data found") {
		t.Errorf("错误里应带上 stderr：%v", err)
	}
}

// 退出码为 0 但没有哈希，也要把 stderr 一起给出来。
func TestExtractVia7z2HashcatNoHashButClean(t *testing.T) {
	script := stubScript(t, "7z2hashcat.pl")
	stubRun(t, "some log line\n", "", nil)

	_, err := ExtractVia7z2Hashcat("a.7z", script, "/usr/bin/perl")
	if !errors.Is(err, ErrNoHash) {
		t.Fatalf("err = %v，want ErrNoHash", err)
	}
}

func TestFind7z2HashcatHash(t *testing.T) {
	const hash = "$7z$0$19$0$$16$00$1$00$16$16$00"

	cases := []struct {
		name string
		out  string
		want string
		ok   bool
	}{
		{"裸哈希", hash + "\n", hash, true},
		{"前后有空行", "\n\n" + hash + "\n\n", hash, true},
		{"CRLF", hash + "\r\n", hash, true},
		{"前面有日志行", "DEBUG: x\n" + hash + "\n", hash, true},
		{"多条取第一条", hash + "\n$7z$9$1$0$$0$$0$1$1$00\n", hash, true},
		{"带文件名前缀（兜底）", "a.7z:" + hash + "\n", hash, true},
		{"只有日志", "no hash here\n", "", false},
		{"空输出", "", "", false},
		{"残缺签名", "$7z$\n", "", false},
	}
	for _, c := range cases {
		got, ok := find7z2HashcatHash(c.out)
		if ok != c.ok {
			t.Errorf("%s: ok = %v，want %v", c.name, ok, c.ok)
			continue
		}
		if c.ok && got != c.want {
			t.Errorf("%s: got %q，want %q", c.name, got, c.want)
		}
	}
}
