package hashextract

import (
	"errors"
	"strings"
	"testing"
)

// testdata 下与 ZipCrypto 相关的两个样本：
//
//	zipcrypto.zip         Store（-mx0），口令 123456 → 必须走 mode 17210
//	zipcrypto_deflate.zip Deflate，口令 abc123  → 必须走 mode 17200
//
// 两个都要有：hashcat 的 17200 只接受 Deflate、17210 只接受 Store，写死其中
// 任何一个都会让另一半文件 No hashes loaded。这两条断言就是防这个回归的。
const (
	zipZipCryptoStore   = "testdata/zipcrypto.zip"
	zipZipCryptoDeflate = "testdata/zipcrypto_deflate.zip"

	zipCryptoStorePassword   = "123456"
	zipCryptoDeflatePassword = "abc123"
)

// splitPKZip2 把 $pkzip2$ 串按 * 切开，方便逐字段断言。
func splitPKZip2(t *testing.T, hash string) []string {
	t.Helper()
	if !strings.HasPrefix(hash, "$pkzip2$") {
		t.Fatalf("哈希没有以 $pkzip2$ 开头: %s", hash)
	}
	if !strings.HasSuffix(hash, "*$/pkzip2$") {
		t.Fatalf("哈希没有以 *$/pkzip2$ 结尾: %s", hash)
	}
	body := strings.TrimSuffix(strings.TrimPrefix(hash, "$pkzip2$"), "*$/pkzip2$")
	return strings.Split(body, "*")
}

// TestExtractZipCryptoStore 覆盖 Store 条目：模式号 17210、compression_type 0。
func TestExtractZipCryptoStore(t *testing.T) {
	res, err := ExtractZipCrypto(zipZipCryptoStore, "")
	if err != nil {
		t.Fatalf("ExtractZipCrypto: %v", err)
	}
	if res.Mode != ModeZipCryptoStore {
		t.Errorf("mode = %d，Store 条目应该是 %d", res.Mode, ModeZipCryptoStore)
	}
	if res.Format != FormatZipCrypto {
		t.Errorf("format = %q，应该是 %q", res.Format, FormatZipCrypto)
	}
	if res.Source != SourceBuiltin {
		t.Errorf("source = %q，应该是 %q（自己解析，不走 john）", res.Source, SourceBuiltin)
	}

	f := splitPKZip2(t, res.Hash)
	// 字段顺序见 ExtractZipCrypto 的注释。
	if len(f) != 14 {
		t.Fatalf("字段数 = %d，应该是 14: %v", len(f), f)
	}
	if f[0] != "1" {
		t.Errorf("hash_count = %q，应该是 1", f[0])
	}
	if f[1] != "1" {
		t.Errorf("checksum_size = %q，应该是 1", f[1])
	}
	if f[2] != "2" {
		t.Errorf("data_type = %q，应该是 2", f[2])
	}
	if f[3] != "0" {
		t.Errorf("magic_type = %q，应该是 0", f[3])
	}
	if f[9] != "0" {
		t.Errorf("compression_type = %q，Store 应该是 0", f[9])
	}
	// data_length 必须等于压缩长度，hashcat 按它切数据段。
	if f[4] != f[10] {
		t.Errorf("compressed_length = %q 与 data_length = %q 不一致", f[4], f[10])
	}
	// data 的十六进制长度必须正好是 2 * data_length。
	if got, want := len(f[13]), 2*mustParseHex(t, f[10]); got != want {
		t.Errorf("data 长度 = %d，应该是 %d", got, want)
	}
	// 12 字节加密头必须包含在数据里，所以至少 24 个十六进制字符。
	if len(f[13]) < 2*zipCryptoHeaderLength {
		t.Errorf("data 只有 %d 个十六进制字符，装不下 %d 字节加密头",
			len(f[13]), zipCryptoHeaderLength)
	}
}

// TestExtractZipCryptoDeflate 覆盖 Deflate 条目：模式号 17200、compression_type 8。
func TestExtractZipCryptoDeflate(t *testing.T) {
	res, err := ExtractZipCrypto(zipZipCryptoDeflate, "")
	if err != nil {
		t.Fatalf("ExtractZipCrypto: %v", err)
	}
	if res.Mode != ModeZipCryptoDeflate {
		t.Errorf("mode = %d，Deflate 条目应该是 %d", res.Mode, ModeZipCryptoDeflate)
	}
	f := splitPKZip2(t, res.Hash)
	if len(f) != 14 {
		t.Fatalf("字段数 = %d，应该是 14: %v", len(f), f)
	}
	if f[9] != "8" {
		t.Errorf("compression_type = %q，Deflate 应该是 8", f[9])
	}
	if f[4] != f[10] {
		t.Errorf("compressed_length = %q 与 data_length = %q 不一致", f[4], f[10])
	}
}

// TestExtractZipCryptoTimestampField 守住 checksum_from_timestamp。
//
// 这一位是实测出来的坑：把它置成 0000，hashcat 会直接报 No hashes loaded，
// 所以必须是本地文件头里的真实 DOS 时间。
func TestExtractZipCryptoTimestampField(t *testing.T) {
	res, err := ExtractZipCrypto(zipZipCryptoStore, "")
	if err != nil {
		t.Fatalf("ExtractZipCrypto: %v", err)
	}
	f := splitPKZip2(t, res.Hash)
	if f[12] == "0000" {
		t.Errorf("checksum_from_timestamp 是 0000，hashcat 会拒绝加载")
	}
	if len(f[12]) != 4 {
		t.Errorf("checksum_from_timestamp = %q，应该是 4 位十六进制", f[12])
	}
	// checksum_from_crc 取 CRC32 的高 16 位。
	if f[11] != f[6][:4] {
		t.Errorf("checksum_from_crc = %q，应该是 crc32 %q 的高 16 位 %q", f[11], f[6], f[6][:4])
	}
}

// TestExtractZIPDispatch 覆盖 ExtractZIP 的路由：AES 走 $zip2$，ZipCrypto 走 $pkzip2$。
func TestExtractZIPDispatch(t *testing.T) {
	aes, err := ExtractZIP(zipAES128, "")
	if err != nil {
		t.Fatalf("AES 路由失败: %v", err)
	}
	if aes.Mode != ModeZip2 {
		t.Errorf("aes128.zip 的 mode = %d，应该是 %d", aes.Mode, ModeZip2)
	}

	zc, err := ExtractZIP(zipZipCryptoStore, "")
	if err != nil {
		t.Fatalf("ZipCrypto 路由失败: %v", err)
	}
	if zc.Mode != ModeZipCryptoStore {
		t.Errorf("zipcrypto.zip 的 mode = %d，应该是 %d", zc.Mode, ModeZipCryptoStore)
	}
}

// TestExtractZIPEntryMismatch 确认指定条目时不会张冠李戴。
func TestExtractZIPEntryMismatch(t *testing.T) {
	// zipcrypto.zip 里只有 ZipCrypto 条目，按 AES 提应该失败。
	if _, err := ExtractZIPAES(zipZipCryptoStore, ""); !errors.Is(err, ErrNoAESEntry) {
		t.Errorf("ExtractZIPAES 对 ZipCrypto 文件返回 %v，应该是 ErrNoAESEntry", err)
	}
	// 反过来，AES 文件按 ZipCrypto 提也应该失败。
	if _, err := ExtractZipCrypto(zipAES128, ""); !errors.Is(err, ErrNoZipCryptoEntry) {
		t.Errorf("ExtractZipCrypto 对 AES 文件返回 %v，应该是 ErrNoZipCryptoEntry", err)
	}
	// 指定一个不存在的条目。
	if _, err := ExtractZipCrypto(zipZipCryptoStore, "nope.txt"); !errors.Is(err, ErrEntryNotFound) {
		t.Errorf("指定不存在条目返回 %v，应该是 ErrEntryNotFound", err)
	}
}

func mustParseHex(t *testing.T, s string) int {
	t.Helper()
	n := 0
	for _, c := range s {
		n *= 16
		switch {
		case c >= '0' && c <= '9':
			n += int(c - '0')
		case c >= 'a' && c <= 'f':
			n += int(c-'a') + 10
		default:
			t.Fatalf("非法十六进制字符 %q（%q）", c, s)
		}
	}
	return n
}
