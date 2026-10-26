package zipservice

import (
	"archive/zip"
	"bytes"
	"encoding/binary"
	"errors"
	"hash/crc32"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"golang.org/x/text/encoding/simplifiedchinese"
)

// ---------------------------------------------------------------------------
// fixture builder
// ---------------------------------------------------------------------------

// fx describes one entry of a hand built archive. Building the bytes ourselves
// is the only way to produce AES, ZIP64 and deliberately inconsistent
// (fake encrypted) archives without external tools.
type fx struct {
	name   string
	gpbf   uint16
	method uint16
	crc    uint32
	csize  uint32
	usize  uint32
	extra  []byte // central directory extra field
	data   []byte

	// localGPBF overrides the flag written in the local file header.
	localGPBF    uint16
	hasLocalGPBF bool

	// zip64 writes saturated 32 bit fields plus a 0x0001 extra field.
	zip64    bool
	z64csize uint64
	z64usize uint64
}

func w16(b *bytes.Buffer, v uint16) {
	var tmp [2]byte
	binary.LittleEndian.PutUint16(tmp[:], v)
	b.Write(tmp[:])
}

func w32(b *bytes.Buffer, v uint32) {
	var tmp [4]byte
	binary.LittleEndian.PutUint32(tmp[:], v)
	b.Write(tmp[:])
}

func w64(b *bytes.Buffer, v uint64) {
	var tmp [8]byte
	binary.LittleEndian.PutUint64(tmp[:], v)
	b.Write(tmp[:])
}

// buildZip assembles a complete archive. base is the absolute file offset at
// which the returned bytes will be written, so all internal offsets stay
// correct for the sparse multi-gigabyte test.
func buildZip(t *testing.T, base int64, entries []fx, comment string, forceZip64 bool) []byte {
	t.Helper()

	var buf bytes.Buffer
	offsets := make([]uint64, len(entries))

	for i, e := range entries {
		offsets[i] = uint64(base) + uint64(buf.Len())

		localGPBF := e.gpbf
		if e.hasLocalGPBF {
			localGPBF = e.localGPBF
		}
		name := []byte(e.name)

		w32(&buf, sigLocalHeader)
		w16(&buf, 20)
		w16(&buf, localGPBF)
		w16(&buf, e.method)
		w16(&buf, 0) // mod time
		w16(&buf, 0) // mod date
		w32(&buf, e.crc)
		if e.zip64 {
			w32(&buf, 0xFFFFFFFF)
			w32(&buf, 0xFFFFFFFF)
		} else {
			w32(&buf, e.csize)
			w32(&buf, e.usize)
		}
		w16(&buf, uint16(len(name)))
		w16(&buf, 0) // no local extra field
		buf.Write(name)
		buf.Write(e.data)
	}

	cdStartRel := buf.Len()
	cdStartAbs := base + int64(cdStartRel)

	for i, e := range entries {
		extra := e.extra
		if e.zip64 {
			var z bytes.Buffer
			w16(&z, extraZip64)
			w16(&z, 24)
			w64(&z, e.z64usize)
			w64(&z, e.z64csize)
			w64(&z, offsets[i])
			extra = append(z.Bytes(), extra...)
		}
		name := []byte(e.name)

		w32(&buf, sigCentralHeader)
		w16(&buf, 0x031E) // version made by
		w16(&buf, 20)     // version needed
		w16(&buf, e.gpbf)
		w16(&buf, e.method)
		w16(&buf, 0) // mod time
		w16(&buf, 0) // mod date
		w32(&buf, e.crc)
		if e.zip64 {
			w32(&buf, 0xFFFFFFFF)
			w32(&buf, 0xFFFFFFFF)
		} else {
			w32(&buf, e.csize)
			w32(&buf, e.usize)
		}
		w16(&buf, uint16(len(name)))
		w16(&buf, uint16(len(extra)))
		w16(&buf, 0) // comment length
		w16(&buf, 0) // disk number start
		w16(&buf, 0) // internal attributes
		w32(&buf, 0) // external attributes
		if e.zip64 {
			w32(&buf, 0xFFFFFFFF)
		} else {
			w32(&buf, uint32(offsets[i]))
		}
		buf.Write(name)
		buf.Write(extra)
	}

	cdSize := uint64(buf.Len() - cdStartRel)

	if forceZip64 {
		z64Offset := base + int64(buf.Len())

		w32(&buf, sigZip64EOCD)
		w64(&buf, 44) // size of the remainder of this record
		w16(&buf, 0x031E)
		w16(&buf, 45)
		w32(&buf, 0) // this disk
		w32(&buf, 0) // disk with central directory
		w64(&buf, uint64(len(entries)))
		w64(&buf, uint64(len(entries)))
		w64(&buf, cdSize)
		w64(&buf, uint64(cdStartAbs))

		w32(&buf, sigZip64Locator)
		w32(&buf, 0) // disk with zip64 EOCD
		w64(&buf, uint64(z64Offset))
		w32(&buf, 1) // total disks

		w32(&buf, sigEOCD)
		w16(&buf, 0)
		w16(&buf, 0)
		w16(&buf, 0xFFFF)
		w16(&buf, 0xFFFF)
		w32(&buf, 0xFFFFFFFF)
		w32(&buf, 0xFFFFFFFF)
		w16(&buf, uint16(len(comment)))
		buf.WriteString(comment)
		return buf.Bytes()
	}

	w32(&buf, sigEOCD)
	w16(&buf, 0) // this disk
	w16(&buf, 0) // disk with central directory
	w16(&buf, uint16(len(entries)))
	w16(&buf, uint16(len(entries)))
	w32(&buf, uint32(cdSize))
	w32(&buf, uint32(cdStartAbs))
	w16(&buf, uint16(len(comment)))
	buf.WriteString(comment)

	return buf.Bytes()
}

func writeFixture(t *testing.T, dir string, blob []byte, base int64) string {
	t.Helper()

	path := filepath.Join(dir, "fixture.zip")
	f, err := os.Create(path)
	if err != nil {
		t.Fatalf("create fixture: %v", err)
	}
	defer f.Close()

	if base > 0 {
		if err := f.Truncate(base); err != nil {
			t.Fatalf("truncate to %d: %v", base, err)
		}
	}
	if _, err := f.WriteAt(blob, base); err != nil {
		t.Fatalf("write fixture at %d: %v", base, err)
	}
	return path
}

func aesExtra(strength byte, method uint16) []byte {
	var b bytes.Buffer
	w16(&b, extraAES)
	w16(&b, 7)
	w16(&b, 2) // AE-2
	b.WriteString("AE")
	b.WriteByte(strength)
	w16(&b, method)
	return b.Bytes()
}

// ---------------------------------------------------------------------------
// plain archive written by the standard library
// ---------------------------------------------------------------------------

func TestInspectPlainZip(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "plain.zip")

	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	zw := zip.NewWriter(f)

	stored, err := zw.CreateHeader(&zip.FileHeader{Name: "readme.txt", Method: zip.Store})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := stored.Write([]byte("hello zip")); err != nil {
		t.Fatal(err)
	}

	deflated, err := zw.CreateHeader(&zip.FileHeader{Name: "目录/数据.csv", Method: zip.Deflate})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := deflated.Write(bytes.Repeat([]byte("a,b\n"), 200)); err != nil {
		t.Fatal(err)
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}

	info, err := Inspect(path)
	if err != nil {
		t.Fatalf("Inspect: %v", err)
	}
	if info.Format != "ZIP" {
		t.Errorf("Format = %q, want ZIP", info.Format)
	}
	if info.EntryCount != 2 || len(info.Entries) != 2 {
		t.Fatalf("EntryCount = %d, entries = %d, want 2", info.EntryCount, len(info.Entries))
	}
	if info.EncryptionType != "None" {
		t.Errorf("EncryptionType = %q, want None", info.EncryptionType)
	}
	if info.IsFakeEncrypted {
		t.Error("IsFakeEncrypted = true, want false")
	}

	if got := info.Entries[0]; got.Name != "readme.txt" || got.Compression != "Store" || got.IsEncrypted {
		t.Errorf("entry 0 = %+v", got)
	}
	if got := info.Entries[1]; got.Name != "目录/数据.csv" || got.Compression != "Deflate" {
		t.Errorf("entry 1 = %+v", got)
	}
	if info.Entries[0].CRC32 == 0 || info.Entries[1].UncompressedSize != 800 {
		t.Errorf("unexpected sizes/crc: %+v", info.Entries)
	}
	if info.FileSize <= 0 {
		t.Errorf("FileSize = %d", info.FileSize)
	}
}

// ---------------------------------------------------------------------------
// ZIP64
// ---------------------------------------------------------------------------

func TestInspectZip64(t *testing.T) {
	dir := t.TempDir()
	entries := []fx{
		{
			name:     "huge.bin",
			gpbf:     0,
			method:   methodStore,
			crc:      0xDEADBEEF,
			zip64:    true,
			z64usize: 5 << 30, // 5 GiB
			z64csize: 3 << 30, // 3 GiB
			data:     []byte("payload"),
		},
	}
	path := writeFixture(t, dir, buildZip(t, 0, entries, "", true), 0)

	info, err := Inspect(path)
	if err != nil {
		t.Fatalf("Inspect: %v", err)
	}
	if info.Format != "ZIP64" {
		t.Errorf("Format = %q, want ZIP64", info.Format)
	}
	if info.EntryCount != 1 {
		t.Fatalf("EntryCount = %d, want 1", info.EntryCount)
	}
	got := info.Entries[0]
	if got.UncompressedSize != 5<<30 || got.CompressedSize != 3<<30 {
		t.Errorf("sizes = %d/%d, want %d/%d", got.UncompressedSize, got.CompressedSize, uint64(5)<<30, uint64(3)<<30)
	}
	if got.LocalHeaderOffset != 0 {
		t.Errorf("LocalHeaderOffset = %d, want 0", got.LocalHeaderOffset)
	}
	if got.CRC32 != 0xDEADBEEF {
		t.Errorf("CRC32 = %08X", got.CRC32)
	}
}

// A sparse file larger than 4 GiB exercises the real ZIP64 path and proves the
// parser never reads the whole archive.
func TestInspectHugeSparseFile(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping multi-gigabyte sparse file test in short mode")
	}

	dir := t.TempDir()
	base := int64(4<<30) + 12345 // just over 4 GiB of leading zeroes

	entries := []fx{
		{name: "big.dat", method: methodDeflate, crc: 0x11223344, zip64: true, z64usize: 4 << 30, z64csize: 1 << 30, data: []byte("tail")},
	}
	path := writeFixture(t, dir, buildZip(t, base, entries, "archive comment", true), base)

	var before, after runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&before)

	info, err := Inspect(path)
	if err != nil {
		t.Fatalf("Inspect: %v", err)
	}

	runtime.ReadMemStats(&after)

	if info.FileSize <= 4<<30 {
		t.Fatalf("FileSize = %d, want > 4 GiB", info.FileSize)
	}
	if info.Format != "ZIP64" || info.EntryCount != 1 {
		t.Fatalf("Format/EntryCount = %q/%d", info.Format, info.EntryCount)
	}
	if info.Entries[0].LocalHeaderOffset != uint64(base) {
		t.Errorf("LocalHeaderOffset = %d, want %d", info.Entries[0].LocalHeaderOffset, base)
	}

	// Total heap growth is reported rather than asserted: it is the number that
	// matters for the "under 50 MB" acceptance criterion.
	if after.TotalAlloc > before.TotalAlloc {
		t.Logf("heap allocated while inspecting a %d byte archive: %d bytes",
			info.FileSize, after.TotalAlloc-before.TotalAlloc)
	}
}

// ---------------------------------------------------------------------------
// AES
// ---------------------------------------------------------------------------

func TestInspectAES(t *testing.T) {
	dir := t.TempDir()
	entries := []fx{
		{
			name:   "aes256.txt",
			gpbf:   flagEncrypted,
			method: methodAES,
			crc:    0xAABBCCDD,
			extra:  aesExtra(3, methodDeflate),
			data:   []byte("salt-verifier-ciphertext"),
		},
		{
			name:   "aes128.txt",
			gpbf:   flagEncrypted,
			method: methodAES,
			extra:  aesExtra(1, methodStore),
			data:   []byte("salt-verifier-ciphertext"),
		},
	}
	path := writeFixture(t, dir, buildZip(t, 0, entries, "", false), 0)

	info, err := Inspect(path)
	if err != nil {
		t.Fatalf("Inspect: %v", err)
	}

	cases := []struct {
		index      int
		encryption string
		method     uint16
		compress   string
	}{
		{0, "AES-256", methodAES, "Deflate"},
		{1, "AES-128", methodAES, "Store"},
	}
	for _, c := range cases {
		got := info.Entries[c.index]
		if got.EncryptionType != c.encryption {
			t.Errorf("entry %d EncryptionType = %q, want %q", c.index, got.EncryptionType, c.encryption)
		}
		if got.Method != c.method {
			t.Errorf("entry %d Method = %d, want %d", c.index, got.Method, c.method)
		}
		if got.Compression != c.compress {
			t.Errorf("entry %d Compression = %q, want %q", c.index, got.Compression, c.compress)
		}
		if !got.IsEncrypted {
			t.Errorf("entry %d IsEncrypted = false", c.index)
		}
	}
	if info.EncryptionType != "Mixed" {
		t.Errorf("file EncryptionType = %q, want Mixed", info.EncryptionType)
	}
}

// The 0x9901 record must be found by walking the TLV list, not by assuming a
// fixed offset.
func TestInspectAESWithPrecedingExtraField(t *testing.T) {
	dir := t.TempDir()

	var extra bytes.Buffer
	w16(&extra, 0x5455) // extended timestamp, 5 bytes of payload
	w16(&extra, 5)
	extra.Write([]byte{1, 0, 0, 0, 0})
	extra.Write(aesExtra(2, methodDeflate))

	entries := []fx{{
		name:   "aes192.txt",
		gpbf:   flagEncrypted,
		method: methodAES,
		extra:  extra.Bytes(),
		data:   []byte("x"),
	}}
	path := writeFixture(t, dir, buildZip(t, 0, entries, "", false), 0)

	info, err := Inspect(path)
	if err != nil {
		t.Fatalf("Inspect: %v", err)
	}
	if got := info.Entries[0].EncryptionType; got != "AES-192" {
		t.Errorf("EncryptionType = %q, want AES-192", got)
	}
	if got := info.Entries[0].Compression; got != "Deflate" {
		t.Errorf("Compression = %q, want Deflate", got)
	}
}

// ---------------------------------------------------------------------------
// mixed / zipcrypto
// ---------------------------------------------------------------------------

func TestInspectMixedEncryption(t *testing.T) {
	dir := t.TempDir()
	entries := []fx{
		{name: "plain.txt", method: methodDeflate, data: []byte("a")},
		{name: "legacy.txt", gpbf: flagEncrypted, method: methodDeflate, data: []byte("b")},
		{name: "modern.txt", gpbf: flagEncrypted, method: methodAES, extra: aesExtra(3, methodDeflate), data: []byte("c")},
	}
	path := writeFixture(t, dir, buildZip(t, 0, entries, "", false), 0)

	info, err := Inspect(path)
	if err != nil {
		t.Fatalf("Inspect: %v", err)
	}
	if info.EncryptionType != "Mixed" {
		t.Errorf("EncryptionType = %q, want Mixed", info.EncryptionType)
	}
	want := []string{"None", "ZipCrypto", "AES-256"}
	for i, w := range want {
		if got := info.Entries[i].EncryptionType; got != w {
			t.Errorf("entry %d = %q, want %q", i, got, w)
		}
	}
}

func TestInspectZipCryptoOnly(t *testing.T) {
	dir := t.TempDir()
	entries := []fx{
		{name: "one.txt", gpbf: flagEncrypted, method: methodDeflate, data: []byte("a")},
		{name: "two.txt", gpbf: flagEncrypted, method: methodStore, data: []byte("b")},
	}
	path := writeFixture(t, dir, buildZip(t, 0, entries, "", false), 0)

	info, err := Inspect(path)
	if err != nil {
		t.Fatalf("Inspect: %v", err)
	}
	if info.EncryptionType != "ZipCrypto" {
		t.Errorf("EncryptionType = %q, want ZipCrypto", info.EncryptionType)
	}
	for i, e := range info.Entries {
		if !e.IsEncrypted || e.EncryptionType != "ZipCrypto" {
			t.Errorf("entry %d = %+v", i, e)
		}
		// GPFlags 必须原样带出中央目录的通用位标记，批量层靠它识别强加密。
		if e.GPFlags&flagEncrypted == 0 {
			t.Errorf("entry %d: GPFlags = 0x%04X, want bit 0 set", i, e.GPFlags)
		}
	}
}

// ---------------------------------------------------------------------------
// fake encryption
// ---------------------------------------------------------------------------

func TestFakeEncryptionDetected(t *testing.T) {
	dir := t.TempDir()
	entries := []fx{{
		name:         "notes.txt",
		gpbf:         flagEncrypted, // central directory claims encryption
		localGPBF:    0,             // local header does not
		hasLocalGPBF: true,
		method:       methodDeflate,
		data:         []byte("definitely not encrypted"),
	}}
	path := writeFixture(t, dir, buildZip(t, 0, entries, "", false), 0)

	info, err := Inspect(path)
	if err != nil {
		t.Fatalf("Inspect: %v", err)
	}
	if !info.IsFakeEncrypted {
		t.Error("IsFakeEncrypted = false, want true")
	}
}

func TestRealEncryptionNotFlagged(t *testing.T) {
	dir := t.TempDir()
	entries := []fx{{
		name:         "secret.txt",
		gpbf:         flagEncrypted,
		localGPBF:    flagEncrypted,
		hasLocalGPBF: true,
		method:       methodDeflate,
		data:         []byte("ciphertext"),
	}}
	path := writeFixture(t, dir, buildZip(t, 0, entries, "", false), 0)

	info, err := Inspect(path)
	if err != nil {
		t.Fatalf("Inspect: %v", err)
	}
	if info.IsFakeEncrypted {
		t.Error("IsFakeEncrypted = true, want false")
	}
}

// ---------------------------------------------------------------------------
// filename decoding
// ---------------------------------------------------------------------------

func TestGBKFilename(t *testing.T) {
	dir := t.TempDir()

	gbkName, err := simplifiedchinese.GBK.NewEncoder().Bytes([]byte("中文文档/说明.txt"))
	if err != nil {
		t.Fatalf("encode gbk: %v", err)
	}

	entries := []fx{{
		name:   string(gbkName), // no UTF-8 flag set
		method: methodDeflate,
		data:   []byte("x"),
	}}
	path := writeFixture(t, dir, buildZip(t, 0, entries, "", false), 0)

	info, err := Inspect(path)
	if err != nil {
		t.Fatalf("Inspect: %v", err)
	}
	if got := info.Entries[0].Name; got != "中文文档/说明.txt" {
		t.Errorf("Name = %q, want 中文文档/说明.txt", got)
	}
}

func TestUTF8FlagFilename(t *testing.T) {
	dir := t.TempDir()
	entries := []fx{{
		name:   "日本語/ファイル.txt",
		gpbf:   flagUTF8Name,
		method: methodDeflate,
		data:   []byte("x"),
	}}
	path := writeFixture(t, dir, buildZip(t, 0, entries, "", false), 0)

	info, err := Inspect(path)
	if err != nil {
		t.Fatalf("Inspect: %v", err)
	}
	if got := info.Entries[0].Name; got != "日本語/ファイル.txt" {
		t.Errorf("Name = %q", got)
	}
}

// ---------------------------------------------------------------------------
// EOCD edge cases
// ---------------------------------------------------------------------------

// A comment containing a fake EOCD signature must not confuse the backwards
// scan.
func TestEOCDCommentWithFakeSignature(t *testing.T) {
	dir := t.TempDir()
	comment := "note PK\x05\x06 this is not a real record"
	entries := []fx{{name: "a.txt", method: methodStore, data: []byte("a")}}
	path := writeFixture(t, dir, buildZip(t, 0, entries, comment, false), 0)

	info, err := Inspect(path)
	if err != nil {
		t.Fatalf("Inspect: %v", err)
	}
	if info.EntryCount != 1 || info.Entries[0].Name != "a.txt" {
		t.Errorf("got %d entries, first = %q", info.EntryCount, info.Entries[0].Name)
	}
}

func TestEmptyZip(t *testing.T) {
	dir := t.TempDir()
	path := writeFixture(t, dir, buildZip(t, 0, nil, "", false), 0)

	info, err := Inspect(path)
	if err != nil {
		t.Fatalf("Inspect: %v", err)
	}
	if info.EntryCount != 0 || len(info.Entries) != 0 {
		t.Errorf("EntryCount = %d", info.EntryCount)
	}
	if info.EncryptionType != "None" {
		t.Errorf("EncryptionType = %q, want None", info.EncryptionType)
	}
}

func TestNotAZip(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "random.bin")
	if err := os.WriteFile(path, bytes.Repeat([]byte{0x41}, 4096), 0o644); err != nil {
		t.Fatal(err)
	}

	_, err := Inspect(path)
	if !errors.Is(err, ErrNotZip) {
		t.Errorf("err = %v, want ErrNotZip", err)
	}
}

func TestMissingFile(t *testing.T) {
	if _, err := Inspect(filepath.Join(t.TempDir(), "nope.zip")); err == nil {
		t.Error("expected an error for a missing file")
	}
}

// ---------------------------------------------------------------------------
// ReadLocalHeader
// ---------------------------------------------------------------------------

func TestReadLocalHeader(t *testing.T) {
	dir := t.TempDir()
	entries := []fx{
		{name: "first.txt", gpbf: flagEncrypted, method: methodDeflate, data: bytes.Repeat([]byte("x"), 200)},
	}
	path := writeFixture(t, dir, buildZip(t, 0, entries, "", false), 0)

	info, err := Inspect(path)
	if err != nil {
		t.Fatalf("Inspect: %v", err)
	}

	buf, err := ReadLocalHeader(path, int64(info.Entries[0].LocalHeaderOffset), 128)
	if err != nil {
		t.Fatalf("ReadLocalHeader: %v", err)
	}
	if len(buf) != 128 {
		t.Fatalf("len = %d, want 128", len(buf))
	}
	if sig := binary.LittleEndian.Uint32(buf[:4]); sig != sigLocalHeader {
		t.Errorf("signature = %08X, want %08X", sig, uint32(sigLocalHeader))
	}
	if gpbf := binary.LittleEndian.Uint16(buf[6:]); gpbf&flagEncrypted == 0 {
		t.Errorf("GPBF = %04X, want encrypted bit set", gpbf)
	}
	if nameLen := binary.LittleEndian.Uint16(buf[26:]); int(nameLen) != len("first.txt") {
		t.Errorf("name length = %d", nameLen)
	}
}

func TestReadLocalHeaderClampsLength(t *testing.T) {
	dir := t.TempDir()
	entries := []fx{{name: "big.bin", method: methodStore, data: bytes.Repeat([]byte("y"), 8192)}}
	path := writeFixture(t, dir, buildZip(t, 0, entries, "", false), 0)

	buf, err := ReadLocalHeader(path, 0, 999999)
	if err != nil {
		t.Fatalf("ReadLocalHeader: %v", err)
	}
	if len(buf) != maxLocalHeaderRead {
		t.Errorf("len = %d, want %d", len(buf), maxLocalHeaderRead)
	}

	if _, err := ReadLocalHeader(path, -1, 128); err == nil {
		t.Error("expected an error for a negative offset")
	}
}

// Reading past EOF returns the bytes that exist rather than failing outright.
func TestReadLocalHeaderPartial(t *testing.T) {
	dir := t.TempDir()
	entries := []fx{{name: "tiny.txt", method: methodStore, data: []byte("ab")}}
	path := writeFixture(t, dir, buildZip(t, 0, entries, "", false), 0)

	buf, err := ReadLocalHeader(path, 0, 4096)
	if err != nil {
		t.Fatalf("ReadLocalHeader: %v", err)
	}
	if len(buf) == 0 || len(buf) == 4096 {
		t.Errorf("len = %d, want a partial read", len(buf))
	}
}

// ---------------------------------------------------------------------------
// fake encryption: evidence, repair, and the repaired archive staying usable
// ---------------------------------------------------------------------------

// fakeFixture 造一个「中央目录说加密、本地头说没加密」的 Store 条目。
// 数据本身是明文，所以清掉加密位之后 archive/zip 能直接读。
func fakeFixture(t *testing.T, name string, payload []byte) []byte {
	t.Helper()
	return buildZip(t, 0, []fx{{
		name:         name,
		gpbf:         flagEncrypted,
		localGPBF:    0,
		hasLocalGPBF: true,
		method:       methodStore,
		crc:          crc32Of(payload),
		csize:        uint32(len(payload)),
		usize:        uint32(len(payload)),
		data:         payload,
	}}, "", false)
}

func crc32Of(b []byte) uint32 {
	return crc32.ChecksumIEEE(b)
}

func TestFakeEncryptionEvidence(t *testing.T) {
	dir := t.TempDir()
	path := writeFixture(t, dir, fakeFixture(t, "notes.txt", []byte("plain text")), 0)

	info, err := Inspect(path)
	if err != nil {
		t.Fatalf("Inspect: %v", err)
	}
	if info.FakeCount != 1 {
		t.Fatalf("FakeCount = %d, want 1", info.FakeCount)
	}
	if !info.Entries[0].IsFakeEncrypted {
		t.Fatal("entry not flagged as fake")
	}
	if !strings.Contains(info.Entries[0].FakeEvidence, "本地文件头") {
		t.Errorf("evidence = %q, want it to mention the local header", info.Entries[0].FakeEvidence)
	}
}

// 真加密的条目必须留下证据，但不能被判成伪加密——否则「修复」会把真包改坏。
func TestRealEncryptionKeepsEvidenceOnly(t *testing.T) {
	dir := t.TempDir()
	entries := []fx{{
		name:         "secret.txt",
		gpbf:         flagEncrypted,
		localGPBF:    flagEncrypted,
		hasLocalGPBF: true,
		method:       methodDeflate,
		data:         []byte("ciphertext"),
	}}
	path := writeFixture(t, dir, buildZip(t, 0, entries, "", false), 0)

	info, err := Inspect(path)
	if err != nil {
		t.Fatalf("Inspect: %v", err)
	}
	if info.Entries[0].IsFakeEncrypted {
		t.Fatal("a genuinely encrypted entry must not be flagged as fake")
	}
	if info.Entries[0].FakeEvidence == "" {
		t.Error("expected evidence text explaining why it was not flagged")
	}
}

// 修复后：新文件能被标准库直接读，内容一致，且原文件一个字节都没变。
func TestFixFakeEncryptionProducesReadableZip(t *testing.T) {
	dir := t.TempDir()
	payload := []byte("hello fake encryption")
	src := writeFixture(t, dir, fakeFixture(t, "notes.txt", payload), 0)
	before, err := os.ReadFile(src)
	if err != nil {
		t.Fatalf("read original: %v", err)
	}

	dst := filepath.Join(dir, "fixed.zip")
	res, err := FixFakeEncryption(src, dst)
	if err != nil {
		t.Fatalf("FixFakeEncryption: %v", err)
	}
	if res.FixedCount != 1 {
		t.Errorf("FixedCount = %d, want 1", res.FixedCount)
	}
	if res.Remaining != 0 {
		t.Errorf("Remaining = %d, want 0", res.Remaining)
	}

	info, err := Inspect(dst)
	if err != nil {
		t.Fatalf("Inspect fixed: %v", err)
	}
	if info.IsFakeEncrypted {
		t.Error("fixed archive is still flagged as fake")
	}
	if info.Entries[0].IsEncrypted {
		t.Error("fixed entry still reports encryption")
	}

	zr, err := zip.OpenReader(dst)
	if err != nil {
		t.Fatalf("the repaired archive must open without a password: %v", err)
	}
	defer zr.Close()
	if len(zr.File) != 1 {
		t.Fatalf("entries = %d, want 1", len(zr.File))
	}
	rc, err := zr.File[0].Open()
	if err != nil {
		t.Fatalf("open entry: %v", err)
	}
	got, err := io.ReadAll(rc)
	rc.Close()
	if err != nil {
		t.Fatalf("read entry: %v", err)
	}
	if !bytes.Equal(got, payload) {
		t.Errorf("content = %q, want %q", got, payload)
	}

	after, err := os.ReadFile(src)
	if err != nil {
		t.Fatalf("read original again: %v", err)
	}
	if !bytes.Equal(before, after) {
		t.Error("the original archive was modified")
	}
}

func TestFixFakeEncryptionRejectsSamePath(t *testing.T) {
	dir := t.TempDir()
	src := writeFixture(t, dir, fakeFixture(t, "notes.txt", []byte("x")), 0)

	if _, err := FixFakeEncryption(src, src); err == nil {
		t.Fatal("expected an error when output == input")
	}
	// 大小写不同但指向同一个文件，也要拦住。
	if _, err := FixFakeEncryption(src, strings.ToUpper(src)); err == nil {
		t.Fatal("expected an error when output resolves to the input file")
	}
}

func TestFixFakeEncryptionNothingToFix(t *testing.T) {
	dir := t.TempDir()
	entries := []fx{{
		name:         "secret.txt",
		gpbf:         flagEncrypted,
		localGPBF:    flagEncrypted,
		hasLocalGPBF: true,
		method:       methodDeflate,
		data:         []byte("ciphertext"),
	}}
	src := writeFixture(t, dir, buildZip(t, 0, entries, "", false), 0)

	_, err := FixFakeEncryption(src, filepath.Join(dir, "out.zip"))
	if !errors.Is(err, ErrNoFakeEncryption) {
		t.Fatalf("err = %v, want ErrNoFakeEncryption", err)
	}
	if _, statErr := os.Stat(filepath.Join(dir, "out.zip")); !os.IsNotExist(statErr) {
		t.Error("no output file should be created when there is nothing to fix")
	}
}

// 混合归档里只修伪加密的那一个，真加密条目的加密位必须原样保留。
func TestFixFakeEncryptionLeavesRealEntriesAlone(t *testing.T) {
	dir := t.TempDir()
	payload := []byte("plain")
	entries := []fx{
		{
			name:         "fake.txt",
			gpbf:         flagEncrypted,
			localGPBF:    0,
			hasLocalGPBF: true,
			method:       methodStore,
			crc:          crc32Of(payload),
			csize:        uint32(len(payload)),
			usize:        uint32(len(payload)),
			data:         payload,
		},
		{
			name:         "real.txt",
			gpbf:         flagEncrypted,
			localGPBF:    flagEncrypted,
			hasLocalGPBF: true,
			method:       methodStore,
			crc:          0x12345678,
			csize:        22,
			usize:        10,
			data:         bytes.Repeat([]byte("z"), 22),
		},
	}
	src := writeFixture(t, dir, buildZip(t, 0, entries, "", false), 0)

	dst := filepath.Join(dir, "mixed-fixed.zip")
	res, err := FixFakeEncryption(src, dst)
	if err != nil {
		t.Fatalf("FixFakeEncryption: %v", err)
	}
	if res.FixedCount != 1 {
		t.Fatalf("FixedCount = %d, want 1", res.FixedCount)
	}

	info, err := Inspect(dst)
	if err != nil {
		t.Fatalf("Inspect fixed: %v", err)
	}
	byName := map[string]Entry{}
	for _, e := range info.Entries {
		byName[e.Name] = e
	}
	if byName["fake.txt"].IsEncrypted {
		t.Error("fake.txt should be readable without a password")
	}
	if !byName["real.txt"].IsEncrypted {
		t.Error("real.txt must stay marked as encrypted")
	}
}
