package zipservice

import (
	"bytes"
	"encoding/binary"
	"errors"
	"hash/crc32"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// ---------------------------------------------------------------------------
// fixture：能控制 modTime / 本地扩展字段 / 数据描述符的构造器
//
// zipservice_test.go 里的 buildZip 把 modTime 固定写成 0、本地扩展字段固定
// 为空，覆盖不到详情视图需要的字段。这里另起一份，避免改动已有测试的语义。
// ---------------------------------------------------------------------------

type dEntry struct {
	name       string
	method     uint16
	gpbf       uint16
	data       []byte
	modTime    uint16
	modDate    uint16
	localExtra []byte
	cdExtra    []byte
	comment    string

	// descriptor 置位时本地头写 0，数据之后追加数据描述符。
	descriptor bool
	descSig    bool // 描述符是否带 0x08074B50 签名
}

// buildDetailZip 按 dEntry 拼一个完整归档（Store 数据，结构完整但不保证可解压）。
func buildDetailZip(entries []dEntry) []byte {
	var buf bytes.Buffer
	offsets := make([]uint32, len(entries))

	for i, e := range entries {
		offsets[i] = uint32(buf.Len())
		name := []byte(e.name)
		crc := crc32.ChecksumIEEE(e.data)
		csize := uint32(len(e.data))
		usize := uint32(len(e.data))

		lfhCRC, lfhCSize, lfhUSize := crc, csize, usize
		gpbf := e.gpbf
		if e.descriptor {
			gpbf |= 0x0008
			lfhCRC, lfhCSize, lfhUSize = 0, 0, 0
		}

		w32(&buf, sigLocalHeader)
		w16(&buf, 20)
		w16(&buf, gpbf)
		w16(&buf, e.method)
		w16(&buf, e.modTime)
		w16(&buf, e.modDate)
		w32(&buf, lfhCRC)
		w32(&buf, lfhCSize)
		w32(&buf, lfhUSize)
		w16(&buf, uint16(len(name)))
		w16(&buf, uint16(len(e.localExtra)))
		buf.Write(name)
		buf.Write(e.localExtra)
		buf.Write(e.data)

		if e.descriptor {
			if e.descSig {
				w32(&buf, descriptorSig)
			}
			w32(&buf, crc)
			w32(&buf, csize)
			w32(&buf, usize)
		}
	}

	cdStart := uint32(buf.Len())
	for i, e := range entries {
		name := []byte(e.name)
		crc := crc32.ChecksumIEEE(e.data)
		csize := uint32(len(e.data))
		usize := uint32(len(e.data))
		gpbf := e.gpbf
		if e.descriptor {
			gpbf |= 0x0008
		}

		w32(&buf, sigCentralHeader)
		w16(&buf, 0x031E)
		w16(&buf, 20)
		w16(&buf, gpbf)
		w16(&buf, e.method)
		w16(&buf, e.modTime)
		w16(&buf, e.modDate)
		w32(&buf, crc)
		w32(&buf, csize)
		w32(&buf, usize)
		w16(&buf, uint16(len(name)))
		w16(&buf, uint16(len(e.cdExtra)))
		w16(&buf, uint16(len(e.comment)))
		w16(&buf, 0) // disk start
		w16(&buf, 0) // internal attrs
		w32(&buf, 0) // external attrs
		w32(&buf, offsets[i])
		buf.Write(name)
		buf.Write(e.cdExtra)
		buf.WriteString(e.comment)
	}
	cdSize := uint32(buf.Len()) - cdStart

	w32(&buf, sigEOCD)
	w16(&buf, 0)
	w16(&buf, 0)
	w16(&buf, uint16(len(entries)))
	w16(&buf, uint16(len(entries)))
	w32(&buf, cdSize)
	w32(&buf, cdStart)
	w16(&buf, 0)
	return buf.Bytes()
}

// emptyZipBytes 是只有 EOCD、零条目的归档。
func emptyZipBytes() []byte {
	var buf bytes.Buffer
	w32(&buf, sigEOCD)
	w16(&buf, 0)
	w16(&buf, 0)
	w16(&buf, 0)
	w16(&buf, 0)
	w32(&buf, 0)
	w32(&buf, 0)
	w16(&buf, 0)
	return buf.Bytes()
}

func writeDetailFixture(t *testing.T, name string, blob []byte) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(path, blob, 0o644); err != nil {
		t.Fatalf("写入 fixture 失败: %v", err)
	}
	return path
}

// extraTLV 拼一个扩展字段记录。
func extraTLV(id uint16, data []byte) []byte {
	var b bytes.Buffer
	w16(&b, id)
	w16(&b, uint16(len(data)))
	b.Write(data)
	return b.Bytes()
}

// 2020-01-02 03:04:06 的 DOS 表示。
const (
	dosDate2020 = uint16((2020-1980)<<9 | 1<<5 | 2) // 2020-01-02
	dosTime0304 = uint16(3<<11 | 4<<5 | 3)          // 03:04:06（秒字段存 3 → 6 秒）
)

// ---------------------------------------------------------------------------
// 纯函数：扩展字段
// ---------------------------------------------------------------------------

func TestParseExtraFields(t *testing.T) {
	zip64 := extraTLV(extraZip64, make([]byte, 8))
	ts := extraTLV(0x5455, []byte{0x03, 0x01, 0x02, 0x03, 0x04})
	unknown := extraTLV(0xABCD, []byte{0x11})

	var blob bytes.Buffer
	blob.Write(zip64)
	blob.Write(ts)
	blob.Write(unknown)

	got := ParseExtraFields(blob.Bytes())
	if len(got) != 3 {
		t.Fatalf("应解析出 3 个扩展字段，实际 %d", len(got))
	}
	if got[0].ID != extraZip64 || got[0].Name != "ZIP64" || got[0].Size != 8 || got[0].Offset != 0 {
		t.Errorf("第 1 个字段不对: %+v", got[0])
	}
	if got[1].ID != 0x5455 || got[1].Name != "扩展时间戳" || got[1].Size != 5 {
		t.Errorf("第 2 个字段不对: %+v", got[1])
	}
	if got[1].Offset != 12 {
		t.Errorf("第 2 个字段偏移应为 12，实际 %d", got[1].Offset)
	}
	if got[2].Name != "0xABCD" {
		t.Errorf("未收录的 id 应显示成 0xABCD，实际 %q", got[2].Name)
	}
}

func TestParseExtraFieldsEdgeCases(t *testing.T) {
	if got := ParseExtraFields(nil); len(got) != 0 {
		t.Errorf("空输入应返回空切片，实际 %d 项", len(got))
	}
	if got := ParseExtraFields([]byte{0x01, 0x00}); len(got) != 0 {
		t.Errorf("不足 4 字节应返回空切片，实际 %d 项", len(got))
	}

	// 声明长度超过剩余字节：应停止，不 panic。
	truncated := []byte{0x01, 0x00, 0xFF, 0x00, 0xAA, 0xBB}
	if got := ParseExtraFields(truncated); len(got) != 0 {
		t.Errorf("截断的 TLV 应被忽略，实际 %d 项", len(got))
	}

	// size 为 0：应终止，不能死循环。
	zero := []byte{0x01, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00}
	got := ParseExtraFields(zero)
	if len(got) != 1 {
		t.Fatalf("size=0 时应只返回 1 项就终止，实际 %d 项", len(got))
	}
	if got[0].Size != 0 {
		t.Errorf("size 应为 0，实际 %d", got[0].Size)
	}
}

func TestExtraFieldName(t *testing.T) {
	cases := map[uint16]string{
		0x0001: "ZIP64",
		0x9901: "AES",
		0x7875: "Unix UID/GID",
		0x1234: "0x1234",
	}
	for id, want := range cases {
		if got := ExtraFieldName(id); got != want {
			t.Errorf("ExtraFieldName(0x%04X) = %q，期望 %q", id, got, want)
		}
	}
}

// ---------------------------------------------------------------------------
// 纯函数：通用位标志
// ---------------------------------------------------------------------------

func TestDescribeGPFlags(t *testing.T) {
	if got := DescribeGPFlags(0); len(got) != 0 {
		t.Errorf("0 应返回空切片，实际 %d 项", len(got))
	}

	got := DescribeGPFlags(0x0009) // 加密 + 数据描述符
	if len(got) != 2 {
		t.Fatalf("0x0009 应展开 2 项，实际 %d", len(got))
	}
	if got[0].Bit != 0x0001 || got[1].Bit != 0x0008 {
		t.Errorf("展开顺序应按位从低到高，实际 %+v", got)
	}

	// 全部位置位时不应漏项，也不应重复。
	all := DescribeGPFlags(0xFFFF)
	if len(all) != len(gpFlagNotes) {
		t.Errorf("0xFFFF 应展开 %d 项，实际 %d", len(gpFlagNotes), len(all))
	}
}

func TestHasDataDescriptor(t *testing.T) {
	if !HasDataDescriptor(0x0008) || !HasDataDescriptor(0x0809) {
		t.Error("bit 3 置位时应返回 true")
	}
	if HasDataDescriptor(0x0001) || HasDataDescriptor(0) {
		t.Error("bit 3 未置位时应返回 false")
	}
}

// ---------------------------------------------------------------------------
// 纯函数：DOS 时间
// ---------------------------------------------------------------------------

func TestFormatDOSDateTime(t *testing.T) {
	got, ok := FormatDOSDateTime(dosDate2020, dosTime0304)
	if !ok {
		t.Fatal("合法日期不应返回 ok=false")
	}
	if got != "2020-01-02 03:04:06" {
		t.Fatalf("格式化结果应为 2020-01-02 03:04:06，实际 %q", got)
	}

	// 边界：日期为 0、月份为 0、月份 13、日 0 都应判为非法。
	for _, c := range []struct {
		name string
		date uint16
		time uint16
	}{
		{"date=0", 0, 0},
		{"month=0", uint16((2020-1980)<<9 | 0<<5 | 1), 0},
		{"month=13", uint16((2020-1980)<<9 | 13<<5 | 1), 0},
		{"day=0", uint16((2020-1980)<<9 | 1<<5 | 0), 0},
	} {
		if _, ok := FormatDOSDateTime(c.date, c.time); ok {
			t.Errorf("%s 应判为非法日期", c.name)
		}
	}

	// 时间越界同样拒绝。
	if _, ok := FormatDOSDateTime(dosDate2020, uint16(25<<11)); ok {
		t.Error("小时 25 应判为非法时间")
	}
}

// ---------------------------------------------------------------------------
// 纯函数：文件头指纹
// ---------------------------------------------------------------------------

func TestMatchKnownHeaders(t *testing.T) {
	sevenZip := []byte{0x50, 0x4b, 0x03, 0x04, 0x14, 0x00, 0x01, 0x00, 0x08, 0x00}
	hits := MatchKnownHeaders(sevenZip)
	if len(hits) != 1 {
		t.Fatalf("应命中 1 条指纹，实际 %d", len(hits))
	}
	if len(hits[0].Vendors) != 2 {
		t.Errorf("360压缩 / 7-Zip 这条应有 2 个厂商，实际 %v", hits[0].Vendors)
	}

	// Bandizip 与 WinRAR 共用的那条：应命中且给出两个厂商。
	shared := []byte{0x50, 0x4b, 0x03, 0x04, 0x14, 0x00, 0x09, 0x00, 0x08, 0x00}
	hits = MatchKnownHeaders(shared)
	if len(hits) != 1 || len(hits[0].Vendors) != 2 {
		t.Fatalf("0x0009 应命中 Bandizip / WinRAR 共用项，实际 %+v", hits)
	}

	// 不认识的头部。
	if hits := MatchKnownHeaders([]byte{0x50, 0x4b, 0x03, 0x04, 0x0A, 0x00, 0x00, 0x00, 0x00, 0x00}); len(hits) != 0 {
		t.Errorf("未知头部不应命中，实际 %+v", hits)
	}

	// 字节数不足：不能 panic，也不能命中。
	if hits := MatchKnownHeaders([]byte{0x50, 0x4b}); len(hits) != 0 {
		t.Errorf("不足 10 字节不应命中，实际 %+v", hits)
	}
}

// ---------------------------------------------------------------------------
// 本地文件头
// ---------------------------------------------------------------------------

func TestReadLocalHeaderInfo(t *testing.T) {
	localExtra := extraTLV(0x7875, []byte{0x01, 0x04, 0xE8, 0x03, 0x00, 0x00, 0x04, 0xE8, 0x03, 0x00, 0x00})
	blob := buildDetailZip([]dEntry{{
		name:       "readme.txt",
		method:     methodStore,
		data:       []byte("hello"),
		modTime:    dosTime0304,
		modDate:    dosDate2020,
		localExtra: localExtra,
	}})
	path := writeDetailFixture(t, "lfh.zip", blob)

	lfh, err := ReadLocalHeaderInfo(path, 0)
	if err != nil {
		t.Fatalf("ReadLocalHeaderInfo: %v", err)
	}
	if lfh.Offset != 0 {
		t.Errorf("Offset 应为 0，实际 %d", lfh.Offset)
	}
	if lfh.Version != 20 {
		t.Errorf("Version 应为 20，实际 %d", lfh.Version)
	}
	if lfh.Method != methodStore || lfh.MethodName != "Store" {
		t.Errorf("方法字段不对: %d / %q", lfh.Method, lfh.MethodName)
	}
	if lfh.Modified != "2020-01-02 03:04:06" {
		t.Errorf("Modified 应为 2020-01-02 03:04:06，实际 %q", lfh.Modified)
	}
	if lfh.CRC32 != crc32.ChecksumIEEE([]byte("hello")) {
		t.Errorf("CRC32 不对: 0x%08X", lfh.CRC32)
	}
	if lfh.CompressedSize != 5 || lfh.UncompressedSize != 5 {
		t.Errorf("大小不对: %d / %d", lfh.CompressedSize, lfh.UncompressedSize)
	}
	if lfh.Name != "readme.txt" || lfh.NameEncoding != "ascii" {
		t.Errorf("文件名不对: %q / %q", lfh.Name, lfh.NameEncoding)
	}
	if len(lfh.Extra) != 1 || lfh.Extra[0].ID != 0x7875 {
		t.Errorf("本地扩展字段应为 1 个 0x7875，实际 %+v", lfh.Extra)
	}
	if lfh.TotalLen != localHeaderSize+len("readme.txt")+len(localExtra) {
		t.Errorf("TotalLen 不对: %d", lfh.TotalLen)
	}
	if len(lfh.Flags) != 0 {
		t.Errorf("GPBF 为 0 时不应有标志说明，实际 %+v", lfh.Flags)
	}
}

func TestReadLocalHeaderInfoErrors(t *testing.T) {
	blob := buildDetailZip([]dEntry{{name: "a.txt", method: methodStore, data: []byte("x")}})
	path := writeDetailFixture(t, "lfh_err.zip", blob)

	// 偏移不在本地头签名上。
	if _, err := ReadLocalHeaderInfo(path, 5); !errors.Is(err, ErrCorrupt) {
		t.Errorf("偏移 5 应报 ErrCorrupt，实际 %v", err)
	}
	// 偏移超出文件。
	if _, err := ReadLocalHeaderInfo(path, 1<<20); !errors.Is(err, ErrCorrupt) {
		t.Errorf("越界偏移应报 ErrCorrupt，实际 %v", err)
	}
	// 空路径。
	if _, err := ReadLocalHeaderInfo("", 0); err == nil {
		t.Error("空路径应报错")
	}
	// 文件不存在。
	if _, err := ReadLocalHeaderInfo(filepath.Join(t.TempDir(), "nope.zip"), 0); err == nil {
		t.Error("不存在的文件应报错")
	}
}

// ---------------------------------------------------------------------------
// 数据描述符
// ---------------------------------------------------------------------------

func TestReadDataDescriptorWithSignature(t *testing.T) {
	blob := buildDetailZip([]dEntry{{
		name:       "desc.txt",
		method:     methodStore,
		data:       []byte("payload"),
		descriptor: true,
		descSig:    true,
	}})
	path := writeDetailFixture(t, "desc.zip", blob)

	entry, err := InspectEntryForTest(path, "desc.txt")
	if err != nil {
		t.Fatal(err)
	}
	if !HasDataDescriptor(entry.GPFlags) {
		t.Fatal("样本应置位 bit 3")
	}

	desc, err := ReadDataDescriptor(path, entry)
	if err != nil {
		t.Fatalf("ReadDataDescriptor: %v", err)
	}
	if desc == nil {
		t.Fatal("应找到数据描述符")
	}
	if !desc.HasSignature {
		t.Error("样本带签名，HasSignature 应为 true")
	}
	if desc.Zip64 {
		t.Error("32 位描述符不应标成 zip64")
	}
	if !desc.MatchesCentral {
		t.Error("描述符应与中央目录一致")
	}
	if desc.UncompressedSize != uint64(len("payload")) {
		t.Errorf("原始大小应为 %d，实际 %d", len("payload"), desc.UncompressedSize)
	}
}

func TestReadDataDescriptorWithoutSignature(t *testing.T) {
	blob := buildDetailZip([]dEntry{{
		name:       "nodesc.txt",
		method:     methodStore,
		data:       []byte("payload"),
		descriptor: true,
		descSig:    false,
	}})
	path := writeDetailFixture(t, "nodesc.zip", blob)

	entry, err := InspectEntryForTest(path, "nodesc.txt")
	if err != nil {
		t.Fatal(err)
	}
	desc, err := ReadDataDescriptor(path, entry)
	if err != nil {
		t.Fatalf("ReadDataDescriptor: %v", err)
	}
	if desc == nil {
		t.Fatal("无签名的描述符也应能识别")
	}
	if desc.HasSignature {
		t.Error("样本不带签名，HasSignature 应为 false")
	}
}

func TestReadDataDescriptorAbsent(t *testing.T) {
	blob := buildDetailZip([]dEntry{{name: "plain.txt", method: methodStore, data: []byte("x")}})
	path := writeDetailFixture(t, "plain.zip", blob)

	entry, err := InspectEntryForTest(path, "plain.txt")
	if err != nil {
		t.Fatal(err)
	}
	// bit 3 未置位 → 明确返回 nil，不是错误。
	desc, err := ReadDataDescriptor(path, entry)
	if err != nil {
		t.Fatalf("不应返回错误: %v", err)
	}
	if desc != nil {
		t.Errorf("没有数据描述符时应返回 nil，实际 %+v", desc)
	}
}

func TestReadDataDescriptorMismatch(t *testing.T) {
	// bit 3 置位，但数据之后没有描述符（有些实现回填本地头后省略它）。
	blob := buildDetailZip([]dEntry{{
		name:   "no-desc.txt",
		method: methodStore,
		data:   []byte("payload"),
		gpbf:   0x0008,
	}})
	path := writeDetailFixture(t, "no-desc.zip", blob)

	entry, err := InspectEntryForTest(path, "no-desc.txt")
	if err != nil {
		t.Fatal(err)
	}
	desc, err := ReadDataDescriptor(path, entry)
	if err != nil {
		t.Fatalf("不应返回错误: %v", err)
	}
	if desc != nil {
		t.Errorf("对不上号的字节不应被当成描述符，实际 %+v", desc)
	}
}

// InspectEntryForTest 是测试辅助：按名字从中央目录取一个 Entry。
func InspectEntryForTest(path, name string) (Entry, error) {
	info, err := Inspect(path)
	if err != nil {
		return Entry{}, err
	}
	for _, e := range info.Entries {
		if e.Name == name {
			return e, nil
		}
	}
	return Entry{}, errors.New("测试样本里没有条目 " + name)
}

// ---------------------------------------------------------------------------
// InspectDetailed
// ---------------------------------------------------------------------------

func TestInspectDetailedBasic(t *testing.T) {
	cdExtra := extraTLV(0x5455, []byte{0x03, 0x01, 0x02, 0x03, 0x04})
	blob := buildDetailZip([]dEntry{
		{
			name:    "a.txt",
			method:  methodStore,
			data:    []byte("alpha"),
			modTime: dosTime0304,
			modDate: dosDate2020,
			cdExtra: cdExtra,
		},
		{
			name:   "中文.txt",
			method: methodDeflate,
			data:   []byte("bravo"),
			gpbf:   0x0800, // UTF-8 名
		},
	})
	path := writeDetailFixture(t, "basic.zip", blob)

	d, err := InspectDetailed(path)
	if err != nil {
		t.Fatalf("InspectDetailed: %v", err)
	}
	if d.EntryCount != 2 || len(d.Entries) != 2 {
		t.Fatalf("应有 2 个条目，实际 count=%d entries=%d", d.EntryCount, len(d.Entries))
	}
	if d.Format != "ZIP" || d.Zip64 {
		t.Errorf("格式判定不对: %q zip64=%v", d.Format, d.Zip64)
	}
	if d.CDRecovered {
		t.Error("正常归档不应标记 CDRecovered")
	}
	if len(d.Warnings) != 0 {
		t.Errorf("正常归档不应有警告，实际 %v", d.Warnings)
	}

	first := d.Entries[0]
	if first.Name != "a.txt" {
		t.Errorf("首个条目名不对: %q", first.Name)
	}
	if first.Modified != "2020-01-02 03:04:06" {
		t.Errorf("Modified 不对: %q", first.Modified)
	}
	if len(first.CentralExtra) != 1 || first.CentralExtra[0].Name != "扩展时间戳" {
		t.Errorf("中央目录扩展字段不对: %+v", first.CentralExtra)
	}
	if first.Local == nil {
		t.Fatalf("应能读到本地文件头，错误: %s", first.LocalErr)
	}
	if !first.Consistent {
		t.Error("正常条目应判为本地头与中央目录一致")
	}
	if first.Descriptor != nil {
		t.Error("没有 bit 3 时不应有数据描述符")
	}
	if first.CentralOffset <= 0 {
		t.Errorf("CentralOffset 应为正数，实际 %d", first.CentralOffset)
	}
	if first.CentralRecordLen != centralHeaderSize+len("a.txt")+len(cdExtra) {
		t.Errorf("CentralRecordLen 不对: %d", first.CentralRecordLen)
	}

	second := d.Entries[1]
	if second.NameEncoding != "utf-8" {
		t.Errorf("置位 bit 11 时应报 utf-8，实际 %q", second.NameEncoding)
	}
	if second.Compression != "Deflate" {
		t.Errorf("压缩方法不对: %q", second.Compression)
	}
	if len(second.Flags) != 1 || second.Flags[0].Bit != 0x0800 {
		t.Errorf("标志说明不对: %+v", second.Flags)
	}
}

func TestInspectDetailedDataDescriptor(t *testing.T) {
	blob := buildDetailZip([]dEntry{{
		name:       "d.txt",
		method:     methodStore,
		data:       []byte("with descriptor"),
		descriptor: true,
		descSig:    true,
	}})
	path := writeDetailFixture(t, "dd.zip", blob)

	d, err := InspectDetailed(path)
	if err != nil {
		t.Fatal(err)
	}
	e := d.Entries[0]
	if e.Local == nil {
		t.Fatalf("应能读到本地文件头: %s", e.LocalErr)
	}
	// 本地头里的 CRC 是 0，中央目录里是真实值 —— 这正是 bit 3 的特征。
	if e.Local.CRC32 != 0 {
		t.Errorf("bit 3 置位时本地头 CRC 应为 0，实际 0x%08X", e.Local.CRC32)
	}
	if e.CRC32 == 0 {
		t.Error("中央目录 CRC 不应为 0")
	}
	if e.Descriptor == nil {
		t.Fatal("应解析出数据描述符")
	}
	if e.Descriptor.CRC32 != e.CRC32 {
		t.Errorf("描述符 CRC 0x%08X 应等于中央目录 0x%08X", e.Descriptor.CRC32, e.CRC32)
	}
	if e.Consistent {
		t.Error("bit 3 条目的本地头与中央目录字段不同，Consistent 应为 false")
	}
}

func TestInspectDetailedEmptyZip(t *testing.T) {
	path := writeDetailFixture(t, "empty.zip", emptyZipBytes())

	d, err := InspectDetailed(path)
	if err != nil {
		t.Fatalf("空归档不应报错: %v", err)
	}
	if d.EntryCount != 0 || len(d.Entries) != 0 {
		t.Errorf("空归档不应有条目，实际 %d / %d", d.EntryCount, len(d.Entries))
	}
	if d.CDSize != 0 {
		t.Errorf("空归档中央目录长度应为 0，实际 %d", d.CDSize)
	}
	if len(d.Warnings) != 0 {
		t.Errorf("正常的空归档不应有警告，实际 %v", d.Warnings)
	}
}

func TestInspectDetailedTruncated(t *testing.T) {
	blob := buildDetailZip([]dEntry{{name: "a.txt", method: methodStore, data: []byte("hello world")}})
	// 砍掉 EOCD，只剩前面一段。
	path := writeDetailFixture(t, "cut.zip", blob[:len(blob)-10])

	if _, err := InspectDetailed(path); !errors.Is(err, ErrNotZip) {
		t.Fatalf("截断文件应报 ErrNotZip，实际 %v", err)
	}
}

func TestInspectDetailedTooSmall(t *testing.T) {
	path := writeDetailFixture(t, "tiny.zip", []byte("PK"))
	if _, err := InspectDetailed(path); !errors.Is(err, ErrNotZip) {
		t.Fatalf("不足 22 字节应报 ErrNotZip，实际 %v", err)
	}
}

func TestInspectDetailedMissingFile(t *testing.T) {
	if _, err := InspectDetailed(filepath.Join(t.TempDir(), "nope.zip")); err == nil {
		t.Fatal("不存在的文件应报错")
	}
}

func TestInspectDetailedDirectory(t *testing.T) {
	if _, err := InspectDetailed(t.TempDir()); err == nil {
		t.Fatal("目录应报错")
	}
}

func TestInspectDetailedZip64(t *testing.T) {
	// 复用 zipservice_test.go 的 ZIP64 构造器。
	blob := buildZip(t, 0, []fx{{
		name:     "big.bin",
		gpbf:     0,
		method:   methodStore,
		crc:      crc32Of([]byte("zip64 data")),
		data:     []byte("zip64 data"),
		zip64:    true,
		z64csize: uint64(len("zip64 data")),
		z64usize: uint64(len("zip64 data")),
	}}, "", true)
	path := writeDetailFixture(t, "z64.zip", blob)

	d, err := InspectDetailed(path)
	if err != nil {
		t.Fatalf("InspectDetailed: %v", err)
	}
	if !d.Zip64 {
		t.Error("应识别为 ZIP64")
	}
	if d.Format != "ZIP64" {
		t.Errorf("Format 应为 ZIP64，实际 %q", d.Format)
	}
	if len(d.Entries) != 1 {
		t.Fatalf("应有 1 个条目，实际 %d", len(d.Entries))
	}
	e := d.Entries[0]
	// ZIP64 扩展字段应出现在中央目录扩展列表里。
	found := false
	for _, ex := range e.CentralExtra {
		if ex.ID == extraZip64 {
			found = true
		}
	}
	if !found {
		t.Errorf("中央目录扩展字段里应有 ZIP64 记录，实际 %+v", e.CentralExtra)
	}
	if e.UncompressedSize != uint64(len("zip64 data")) {
		t.Errorf("ZIP64 提升后的原始大小不对: %d", e.UncompressedSize)
	}
}

func TestInspectDetailedFakeEncryption(t *testing.T) {
	// fakeFixture 造的是"中央目录说加密、本地头说没加密"的伪加密条目。
	blob := fakeFixture(t, "secret.txt", []byte("not really encrypted"))
	path := writeDetailFixture(t, "fake.zip", blob)

	d, err := InspectDetailed(path)
	if err != nil {
		t.Fatalf("InspectDetailed: %v", err)
	}
	if len(d.Entries) != 1 {
		t.Fatalf("应有 1 个条目，实际 %d", len(d.Entries))
	}
	e := d.Entries[0]
	if !e.IsFakeEncrypted {
		t.Error("应沿用 Inspect 的伪加密判定")
	}
	if e.Local == nil {
		t.Fatalf("应能读到本地文件头: %s", e.LocalErr)
	}
	if e.Consistent {
		t.Error("伪加密条目的本地头与中央目录必然不一致")
	}
	// 中央目录说加密，本地头说没有。
	if e.GPFlags&flagEncrypted == 0 {
		t.Error("中央目录应标记为加密")
	}
	if e.Local.GPFlags&flagEncrypted != 0 {
		t.Error("本地头应标记为未加密")
	}
}

func TestInspectDetailedGBKName(t *testing.T) {
	// 用 GBK 编码的中文文件名，且不置位 bit 11。
	gbkName := []byte{0xD6, 0xD0, 0xCE, 0xC4} // “中文”
	blob := buildDetailZip([]dEntry{{name: string(gbkName), method: methodStore, data: []byte("x")}})
	path := writeDetailFixture(t, "gbk.zip", blob)

	d, err := InspectDetailed(path)
	if err != nil {
		t.Fatal(err)
	}
	e := d.Entries[0]
	if e.Name != "中文" {
		t.Errorf("GBK 文件名应解码成“中文”，实际 %q", e.Name)
	}
	if e.NameEncoding != "gbk" {
		t.Errorf("编码应报 gbk，实际 %q", e.NameEncoding)
	}
}

func TestInspectDetailedCP437Name(t *testing.T) {
	// 0x82 在 CP437 里是 é；GBK 里 0x82 后面跟 '.' 不是合法尾字节，解码会失败。
	name := string([]byte{'c', 'a', 'f', 0x82, '.', 't', 'x', 't'})
	blob := buildDetailZip([]dEntry{{name: name, method: methodStore, data: []byte("x")}})
	path := writeDetailFixture(t, "cp437.zip", blob)

	d, err := InspectDetailed(path)
	if err != nil {
		t.Fatal(err)
	}
	e := d.Entries[0]
	if e.NameEncoding != "cp437" {
		t.Fatalf("编码应回退到 cp437，实际 %q（名字 %q）", e.NameEncoding, e.Name)
	}
	if e.Name != "café.txt" {
		t.Errorf("CP437 解码应为 café.txt，实际 %q", e.Name)
	}
}

func TestInspectDetailedComment(t *testing.T) {
	var blob bytes.Buffer
	body := buildDetailZip([]dEntry{{name: "a.txt", method: methodStore, data: []byte("x")}})
	// 去掉原 EOCD（22 字节），自己写一个带注释的。
	blob.Write(body[:len(body)-22])
	w32(&blob, sigEOCD)
	w16(&blob, 0)
	w16(&blob, 0)
	w16(&blob, 1)
	w16(&blob, 1)
	w32(&blob, uint32(len(body)-22-30-len("a.txt")-4))
	w32(&blob, uint32(30+len("a.txt")+4))
	comment := "built by zipkit"
	w16(&blob, uint16(len(comment)))
	blob.WriteString(comment)

	path := writeDetailFixture(t, "comment.zip", blob.Bytes())
	d, err := InspectDetailed(path)
	if err != nil {
		t.Fatalf("InspectDetailed: %v", err)
	}
	if d.Comment != comment {
		t.Errorf("注释应为 %q，实际 %q", comment, d.Comment)
	}
}

// ---------------------------------------------------------------------------
// ReadEntryDetail
// ---------------------------------------------------------------------------

func TestReadEntryDetail(t *testing.T) {
	blob := buildDetailZip([]dEntry{
		{name: "one.txt", method: methodStore, data: []byte("1")},
		{name: "two.txt", method: methodStore, data: []byte("22")},
	})
	path := writeDetailFixture(t, "two.zip", blob)

	d, err := ReadEntryDetail(path, "two.txt")
	if err != nil {
		t.Fatalf("ReadEntryDetail: %v", err)
	}
	if d.Name != "two.txt" {
		t.Errorf("应返回 two.txt，实际 %q", d.Name)
	}
	if d.UncompressedSize != 2 {
		t.Errorf("大小应为 2，实际 %d", d.UncompressedSize)
	}
	if d.Local == nil {
		t.Fatalf("应读到本地文件头: %s", d.LocalErr)
	}
}

func TestReadEntryDetailNotFound(t *testing.T) {
	blob := buildDetailZip([]dEntry{{name: "one.txt", method: methodStore, data: []byte("1")}})
	path := writeDetailFixture(t, "one.zip", blob)

	if _, err := ReadEntryDetail(path, "missing.txt"); !errors.Is(err, ErrEntryNotFound) {
		t.Fatalf("应报 ErrEntryNotFound，实际 %v", err)
	}
}

// ---------------------------------------------------------------------------
// 与 Inspect 的一致性
// ---------------------------------------------------------------------------

func TestDetailedAgreesWithInspect(t *testing.T) {
	blob := buildDetailZip([]dEntry{
		{name: "a.txt", method: methodStore, data: []byte("alpha")},
		{name: "b.txt", method: methodDeflate, data: []byte("bravo")},
		{name: "c.txt", method: methodStore, data: []byte("charlie"), gpbf: 0x0001},
	})
	path := writeDetailFixture(t, "agree.zip", blob)

	info, err := Inspect(path)
	if err != nil {
		t.Fatal(err)
	}
	d, err := InspectDetailed(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(info.Entries) != len(d.Entries) {
		t.Fatalf("条目数不一致: Inspect=%d Detailed=%d", len(info.Entries), len(d.Entries))
	}
	for i := range info.Entries {
		a, b := info.Entries[i], d.Entries[i]
		if a.Name != b.Name || a.Method != b.Method || a.CRC32 != b.CRC32 ||
			a.CompressedSize != b.CompressedSize || a.UncompressedSize != b.UncompressedSize ||
			a.LocalHeaderOffset != b.LocalHeaderOffset || a.EncryptionType != b.EncryptionType ||
			a.IsFakeEncrypted != b.IsFakeEncrypted || a.Compression != b.Compression {
			t.Errorf("第 %d 个条目两个接口不一致:\n Inspect=%+v\nDetailed=%+v", i, a, b)
		}
	}
}

// TestDecodeNameEncodingLabels 覆盖文件名编码判定表的每一档。
func TestDecodeNameEncodingLabels(t *testing.T) {
	cases := []struct {
		name     string
		bytes    []byte
		utf8Flag bool
		wantName string
		wantEnc  string
	}{
		{"空", nil, false, "", "empty"},
		{"ASCII", []byte("hello.txt"), false, "hello.txt", "ascii"},
		{"UTF-8 无标志", []byte("中文.txt"), false, "中文.txt", "utf-8"},
		{"UTF-8 带标志", []byte("中文.txt"), true, "中文.txt", "utf-8"},
		{"GBK", []byte{0xD6, 0xD0, 0xCE, 0xC4}, false, "中文", "gbk"},
		{"CP437", []byte{'c', 0x82}, false, "cé", "cp437"},
	}
	for _, c := range cases {
		name, enc := decodeNameWithEncoding(c.bytes, c.utf8Flag)
		if name != c.wantName || enc != c.wantEnc {
			t.Errorf("%s: 得到 (%q, %q)，期望 (%q, %q)", c.name, name, enc, c.wantName, c.wantEnc)
		}
	}
}

// TestDecodeNameKeepsInspectBehaviour 确认 Inspect 用的 decodeName 与新函数一致。
func TestDecodeNameKeepsInspectBehaviour(t *testing.T) {
	for _, b := range [][]byte{
		[]byte("plain.txt"),
		[]byte("中文.txt"),
		{0xD6, 0xD0, 0xCE, 0xC4},
		{'c', 0x82},
	} {
		want, _ := decodeNameWithEncoding(b, false)
		if got := decodeName(b, false); got != want {
			t.Errorf("decodeName(%q) = %q，与 decodeNameWithEncoding 的 %q 不一致", b, got, want)
		}
	}
}

// TestCompressionNames 确认扩展后的方法表覆盖了 ziptool 的映射，且
// Store / Deflate 这两个被批量逻辑依赖的名字没有变。
func TestCompressionNames(t *testing.T) {
	cases := map[uint16]string{
		0:  "Store",
		1:  "Shrink",
		6:  "Implode",
		8:  "Deflate",
		9:  "Deflate64",
		12: "BZip2",
		14: "LZMA",
		93: "Zstandard",
		95: "XZ",
		96: "JPEG",
		97: "WavPack",
		98: "PPMd",
		99: "AES",
		77: "Unknown",
	}
	for code, want := range cases {
		if got := compressionName(code); got != want {
			t.Errorf("compressionName(%d) = %q，期望 %q", code, got, want)
		}
	}
}

// TestInspectDetailedHeaderMatchSkipsDirectories 确认指纹比对跳过目录条目。
//
// 目录条目的本地头通常由另一段代码写出（版本号、GPBF 都不同），拿它去比对
// 软件指纹会一条都命不中。真实案例：微信账单 ZIP 的第一个条目就是目录。
func TestInspectDetailedHeaderMatchSkipsDirectories(t *testing.T) {
	blob := buildDetailZip([]dEntry{
		{name: "dir/", method: methodStore, gpbf: 0x0800},
		{name: "dir/file.txt", method: methodDeflate, gpbf: 0x0001},
	})
	path := writeDetailFixture(t, "withdir.zip", blob)

	d, err := InspectDetailed(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(d.HeaderMatches) == 0 {
		t.Fatal("应命中 7-Zip 指纹（第一个真实文件条目），说明没有跳过目录条目")
	}
	if d.HeaderMatches[0].Label != "360压缩 / 7-Zip" {
		t.Errorf("指纹应为 360压缩 / 7-Zip，实际 %q", d.HeaderMatches[0].Label)
	}
}

func TestIsDirectoryName(t *testing.T) {
	cases := map[string]bool{
		"dir/":         true,
		`dir\`:         true,
		"a/b/":         true,
		"file.txt":     false,
		"a/b/file.txt": false,
		"":             false,
	}
	for name, want := range cases {
		if got := isDirectoryName(name); got != want {
			t.Errorf("isDirectoryName(%q) = %v，期望 %v", name, got, want)
		}
	}
}

// TestInspectDetailedSuffixDataIsIgnored 确认归档后面追加的垃圾不会影响解析。
func TestInspectDetailedSuffixDataIsIgnored(t *testing.T) {
	blob := buildDetailZip([]dEntry{{name: "a.txt", method: methodStore, data: []byte("x")}})
	blob = append(blob, bytes.Repeat([]byte{0x00}, 128)...)
	path := writeDetailFixture(t, "suffix.zip", blob)

	d, err := InspectDetailed(path)
	if err != nil {
		t.Fatalf("尾部追加数据不应导致失败: %v", err)
	}
	if len(d.Entries) != 1 {
		t.Fatalf("应仍解析出 1 个条目，实际 %d", len(d.Entries))
	}
	if !strings.HasPrefix(d.Entries[0].Name, "a.txt") {
		t.Errorf("条目名不对: %q", d.Entries[0].Name)
	}
}

// TestInspectDetailedCorruptCentralDirectory 覆盖"中央目录签名坏掉"的路径。
func TestInspectDetailedCorruptCentralDirectory(t *testing.T) {
	blob := buildDetailZip([]dEntry{{name: "a.txt", method: methodStore, data: []byte("x")}})
	// 找到中央目录签名并改坏第一个字节。
	idx := bytes.Index(blob, []byte{0x50, 0x4b, 0x01, 0x02})
	if idx < 0 {
		t.Fatal("样本里找不到中央目录签名")
	}
	blob[idx] = 0x00
	path := writeDetailFixture(t, "badcd.zip", blob)

	d, err := InspectDetailed(path)
	if err != nil {
		t.Fatalf("不应直接失败，应降级并给警告: %v", err)
	}
	if len(d.Entries) != 0 {
		t.Errorf("签名坏掉时解析不到条目，实际 %d", len(d.Entries))
	}
	if len(d.Warnings) == 0 {
		t.Error("签名坏掉时必须有警告")
	}
}

// TestEOCDRecordFields 确认新增的 EOCD 字段被正确填充。
func TestEOCDRecordFields(t *testing.T) {
	blob := buildDetailZip([]dEntry{{name: "a.txt", method: methodStore, data: []byte("x")}})
	path := writeDetailFixture(t, "eocd.zip", blob)

	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	st, _ := f.Stat()

	rec, err := findEOCD(f, st.Size())
	if err != nil {
		t.Fatal(err)
	}
	if rec.eocdAbs != st.Size()-eocdSize {
		t.Errorf("eocdAbs 应为 %d，实际 %d", st.Size()-eocdSize, rec.eocdAbs)
	}
	if rec.comment != "" {
		t.Errorf("无注释时应为空串，实际 %q", rec.comment)
	}
	if rec.diskNumber != 0 || rec.cdDisk != 0 {
		t.Errorf("单卷归档的卷号应为 0，实际 %d / %d", rec.diskNumber, rec.cdDisk)
	}
	if int(rec.entriesDisk) != int(rec.entries) {
		t.Errorf("本卷条目数与总条目数应相等: %d / %d", rec.entriesDisk, rec.entries)
	}
}

// 确保 binary 包被使用（buildDetailZip 里通过 w16/w32 间接用到，这里显式引用一次）。
var _ = binary.LittleEndian
