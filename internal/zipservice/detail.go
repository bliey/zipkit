package zipservice

// 本文件实现「单个条目的完整结构分析」：把中央目录字段、本地文件头字段、
// 扩展字段、数据描述符、通用位标志说明、DOS 时间全部展开成结构体。
//
// 这些能力合并自 ziptool（一个纯前端 ZIP 检测器）的解析核心，按 zipkit 的
// 风格重写为 Go 结构体接口。
//
// 与 Inspect 的关系：Inspect 只回答"这个包里有什么、要不要密码"，
// 返回的 Entry 刻意保持精简；InspectDetailed 回答"这个条目的字节长什么样"，
// 是单文件详情视图的数据源。两者共用同一套 EOCD / 中央目录解析，Inspect
// 的签名与行为完全不变。

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
)

// 结构常量。
const (
	// descriptorSig 是数据描述符的可选签名（PK\x07\x08）。
	descriptorSig = 0x08074b50
	// maxDescriptorProbe 是数据描述符探测窗口：签名 + CRC + 两个 8 字节长度。
	maxDescriptorProbe = 24
	// maxHeaderMatchBytes 是文件头指纹比对的字节数。
	maxHeaderMatchBytes = 10
)

// ---------------------------------------------------------------------------
// 扩展字段
// ---------------------------------------------------------------------------

// ExtraField 是扩展字段里的一个 TLV 记录。
//
// Offset 是记录头部相对于整个扩展字段起点的偏移，便于在十六进制视图里定位。
// Data 是记录体（不含 4 字节的 id + size 头）。
type ExtraField struct {
	ID     uint16
	Name   string
	Size   int
	Offset int
	Data   []byte
}

// extraFieldNames 是常见扩展字段 id 的可读名。
//
// 表里的名字来自 PKWARE APPNOTE 与 Info-ZIP / WinZip 的实际实现；
// 未收录的 id 一律显示成 "0xXXXX"，不做猜测。
var extraFieldNames = map[uint16]string{
	0x0001: "ZIP64",
	0x0007: "AV Info",
	0x0008: "扩展语言编码",
	0x0009: "OS/2",
	0x000A: "NTFS 时间戳",
	0x000C: "Unix 新",
	0x000D: "Unix 旧",
	0x000E: "Pkware Unix",
	0x0014: "PKCS#7 签名",
	0x0015: "补丁数据",
	0x0016: "强加密头",
	0x0017: "强加密记录",
	0x0018: "记录管理",
	0x0019: "PKCS#7 信封",
	0x0020: "旧 Unix",
	0x0021: "Polaris 端口",
	0x0022: "Polaris 文件类型",
	0x0023: "Polaris 标记",
	0x0065: "AES 证书",
	0x0066: "AES 中心目录",
	0x4690: "POSZIP 4690",
	0x07C8: "macOS 元数据",
	0x2605: "ZipIt Macintosh",
	0x2705: "ZipIt Macintosh 2",
	0x2805: "ZipIt Macintosh 3",
	0x334D: "Info-ZIP Macintosh",
	0x4341: "Acorn/SparkFS",
	0x4453: "Windows NT 安全",
	0x4704: "NEC VMS",
	0x470F: "MVS",
	0x4B46: "FWKCS MD5",
	0x4C41: "OS/2 访问控制",
	0x4D49: "VMS 属性",
	0x4D63: "Mac 符号链接",
	0x5356: "Simple Unix",
	0x5455: "扩展时间戳",
	0x554E: "Xceed Unicode",
	0x5855: "Info-ZIP Unix",
	0x6375: "Unicode 注释",
	0x6542: "BeOS",
	0x6854: "theos",
	0x7075: "Unicode 路径",
	0x756E: "ASi Unix",
	0x7855: "Info-ZIP Unix 新",
	0x7875: "Unix UID/GID",
	0x9901: "AES",
	0xA11E: "Google Play 签名",
	0xA220: "微软通用标志",
}

// ExtraFieldName 返回扩展字段 id 的可读名；未收录时返回 "0xXXXX"。
func ExtraFieldName(id uint16) string {
	if name, ok := extraFieldNames[id]; ok {
		return name
	}
	return fmt.Sprintf("0x%04X", id)
}

// ParseExtraFields 把扩展字段拆成 TLV 列表。
//
// 遇到长度越界的记录就停止，并把已解析的部分返回——损坏的扩展字段不应该
// 让整个条目变得不可读。size 为 0 的记录同样终止，否则会死循环。
func ParseExtraFields(extra []byte) []ExtraField {
	out := make([]ExtraField, 0, 4)
	for off := 0; off+4 <= len(extra); {
		id := binary.LittleEndian.Uint16(extra[off:])
		size := int(binary.LittleEndian.Uint16(extra[off+2:]))
		if size > len(extra)-off-4 {
			break // 截断的 TLV，忽略剩余部分
		}
		data := make([]byte, size)
		copy(data, extra[off+4:off+4+size])
		out = append(out, ExtraField{
			ID:     id,
			Name:   ExtraFieldName(id),
			Size:   size,
			Offset: off,
			Data:   data,
		})
		if size == 0 {
			break // 防止损坏字段导致死循环
		}
		off += 4 + size
	}
	return out
}

// ---------------------------------------------------------------------------
// 通用位标志
// ---------------------------------------------------------------------------

// FlagNote 是通用位标志里的一位及其含义。
type FlagNote struct {
	Bit  uint16 // 位掩码，例如 0x0008
	Name string // 中文含义
}

// gpFlagNotes 是通用位标志的逐位说明，按 PKWARE APPNOTE 4.4.4 排列。
var gpFlagNotes = []FlagNote{
	{0x0001, "加密"},
	{0x0002, "压缩选项（方法相关）"},
	{0x0004, "压缩选项（方法相关）"},
	{0x0008, "使用数据描述符（CRC / 大小写在数据之后）"},
	{0x0010, "增强压缩（方法相关）"},
	{0x0020, "补丁数据"},
	{0x0040, "强加密"},
	{0x0800, "文件名与注释为 UTF-8"},
	{0x2000, "掩码头（中央目录加密）"},
}

// DescribeGPFlags 把通用位标志展开成人类可读的列表。未置位时返回空切片。
func DescribeGPFlags(flags uint16) []FlagNote {
	out := make([]FlagNote, 0, len(gpFlagNotes))
	for _, note := range gpFlagNotes {
		if flags&note.Bit != 0 {
			out = append(out, note)
		}
	}
	return out
}

// HasDataDescriptor 判断条目是否声明了数据描述符（GPBF bit 3）。
func HasDataDescriptor(flags uint16) bool { return flags&0x0008 != 0 }

// ---------------------------------------------------------------------------
// DOS 日期时间
// ---------------------------------------------------------------------------

// FormatDOSDateTime 把 ZIP 里的 DOS 日期 / 时间字段格式化成
// "YYYY-MM-DD HH:MM:SS"。日期为 0 或月份 / 日非法时返回 ok=false。
//
// DOS 时间只有 2 秒精度（秒字段存的是秒数除以 2），这里如实还原。
func FormatDOSDateTime(date, time uint16) (string, bool) {
	if date == 0 {
		return "", false
	}
	year := 1980 + int(date>>9&0x7f)
	month := int(date >> 5 & 0x0f)
	day := int(date & 0x1f)
	hour := int(time >> 11 & 0x1f)
	minute := int(time >> 5 & 0x3f)
	second := int(time&0x1f) * 2
	if month < 1 || month > 12 || day < 1 || day > 31 {
		return "", false
	}
	if hour > 23 || minute > 59 || second > 59 {
		return "", false
	}
	return fmt.Sprintf("%04d-%02d-%02d %02d:%02d:%02d",
		year, month, day, hour, minute, second), true
}

// ---------------------------------------------------------------------------
// 本地文件头
// ---------------------------------------------------------------------------

// LocalHeader 是一个本地文件头的完整字段。
//
// 与中央目录的 Entry 分开建模：两者理论上应该一致，但伪加密、被改坏偏移的包
// 恰恰是"不一致"才暴露问题，所以不能合并成一份。
type LocalHeader struct {
	Offset           int64
	Version          uint16
	GPFlags          uint16
	Method           uint16
	MethodName       string
	ModTime          uint16
	ModDate          uint16
	Modified         string
	CRC32            uint32
	CompressedSize   uint64
	UncompressedSize uint64
	NameLen          int
	ExtraLen         int
	Name             string
	NameEncoding     string
	Extra            []ExtraField
	Flags            []FlagNote
	TotalLen         int
}

// ReadLocalHeaderInfo 解析 offset 处的本地文件头。
//
// 与 ReadLocalHeader 的区别：那个只返回原始字节（供十六进制视图用），
// 这个返回结构化字段。两处都不做解密，也不读条目数据。
func ReadLocalHeaderInfo(path string, offset uint64) (*LocalHeader, error) {
	if strings.TrimSpace(path) == "" {
		return nil, errors.New("zipservice: empty path")
	}
	if offset > 1<<62 {
		return nil, fmt.Errorf("%w: local header offset %d is out of range", ErrCorrupt, offset)
	}

	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("zipservice: open %q: %w", path, err)
	}
	defer f.Close()

	st, err := f.Stat()
	if err != nil {
		return nil, fmt.Errorf("zipservice: stat %q: %w", path, err)
	}
	size := st.Size()
	if int64(offset)+localHeaderSize > size {
		return nil, fmt.Errorf("%w: 本地文件头偏移 %d 超出文件末尾（共 %d 字节）", ErrCorrupt, offset, size)
	}

	fixed := make([]byte, localHeaderSize)
	if _, err := f.ReadAt(fixed, int64(offset)); err != nil && !errors.Is(err, io.EOF) {
		return nil, fmt.Errorf("zipservice: 读取本地文件头失败: %w", err)
	}
	if binary.LittleEndian.Uint32(fixed) != sigLocalHeader {
		return nil, fmt.Errorf("%w: 偏移 %d 处不是本地文件头（签名 0x%08X）",
			ErrCorrupt, offset, binary.LittleEndian.Uint32(fixed))
	}

	nameLen := int(binary.LittleEndian.Uint16(fixed[26:]))
	extraLen := int(binary.LittleEndian.Uint16(fixed[28:]))
	bodyLen := nameLen + extraLen
	// 名字 + 扩展字段再长也不可能超过一个 int，这里顺手把荒谬值挡掉。
	if bodyLen < 0 || bodyLen > maxLocalHeaderRead {
		return nil, fmt.Errorf("%w: 本地文件头可变部分 %d 字节过大", ErrCorrupt, bodyLen)
	}

	body := make([]byte, bodyLen)
	if bodyLen > 0 {
		if int64(offset)+localHeaderSize+int64(bodyLen) > size {
			return nil, fmt.Errorf("%w: 本地文件头越界（偏移 %d，需要 %d 字节）", ErrCorrupt, offset, bodyLen)
		}
		if _, err := f.ReadAt(body, int64(offset)+localHeaderSize); err != nil && !errors.Is(err, io.EOF) {
			return nil, fmt.Errorf("zipservice: 读取本地文件名失败: %w", err)
		}
	}

	flags := binary.LittleEndian.Uint16(fixed[6:])
	method := binary.LittleEndian.Uint16(fixed[8:])
	modTime := binary.LittleEndian.Uint16(fixed[10:])
	modDate := binary.LittleEndian.Uint16(fixed[12:])

	name, encoding := decodeNameWithEncoding(body[:nameLen], flags&flagUTF8Name != 0)
	modified, _ := FormatDOSDateTime(modDate, modTime)

	return &LocalHeader{
		Offset:           int64(offset),
		Version:          binary.LittleEndian.Uint16(fixed[4:]),
		GPFlags:          flags,
		Method:           method,
		MethodName:       compressionName(method),
		ModTime:          modTime,
		ModDate:          modDate,
		Modified:         modified,
		CRC32:            binary.LittleEndian.Uint32(fixed[14:]),
		CompressedSize:   uint64(binary.LittleEndian.Uint32(fixed[18:])),
		UncompressedSize: uint64(binary.LittleEndian.Uint32(fixed[22:])),
		NameLen:          nameLen,
		ExtraLen:         extraLen,
		Name:             name,
		NameEncoding:     encoding,
		Extra:            ParseExtraFields(body[nameLen:]),
		Flags:            DescribeGPFlags(flags),
		TotalLen:         localHeaderSize + bodyLen,
	}, nil
}

// ---------------------------------------------------------------------------
// 数据描述符
// ---------------------------------------------------------------------------

// DataDescriptor 是条目数据之后的「数据描述符」记录。
//
// GPBF bit 3 置位时，本地文件头里的 CRC / 大小可以是 0，真实值写在数据之后。
// 有的实现会带上 0x08074B50 签名，有的不带，两种都要认。
type DataDescriptor struct {
	Offset           int64
	HasSignature     bool
	Zip64            bool
	CRC32            uint32
	CompressedSize   uint64
	UncompressedSize uint64
	MatchesCentral   bool
}

// ReadDataDescriptor 定位并解析 entry 的数据描述符。
//
// 返回 (nil, nil) 表示这个条目没有数据描述符——要么 GPBF bit 3 没置位，
// 要么置位了但数据之后找不到能和中央目录对上号的记录（有些实现会回填本地
// 文件头而省略描述符）。这不是错误，所以不用 error 表达。
func ReadDataDescriptor(path string, entry Entry) (*DataDescriptor, error) {
	if !HasDataDescriptor(entry.GPFlags) {
		return nil, nil
	}

	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("zipservice: open %q: %w", path, err)
	}
	defer f.Close()

	st, err := f.Stat()
	if err != nil {
		return nil, fmt.Errorf("zipservice: stat %q: %w", path, err)
	}
	size := st.Size()

	nameLen, extraLen, ok := readLocalHeaderLengths(f, entry.LocalHeaderOffset)
	if !ok {
		return nil, nil
	}

	off := int64(entry.LocalHeaderOffset) + localHeaderSize +
		int64(nameLen) + int64(extraLen) + int64(entry.CompressedSize)
	if off < 0 || off >= size {
		return nil, nil
	}

	probe := make([]byte, maxDescriptorProbe)
	n := int64(maxDescriptorProbe)
	if off+n > size {
		n = size - off
	}
	if _, err := f.ReadAt(probe[:n], off); err != nil && !errors.Is(err, io.EOF) {
		return nil, fmt.Errorf("zipservice: 读取数据描述符失败: %w", err)
	}
	probe = probe[:n]

	// 先按「带签名 + 32 位长度」试，再试「带签名 + 64 位长度」，最后试不带签名。
	type layout struct {
		hasSig bool
		zip64  bool
		head   int
	}
	layouts := []layout{
		{hasSig: true, head: 4},
		{hasSig: true, zip64: true, head: 4},
		{hasSig: false, head: 0},
		{hasSig: false, zip64: true, head: 0},
	}

	for _, l := range layouts {
		if l.hasSig {
			if len(probe) < 4 || binary.LittleEndian.Uint32(probe) != descriptorSig {
				continue
			}
		} else {
			// 不带签名的布局只有在带签名那条对不上时才尝试，
			// 否则 CRC 恰好等于 0x08074B50 时会误判。
			if len(probe) >= 4 && binary.LittleEndian.Uint32(probe) == descriptorSig {
				continue
			}
		}

		need := l.head + 12
		if l.zip64 {
			need = l.head + 20
		}
		if len(probe) < need {
			continue
		}

		crc := binary.LittleEndian.Uint32(probe[l.head:])
		var comp, uncomp uint64
		if l.zip64 {
			comp = binary.LittleEndian.Uint64(probe[l.head+4:])
			uncomp = binary.LittleEndian.Uint64(probe[l.head+12:])
		} else {
			comp = uint64(binary.LittleEndian.Uint32(probe[l.head+4:]))
			uncomp = uint64(binary.LittleEndian.Uint32(probe[l.head+8:]))
		}

		// 只有和中央目录对得上才认，避免把条目数据的尾部误当成描述符。
		if crc != entry.CRC32 || comp != entry.CompressedSize || uncomp != entry.UncompressedSize {
			continue
		}
		return &DataDescriptor{
			Offset:           off,
			HasSignature:     l.hasSig,
			Zip64:            l.zip64,
			CRC32:            crc,
			CompressedSize:   comp,
			UncompressedSize: uncomp,
			MatchesCentral:   true,
		}, nil
	}

	return nil, nil
}

// ---------------------------------------------------------------------------
// 常见 ZIP 文件头指纹
// ---------------------------------------------------------------------------

// HeaderMatch 是一条文件头指纹。
type HeaderMatch struct {
	Label   string
	Vendors []string
	Bytes   []byte

	// 下面三个是「来源识别」（creator.go）用的判定信息，首字母小写，
	// **不参与 JSON 序列化**，所以 EntryDetail 的返回结构没变。
	//
	// confidence 取 high / medium / low：这 10 字节有多少区分度。
	// reason 是给用户看的判定依据。
	// degenerate 表示这是 ZIP 的默认组合，几乎所有工具都这么写，
	// 命中它不能报厂商名（详见 creator.go）。
	confidence string
	reason     string
	degenerate bool
}

// KnownLocalHeaders 是常见压缩软件写出的本地文件头指纹。
//
// 比对的是前 10 字节：签名(4) + 解压版本(2) + 通用位标志(2) + 压缩方法(2)。
//
// 注意这只是启发式：同一款软件的不同版本、不同加密选项会写出不同头部，
// 所以同一家会出现多条；0x0009 那条 Bandizip 与 WinRAR 完全相同，仅凭
// 文件头分不出来。
var KnownLocalHeaders = []HeaderMatch{
	{
		Label:   "360压缩 / 7-Zip",
		Vendors: []string{"360压缩", "7-Zip"},
		Bytes:   []byte{0x50, 0x4b, 0x03, 0x04, 0x14, 0x00, 0x01, 0x00, 0x08, 0x00},
		// 两家写出完全相同的前 10 字节，结构上分不出来。
		confidence: ConfidenceMedium,
		reason:     "GPBF=0x0001（加密）+ Deflate，但 360压缩 与 7-Zip 写出完全相同的前 10 字节",
	},
	{
		Label:      "Bandizip",
		Vendors:    []string{"Bandizip"},
		Bytes:      []byte{0x50, 0x4b, 0x03, 0x04, 0x14, 0x00, 0x0b, 0x00, 0x08, 0x00},
		confidence: ConfidenceHigh,
		reason:     "GPBF=0x000B（加密 + bit1 + 数据描述符）是 Bandizip 的特征写法",
	},
	{
		Label:      "Bandizip / WinRAR",
		Vendors:    []string{"Bandizip", "WinRAR"},
		Bytes:      []byte{0x50, 0x4b, 0x03, 0x04, 0x14, 0x00, 0x09, 0x00, 0x08, 0x00},
		confidence: ConfidenceMedium,
		reason:     "GPBF=0x0009（加密 + 数据描述符），Bandizip 与 WinRAR 都会这么写",
	},
	{
		Label:   "Bandizip",
		Vendors: []string{"Bandizip"},
		Bytes:   []byte{0x50, 0x4b, 0x03, 0x04, 0x14, 0x00, 0x00, 0x00, 0x08, 0x00},
		// GPBF=0 + Deflate 是 ZIP 的默认写法，Windows 资源管理器等都会这么打，
		// 命中它等于没有信息量。ziptool 把它归给 Bandizip，这里改成「退化」。
		confidence: ConfidenceLow,
		reason:     "GPBF=0 且 Deflate 是 ZIP 最常见的默认组合，Windows 资源管理器等工具都会写出同样的字节",
		degenerate: true,
	},
	{
		Label:      "2345 好压",
		Vendors:    []string{"2345 好压"},
		Bytes:      []byte{0x50, 0x4b, 0x03, 0x04, 0x14, 0x00, 0x01, 0x08, 0x08, 0x00},
		confidence: ConfidenceHigh,
		reason:     "GPBF=0x0801（加密 + UTF-8 文件名标志）是 2345 好压的写入方式",
	},
}

// MatchKnownHeaders 用前 10 字节比对指纹表，返回所有命中项。
func MatchKnownHeaders(b []byte) []HeaderMatch {
	hits := make([]HeaderMatch, 0, 2)
	for _, known := range KnownLocalHeaders {
		if len(b) < len(known.Bytes) {
			continue
		}
		match := true
		for i, want := range known.Bytes {
			if b[i] != want {
				match = false
				break
			}
		}
		if match {
			hits = append(hits, known)
		}
	}
	return hits
}

// ---------------------------------------------------------------------------
// 文件级 + 条目级详情
// ---------------------------------------------------------------------------

// EntryDetail 是单个条目的完整结构分析。
type EntryDetail struct {
	// Entry 是中央目录里的字段（与 Inspect 返回的完全一致）。
	Entry

	NameEncoding string

	// 中央目录记录本身的位置与长度，便于在十六进制视图里跳转。
	CentralOffset    int64
	CentralRecordLen int
	NameLen          int
	ExtraLen         int
	CommentLen       int

	// 中央目录里剩下的固定字段，Inspect 的 Entry 不暴露它们，
	// 但详情视图的字段对照表需要完整。
	VersionMadeBy uint16
	VersionNeeded uint16
	DiskStart     uint16
	InternalAttrs uint16
	ExternalAttrs uint32

	// 中央目录里的 DOS 时间（Entry 里没有，单独给）。
	ModTime  uint16
	ModDate  uint16
	Modified string

	// ActualMethod 是真实压缩方法码。AES 条目的 Entry.Method 是 99，
	// 真实方法藏在 0x9901 扩展字段里。
	ActualMethod uint16

	CentralExtra []ExtraField
	Flags        []FlagNote

	// Local 读不到时为 nil（偏移被改坏、条目被截断等）。
	Local *LocalHeader
	// LocalErr 记录 Local 为 nil 的原因，直接展示给用户。
	LocalErr string

	// Descriptor 为 nil 表示没有数据描述符。
	Descriptor *DataDescriptor

	// LocalMatchesCentral 汇总本地文件头与中央目录是否一致。
	// 两者都读到时才有意义；伪加密就是在这里露馅的。
	Consistent bool
}

// ZipDetail 是 InspectDetailed 的返回值。
type ZipDetail struct {
	Path       string
	FileSize   int64
	Format     string
	Zip64      bool
	EntryCount int

	CDOffset   int64
	CDSize     int64
	EOCDOffset int64
	// CDRecovered 表示中央目录偏移越界、已按 EOCD 位置回推修正。
	CDRecovered bool
	Comment     string

	// HeaderMatches 是针对"第一个本地文件头"的指纹比对结果，
	// 用来推测归档由哪款软件生成。
	HeaderMatches []HeaderMatch

	Warnings []string
	Entries  []EntryDetail
}

// cdRecord 是中央目录里的一条原始记录，带上它自己的位置信息。
type cdRecord struct {
	entry         Entry
	offset        int64
	total         int
	nameLen       int
	extraLen      int
	commentLn     int
	modTime       uint16
	modDate       uint16
	versionMadeBy uint16
	versionNeeded uint16
	diskStart     uint16
	internalAttrs uint16
	externalAttrs uint32
	extra         []byte
	encoding      string
}

// detailSession 是一次详情解析的中间结果。
//
// 拆出来的目的是让 InspectDetailed（解析全部条目）和 ReadEntryDetail
// （只解析一个条目）共用同一套 EOCD / 中央目录 / 伪加密逻辑，避免重复实现。
type detailSession struct {
	detail  *ZipDetail
	records []cdRecord
	entries []Entry
}

// loadDetail 打开归档、解析 EOCD 与中央目录，并完成伪加密标注。
func loadDetail(path string) (*detailSession, error) {
	if strings.TrimSpace(path) == "" {
		return nil, errors.New("zipservice: empty path")
	}

	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("zipservice: open %q: %w", path, err)
	}
	defer f.Close()

	st, err := f.Stat()
	if err != nil {
		return nil, fmt.Errorf("zipservice: stat %q: %w", path, err)
	}
	if st.IsDir() {
		return nil, fmt.Errorf("zipservice: %q is a directory", path)
	}
	size := st.Size()
	if size < eocdSize {
		return nil, fmt.Errorf("%w: file is only %d bytes", ErrNotZip, size)
	}

	eocd, err := findEOCD(f, size)
	if err != nil {
		return nil, err
	}

	detail := &ZipDetail{
		Path:       path,
		FileSize:   size,
		Format:     "ZIP",
		Zip64:      eocd.zip64,
		EntryCount: int(eocd.entries),
		CDSize:     int64(eocd.cdSize),
		EOCDOffset: eocd.eocdAbs,
		Comment:    eocd.comment,
	}
	if eocd.zip64 {
		detail.Format = "ZIP64"
	}
	if eocd.diskNumber != 0 || eocd.cdDisk != 0 || int(eocd.entriesDisk) != int(eocd.entries) {
		detail.Warnings = append(detail.Warnings, fmt.Sprintf(
			"这个包声明为分卷压缩（第 %d 卷，中央目录在第 %d 卷）。单卷文件只能看到当前卷的条目，结论可能不完整。",
			eocd.diskNumber+1, eocd.cdDisk+1))
	}

	cdOff := int64(eocd.cdOffset)
	cdSize := int64(eocd.cdSize)

	// 偏移越界 → 按 EOCD 位置回推。自解压包在前面塞了数据时很常见。
	if cdOff < 0 || cdOff+cdSize > size {
		alt := eocd.eocdAbs - cdSize
		if alt >= 0 && alt+cdSize <= size {
			detail.CDRecovered = true
			detail.Warnings = append(detail.Warnings,
				"中央目录偏移超出文件范围，已按 EOCD 位置回推修正（常见于前置了数据的自解压包）。")
			cdOff = alt
		} else {
			return nil, fmt.Errorf("%w: 中央目录范围 %d+%d 超出文件（%d 字节）", ErrCorrupt, cdOff, cdSize, size)
		}
	}

	if cdSize > maxCentralDirectoryRead {
		return nil, fmt.Errorf("%w: 中央目录 %d 字节超过解析上限", ErrCorrupt, cdSize)
	}
	if cdSize == 0 {
		if detail.EntryCount > 0 {
			detail.Warnings = append(detail.Warnings, fmt.Sprintf(
				"EOCD 声称有 %d 个条目，但中央目录长度为 0，文件很可能已损坏。", detail.EntryCount))
		}
		detail.CDOffset = cdOff
		return &detailSession{detail: detail}, nil
	}

	cd := make([]byte, cdSize)
	if _, err := f.ReadAt(cd, cdOff); err != nil && !errors.Is(err, io.EOF) {
		return nil, fmt.Errorf("zipservice: read central directory: %w", err)
	}

	// 签名对不上 → 再按 EOCD 位置回推试一次（偏移字段被写坏的情形）。
	if len(cd) >= 4 && binary.LittleEndian.Uint32(cd) != sigCentralHeader {
		alt := eocd.eocdAbs - cdSize
		if alt >= 0 && alt != cdOff && alt+cdSize <= size {
			altBuf := make([]byte, cdSize)
			if _, err := f.ReadAt(altBuf, alt); err == nil || errors.Is(err, io.EOF) {
				if len(altBuf) >= 4 && binary.LittleEndian.Uint32(altBuf) == sigCentralHeader {
					detail.CDRecovered = true
					detail.Warnings = append(detail.Warnings,
						"按 EOCD 记录的偏移读到的不是中央目录，已改用回推位置（偏移字段可能被写坏）。")
					cd, cdOff = altBuf, alt
				}
			}
		}
		if len(cd) >= 4 && binary.LittleEndian.Uint32(cd) != sigCentralHeader {
			detail.Warnings = append(detail.Warnings,
				"中央目录签名不匹配，文件可能已损坏，下面的结果仅供参考。")
		}
	}

	detail.CDOffset = cdOff
	// 回推后，条目里的本地头偏移也要同步平移。
	shift := cdOff - int64(eocd.cdOffset)

	records, err := walkCentralRecords(cd, cdOff, shift)
	if err != nil {
		return nil, err
	}
	if detail.EntryCount > 0 && len(records) != detail.EntryCount {
		detail.Warnings = append(detail.Warnings, fmt.Sprintf(
			"EOCD 记录的条目数是 %d，实际解析到 %d 个，两者不一致（文件可能损坏，或含不支持的条目类型）。",
			detail.EntryCount, len(records)))
	}

	// 复用 Inspect 的伪加密判定，保证两边的结论一致。
	entries := make([]Entry, len(records))
	for i := range records {
		entries[i] = records[i].entry
	}
	annotateFakeEncryption(f, entries)

	return &detailSession{detail: detail, records: records, entries: entries}, nil
}

// InspectDetailed 解析归档并返回每个条目的完整结构。
//
// 与 Inspect 的差异：
//   - 额外解析本地文件头、扩展字段 TLV、数据描述符；
//   - 中央目录偏移越界时会按 EOCD 位置回推（自解压包前置数据的常见情形），
//     并把这件事记进 Warnings；
//   - 额外给出分卷、条目数不一致等结构警告。
//
// 代价是要把中央目录整个读进内存（上限 maxCentralDirectoryRead），
// 所以它只用于单文件详情视图，批量侦察仍然走 Inspect。
func InspectDetailed(path string) (*ZipDetail, error) {
	sess, err := loadDetail(path)
	if err != nil {
		return nil, err
	}

	d := sess.detail
	d.Entries = make([]EntryDetail, 0, len(sess.records))
	for i := range sess.records {
		d.Entries = append(d.Entries, buildEntryDetail(path, sess.entries[i], &sess.records[i]))
	}

	// 指纹比对只针对文件里最靠前的那个本地文件头。
	if first, ok := firstLocalEntry(sess.records); ok {
		if lfh, err := ReadLocalHeaderInfo(path, uint64(first)); err == nil {
			d.HeaderMatches = matchLocalHeaderFile(path, lfh.Offset)
		}
	}

	return d, nil
}

// ReadEntryDetail 只解析指定名称的条目。
//
// 条目展开时按需调用，避免为了看一个条目就把整个归档的所有条目都展开。
func ReadEntryDetail(path, entryName string) (*EntryDetail, error) {
	sess, err := loadDetail(path)
	if err != nil {
		return nil, err
	}
	for i := range sess.records {
		if sess.records[i].entry.Name == entryName {
			d := buildEntryDetail(path, sess.entries[i], &sess.records[i])
			return &d, nil
		}
	}
	return nil, fmt.Errorf("%w: %q", ErrEntryNotFound, entryName)
}

// matchLocalHeaderFile 读文件头前 10 字节并比对指纹。
func matchLocalHeaderFile(path string, offset int64) []HeaderMatch {
	raw, err := ReadLocalHeader(path, offset, maxHeaderMatchBytes)
	if err != nil || len(raw) == 0 {
		return nil
	}
	return MatchKnownHeaders(raw)
}

// firstLocalEntry 返回"第一个真实文件"的本地头偏移。
//
// 目录条目也会有自己的本地头，但它通常由另一段代码路径写出（版本号、
// 扩展字段都不一样），拿它去比对软件指纹容易一条都命不中。所以优先跳过
// 以 "/" 结尾的目录条目，全都跳过时再退回第一个条目。
func firstLocalEntry(records []cdRecord) (int64, bool) {
	var (
		best     int64
		found    bool
		dirBest  int64
		dirFound bool
	)
	for _, r := range records {
		off := int64(r.entry.LocalHeaderOffset)
		if off <= 0 {
			continue
		}
		if isDirectoryName(r.entry.Name) {
			if !dirFound || off < dirBest {
				dirBest, dirFound = off, true
			}
			continue
		}
		if !found || off < best {
			best, found = off, true
		}
	}
	if found {
		return best, true
	}
	return dirBest, dirFound
}

// isDirectoryName 判断条目名是否代表一个目录。
func isDirectoryName(name string) bool {
	return strings.HasSuffix(name, "/") || strings.HasSuffix(name, `\`)
}

// walkCentralRecords 遍历中央目录，返回带位置信息的原始记录。
func walkCentralRecords(cd []byte, base, shift int64) ([]cdRecord, error) {
	records := make([]cdRecord, 0, 64)
	pos := 0

	for pos+centralHeaderSize <= len(cd) {
		sig := binary.LittleEndian.Uint32(cd[pos:])
		switch sig {
		case sigCentralHeader:
		case sigDigitalSig:
			// 目录末尾的可选数字签名记录，跳过。
			if pos+6 > len(cd) {
				return records, nil
			}
			pos += 6 + int(binary.LittleEndian.Uint16(cd[pos+4:]))
			continue
		default:
			// 签名不认识就停下，把已解析的部分返回，交给 Warnings 说明。
			return records, nil
		}

		entry, total, err := parseCentralEntry(cd[pos:])
		if errors.Is(err, errIncomplete) {
			return records, nil
		}
		if err != nil {
			return records, err
		}

		nameLen := int(binary.LittleEndian.Uint16(cd[pos+28:]))
		extraLen := int(binary.LittleEndian.Uint16(cd[pos+30:]))
		commentLen := int(binary.LittleEndian.Uint16(cd[pos+32:]))

		rawName := cd[pos+centralHeaderSize : pos+centralHeaderSize+nameLen]
		name, encoding := decodeNameWithEncoding(rawName, entry.GPFlags&flagUTF8Name != 0)
		entry.Name = name

		extra := cd[pos+centralHeaderSize+nameLen : pos+centralHeaderSize+nameLen+extraLen]
		modTime := binary.LittleEndian.Uint16(cd[pos+12:])
		modDate := binary.LittleEndian.Uint16(cd[pos+14:])

		// 回推时同步平移本地头偏移，但 ZIP64 的 0xFFFFFFFF 占位不要动。
		if shift != 0 && entry.LocalHeaderOffset != 0xFFFFFFFF {
			shifted := int64(entry.LocalHeaderOffset) + shift
			if shifted >= 0 {
				entry.LocalHeaderOffset = uint64(shifted)
			}
		}

		records = append(records, cdRecord{
			entry:         entry,
			offset:        base + int64(pos),
			total:         total,
			nameLen:       nameLen,
			extraLen:      extraLen,
			commentLn:     commentLen,
			modTime:       modTime,
			modDate:       modDate,
			versionMadeBy: binary.LittleEndian.Uint16(cd[pos+4:]),
			versionNeeded: binary.LittleEndian.Uint16(cd[pos+6:]),
			diskStart:     binary.LittleEndian.Uint16(cd[pos+34:]),
			internalAttrs: binary.LittleEndian.Uint16(cd[pos+36:]),
			externalAttrs: binary.LittleEndian.Uint32(cd[pos+38:]),
			extra:         append([]byte(nil), extra...),
			encoding:      encoding,
		})

		pos += total
		if len(records) >= maxEntries {
			break
		}
	}
	return records, nil
}

// buildEntryDetail 把一个中央目录记录展开成完整的条目详情。
func buildEntryDetail(path string, entry Entry, rec *cdRecord) EntryDetail {
	modified, _ := FormatDOSDateTime(rec.modDate, rec.modTime)

	actualMethod := entry.Method
	if entry.Method == methodAES {
		if _, real, ok := parseAESExtra(rec.extra); ok {
			actualMethod = real
		}
	}

	d := EntryDetail{
		Entry:            entry,
		NameEncoding:     rec.encoding,
		CentralOffset:    rec.offset,
		CentralRecordLen: rec.total,
		NameLen:          rec.nameLen,
		ExtraLen:         rec.extraLen,
		CommentLen:       rec.commentLn,
		VersionMadeBy:    rec.versionMadeBy,
		VersionNeeded:    rec.versionNeeded,
		DiskStart:        rec.diskStart,
		InternalAttrs:    rec.internalAttrs,
		ExternalAttrs:    rec.externalAttrs,
		ModTime:          rec.modTime,
		ModDate:          rec.modDate,
		Modified:         modified,
		ActualMethod:     actualMethod,
		CentralExtra:     ParseExtraFields(rec.extra),
		Flags:            DescribeGPFlags(entry.GPFlags),
	}

	lfh, err := ReadLocalHeaderInfo(path, entry.LocalHeaderOffset)
	if err != nil {
		d.LocalErr = err.Error()
	} else {
		d.Local = lfh
		d.Consistent = localMatchesCentral(lfh, &entry)
	}

	if desc, err := ReadDataDescriptor(path, entry); err == nil {
		d.Descriptor = desc
	} else {
		d.Descriptor = nil
	}

	return d
}

// localMatchesCentral 比较本地文件头与中央目录的关键字段。
func localMatchesCentral(lfh *LocalHeader, entry *Entry) bool {
	return lfh.GPFlags == entry.GPFlags &&
		lfh.Method == entry.Method &&
		lfh.CRC32 == entry.CRC32 &&
		lfh.CompressedSize == entry.CompressedSize &&
		lfh.UncompressedSize == entry.UncompressedSize
}
