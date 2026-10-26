// Package zipservice implements a read-only reconnaissance layer for ZIP
// archives.
//
// The package only ever parses structure: it locates the End Of Central
// Directory record, walks the central directory and reports what it finds.
// It never extracts data, never decrypts anything and never writes to the
// archive. All file access goes through os.File.ReadAt so that multi-gigabyte
// archives can be inspected with a small, bounded memory footprint.
package zipservice

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"unicode/utf8"

	"golang.org/x/text/encoding/simplifiedchinese"
)

// Entry describes a single central directory record.
type Entry struct {
	Name              string
	Compression       string // "Store" / "Deflate" / "Unknown"
	Method            uint16 // raw compression method code
	IsEncrypted       bool
	EncryptionType    string // "ZipCrypto" / "AES-128" / "AES-192" / "AES-256" / "None" / "Unknown"
	GPFlags           uint16 // general purpose bit flags, straight from the central record
	CRC32             uint32
	CompressedSize    uint64
	UncompressedSize  uint64
	LocalHeaderOffset uint64

	// IsFakeEncrypted 表示这个条目的加密标记只改在中央目录里，数据本身没加密。
	// 只有「中央目录说加密、本地文件头说没加密」这种硬证据才会置为 true。
	IsFakeEncrypted bool
	// FakeEvidence 是判定依据（或「为什么没判成伪加密」），直接展示给用户。
	FakeEvidence string
}

// ZipInfo is the file level summary returned by Inspect.
type ZipInfo struct {
	Path            string
	FileSize        int64
	Format          string // "ZIP" / "ZIP64" / "Unknown"
	EncryptionType  string // file level summary, "Mixed" when entries disagree
	EntryCount      int
	Entries         []Entry
	IsFakeEncrypted bool // 任一条目被判为伪加密则为 true
	FakeCount       int  // 被判为伪加密的条目数
}

// Errors returned by the package. Callers can test them with errors.Is.
var (
	// ErrNotZip means no End Of Central Directory record could be located.
	ErrNotZip = errors.New("zipservice: not a zip archive")
	// ErrCorrupt means a signature was found but the structure is unusable.
	ErrCorrupt = errors.New("zipservice: corrupt zip structure")
	// ErrNoFakeEncryption means there is nothing to fix.
	ErrNoFakeEncryption = errors.New("zipservice: 没有检测到伪加密条目")
	// ErrEntryNotFound 表示中央目录里没有指定名称的条目。
	ErrEntryNotFound = errors.New("zipservice: 未找到指定条目")
)

// Signature values, little endian on disk.
const (
	sigLocalHeader   = 0x04034b50 // PK\x03\x04
	sigCentralHeader = 0x02014b50 // PK\x01\x02
	sigEOCD          = 0x06054b50 // PK\x05\x06
	sigZip64EOCD     = 0x06064b50 // PK\x06\x06
	sigZip64Locator  = 0x07064b50 // PK\x06\x07
	sigDigitalSig    = 0x05054b50 // PK\x05\x05
)

// Structure sizes and limits.
const (
	eocdSize          = 22
	zip64LocatorSize  = 20
	zip64EOCDMinSize  = 56
	centralHeaderSize = 46
	localHeaderSize   = 30

	// maxCommentLength is the largest archive comment the format allows, so
	// the EOCD signature can never sit further than 22+65535 bytes from EOF.
	maxCommentLength = 65535
	eocdSearchWindow = eocdSize + maxCommentLength

	// maxLocalHeaderRead caps a single ReadLocalHeader call.
	maxLocalHeaderRead = 4096

	// cdReadChunk is the central directory streaming window. Entries are
	// parsed out of this buffer as it slides over the directory, so peak
	// memory stays around one chunk instead of the whole directory.
	cdReadChunk = 64 << 10

	// maxEntries bounds the number of parsed entries so a crafted archive
	// cannot exhaust memory. EntryCount still reports the declared total.
	maxEntries = 200000

	// maxFakeEncryptionProbes bounds extra local header reads.
	maxFakeEncryptionProbes = 256

	// cryptoHeaderSize is the ZipCrypto encryption header that sits right
	// after the local file header when the entry really is encrypted.
	cryptoHeaderSize = 12

	// maxCentralDirectoryRead caps the in-memory copy used by
	// FixFakeEncryption. 200k entries with long names stay well below this.
	maxCentralDirectoryRead = 256 << 20
)

// General purpose bit flags.
const (
	flagEncrypted = 1 << 0
	flagUTF8Name  = 1 << 11
)

// Compression methods and extra field ids.
const (
	methodStore   = 0
	methodDeflate = 8
	methodAES     = 99

	extraZip64 = 0x0001
	extraAES   = 0x9901
)

// errIncomplete signals that the buffer does not yet hold a full record.
var errIncomplete = errors.New("zipservice: incomplete record")

// Inspect parses the structure of the archive at path.
//
// Only the tail of the file and the central directory are read; the entry data
// is never touched, which keeps the cost independent of the archive size.
func Inspect(path string) (*ZipInfo, error) {
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

	if eocd.cdOffset > uint64(size) || eocd.cdSize > uint64(size)-eocd.cdOffset {
		return nil, fmt.Errorf("%w: central directory at %d+%d is outside the file (%d bytes)",
			ErrCorrupt, eocd.cdOffset, eocd.cdSize, size)
	}

	entries, err := readCentralDirectory(f, int64(eocd.cdOffset), int64(eocd.cdSize))
	if err != nil {
		return nil, err
	}

	info := &ZipInfo{
		Path:           path,
		FileSize:       size,
		Format:         "ZIP",
		EncryptionType: summarizeEncryption(entries),
		EntryCount:     len(entries),
		Entries:        entries,
	}
	if eocd.zip64 {
		info.Format = "ZIP64"
	}
	// The declared count may exceed what we parsed when maxEntries was hit.
	if declared := eocd.entries; declared > uint64(len(entries)) && declared < 1<<32 {
		info.EntryCount = int(declared)
	}
	info.IsFakeEncrypted, info.FakeCount = annotateFakeEncryption(f, entries)

	return info, nil
}

// ReadLocalHeader returns up to length bytes starting at offset, which is
// normally an Entry.LocalHeaderOffset. length is clamped to [1, 4096].
func ReadLocalHeader(path string, offset int64, length int) ([]byte, error) {
	if strings.TrimSpace(path) == "" {
		return nil, errors.New("zipservice: empty path")
	}
	if offset < 0 {
		return nil, fmt.Errorf("zipservice: negative offset %d", offset)
	}
	if length <= 0 {
		length = 128
	}
	if length > maxLocalHeaderRead {
		length = maxLocalHeaderRead
	}

	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("zipservice: open %q: %w", path, err)
	}
	defer f.Close()

	buf := make([]byte, length)
	n, err := f.ReadAt(buf, offset)
	if err != nil && !errors.Is(err, io.EOF) {
		return nil, fmt.Errorf("zipservice: read local header at %d: %w", offset, err)
	}
	if n == 0 {
		return nil, fmt.Errorf("zipservice: read local header at %d: %w", offset, io.ErrUnexpectedEOF)
	}
	return buf[:n], nil
}

// eocdRecord holds the fields of the End Of Central Directory record that we
// care about, already promoted from ZIP64 structures when needed.
type eocdRecord struct {
	cdOffset uint64
	cdSize   uint64
	entries  uint64
	zip64    bool

	// 以下字段只给 InspectDetailed 用，Inspect 不读。
	eocdAbs     int64  // EOCD 记录在文件中的绝对偏移
	comment     string // 归档注释
	diskNumber  uint16 // 当前卷号
	cdDisk      uint16 // 中央目录所在卷号
	entriesDisk uint16 // 本卷条目数
}

// findEOCD scans backwards from EOF for the End Of Central Directory record.
func findEOCD(f *os.File, size int64) (*eocdRecord, error) {
	window := int64(eocdSearchWindow)
	if window > size {
		window = size
	}
	tail := make([]byte, window)
	if _, err := f.ReadAt(tail, size-window); err != nil && !errors.Is(err, io.EOF) {
		return nil, fmt.Errorf("zipservice: read tail: %w", err)
	}

	pos := findEOCDSignature(tail)
	if pos < 0 {
		return nil, ErrNotZip
	}
	rec := tail[pos : pos+eocdSize]

	entriesDisk := uint64(binary.LittleEndian.Uint16(rec[8:]))
	entriesTotal := uint64(binary.LittleEndian.Uint16(rec[10:]))
	cdSize := uint64(binary.LittleEndian.Uint32(rec[12:]))
	cdOffset := uint64(binary.LittleEndian.Uint32(rec[16:]))

	eocdAbs := size - window + int64(pos)

	// 注释紧跟在 EOCD 固定部分之后，长度字段在偏移 20。
	commentLen := int(binary.LittleEndian.Uint16(rec[20:]))
	var comment string
	if commentLen > 0 && pos+eocdSize+commentLen <= len(tail) {
		comment = string(tail[pos+eocdSize : pos+eocdSize+commentLen])
	}

	out := &eocdRecord{
		cdOffset:    cdOffset,
		cdSize:      cdSize,
		entries:     entriesTotal,
		eocdAbs:     eocdAbs,
		comment:     comment,
		diskNumber:  binary.LittleEndian.Uint16(rec[4:]),
		cdDisk:      binary.LittleEndian.Uint16(rec[6:]),
		entriesDisk: uint16(entriesDisk),
	}

	// Any saturated field means the real values live in the ZIP64 records.
	if entriesTotal == 0xFFFF || entriesDisk == 0xFFFF ||
		cdSize == 0xFFFFFFFF || cdOffset == 0xFFFFFFFF {
		z64Offset, z64Size, z64Entries, err := readZip64EOCD(f, eocdAbs)
		if err != nil {
			return nil, err
		}
		out.zip64 = true
		out.cdOffset = z64Offset
		out.cdSize = z64Size
		out.entries = z64Entries
	}

	return out, nil
}

// findEOCDSignature returns the index of the EOCD signature inside tail, or -1.
//
// The record is validated by checking that its comment length reaches exactly
// to the end of the file, which rejects stray "PK\x05\x06" byte sequences
// inside archive comments or entry data. A looser pass tolerates writers that
// pad after the comment.
func findEOCDSignature(tail []byte) int {
	for i := len(tail) - eocdSize; i >= 0; i-- {
		if binary.LittleEndian.Uint32(tail[i:]) != sigEOCD {
			continue
		}
		commentLen := int(binary.LittleEndian.Uint16(tail[i+20:]))
		if i+eocdSize+commentLen == len(tail) {
			return i
		}
	}
	for i := len(tail) - eocdSize; i >= 0; i-- {
		if binary.LittleEndian.Uint32(tail[i:]) == sigEOCD {
			return i
		}
	}
	return -1
}

// readZip64EOCD resolves the ZIP64 end of central directory record via its
// locator, which normally sits immediately before the EOCD.
func readZip64EOCD(f *os.File, eocdAbs int64) (cdOffset, cdSize, entries uint64, err error) {
	loc := make([]byte, zip64LocatorSize)

	// The locator is defined as the 20 bytes right before the EOCD, but some
	// writers leave a little slack, so probe a few positions before giving up.
	for back := int64(zip64LocatorSize); back <= zip64LocatorSize+64; back++ {
		if eocdAbs-back < 0 {
			break
		}
		if _, rerr := f.ReadAt(loc, eocdAbs-back); rerr != nil {
			break
		}
		if binary.LittleEndian.Uint32(loc) != sigZip64Locator {
			continue
		}
		recOffset := int64(binary.LittleEndian.Uint64(loc[8:]))
		if recOffset < 0 {
			break
		}
		rec := make([]byte, zip64EOCDMinSize)
		if _, rerr := f.ReadAt(rec, recOffset); rerr != nil {
			return 0, 0, 0, fmt.Errorf("%w: ZIP64 EOCD at %d: %v", ErrCorrupt, recOffset, rerr)
		}
		if binary.LittleEndian.Uint32(rec) != sigZip64EOCD {
			return 0, 0, 0, fmt.Errorf("%w: bad ZIP64 EOCD signature at %d", ErrCorrupt, recOffset)
		}
		entries = binary.LittleEndian.Uint64(rec[32:])
		cdSize = binary.LittleEndian.Uint64(rec[40:])
		cdOffset = binary.LittleEndian.Uint64(rec[48:])
		return cdOffset, cdSize, entries, nil
	}
	return 0, 0, 0, fmt.Errorf("%w: ZIP64 locator not found", ErrCorrupt)
}

// readCentralDirectory streams the central directory and parses its records.
func readCentralDirectory(f *os.File, off, size int64) ([]Entry, error) {
	entries := make([]Entry, 0, 64)
	buf := make([]byte, 0, cdReadChunk*2)
	pos := off
	remaining := size

	for {
		consumed := 0
		for len(buf)-consumed >= centralHeaderSize {
			rest := buf[consumed:]
			sig := binary.LittleEndian.Uint32(rest)
			switch sig {
			case sigDigitalSig:
				// Optional digital signature record at the end of the directory.
				if len(rest) < 6 {
					goto flush
				}
				n := 6 + int(binary.LittleEndian.Uint16(rest[4:]))
				if len(rest) < n {
					goto flush
				}
				consumed += n
			case sigCentralHeader:
				entry, n, err := parseCentralEntry(rest)
				if errors.Is(err, errIncomplete) {
					goto flush
				}
				if err != nil {
					return entries, err
				}
				if len(entries) < maxEntries {
					entries = append(entries, entry)
				}
				consumed += n
			default:
				return entries, fmt.Errorf("%w: unexpected record 0x%08X in central directory", ErrCorrupt, sig)
			}
		}

	flush:
		if consumed > 0 {
			copy(buf, buf[consumed:])
			buf = buf[:len(buf)-consumed]
		}
		if remaining <= 0 || len(entries) >= maxEntries {
			break
		}

		n := int64(cdReadChunk)
		if n > remaining {
			n = remaining
		}
		start := len(buf)
		buf = append(buf, make([]byte, n)...)
		if _, err := f.ReadAt(buf[start:], pos); err != nil && !errors.Is(err, io.EOF) {
			return entries, fmt.Errorf("zipservice: read central directory: %w", err)
		}
		pos += n
		remaining -= n
	}

	return entries, nil
}

// parseCentralEntry decodes one central directory record. The returned int is
// the total record length, including name, extra field and comment.
func parseCentralEntry(b []byte) (Entry, int, error) {
	nameLen := int(binary.LittleEndian.Uint16(b[28:]))
	extraLen := int(binary.LittleEndian.Uint16(b[30:]))
	commentLen := int(binary.LittleEndian.Uint16(b[32:]))
	total := centralHeaderSize + nameLen + extraLen + commentLen
	if len(b) < total {
		return Entry{}, 0, errIncomplete
	}

	gpbf := binary.LittleEndian.Uint16(b[8:])
	method := binary.LittleEndian.Uint16(b[10:])

	entry := Entry{
		Method:            method,
		GPFlags:           gpbf,
		CRC32:             binary.LittleEndian.Uint32(b[16:]),
		CompressedSize:    uint64(binary.LittleEndian.Uint32(b[20:])),
		UncompressedSize:  uint64(binary.LittleEndian.Uint32(b[24:])),
		LocalHeaderOffset: uint64(binary.LittleEndian.Uint32(b[42:])),
	}

	nameBytes := b[centralHeaderSize : centralHeaderSize+nameLen]
	extra := b[centralHeaderSize+nameLen : centralHeaderSize+nameLen+extraLen]

	applyZip64(&entry, extra)
	entry.Name = decodeName(nameBytes, gpbf&flagUTF8Name != 0)

	// Encryption detection. AES entries use method 99 and keep the real
	// compression method inside the 0x9901 extra field.
	actualMethod := method
	if method == methodAES {
		entry.IsEncrypted = true
		if strength, realMethod, ok := parseAESExtra(extra); ok {
			entry.EncryptionType = aesTypeName(strength)
			actualMethod = realMethod
		} else {
			entry.EncryptionType = "Unknown"
		}
	} else if gpbf&flagEncrypted != 0 {
		entry.IsEncrypted = true
		entry.EncryptionType = "ZipCrypto"
	} else {
		entry.EncryptionType = "None"
	}
	entry.Compression = compressionName(actualMethod)

	return entry, total, nil
}

// applyZip64 promotes saturated 32 bit fields from the 0x0001 extra field.
// The fields appear in a fixed order, but only those that were saturated.
func applyZip64(entry *Entry, extra []byte) {
	needSize := entry.UncompressedSize == 0xFFFFFFFF
	needCompressed := entry.CompressedSize == 0xFFFFFFFF
	needOffset := entry.LocalHeaderOffset == 0xFFFFFFFF
	if !needSize && !needCompressed && !needOffset {
		return
	}

	eachExtra(extra, func(id uint16, data []byte) bool {
		if id != extraZip64 {
			return true
		}
		if needSize && len(data) >= 8 {
			entry.UncompressedSize = binary.LittleEndian.Uint64(data)
			data = data[8:]
		}
		if needCompressed && len(data) >= 8 {
			entry.CompressedSize = binary.LittleEndian.Uint64(data)
			data = data[8:]
		}
		if needOffset && len(data) >= 8 {
			entry.LocalHeaderOffset = binary.LittleEndian.Uint64(data)
		}
		return false
	})
}

// parseAESExtra reads the WinZip AES 0x9901 record:
// version(2) vendor(2) strength(1) actual compression method(2).
func parseAESExtra(extra []byte) (strength byte, method uint16, ok bool) {
	eachExtra(extra, func(id uint16, data []byte) bool {
		if id != extraAES {
			return true
		}
		if len(data) < 7 {
			return false
		}
		strength = data[4]
		method = binary.LittleEndian.Uint16(data[5:])
		ok = true
		return false
	})
	return strength, method, ok
}

// eachExtra walks the extra field as a sequence of TLV records. Returning
// false from fn stops the walk.
func eachExtra(extra []byte, fn func(id uint16, data []byte) bool) {
	for len(extra) >= 4 {
		id := binary.LittleEndian.Uint16(extra)
		size := int(binary.LittleEndian.Uint16(extra[2:]))
		if size > len(extra)-4 {
			return // truncated TLV, ignore the remainder
		}
		if !fn(id, extra[4:4+size]) {
			return
		}
		extra = extra[4+size:]
	}
}

func compressionName(method uint16) string {
	switch method {
	case methodStore:
		return "Store"
	case 1:
		return "Shrink"
	case 2, 3, 4, 5:
		return "Reduce"
	case 6:
		return "Implode"
	case methodDeflate:
		return "Deflate"
	case 9:
		return "Deflate64"
	case 10:
		return "PKWARE DCL Implode"
	case 12:
		return "BZip2"
	case 14:
		return "LZMA"
	case 18:
		return "IBM TERSE"
	case 19:
		return "IBM LZ77 z"
	case 93:
		return "Zstandard"
	case 95:
		return "XZ"
	case 96:
		return "JPEG"
	case 97:
		return "WavPack"
	case 98:
		return "PPMd"
	case methodAES:
		return "AES"
	default:
		return "Unknown"
	}
}

func aesTypeName(strength byte) string {
	switch strength {
	case 1:
		return "AES-128"
	case 2:
		return "AES-192"
	case 3:
		return "AES-256"
	default:
		return "Unknown"
	}
}

// decodeName turns raw filename bytes into a display string.
func decodeName(b []byte, utf8Flag bool) string {
	name, _ := decodeNameWithEncoding(b, utf8Flag)
	return name
}

// decodeNameWithEncoding 解码文件名并报告实际使用的编码。
//
// 回退顺序（与 ziptool 的实现对齐）：
//
//	纯 ASCII        → ascii
//	bit 11 置位     → 严格 UTF-8，失败则继续回退（部分国产软件会置位却写 GBK）
//	合法 UTF-8      → utf-8
//	GBK 且含中日韩  → gbk
//	其余            → cp437（ZIP 规范在未声明编码时的默认字符集）
//
// 最后一步是关键：早期实现直接拿 U+FFFD 替换，遇到 Big5 / Shift-JIS / CP437
// 的文件名会显示成一串「�」。CP437 是规范默认值，至少能给出稳定可读的结果。
func decodeNameWithEncoding(b []byte, utf8Flag bool) (name, encoding string) {
	if len(b) == 0 {
		return "", "empty"
	}

	ascii := true
	for _, c := range b {
		if c > 0x7f {
			ascii = false
			break
		}
	}
	if ascii {
		return string(b), "ascii"
	}

	if utf8Flag {
		if utf8.Valid(b) {
			return string(b), "utf-8"
		}
	}
	if utf8.Valid(b) {
		return string(b), "utf-8"
	}

	if decoded, err := simplifiedchinese.GBK.NewDecoder().Bytes(b); err == nil && utf8.Valid(decoded) && containsCJK(decoded) {
		return string(decoded), "gbk"
	}

	return decodeCP437(b), "cp437"
}

// containsCJK 判断解码结果里是否含中日韩字符或全角标点。
//
// GBK 几乎能把任意字节序列"解码"成功，所以不能只看 err == nil；
// 要求结果里出现 CJK 才能确认这次 GBK 解码是有意义的。
func containsCJK(s []byte) bool {
	for _, r := range string(s) {
		switch {
		case r >= 0x2E80 && r <= 0x9FFF: // CJK 部首扩展 ~ 统一汉字
			return true
		case r >= 0xF900 && r <= 0xFAFF: // CJK 兼容汉字
			return true
		case r >= 0x3000 && r <= 0x303F: // CJK 标点
			return true
		case r >= 0xFF00 && r <= 0xFFEF: // 全角字符
			return true
		}
	}
	return false
}

// cp437High 是 CP437 的 0x80–0xFF 区段，ZIP 规范在文件名未声明编码时的默认字符集。
const cp437High = "ÇüéâäàåçêëèïîìÄÅ" +
	"ÉæÆôöòûùÿÖÜ¢£¥₧ƒ" +
	"áíóúñÑªº¿⌐¬½¼¡«»" +
	"░▒▓│┤╡╢╖╕╣║╗╝╜╛┐" +
	"└┴┬├─┼╞╟╚╔╩╦╠═╬╧" +
	"╨╤╥╙╘╒╓╫╪┘┌█▄▌▐▀" +
	"αßΓπΣσµτΦΘΩδ∞φε∩" +
	"≡±≥≤⌠⌡÷≈°∙·√ⁿ²■\u00a0"

// cp437Runes 把 cp437High 预先拆成 rune 切片，避免逐字节做字符串索引。
var cp437Runes = []rune(cp437High)

// decodeCP437 按 CP437 解码。低半区与 ASCII 一致，高半区查表。
func decodeCP437(b []byte) string {
	out := make([]rune, 0, len(b))
	for _, c := range b {
		if c < 0x80 {
			out = append(out, rune(c))
			continue
		}
		if idx := int(c) - 0x80; idx < len(cp437Runes) {
			out = append(out, cp437Runes[idx])
		} else {
			out = append(out, rune(c))
		}
	}
	return string(out)
}

// summarizeEncryption reduces the per-entry encryption types to one label.
func summarizeEncryption(entries []Entry) string {
	if len(entries) == 0 {
		return "None"
	}
	seen := make(map[string]struct{}, 4)
	for _, e := range entries {
		seen[e.EncryptionType] = struct{}{}
	}
	if len(seen) == 1 {
		for only := range seen {
			return only
		}
	}
	return "Mixed"
}

// annotateFakeEncryption fills Entry.IsFakeEncrypted / FakeEvidence and
// returns (any fake, count).
//
// The hard evidence is a disagreement between the central directory and the
// local file header: the central record says "encrypted", the local header for
// the same entry says "not encrypted". That combination cannot happen by
// accident — it is exactly what tools that fake encryption produce.
//
// When both records claim encryption we cannot tell a wrong password from a
// fake entry, so we stay conservative: record the evidence, do not flag it.
// Only a bounded number of local headers are read so this stays cheap on
// archives with many entries.
func annotateFakeEncryption(f *os.File, entries []Entry) (bool, int) {
	probes := 0
	fake := 0

	for i := range entries {
		e := &entries[i]
		if !e.IsEncrypted {
			continue
		}
		if probes >= maxFakeEncryptionProbes {
			break
		}
		probes++

		gpbf, ok := readLocalGPBF(f, e.LocalHeaderOffset)
		if !ok {
			e.FakeEvidence = "读不到本地文件头，无法判断"
			continue
		}

		if gpbf&flagEncrypted == 0 {
			e.IsFakeEncrypted = true
			e.FakeEvidence = "中央目录加密位为 1，本地文件头加密位为 0"
			fake++
			continue
		}

		// Both records claim encryption. Try the empty password: a fake entry
		// has no 12 byte crypto header at all, so the check byte almost never
		// matches. A match is ambiguous (it could be an empty password), so we
		// still do not flag it — just say what we saw.
		if e.EncryptionType == "ZipCrypto" && emptyPasswordPasses(f, *e) {
			e.FakeEvidence = "中央目录与本地头都标为加密，但空密码可以通过校验（可能是空密码加密，未做修复）"
			continue
		}
		e.FakeEvidence = "中央目录与本地文件头都标记为加密，未通过空密码校验"
	}

	return fake > 0, fake
}

// readLocalGPBF reads the general purpose bit flags out of a local file
// header. ok is false when the header cannot be read or is not a local header.
func readLocalGPBF(f *os.File, offset uint64) (uint16, bool) {
	if offset > 1<<62 {
		return 0, false
	}
	var header [localHeaderSize]byte
	n, err := f.ReadAt(header[:], int64(offset))
	if err != nil && !errors.Is(err, io.EOF) {
		return 0, false
	}
	if n < localHeaderSize {
		return 0, false
	}
	if binary.LittleEndian.Uint32(header[:]) != sigLocalHeader {
		return 0, false
	}
	// GPBF lives at offset 6 in the local file header.
	return binary.LittleEndian.Uint16(header[6:]), true
}

// emptyPasswordPasses decrypts the 12 byte ZipCrypto header with the empty
// password and compares the check byte against the entry's CRC.
//
// The check byte is the high byte of the CRC32, which is only knowable when
// the entry is not using a data descriptor (bit 3). Entries written with a
// descriptor store the DOS time there instead, and we do not keep the DOS
// time around, so those simply return false — no evidence either way.
func emptyPasswordPasses(f *os.File, e Entry) bool {
	if e.GPFlags&0x0008 != 0 {
		return false
	}
	if e.CompressedSize < cryptoHeaderSize {
		return false
	}
	if e.LocalHeaderOffset > 1<<62 {
		return false
	}

	nameLen, extraLen, ok := readLocalHeaderLengths(f, e.LocalHeaderOffset)
	if !ok {
		return false
	}

	start := int64(e.LocalHeaderOffset) + localHeaderSize + int64(nameLen) + int64(extraLen)
	var head [cryptoHeaderSize]byte
	if n, err := f.ReadAt(head[:], start); err != nil && (n < cryptoHeaderSize || !errors.Is(err, io.EOF)) {
		return false
	}

	k := initCryptoKeys()
	for _, b := range head {
		k = cryptoUpdate(k, b)
	}
	return byte(k.k2>>24) == byte(e.CRC32>>24)
}

// readLocalHeaderLengths returns the name and extra field lengths of the
// local header at offset.
func readLocalHeaderLengths(f *os.File, offset uint64) (nameLen, extraLen int, ok bool) {
	if offset > 1<<62 {
		return 0, 0, false
	}
	var header [localHeaderSize]byte
	n, err := f.ReadAt(header[:], int64(offset))
	if err != nil && (n < localHeaderSize || !errors.Is(err, io.EOF)) {
		return 0, 0, false
	}
	if n < localHeaderSize {
		return 0, 0, false
	}
	return int(binary.LittleEndian.Uint16(header[26:])), int(binary.LittleEndian.Uint16(header[28:])), true
}

// cryptoKeys is the three word ZipCrypto key state.
type cryptoKeys struct{ k0, k1, k2 uint32 }

func initCryptoKeys() cryptoKeys {
	return cryptoKeys{0x12345678, 0x23456789, 0x34567890}
}

// crcTableOnce builds the standard CRC-32 table used by ZipCrypto.
var crcTableOnce = func() [256]uint32 {
	var table [256]uint32
	for i := 0; i < 256; i++ {
		c := uint32(i)
		for j := 0; j < 8; j++ {
			if c&1 != 0 {
				c = 0xEDB88320 ^ (c >> 1)
			} else {
				c >>= 1
			}
		}
		table[i] = c
	}
	return table
}()

// cryptoUpdate advances the key state with one ciphertext byte.
func cryptoUpdate(k cryptoKeys, b byte) cryptoKeys {
	k0 := (k.k0 >> 8) ^ crcTableOnce[byte(k.k0)^b]
	k1 := (k.k1+(k0&0xFF))*134775813 + 1
	k2 := (k.k2 >> 8) ^ crcTableOnce[byte(k.k2)^byte(k1>>24)]
	return cryptoKeys{k0, k1, k2}
}

// FixResult 描述一次伪加密修复的结果。
type FixResult struct {
	OutputPath string `json:"outputPath"`
	FixedCount int    `json:"fixedCount"`
	// Remaining 是修复后重新侦察仍然被判为伪加密的条目数，正常应为 0。
	Remaining int `json:"remaining"`
}

// FixFakeEncryption writes a repaired copy of path to outputPath.
//
// What it changes: for every entry whose central directory record claims
// encryption while its local file header does not, bit 0 of the central GPBF
// is cleared. The local file header is never touched — rewriting it would
// corrupt entries that really are encrypted, because the 12 byte ZipCrypto
// header behind it is not part of the header itself.
//
// The original file is never modified: the whole archive is copied first and
// only the copy is patched. Afterwards the copy is re-inspected; if anything
// is still flagged as fake, the fix is reported as failed.
func FixFakeEncryption(path, outputPath string) (FixResult, error) {
	if strings.TrimSpace(path) == "" {
		return FixResult{}, errors.New("zipservice: 没有指定要修复的文件")
	}
	if strings.TrimSpace(outputPath) == "" {
		return FixResult{}, errors.New("zipservice: 没有指定输出路径")
	}
	if sameFile(path, outputPath) {
		return FixResult{}, errors.New("zipservice: 输出路径不能和原文件相同，修复结果必须另存")
	}

	src, err := os.Open(path)
	if err != nil {
		return FixResult{}, fmt.Errorf("zipservice: 打开 %s 失败：%w", path, err)
	}
	defer src.Close()

	st, err := src.Stat()
	if err != nil {
		return FixResult{}, fmt.Errorf("zipservice: 读取 %s 的信息失败：%w", path, err)
	}
	size := st.Size()

	eocd, err := findEOCD(src, size)
	if err != nil {
		return FixResult{}, err
	}
	if eocd.cdSize > maxCentralDirectoryRead {
		return FixResult{}, fmt.Errorf("zipservice: 中央目录有 %d 字节，超过修复上限", eocd.cdSize)
	}
	if eocd.cdOffset > uint64(size) || eocd.cdSize > uint64(size)-eocd.cdOffset {
		return FixResult{}, fmt.Errorf("%w: 中央目录越界", ErrCorrupt)
	}

	cd := make([]byte, eocd.cdSize)
	if _, err := src.ReadAt(cd, int64(eocd.cdOffset)); err != nil && !errors.Is(err, io.EOF) {
		return FixResult{}, fmt.Errorf("zipservice: 读取中央目录失败：%w", err)
	}

	fixed, err := patchCentralDirectory(src, cd)
	if err != nil {
		return FixResult{}, err
	}
	if fixed == 0 {
		return FixResult{}, ErrNoFakeEncryption
	}

	// 先整份复制，再只把中央目录那一段覆盖成打过补丁的版本。
	if _, err := src.Seek(0, io.SeekStart); err != nil {
		return FixResult{}, fmt.Errorf("zipservice: 定位 %s 失败：%w", path, err)
	}
	dst, err := os.Create(outputPath)
	if err != nil {
		return FixResult{}, fmt.Errorf("zipservice: 无法写入 %s：%w", outputPath, err)
	}
	if _, err := io.Copy(dst, src); err != nil {
		dst.Close()
		return FixResult{}, fmt.Errorf("zipservice: 复制到 %s 失败：%w", outputPath, err)
	}
	if _, err := dst.WriteAt(cd, int64(eocd.cdOffset)); err != nil {
		dst.Close()
		return FixResult{}, fmt.Errorf("zipservice: 写入 %s 的中央目录失败：%w", outputPath, err)
	}
	if err := dst.Close(); err != nil {
		return FixResult{}, fmt.Errorf("zipservice: 关闭 %s 失败：%w", outputPath, err)
	}

	res := FixResult{OutputPath: outputPath, FixedCount: fixed}

	// 重新侦察，确认修复真的生效。
	info, err := Inspect(outputPath)
	if err != nil {
		return res, fmt.Errorf("zipservice: 修复后无法重新解析 %s：%w", outputPath, err)
	}
	res.Remaining = info.FakeCount
	if res.Remaining > 0 {
		return res, fmt.Errorf("zipservice: 修复后仍有 %d 个条目被标记为伪加密", res.Remaining)
	}
	return res, nil
}

// patchCentralDirectory walks the in-memory central directory and clears bit 0
// of the GPBF for entries whose local header says "not encrypted". It returns
// the number of patched records.
func patchCentralDirectory(f *os.File, cd []byte) (int, error) {
	fixed := 0
	pos := 0

	for pos+centralHeaderSize <= len(cd) {
		if binary.LittleEndian.Uint32(cd[pos:]) != sigCentralHeader {
			// Digital signature record or padding at the end; stop here.
			break
		}

		entry, total, err := parseCentralEntry(cd[pos:])
		if err != nil {
			return fixed, fmt.Errorf("%w: 中央目录条目解析失败", ErrCorrupt)
		}

		if entry.GPFlags&flagEncrypted != 0 {
			if lfhGPBF, ok := readLocalGPBF(f, entry.LocalHeaderOffset); ok && lfhGPBF&flagEncrypted == 0 {
				cleared := entry.GPFlags &^ uint16(flagEncrypted)
				binary.LittleEndian.PutUint16(cd[pos+8:], cleared)
				fixed++
			}
		}

		pos += total
	}
	return fixed, nil
}

// sameFile 判断两个路径是否指向同一个文件（大小写、分隔符、相对路径都算）。
func sameFile(a, b string) bool {
	absA, errA := filepath.Abs(a)
	absB, errB := filepath.Abs(b)
	if errA != nil || errB != nil {
		return a == b
	}
	return strings.EqualFold(filepath.Clean(absA), filepath.Clean(absB))
}

// ZipService is the Wails bound facade over the package.
type ZipService struct{}

// Inspect implements the bound method exposed to the frontend.
func (z *ZipService) Inspect(path string) (*ZipInfo, error) {
	return Inspect(path)
}

// ReadLocalHeader implements the bound method exposed to the frontend.
func (z *ZipService) ReadLocalHeader(path string, offset int64, length int) ([]byte, error) {
	return ReadLocalHeader(path, offset, length)
}

// FixFakeEncryption implements the bound method exposed to the frontend.
func (z *ZipService) FixFakeEncryption(path, outputPath string) (FixResult, error) {
	return FixFakeEncryption(path, outputPath)
}

// InspectDetailed implements the bound method exposed to the frontend.
//
// 它给单文件详情视图用：比 Inspect 多返回本地文件头字段、扩展字段 TLV、
// 数据描述符、标志位说明和 DOS 时间。批量侦察仍然走 Inspect。
func (z *ZipService) InspectDetailed(path string) (*ZipDetail, error) {
	return InspectDetailed(path)
}

// ReadEntryDetail implements the bound method exposed to the frontend.
//
// 只解析单个条目，供条目展开时按需加载（大归档不必把全部条目都展开）。
func (z *ZipService) ReadEntryDetail(path, entryName string) (*EntryDetail, error) {
	return ReadEntryDetail(path, entryName)
}
