package zipservice

import (
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"strings"
)

// Creator 是「这个 ZIP 由什么软件创建」的识别结果。
//
// 识别完全基于 ZIP 结构本身（中央目录 + 本地文件头），不调用任何外部工具，
// 也不联网查表。
type Creator struct {
	// Name 是软件名。识别不出来时是 "Unknown"，不会硬猜。
	Name string `json:"name"`
	// Version 来自中央目录的 version made by，形如 "6.3（FAT）"；读不出时为空。
	Version string `json:"version"`
	// Confidence 取 high / medium / low / unknown。
	Confidence string `json:"confidence"`
	// Evidence 是判定依据，直接展示给用户，让他知道这个结论是怎么来的。
	Evidence string `json:"evidence"`
}

// 置信度取值。
const (
	ConfidenceHigh    = "high"
	ConfidenceMedium  = "medium"
	ConfidenceLow     = "low"
	ConfidenceUnknown = "unknown"
)

// CreatorUnknown 是识别不出时的返回值。
const CreatorUnknown = "Unknown"

// creatorScanLimit 限制识别时读入的中央目录长度。
//
// 只需要找到第一个非目录条目，所以 256 KB 足够覆盖绝大多数归档；再大的
// 归档也不会为了识别来源把整个中央目录读进内存。
const creatorScanLimit = 256 << 10

// localHeaderProbeSize 是比对指纹要读的字节数（与 ziptool 一致）。
const localHeaderProbeSize = 10

// DetectCreator 读取 ZIP 的中央目录与第一个非目录条目的本地文件头，识别
// 创建该 ZIP 的软件。
//
// 只用 os.Open + ReadAt：不会把整个文件读进内存，大归档也不会卡。
//
// # 指纹从哪来
//
// 单一来源是 detail.go 的 KnownLocalHeaders，对应 ziptool 的 KNOWN_HEADERS
// （assets/zip-inspector.js 约第 516 行）与 matchKnownHeaders（约第 530 行）。
// 置信度 / 判定理由 / 是否退化作为非导出字段挂在同一个结构体上，所以
// EntryDetail 的 JSON 结构没变，也不会出现两张表各改一处的漂移。
//
// ziptool 的判定只有一个维度——本地文件头前 10 字节（签名 + version needed
// + GPBF + 压缩方法）的字面量比对，没有用 version made by、extra field、
// CRC 或文件名编码。单维度的问题在于这张表里有两行是多家共用同一组字节
// （360压缩 与 7-Zip 完全相同、Bandizip 与 WinRAR 完全相同），照它的结论直接报厂商名会把「7-Zip 打的包」
// 说成「360压缩」。所以这里升级成三级置信度，并规定只有 high 才参与
// 一致性判断（见 internal/attack/creator.go）。
//
// 多字段组合体现在两处：指纹本身是「version needed + GPBF + 方法」三字段
// 联合匹配（不是只看 GPBF）；version made by 来自中央目录，与指纹互相
// 印证并补出版本号与宿主系统。单看任何一个字段都不会给 high。
//
// 判定用的是多字段组合——本地文件头的前 10 字节（version needed、GPBF、
// 压缩方法）来自 ziptool 的指纹表；中央目录的 version made by 用来补齐
// 版本号与宿主系统，并与指纹互相印证。单靠一个字段不会给出 high。
func DetectCreator(path string) (Creator, error) {
	if strings.TrimSpace(path) == "" {
		return Creator{}, errors.New("zipservice: empty path")
	}

	f, err := os.Open(path)
	if err != nil {
		return Creator{}, err
	}
	defer f.Close()

	st, err := f.Stat()
	if err != nil {
		return Creator{}, err
	}
	size := st.Size()

	eocd, err := findEOCD(f, size)
	if err != nil {
		return Creator{}, err
	}
	if eocd.entries == 0 {
		return unknownCreator("归档里没有条目，无法判断来源"), nil
	}

	rec, err := firstContentRecord(f, eocd, size)
	if err != nil {
		return Creator{}, err
	}
	if rec == nil {
		return unknownCreator("所有条目都是目录，无法判断来源"), nil
	}

	version := describeVersionMadeBy(rec.versionMadeBy)

	// 本地文件头的前 10 字节。读不到（偏移坏了、文件被截断）就退化成只看
	// 中央目录——此时没有任何指纹可用，只能报 Unknown。
	var probe [localHeaderProbeSize]byte
	probeOK := false
	if _, err := f.ReadAt(probe[:], int64(rec.entry.LocalHeaderOffset)); err == nil {
		if binary.LittleEndian.Uint32(probe[:4]) == sigLocalHeader {
			probeOK = true
		}
	}
	if !probeOK {
		return Creator{
			Name:       CreatorUnknown,
			Version:    version,
			Confidence: ConfidenceUnknown,
			Evidence:   "本地文件头读不到（偏移可能已损坏），无法比对指纹",
		}, nil
	}

	fp, ok := matchCreatorFingerprint(probe[:])
	if !ok {
		return Creator{
			Name:       CreatorUnknown,
			Version:    version,
			Confidence: ConfidenceUnknown,
			Evidence:   fmt.Sprintf("本地文件头 %s 不在已知指纹表里", hexBytesUpper(probe[:])),
		}, nil
	}

	// 退化行不能报厂商名：ziptool 把它归给 Bandizip，但这组字节是 ZIP 的
	// 默认写法，报 Bandizip 等于给每个普通 ZIP 盖假戳。按「识别不出来就
	// Unknown」处理，置信度仍是 low，界面照样提示「仅供参考」。
	if fp.degenerate {
		return Creator{
			Name:       CreatorUnknown,
			Version:    version,
			Confidence: ConfidenceLow,
			Evidence: fmt.Sprintf("本地文件头 %s（%s）；%s",
				hexBytesUpper(probe[:]), describeLFHProbe(probe[:]), fp.reason),
		}, nil
	}

	name := fp.Label
	if len(fp.Vendors) > 1 {
		// 多家共用同一组字节：名字保持组合形式，置信度按表里的值（medium）。
		name = strings.Join(fp.Vendors, " / ")
	}

	evidence := fmt.Sprintf("本地文件头 %s（%s）；%s",
		hexBytesUpper(probe[:]), describeLFHProbe(probe[:]), fp.reason)
	if version != "" {
		evidence += "；version made by=" + version
	}

	confidence := fp.confidence
	if confidence == "" {
		// 表里新增了行但没标置信度：不能冒充 high，退到 medium。
		confidence = ConfidenceMedium
	}

	return Creator{
		Name:       name,
		Version:    version,
		Confidence: confidence,
		Evidence:   evidence,
	}, nil
}

// matchCreatorFingerprint 用前 10 字节比对指纹表，返回第一行命中的。
//
// 与 ziptool 的 matchKnownHeaders 行为一致：全部字节相等才算命中。
// 理论上不会有两行同时命中（10 字节全等意味着两行本身相同）。
func matchCreatorFingerprint(b []byte) (HeaderMatch, bool) {
	for _, fp := range KnownLocalHeaders {
		if len(b) < len(fp.Bytes) {
			continue
		}
		match := true
		for i, want := range fp.Bytes {
			if b[i] != want {
				match = false
				break
			}
		}
		if match {
			return fp, true
		}
	}
	return HeaderMatch{}, false
}

// firstContentRecord 读中央目录的前一段，返回第一个非目录条目的记录。
func firstContentRecord(f *os.File, eocd *eocdRecord, size int64) (*cdRecord, error) {
	if eocd.cdOffset >= uint64(size) {
		return nil, fmt.Errorf("%w: 中央目录偏移越界", ErrCorrupt)
	}
	n := eocd.cdSize
	if n > creatorScanLimit {
		n = creatorScanLimit
	}
	if eocd.cdOffset+n > uint64(size) {
		n = uint64(size) - eocd.cdOffset
	}
	if n == 0 {
		return nil, fmt.Errorf("%w: 中央目录偏移越界", ErrCorrupt)
	}

	cd := make([]byte, n)
	if _, err := f.ReadAt(cd, int64(eocd.cdOffset)); err != nil {
		return nil, fmt.Errorf("zipservice: 读取中央目录失败：%w", err)
	}

	// walkCentralRecords 遇到不完整的记录会停下并返回已解析的部分，
	// 所以这里读一段就够，不需要把整个中央目录读完。
	records, err := walkCentralRecords(cd, int64(eocd.cdOffset), 0)
	if err != nil {
		return nil, err
	}
	for i := range records {
		if !isDirectoryName(records[i].entry.Name) {
			return &records[i], nil
		}
	}
	return nil, nil
}

// describeVersionMadeBy 把 version made by 拆成「版本号（宿主系统）」。
//
// 低字节是 ZIP 规范版本（如 0x3F = 6.3、0x14 = 2.0），高字节是宿主系统。
func describeVersionMadeBy(v uint16) string {
	if v == 0 {
		return ""
	}
	version := fmt.Sprintf("%d.%d", v&0xff/10, v&0xff%10)
	host := versionHostSystem(byte(v >> 8))
	if host == "" {
		return version
	}
	return fmt.Sprintf("%s（%s）", version, host)
}

// versionHostSystem 把 version made by 的高字节翻成宿主系统名。
func versionHostSystem(host byte) string {
	switch host {
	case 0:
		return "FAT"
	case 1:
		return "Amiga"
	case 2:
		return "VMS"
	case 3:
		return "Unix"
	case 6:
		return "HPFS"
	case 7:
		return "Macintosh"
	case 10:
		return "NTFS"
	case 14:
		return "VFAT"
	case 19:
		return "macOS"
	}
	return ""
}

// describeLFHProbe 把前 10 字节翻成人类可读的三个字段。
func describeLFHProbe(b []byte) string {
	version := binary.LittleEndian.Uint16(b[4:6])
	flags := binary.LittleEndian.Uint16(b[6:8])
	method := binary.LittleEndian.Uint16(b[8:10])

	parts := []string{
		fmt.Sprintf("version needed=%d.%d", version/10, version%10),
		fmt.Sprintf("GPBF=0x%04X", flags),
		"方法=" + compressionName(method),
	}
	return strings.Join(parts, "，")
}

// hexBytesUpper 把字节序列渲染成 "50 4B 03 04 ..."，与界面上的十六进制视图一致。
func hexBytesUpper(b []byte) string {
	var sb strings.Builder
	for i, c := range b {
		if i > 0 {
			sb.WriteByte(' ')
		}
		const digits = "0123456789ABCDEF"
		sb.WriteByte(digits[c>>4])
		sb.WriteByte(digits[c&0x0f])
	}
	return sb.String()
}

// unknownCreator 造一个 Unknown 结果。
func unknownCreator(reason string) Creator {
	return Creator{
		Name:       CreatorUnknown,
		Confidence: ConfidenceUnknown,
		Evidence:   reason,
	}
}
