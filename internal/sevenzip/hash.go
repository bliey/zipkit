// Package sevenzip 直接从 7z 容器里提取 hashcat -m 11600 需要的 $7z$ 哈希。
//
// 为什么不用 john 的 7z2john：john 的 Windows 构建里只有 7z2john.pl（Perl
// 脚本），没有对应的 .exe——不像 rar2john 那样有一个 9 KB 的存根可以转调
// john.exe。要跑它就得让用户自己装 Perl 和 Compress::Raw::Lzma，这跟「下载
// 即用」的目标冲突。所以这里按 7z2john.pl 的算法实现了一份原生提取器。
//
// 只覆盖 hashcat 能校验的几种编码链（AES 单独，或 AES + LZMA/LZMA2），
// 遇到 BCJ2、PPMd 这类多输入编码器会明确报错，而不是给一个校验不过的哈希。
//
// 哈希格式（与 7z2john.pl 一致）：
//
//	$7z$<type>$<cost>$<saltLen>$<salt>$<ivLen>$<iv>$<crc>$<dataLen>$<unpackLen>$<data>
//	                                                        [$<crcLen>$<coderAttrs>]
//
// 其中 type 为 0 表示解密后不用再解压，1/2 表示还要过 LZMA1/LZMA2，此时末尾
// 追加 CRC 校验长度和编码器属性。iv 不足 16 字节时补零后按 16 字节输出。
package sevenzip

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"

	"github.com/ulikunitz/xz/lzma"
)

// ErrUnsupported 表示这个归档用了当前实现没覆盖的编码器组合。
var ErrUnsupported = errors.New("sevenzip: 暂不支持这种 7z 结构")

// errNoAES 是内部哨兵：这组流里一个 AES 编码器都没有。
//
// 它必须和「结构错误」分开，因为两种情形要区别对待：解析头部流时发现没有
// AES，说明头部只是被压缩，应该先解出头部再往下一层找；而解析主数据流时
// 没有 AES，说明这本来就是个没加密的归档，要直接报错给用户。
var errNoAES = errors.New("sevenzip: 这组流里没有 AES 编码")

// 7z 头部的属性 ID。
const (
	idEnd                   = 0x00
	idHeader                = 0x01
	idArchiveProperties     = 0x02
	idAdditionalStreamsInfo = 0x03
	idMainStreamsInfo       = 0x04
	idFilesInfo             = 0x05
	idPackInfo              = 0x06
	idUnpackInfo            = 0x07
	idSubStreamsInfo        = 0x08
	idSize                  = 0x09
	idCRC                   = 0x0a
	idFolder                = 0x0b
	idCodersUnpackSize      = 0x0c
	idNumUnpackStream       = 0x0d
	idEncodedHeader         = 0x17
)

// 编码器 ID（小端存储，这里是按字节顺序写的）。
var (
	coderCopy  = []byte{0x00}
	coderAES   = []byte{0x06, 0xf1, 0x07, 0x01}
	coderLZMA  = []byte{0x03, 0x01, 0x01}
	coderLZMA2 = []byte{0x21}
)

// 数据类型：解密后是否还需要解压。
const (
	dataPlain  = 0 // 解密后直接算 CRC
	dataLZMA1  = 1
	dataLZMA2  = 2
	ivPadTo    = 16
	sigHdrSize = 32
)

// ExtractHash 读取 7z 文件并返回 $7z$ 哈希串。
func ExtractHash(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", fmt.Errorf("sevenzip: 打开失败：%w", err)
	}
	defer f.Close()

	info, err := f.Stat()
	if err != nil {
		return "", fmt.Errorf("sevenzip: 读取文件信息失败：%w", err)
	}
	size := info.Size()
	if size < sigHdrSize {
		return "", fmt.Errorf("%w：文件不足 %d 字节", ErrUnsupported, sigHdrSize)
	}

	var sig [sigHdrSize]byte
	if _, err := io.ReadFull(f, sig[:]); err != nil {
		return "", fmt.Errorf("sevenzip: 读取签名头失败：%w", err)
	}
	if string(sig[:6]) != "7z\xbc\xaf\x27\x1c" {
		return "", fmt.Errorf("%w：不是 7z 文件", ErrUnsupported)
	}

	nextOffset := binary.LittleEndian.Uint64(sig[12:20])
	nextSize := binary.LittleEndian.Uint64(sig[20:28])
	if nextSize == 0 || nextSize > 1<<28 {
		return "", fmt.Errorf("%w：头部长度异常（%d）", ErrUnsupported, nextSize)
	}
	dataStart := int64(sigHdrSize) + int64(nextOffset)
	if dataStart+int64(nextSize) > size {
		return "", fmt.Errorf("%w：头部越界，可能是分卷归档", ErrUnsupported)
	}

	next := make([]byte, nextSize)
	if _, err := f.ReadAt(next, dataStart); err != nil {
		return "", fmt.Errorf("sevenzip: 读取头部失败：%w", err)
	}

	streams, sel, err := locateTarget(f, size, next)
	if err != nil {
		return "", err
	}

	offset := int64(sigHdrSize) + int64(streams.packPos) + sel.packOffset
	if offset < 0 || offset+int64(sel.dataLen) > size {
		return "", fmt.Errorf("%w：加密数据越界", ErrUnsupported)
	}
	data := make([]byte, sel.dataLen)
	if _, err := f.ReadAt(data, offset); err != nil {
		return "", fmt.Errorf("sevenzip: 读取加密数据失败：%w", err)
	}

	return sel.buildHash(data)
}

// locateTarget 解析 NextHeader，定位「真正要拿去破解的那段加密数据」。
//
// 7z 的头部有两种形态，这里的处理差别很关键：
//
//   - kHeader（0x01）：明文头部，MainStreamsInfo 直接描述文件数据流，
//     从里面找带 AES 编码器的 folder 即可。
//   - kEncodedHeader（0x17）：头部**自己**存在一条流里。这条流可能只是被
//     压缩（-mhc=on，7-Zip 在条目数 ≥ 2 且头部未加密时的默认行为），也可能
//     连压缩带加密（-mhe=on）。前者的 StreamsInfo 描述的是头部，不是文件数据；
//     直接拿它去找 AES 会一无所获——这正是「仅加密数据、未加密文件名」的
//     7z 一直报「归档里没有 AES 加密的数据流」的原因。
//
// 所以这里分两步：头部流带 AES 就直接拿它当目标（没有密码解不开，但密码
// 对不对一样能验证，7z2john 也是这么做的）；不带 AES 就先把头部解出来，
// 再按明文头部的方式往下找。
func locateTarget(f *os.File, size int64, next []byte) (*streamsInfo, *selection, error) {
	cur := &cursor{b: next}
	headerID, err := cur.u8()
	if err != nil {
		return nil, nil, fmt.Errorf("sevenzip: 头部不完整：%w", err)
	}

	switch headerID {
	case idHeader:
		return targetFromHeader(cur)

	case idEncodedHeader:
		hdr, err := readStreamsInfo(cur)
		if err != nil {
			return nil, nil, err
		}
		sel, err := hdr.pickEncrypted()
		if err == nil {
			// 头部被加密（-mhe=on）：目标就是头部流本身。
			return hdr, sel, nil
		}
		if !errors.Is(err, errNoAES) {
			return nil, nil, err
		}

		decoded, err := decodeHeaderStream(f, size, hdr)
		if err != nil {
			return nil, nil, err
		}
		cur = &cursor{b: decoded}
		id, err := cur.u8()
		if err != nil {
			return nil, nil, fmt.Errorf("sevenzip: 解出的头部不完整：%w", err)
		}
		if id != idHeader {
			return nil, nil, fmt.Errorf("%w：解出的头部类型是 0x%02x，不是 Header", ErrUnsupported, id)
		}
		return targetFromHeader(cur)
	}
	return nil, nil, fmt.Errorf("%w：未知的头部类型 0x%02x", ErrUnsupported, headerID)
}

// targetFromHeader 从明文头部里读出主数据流并挑出加密 folder。
func targetFromHeader(cur *cursor) (*streamsInfo, *selection, error) {
	streams, err := scanMainStreams(cur)
	if err != nil {
		return nil, nil, err
	}
	if streams == nil {
		return nil, nil, fmt.Errorf("%w：归档里没有数据流（空归档？）", ErrUnsupported)
	}
	sel, err := streams.pickEncrypted()
	if err != nil {
		if errors.Is(err, errNoAES) {
			return nil, nil, fmt.Errorf("%w：归档里没有 AES 加密的数据流", ErrUnsupported)
		}
		return nil, nil, err
	}
	return streams, sel, nil
}

// ---------------------------------------------------------------- 数据结构

type coder struct {
	id     []byte
	props  []byte
	numIn  int
	numOut int
}

type folder struct {
	coders   []coder
	totalIn  int
	totalOut int
	// unpackSizes 是每个输出流的长度。线性链里 unpackSizes[0] 是第一个
	// 编码器（AES）的输出长度，最后一个是整个 folder 解压后的长度。
	unpackSizes []uint64
	// crc / crcDefined 来自 UnpackInfo 里的 folder 摘要。
	crc        uint32
	crcDefined bool
	// 子流信息（SubStreamsInfo）。
	subSizes    []uint64
	subCRCs     []uint32
	subCRCDef   []bool
	packStreams int
}

// finalSize 是整个 folder 解压后的长度。
func (f *folder) finalSize() uint64 {
	if len(f.unpackSizes) == 0 {
		return 0
	}
	return f.unpackSizes[len(f.unpackSizes)-1]
}

type streamsInfo struct {
	packPos   uint64
	packSizes []uint64
	folders   []*folder
}

// selection 描述「取哪个 folder、读哪段数据、用什么参数算 CRC」。
type selection struct {
	packOffset int64
	dataLen    int
	// unpackLen 是 AES 解码后的字节数（可能小于 dataLen，7z 会补零到块边界）。
	unpackLen  uint64
	crc        uint32
	crcLen     uint64
	cycles     uint8
	salt       []byte
	iv         []byte
	dataType   int
	coderAttrs []byte
}

// ---------------------------------------------------------------- 解析

func readStreamsInfo(cur *cursor) (*streamsInfo, error) {
	si := &streamsInfo{}

	// PackInfo
	id, err := cur.u8()
	if err != nil {
		return nil, fmt.Errorf("sevenzip: 读取 PackInfo 失败：%w", err)
	}
	if id != idPackInfo {
		return nil, fmt.Errorf("%w：缺少 PackInfo（0x%02x）", ErrUnsupported, id)
	}
	si.packPos, err = cur.number()
	if err != nil {
		return nil, err
	}
	numPack, err := cur.number()
	if err != nil {
		return nil, err
	}
	if numPack > 1<<20 {
		return nil, fmt.Errorf("%w：打包流数量异常（%d）", ErrUnsupported, numPack)
	}
	si.packSizes = make([]uint64, numPack)
	for {
		pid, err := cur.u8()
		if err != nil {
			return nil, err
		}
		switch pid {
		case idSize:
			for i := range si.packSizes {
				if si.packSizes[i], err = cur.number(); err != nil {
					return nil, err
				}
			}
		case idCRC:
			if _, _, err := cur.digests(int(numPack)); err != nil {
				return nil, err
			}
		case idEnd:
			goto unpack
		default:
			return nil, fmt.Errorf("%w：PackInfo 里出现未知 ID 0x%02x", ErrUnsupported, pid)
		}
	}

unpack:
	// UnpackInfo
	if id, err = cur.u8(); err != nil {
		return nil, err
	}
	if id != idUnpackInfo {
		return nil, fmt.Errorf("%w：缺少 UnpackInfo（0x%02x）", ErrUnsupported, id)
	}
	if id, err = cur.u8(); err != nil {
		return nil, err
	}
	if id != idFolder {
		return nil, fmt.Errorf("%w：缺少 kFolder（0x%02x）", ErrUnsupported, id)
	}
	numFolders, err := cur.number()
	if err != nil {
		return nil, err
	}
	if numFolders == 0 || numFolders > 1<<20 {
		return nil, fmt.Errorf("%w：folder 数量异常（%d）", ErrUnsupported, numFolders)
	}
	external, err := cur.u8()
	if err != nil {
		return nil, err
	}
	if external != 0 {
		return nil, fmt.Errorf("%w：folder 定义在外部流里", ErrUnsupported)
	}
	si.folders = make([]*folder, numFolders)
	for i := range si.folders {
		fd, err := readFolder(cur)
		if err != nil {
			return nil, err
		}
		si.folders[i] = fd
	}

	if id, err = cur.u8(); err != nil {
		return nil, err
	}
	if id != idCodersUnpackSize {
		return nil, fmt.Errorf("%w：缺少 kCodersUnpackSize（0x%02x）", ErrUnsupported, id)
	}
	for _, fd := range si.folders {
		fd.unpackSizes = make([]uint64, fd.totalOut)
		for j := 0; j < fd.totalOut; j++ {
			n, err := cur.number()
			if err != nil {
				return nil, err
			}
			fd.unpackSizes[j] = n
		}
	}
	for {
		uid, err := cur.u8()
		if err != nil {
			return nil, err
		}
		switch uid {
		case idCRC:
			crcs, defined, err := cur.digests(int(numFolders))
			if err != nil {
				return nil, err
			}
			for i, fd := range si.folders {
				fd.crc = crcs[i]
				fd.crcDefined = defined[i]
			}
		case idEnd:
			goto subs
		default:
			return nil, fmt.Errorf("%w：UnpackInfo 里出现未知 ID 0x%02x", ErrUnsupported, uid)
		}
	}

subs:
	// SubStreamsInfo 可以整段缺席。
	id, err = cur.u8()
	if err != nil {
		return nil, err
	}
	if id == idSubStreamsInfo {
		if err := readSubStreams(cur, si); err != nil {
			return nil, err
		}
	}

	// 每个 folder 假设只有一个打包流：这样 pack 索引就等于 folder 索引。
	for _, fd := range si.folders {
		if fd.packStreams != 1 {
			return nil, fmt.Errorf("%w：folder 有 %d 个打包流", ErrUnsupported, fd.packStreams)
		}
		if len(fd.subSizes) == 0 {
			fd.subSizes = []uint64{fd.finalSize()}
			fd.subCRCs = []uint32{fd.crc}
			fd.subCRCDef = []bool{fd.crcDefined}
		}
	}
	return si, nil
}

// scanMainStreams 在明文头部里找到 MainStreamsInfo。
func scanMainStreams(cur *cursor) (*streamsInfo, error) {
	for {
		id, err := cur.u8()
		if err != nil {
			return nil, fmt.Errorf("sevenzip: 头部提前结束：%w", err)
		}
		switch id {
		case idEnd, idFilesInfo:
			// 文件名等信息对提哈希没用，到这里就可以停了。
			return nil, nil
		case idArchiveProperties:
			if err := skipProperties(cur); err != nil {
				return nil, err
			}
		case idAdditionalStreamsInfo:
			if _, err := readStreamsInfo(cur); err != nil {
				return nil, err
			}
		case idMainStreamsInfo:
			return readStreamsInfo(cur)
		default:
			return nil, fmt.Errorf("%w：头部里出现未知 ID 0x%02x", ErrUnsupported, id)
		}
	}
}

func skipProperties(cur *cursor) error {
	for {
		id, err := cur.u8()
		if err != nil {
			return err
		}
		if id == idEnd {
			return nil
		}
		if _, err := cur.number(); err != nil {
			return err
		}
		n, err := cur.number()
		if err != nil {
			return err
		}
		if _, err := cur.take(int(n)); err != nil {
			return err
		}
	}
}

func readFolder(cur *cursor) (*folder, error) {
	numCoders, err := cur.number()
	if err != nil {
		return nil, err
	}
	if numCoders == 0 || numCoders > 64 {
		return nil, fmt.Errorf("%w：编码器数量异常（%d）", ErrUnsupported, numCoders)
	}

	fd := &folder{}
	for i := uint64(0); i < numCoders; i++ {
		flags, err := cur.u8()
		if err != nil {
			return nil, err
		}
		idLen := int(flags & 0x0f)
		id, err := cur.take(idLen)
		if err != nil {
			return nil, err
		}
		c := coder{id: id, numIn: 1, numOut: 1}
		// 字段顺序是 id → (numIn, numOut) → (propsSize, props)。
		if flags&0x10 != 0 {
			nin, err := cur.number()
			if err != nil {
				return nil, err
			}
			nout, err := cur.number()
			if err != nil {
				return nil, err
			}
			c.numIn, c.numOut = int(nin), int(nout)
		}
		if flags&0x20 != 0 {
			propLen, err := cur.number()
			if err != nil {
				return nil, err
			}
			if c.props, err = cur.take(int(propLen)); err != nil {
				return nil, err
			}
		}
		fd.coders = append(fd.coders, c)
		fd.totalIn += c.numIn
		fd.totalOut += c.numOut
	}

	bindPairs := fd.totalOut - 1
	if bindPairs < 0 {
		return nil, fmt.Errorf("%w：folder 输出流数量异常", ErrUnsupported)
	}
	for i := 0; i < bindPairs; i++ {
		if _, err := cur.number(); err != nil {
			return nil, err
		}
		if _, err := cur.number(); err != nil {
			return nil, err
		}
	}
	fd.packStreams = fd.totalIn - bindPairs
	if fd.packStreams > 1 {
		for i := 0; i < fd.packStreams; i++ {
			if _, err := cur.number(); err != nil {
				return nil, err
			}
		}
	}
	if fd.packStreams < 1 {
		return nil, fmt.Errorf("%w：folder 没有打包流", ErrUnsupported)
	}
	return fd, nil
}

func readSubStreams(cur *cursor, si *streamsInfo) error {
	for _, fd := range si.folders {
		fd.subSizes = []uint64{fd.finalSize()}
	}
	numStreams := make([]uint64, len(si.folders))
	for i := range numStreams {
		numStreams[i] = 1
	}

	for {
		id, err := cur.u8()
		if err != nil {
			return err
		}
		switch id {
		case idNumUnpackStream:
			for i := range numStreams {
				if numStreams[i], err = cur.number(); err != nil {
					return err
				}
			}
		case idSize:
			for i, fd := range si.folders {
				n := numStreams[i]
				if n == 0 {
					fd.subSizes = nil
					continue
				}
				sizes := make([]uint64, n)
				var sum uint64
				for j := uint64(0); j+1 < n; j++ {
					if sizes[j], err = cur.number(); err != nil {
						return err
					}
					sum += sizes[j]
				}
				if fd.finalSize() < sum {
					return fmt.Errorf("%w：子流长度超过 folder 长度", ErrUnsupported)
				}
				sizes[n-1] = fd.finalSize() - sum
				fd.subSizes = sizes
			}
		case idCRC:
			// 只有一个子流、且 folder 摘要已定义时，子流摘要不单独存储。
			total := 0
			for i, fd := range si.folders {
				if numStreams[i] == 1 && fd.crcDefined {
					continue
				}
				total += int(numStreams[i])
			}
			crcs, defined, err := cur.digests(total)
			if err != nil {
				return err
			}
			pos := 0
			for i, fd := range si.folders {
				n := int(numStreams[i])
				fd.subCRCs = make([]uint32, n)
				fd.subCRCDef = make([]bool, n)
				if n == 1 && fd.crcDefined {
					fd.subCRCs[0] = fd.crc
					fd.subCRCDef[0] = true
					continue
				}
				for j := 0; j < n; j++ {
					fd.subCRCs[j] = crcs[pos]
					fd.subCRCDef[j] = defined[pos]
					pos++
				}
			}
		case idEnd:
			return nil
		default:
			return fmt.Errorf("%w：SubStreamsInfo 里出现未知 ID 0x%02x", ErrUnsupported, id)
		}
	}
}

// ---------------------------------------------------------------- 选取与组装

// pickEncrypted 找到第一个带 AES 编码器的 folder，并算出取数参数。
func (si *streamsInfo) pickEncrypted() (*selection, error) {
	var packOffset int64
	for idx, fd := range si.folders {
		sel, err := buildSelection(fd, idx, si.packSizes)
		if err != nil {
			return nil, err
		}
		if sel != nil {
			sel.packOffset = packOffset
			return sel, nil
		}
		if idx < len(si.packSizes) {
			packOffset += int64(si.packSizes[idx])
		}
	}
	return nil, errNoAES
}

func buildSelection(fd *folder, idx int, packSizes []uint64) (*selection, error) {
	aesAt := -1
	for i, c := range fd.coders {
		if bytesEqual(c.id, coderAES) {
			aesAt = i
			break
		}
	}
	if aesAt < 0 {
		return nil, nil
	}
	if aesAt != 0 {
		// AES 前面还有编码器，说明数据先被压缩再加密，这种链 7z 不会产生。
		return nil, fmt.Errorf("%w：AES 不在编码链首位", ErrUnsupported)
	}
	if fd.totalIn != len(fd.coders) || fd.totalOut != len(fd.coders) {
		return nil, fmt.Errorf("%w：编码链不是线性结构（可能是 BCJ2）", ErrUnsupported)
	}
	if idx >= len(packSizes) {
		return nil, fmt.Errorf("%w：folder 索引超出打包流数量", ErrUnsupported)
	}

	sel := &selection{dataLen: int(packSizes[idx])}
	if sel.dataLen <= 0 {
		return nil, fmt.Errorf("%w：加密数据长度为 0", ErrUnsupported)
	}
	if len(fd.unpackSizes) == 0 {
		return nil, fmt.Errorf("%w：缺少解压后长度", ErrUnsupported)
	}
	sel.unpackLen = fd.unpackSizes[0]
	if sel.unpackLen == 0 || sel.unpackLen > uint64(sel.dataLen) {
		return nil, fmt.Errorf("%w：AES 输出长度异常（%d/%d）", ErrUnsupported, sel.unpackLen, sel.dataLen)
	}

	cycles, salt, iv, err := parseAESProps(fd.coders[aesAt].props)
	if err != nil {
		return nil, err
	}
	sel.cycles, sel.salt, sel.iv = cycles, salt, iv

	// AES 之后的编码器决定解密后还要不要解压。
	if len(fd.coders) > 1 {
		next := fd.coders[1]
		switch {
		case bytesEqual(next.id, coderCopy):
			// Store（-mx=0）：解密出来就是原始数据，CRC 直接算在明文上，
			// 所以 dataType=0，哈希不带尾部两个字段。
			sel.dataType = dataPlain
		case bytesEqual(next.id, coderLZMA):
			sel.dataType = dataLZMA1
			sel.coderAttrs = next.props
			if len(sel.coderAttrs) != 5 {
				return nil, fmt.Errorf("%w：LZMA 属性长度异常（%d）", ErrUnsupported, len(sel.coderAttrs))
			}
		case bytesEqual(next.id, coderLZMA2):
			sel.dataType = dataLZMA2
			sel.coderAttrs = next.props
			if len(sel.coderAttrs) != 1 {
				return nil, fmt.Errorf("%w：LZMA2 属性长度异常（%d）", ErrUnsupported, len(sel.coderAttrs))
			}
		default:
			return nil, fmt.Errorf("%w：AES 之后的编码器 %x 不在支持范围内", ErrUnsupported, next.id)
		}
		if len(fd.coders) > 2 {
			return nil, fmt.Errorf("%w：编码链超过两级", ErrUnsupported)
		}
	}

	// CRC 优先用 folder 摘要（覆盖整个 folder 输出），否则退回第一个子流。
	switch {
	case fd.crcDefined:
		sel.crc = fd.crc
		sel.crcLen = fd.finalSize()
	case len(fd.subCRCDef) > 0 && fd.subCRCDef[0]:
		sel.crc = fd.subCRCs[0]
		sel.crcLen = fd.subSizes[0]
	default:
		return nil, fmt.Errorf("%w：归档里没有可用的 CRC，无法校验", ErrUnsupported)
	}
	if sel.crcLen == 0 {
		return nil, fmt.Errorf("%w：CRC 校验长度为 0", ErrUnsupported)
	}
	return sel, nil
}

// parseAESProps 按 7zAES 的属性格式取出迭代次数、salt 和 iv。
func parseAESProps(props []byte) (cycles uint8, salt, iv []byte, err error) {
	if len(props) < 1 {
		return 0, nil, nil, fmt.Errorf("%w：AES 属性为空", ErrUnsupported)
	}
	first := props[0]
	cycles = first & 0x3f
	if first&0xc0 == 0 {
		// 没有 salt 和 iv，用 7z 的默认 iv（全零，16 字节）。
		return cycles, nil, make([]byte, ivPadTo), nil
	}
	if len(props) < 2 {
		return 0, nil, nil, fmt.Errorf("%w：AES 属性不完整", ErrUnsupported)
	}
	saltLen := int((first>>7)&1) + int(props[1]>>4)
	ivLen := int((first>>6)&1) + int(props[1]&0x0f)
	pos := 2
	if pos+saltLen+ivLen > len(props) {
		return 0, nil, nil, fmt.Errorf("%w：AES 属性长度与实际不符", ErrUnsupported)
	}
	salt = props[pos : pos+saltLen]
	pos += saltLen
	iv = props[pos : pos+ivLen]

	// iv 补零到 16 字节再输出，和 7z2john.pl 保持一致。
	padded := make([]byte, ivPadTo)
	copy(padded, iv)
	return cycles, salt, padded, nil
}

// maxHeaderDecoded 是解出头部的长度上限。头部通常只有几十 KB，
// 给到 64 MB 是为了容纳几万个条目的归档，同时挡住恶意文件撑爆内存。
const maxHeaderDecoded = 64 << 20

// decodeHeaderStream 把 kEncodedHeader 描述的那条流解成明文字节。
//
// 只处理 Copy / LZMA1 / LZMA2 三种编码器：头部流被加密的情形在调用方已经
// 提前拦掉了（没有密码就解不开），剩下的组合 7-Zip 只会写这几种。
func decodeHeaderStream(f *os.File, size int64, si *streamsInfo) ([]byte, error) {
	if len(si.folders) != 1 {
		return nil, fmt.Errorf("%w：头部流有 %d 个 folder，只支持 1 个", ErrUnsupported, len(si.folders))
	}
	if len(si.packSizes) != 1 {
		return nil, fmt.Errorf("%w：头部流有 %d 个打包流，只支持 1 个", ErrUnsupported, len(si.packSizes))
	}
	fd := si.folders[0]
	if fd.packStreams != 1 {
		return nil, fmt.Errorf("%w：头部流有 %d 个打包流", ErrUnsupported, fd.packStreams)
	}
	if fd.totalIn != len(fd.coders) || fd.totalOut != len(fd.coders) {
		return nil, fmt.Errorf("%w：头部流编码链不是线性结构", ErrUnsupported)
	}

	offset := int64(sigHdrSize) + int64(si.packPos)
	packedLen := int64(si.packSizes[0])
	if offset < 0 || packedLen <= 0 || offset+packedLen > size {
		return nil, fmt.Errorf("%w：头部流越界", ErrUnsupported)
	}
	packed := make([]byte, packedLen)
	if _, err := f.ReadAt(packed, offset); err != nil {
		return nil, fmt.Errorf("sevenzip: 读取头部流失败：%w", err)
	}

	data := packed
	for i, c := range fd.coders {
		var out uint64
		if i < len(fd.unpackSizes) {
			out = fd.unpackSizes[i]
		}
		var err error
		switch {
		case bytesEqual(c.id, coderCopy):
			// 原样通过，不需要动。
		case bytesEqual(c.id, coderLZMA):
			data, err = decodeLZMA1(data, c.props, out)
		case bytesEqual(c.id, coderLZMA2):
			data, err = decodeLZMA2(data, c.props, out)
		case bytesEqual(c.id, coderAES):
			return nil, fmt.Errorf("%w：头部流被加密，没有密码无法解开", ErrUnsupported)
		default:
			return nil, fmt.Errorf("%w：头部流用了不支持的编码器 %x", ErrUnsupported, c.id)
		}
		if err != nil {
			return nil, err
		}
	}
	if len(data) == 0 {
		return nil, fmt.Errorf("%w：解出的头部是空的", ErrUnsupported)
	}
	return data, nil
}

// decodeLZMA1 解 7z 里的 LZMA1 流。
//
// 7z 的 LZMA1 coder 只存 5 字节属性（lc/lp/pb + 字典大小），而
// ulikunitz/xz 的 Reader 吃的是 .lzma 容器的 13 字节头，所以这里把
// 「5 字节属性 + 8 字节原始长度」拼在前面喂给它。
func decodeLZMA1(data, props []byte, out uint64) ([]byte, error) {
	if len(props) != 5 {
		return nil, fmt.Errorf("%w：LZMA 属性是 %d 字节，应为 5", ErrUnsupported, len(props))
	}
	if out == 0 || out > maxHeaderDecoded {
		return nil, fmt.Errorf("%w：LZMA 解出长度异常（%d）", ErrUnsupported, out)
	}
	head := make([]byte, 13)
	copy(head, props)
	binary.LittleEndian.PutUint64(head[5:], out)

	// DictCap 只是上限校验，真正的字典按头部声明的字典大小与解出长度取小值，
	// 所以这里给最大值不会真的分配 4 GB。
	cfg := lzma.ReaderConfig{DictCap: lzma.MaxDictCap}
	r, err := cfg.NewReader(io.MultiReader(bytes.NewReader(head), bytes.NewReader(data)))
	if err != nil {
		return nil, fmt.Errorf("%w：LZMA 头部无法解析：%v", ErrUnsupported, err)
	}
	return readAllHeader(r)
}

// decodeLZMA2 解 7z 里的 LZMA2 流。属性只有 1 字节，是字典大小编码。
func decodeLZMA2(data, props []byte, out uint64) ([]byte, error) {
	if len(props) != 1 {
		return nil, fmt.Errorf("%w：LZMA2 属性是 %d 字节，应为 1", ErrUnsupported, len(props))
	}
	if out == 0 || out > maxHeaderDecoded {
		return nil, fmt.Errorf("%w：LZMA2 解出长度异常（%d）", ErrUnsupported, out)
	}
	cfg := lzma.Reader2Config{DictCap: lzma2DictCap(props[0], out)}
	r, err := cfg.NewReader2(bytes.NewReader(data))
	if err != nil {
		return nil, fmt.Errorf("%w：LZMA2 流无法解析：%v", ErrUnsupported, err)
	}
	return readAllHeader(r)
}

// lzma2DictCap 把 LZMA2 的字典大小属性换算成字节数。
//
// 这个编码来自 7z 规范：prop = 40 表示 4 GiB - 1，其余情况
// dictSize = (2 | (prop & 1)) << (prop / 2 + 11)。
//
// 返回值会被压到「解出长度」量级：字典只影响向后引用的距离，而整条流总共
// 才 out 字节，用不到更大的字典。不这么压，ulikunitz/xz 会按声明值一次性
// 分配几十 MB。
func lzma2DictCap(prop byte, out uint64) int {
	var size uint64
	switch {
	case prop > 40:
		size = lzma.MinDictCap
	case prop == 40:
		size = 1<<32 - 1
	default:
		size = uint64(2|(prop&1)) << (prop/2 + 11)
	}
	if out > 0 && size > out {
		size = out
	}
	if size < lzma.MinDictCap {
		size = lzma.MinDictCap
	}
	if size > 1<<32-1 {
		size = 1<<32 - 1
	}
	return int(size)
}

// readAllHeader 读完解码器输出，并挡住超出上限的头部。
func readAllHeader(r io.Reader) ([]byte, error) {
	out, err := io.ReadAll(io.LimitReader(r, maxHeaderDecoded+1))
	if err != nil {
		return nil, fmt.Errorf("%w：解压头部失败：%v", ErrUnsupported, err)
	}
	if len(out) > maxHeaderDecoded {
		return nil, fmt.Errorf("%w：解出的头部超过 %d 字节", ErrUnsupported, maxHeaderDecoded)
	}
	return out, nil
}

// buildHash 把选中的密文与参数拼成 $7z$ 字符串。
func (s *selection) buildHash(data []byte) (string, error) {
	hash := fmt.Sprintf("$7z$%d$%d$%d$%s$%d$%s$%d$%d$%d$%s",
		s.dataType,
		s.cycles,
		len(s.salt), hex.EncodeToString(s.salt),
		len(s.iv), hex.EncodeToString(s.iv),
		s.crc,
		len(data),
		s.unpackLen,
		hex.EncodeToString(data),
	)
	if s.dataType != dataPlain {
		hash += fmt.Sprintf("$%d$%s", s.crcLen, hex.EncodeToString(s.coderAttrs))
	}
	return hash, nil
}

// ---------------------------------------------------------------- 读取工具

type cursor struct {
	b []byte
	i int
}

func (c *cursor) u8() (byte, error) {
	if c.i >= len(c.b) {
		return 0, io.ErrUnexpectedEOF
	}
	v := c.b[c.i]
	c.i++
	return v, nil
}

func (c *cursor) take(n int) ([]byte, error) {
	if n < 0 || c.i+n > len(c.b) {
		return nil, io.ErrUnexpectedEOF
	}
	v := c.b[c.i : c.i+n]
	c.i += n
	return v, nil
}

// number 解 7z 的变长整数编码。
func (c *cursor) number() (uint64, error) {
	first, err := c.u8()
	if err != nil {
		return 0, err
	}
	var value uint64
	mask := byte(0x80)
	for i := 0; i < 8; i++ {
		if first&mask == 0 {
			value |= uint64(first&(mask-1)) << (8 * uint(i))
			return value, nil
		}
		b, err := c.u8()
		if err != nil {
			return 0, err
		}
		value |= uint64(b) << (8 * uint(i))
		mask >>= 1
	}
	return value, nil
}

// digests 读一组 CRC：先读「是否全部定义」，未全部定义时再读位图。
func (c *cursor) digests(n int) ([]uint32, []bool, error) {
	if n < 0 || n > 1<<20 {
		return nil, nil, fmt.Errorf("%w：摘要数量异常（%d）", ErrUnsupported, n)
	}
	defined := make([]bool, n)
	allDefined, err := c.u8()
	if err != nil {
		return nil, nil, err
	}
	if allDefined != 0 {
		for i := range defined {
			defined[i] = true
		}
	} else {
		mask := byte(0)
		for i := range defined {
			if mask == 0 {
				if mask, err = c.u8(); err != nil {
					return nil, nil, err
				}
			}
			defined[i] = mask&0x80 != 0
			mask <<= 1
		}
	}
	crcs := make([]uint32, n)
	for i := range defined {
		if !defined[i] {
			continue
		}
		raw, err := c.take(4)
		if err != nil {
			return nil, nil, err
		}
		crcs[i] = binary.LittleEndian.Uint32(raw)
	}
	return crcs, defined, nil
}

func bytesEqual(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
