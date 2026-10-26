// Package hashextract 从加密归档中提取 hashcat 可识别的哈希字符串。
//
// 支持三类来源：
//
//  1. ZIP AES（WinZip AES，AE-1/AE-2）—— 本包自行解析，不依赖 john。
//     输出 $zip2$ 格式，对应 hashcat mode 13600。
//  2. ZIP ZipCrypto（传统加密）—— 本包自行解析，不依赖 john。
//     输出 $pkzip2$ 格式，Deflate 走 mode 17200、Store 走 mode 17210。
//  3. RAR5 / 7z —— 调用 john 的 rar2john / 7z2john 提取，
//     分别输出 $rar5$（mode 13000）与 $7z$（mode 11600）。
//
// $zip2$ 的字段布局来自 hashcat module_13600.c 的 module_hash_decode，
// 以及 john 的 zip2john.c 中 process_aes() 的输出逻辑，两者一致：
//
//	$zip2$*Ty*Mo*Ma*Sa*Va*Le*DF*Au*$/zip2$
//
//	Ty = type，固定 0（hashcat 只接受 0）
//	Mo = mode = AES 强度 1/2/3 → AES-128/192/256，盐长度 = 4 + 4*mode
//	Ma = magic，固定 0
//	Sa = salt，十六进制，8/12/16 字节
//	Va = 2 字节密码校验值，按文件中的原始字节序输出（4 个十六进制字符）
//	Le = 纯密文长度（十六进制）= 压缩长度 - 盐 - 2 - 10
//	DF = 纯密文（十六进制），不含盐、校验值与认证码
//	Au = 10 字节 HMAC-SHA1 认证码（20 个十六进制字符）
//
// 特别注意：这个格式里没有 CRC 字段（AE-2 本来就不写 CRC），
// 校验完全依赖 Au —— 它是对密文做 HMAC-SHA1 的结果，密钥由 PBKDF2-HMAC-SHA1
// （1000 轮）从口令与盐派生。
package hashextract

import (
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/bliey/zipkit/internal/executil"
	"github.com/bliey/zipkit/internal/sevenzip"
	"github.com/bliey/zipkit/internal/zipservice"
)

// hashcat 模式号。
const (
	ModeZip2 = 13600 // WinZip AES（$zip2$）
	ModeRAR5 = 13000 // RAR5（$rar5$）
	Mode7z   = 11600 // 7-Zip（$7z$）

	// ZipCrypto（传统加密）的两个模式号。这两个号是**实测查证**的，不是照抄
	// 记忆：用本地 bin/hashcat-7.1.2/hashcat.exe --example-hashes 列出 17xxx
	// 段的全部条目，再用真实文件回验：
	//
	//	17200 = PKZIP (Compressed)   只接受 Deflate 压缩的条目
	//	17210 = PKZIP (Uncompressed) 只接受 Store（不压缩）的条目
	//
	// 回验过程：internal/hashextract/testdata/zipcrypto.zip 里的条目是 Store
	// （cmplen=57 / decmplen=45），把它生成的 $pkzip2$ 交给 -m 17200 会直接报
	//   Hash contains unsupported compression type for current mode
	//   No hashes loaded.
	// 换成 -m 17210 立刻解出 123456；而 Deflate 条目（alpha6.zip）反过来只在
	// 17200 下工作。所以这里必须按条目真实的压缩方法二选一，写死任何一个都会
	// 让另一半文件「No hashes loaded」。
	//
	// 另外注意 20500 是 PKZIP Master Key（16 字节裸密钥，形如
	// f1eff5c0368d10311dcfc419），不是条目哈希，不能拿来跑这里生成的串。
	ModeZipCryptoDeflate = 17200
	ModeZipCryptoStore   = 17210
)

// 格式名，用于界面展示。
const (
	FormatZIPAES    = "ZIP-AES"
	FormatZipCrypto = "ZIP-ZipCrypto"
	FormatRAR5      = "RAR5"
	Format7z        = "7z"
)

// 来源标记。
const (
	SourceBuiltin = "builtin"
	SourceZip2    = "zip2john"
	SourceRar2    = "rar2john"
	Source7z2     = "7z2john"
	// Source7z2Hashcat 表示哈希来自 philsmd 的 7z2hashcat（Perl 脚本或 .exe）。
	Source7z2Hashcat = "7z2hashcat"
)

// ZIP AES 的数据布局常量。
const (
	aesSaltBase       = 4  // 盐长度 = aesSaltBase + aesSaltStep*strength
	aesSaltStep       = 4  // → strength 1/2/3 对应 8/12/16 字节
	aesVerifierLength = 2  // 密码校验值
	aesAuthLength     = 10 // HMAC-SHA1 截断到 10 字节
	aesOverhead       = aesVerifierLength + aesAuthLength
)

// localHeaderLength 是本地文件头的固定长度（不含文件名与扩展字段）。
const localHeaderLength = 30

// HashResult 是一次哈希提取的结果。
type HashResult struct {
	Hash     string   `json:"hash"`     // hashcat 可识别的哈希字符串（以 $xxx$ 开头、$ 结尾）
	Mode     int      `json:"mode"`     // hashcat 模式号
	Format   string   `json:"format"`   // "ZIP-AES" / "RAR5" / "7z"
	Source   string   `json:"source"`   // "builtin" / "zip2john" / "rar2john" / "7z2john"
	Warnings []string `json:"warnings"` // 非致命提示，例如密文为空
}

// 提取过程中可能返回的错误。
var (
	// ErrNoAESEntry 表示归档里没有 AES 加密的条目。
	ErrNoAESEntry = errors.New("hashextract: 没有找到 AES 加密条目")
	// ErrEntryNotFound 表示中央目录中没有指定名称的条目。
	ErrEntryNotFound = errors.New("hashextract: 未找到指定条目")
	// ErrNotAESEntry 表示指定条目存在，但不是 AES 加密。
	ErrNotAESEntry = errors.New("hashextract: 指定条目不是 AES 加密")
	// ErrBadAESData 表示条目数据长度不足或越界，无法切分出盐与认证码。
	ErrBadAESData = errors.New("hashextract: AES 条目数据不完整")
	// ErrBadZipCryptoData 表示 ZipCrypto 条目的数据越界或长度不足。
	ErrBadZipCryptoData = errors.New("hashextract: ZipCrypto 条目数据不完整")
	// ErrNoHash 表示外部工具没有输出任何可识别的哈希。
	ErrNoHash = errors.New("hashextract: 工具没有输出可用的哈希")
	// ErrUnknownTool 表示无法从工具名判断是 rar2john 还是 7z2john。
	ErrUnknownTool = errors.New("hashextract: 无法识别的 john 工具")
	// ErrNoZipCryptoEntry 表示归档里没有 ZipCrypto 加密的条目。
	ErrNoZipCryptoEntry = errors.New("hashextract: 没有找到 ZipCrypto 加密条目")
	// ErrNotZipCryptoEntry 表示指定条目存在，但不是 ZipCrypto 加密。
	ErrNotZipCryptoEntry = errors.New("hashextract: 指定条目不是 ZipCrypto 加密")
	// ErrUnsupportedCompression 表示条目的压缩方法不是 hashcat 17xxx 段能处理的
	// Store / Deflate（例如 Deflate64、bzip2、LZMA、PPMd）。
	ErrUnsupportedCompression = errors.New("hashextract: 该压缩方法无法生成 $pkzip2$ 哈希")
	// ErrNoZipEntry 表示归档里一个条目都没有。
	ErrNoZipEntry = errors.New("hashextract: 归档中没有条目")
)

// runCommand 允许测试替换外部命令的执行。生产路径是 executil.Command(name, args...).Output()。
var runCommand = func(name string, args ...string) ([]byte, error) {
	cmd := executil.Command(name, args...)
	return cmd.Output()
}

// runScriptOutput 执行脚本并分别拿到 stdout 与 stderr。
//
// 和 runCommand 分开是因为 7z2hashcat 把哈希写 stdout、把诊断写 stderr，
// 两者都要用：成功时只取 stdout，失败时把 stderr 原样展示给用户。
var runScriptOutput = func(name string, args ...string) (stdout, stderr string, err error) {
	cmd := executil.Command(name, args...)
	var errBuf strings.Builder
	cmd.Stderr = &errBuf
	out, runErr := cmd.Output()
	return string(out), errBuf.String(), runErr
}

// execLookPath 允许测试替换 PATH 查找。
var execLookPath = exec.LookPath

// ExtractZIPAES 从 ZIP 中提取 WinZip AES 条目的 $zip2$ 哈希。
//
// entryName 为空时取第一个 AES 加密条目。哈希格式见包注释。
func ExtractZIPAES(zipPath, entryName string) (HashResult, error) {
	info, err := zipservice.Inspect(zipPath)
	if err != nil {
		return HashResult{}, err
	}
	entry, err := pickAESEntry(info.Entries, entryName)
	if err != nil {
		return HashResult{}, err
	}

	strength, ok := aesStrength(entry.EncryptionType)
	if !ok {
		return HashResult{}, fmt.Errorf("%w: 条目 %q 的加密类型为 %q",
			ErrNotAESEntry, entry.Name, entry.EncryptionType)
	}
	saltLen := aesSaltBase + aesSaltStep*strength

	if entry.CompressedSize < uint64(saltLen+aesOverhead) {
		return HashResult{}, fmt.Errorf("%w: 条目 %q 的压缩长度为 %d，不足 %d 字节",
			ErrBadAESData, entry.Name, entry.CompressedSize, saltLen+aesOverhead)
	}

	payload, err := readEntryPayload(zipPath, entry)
	if err != nil {
		return HashResult{}, err
	}

	salt := payload[:saltLen]
	verifier := payload[saltLen : saltLen+aesVerifierLength]
	cipher := payload[saltLen+aesVerifierLength : len(payload)-aesAuthLength]
	auth := payload[len(payload)-aesAuthLength:]

	res := HashResult{
		Hash: fmt.Sprintf("$zip2$*0*%x*0*%s*%s*%x*%s*%s*$/zip2$",
			strength,
			hex.EncodeToString(salt),
			hex.EncodeToString(verifier),
			len(cipher),
			hex.EncodeToString(cipher),
			hex.EncodeToString(auth),
		),
		Mode:   ModeZip2,
		Format: FormatZIPAES,
		Source: SourceBuiltin,
	}
	if len(cipher) == 0 {
		res.Warnings = append(res.Warnings, "条目密文为空（明文可能是 0 字节），仍可尝试破解")
	}
	if entry.Compression == "Unknown" {
		res.Warnings = append(res.Warnings,
			"条目的真实压缩方法未知，密码可以恢复，但解密后的内容可能无法直接解压")
	}
	return res, nil
}

// ---------------------------------------------------------------------------
// ZipCrypto（传统加密）→ $pkzip2$
// ---------------------------------------------------------------------------

// $pkzip2$ 的字段布局来自 hashcat src/modules/module_17200.c 的
// module_hash_decode / module_hash_encode，逐段对应如下（* 分隔）：
//
//	$pkzip2$<hash_count>*<checksum_size>*<data_type>*<magic_type>*
//	        <compressed_length>*<uncompressed_length>*<crc32>*<offset>*
//	        <additional_offset>*<compression_type>*<data_length>*
//	        <checksum_from_crc>*<checksum_from_timestamp>*<data>*$/pkzip2$
//
// 注意 <hash_count> 紧贴在 $pkzip2$ 后面、中间没有 *，因为 hashcat 是把
// 签名和这个数字当成同一个 token 解析的（$pkzip2$1 共 9 个字符 → version 2）。
//
// 各字段取值：
//
//	hash_count              固定 1（module 只接受单条目的哈希）
//	checksum_size           1 —— 传统加密的校验字节只有 1 字节
//	data_type               2 —— 表示后面带着完整的长度 / CRC 信息
//	magic_type              0
//	compressed_length       条目在文件里的存储长度（含 12 字节加密头）
//	uncompressed_length     条目解压后的长度
//	crc32                   中央目录里的 CRC32
//	offset                  0 —— 本实现只给一条哈希，不需要全局偏移
//	additional_offset       本地文件头之后、数据之前的那段长度
//	                        （= 30 + 文件名长度 + 扩展字段长度）
//	compression_type        8 = Deflate（mode 17200），0 = Store（mode 17210）
//	data_length             = len(data) = compressed_length
//	checksum_from_crc       CRC32 的高 16 位；checksum_size=1 时 hashcat 只用
//	                        它最高的那个字节，也就是传统加密写在加密头第 12
//	                        字节里的校验值
//	checksum_from_timestamp 本地文件头里的 DOS 修改时间。这个字段不是可选项：
//	                        置 0 时 hashcat 会直接 No hashes loaded（实测）
//	data                    条目在文件里的**原始存储字节**（12 字节加密头 +
//	                        加密后的压缩数据），按原样十六进制输出
//
// 与 AES 的区别：AES 的 $zip2$ 需要自己切出盐、校验值、密文、认证码四段；
// ZipCrypto 只需要按偏移把整段原始字节搬过来，所以这里完全自己解析，
// 不调用 john 的 zip2john。
func ExtractZipCrypto(zipPath, entryName string) (HashResult, error) {
	info, err := zipservice.Inspect(zipPath)
	if err != nil {
		return HashResult{}, err
	}
	entry, err := pickZipCryptoEntry(info.Entries, entryName)
	if err != nil {
		return HashResult{}, err
	}

	mode, compType, err := zipCryptoMode(entry)
	if err != nil {
		return HashResult{}, err
	}

	if entry.CompressedSize < zipCryptoHeaderLength {
		return HashResult{}, fmt.Errorf("%w: 条目 %q 的压缩长度只有 %d 字节，装不下 %d 字节的加密头",
			ErrBadZipCryptoData, entry.Name, entry.CompressedSize, zipCryptoHeaderLength)
	}

	payload, dosTime, additional, localCRC, err := readZipCryptoPayload(zipPath, entry)
	if err != nil {
		return HashResult{}, err
	}

	res := HashResult{
		Hash: fmt.Sprintf(
			"$pkzip2$1*1*2*0*%x*%x*%x*0*%x*%d*%x*%04x*%04x*%s*$/pkzip2$",
			entry.CompressedSize,
			entry.UncompressedSize,
			entry.CRC32,
			additional,
			compType,
			len(payload),
			uint16(entry.CRC32>>16),
			dosTime,
			hex.EncodeToString(payload),
		),
		Mode:   mode,
		Format: FormatZipCrypto,
		Source: SourceBuiltin,
	}

	if len(payload) > zipCryptoPayloadLimit {
		res.Warnings = append(res.Warnings, fmt.Sprintf(
			"条目数据有 %d 字节，超出 hashcat 单条目上限，可能被拒绝加载；建议改用字典工具",
			len(payload)))
	}
	if entry.GPFlags&0x0008 != 0 && localCRC == 0 {
		// 只有「数据描述符 + 本地 CRC 为 0」才是真问题：这时校验字节
		// 其实是 DOS 时间的高字节，$pkzip2$ 里的 checksum_from_crc 会失真。
		res.Warnings = append(res.Warnings,
			"条目的 CRC 写在数据之后（数据描述符），本地文件头里是 0，哈希可能校验不过")
	}
	return res, nil
}

// ExtractZIP 是 ZIP 的统一入口：按条目实际的加密类型选择 AES 或 ZipCrypto。
//
// entryName 为空时优先挑 AES 条目（$zip2$ 校验更可靠），没有 AES 再退到
// ZipCrypto。指定了条目就只认那一条，类型不符直接报错。
func ExtractZIP(zipPath, entryName string) (HashResult, error) {
	info, err := zipservice.Inspect(zipPath)
	if err != nil {
		return HashResult{}, err
	}
	if len(info.Entries) == 0 {
		return HashResult{}, fmt.Errorf("%w: %s", ErrNoZipEntry, filepath.Base(zipPath))
	}

	if entryName != "" {
		for _, e := range info.Entries {
			if e.Name != entryName {
				continue
			}
			if _, ok := aesStrength(e.EncryptionType); ok {
				return ExtractZIPAES(zipPath, entryName)
			}
			if e.EncryptionType == "ZipCrypto" {
				return ExtractZipCrypto(zipPath, entryName)
			}
			return HashResult{}, fmt.Errorf("%w: %q 的加密类型为 %q",
				ErrNotAESEntry, e.Name, e.EncryptionType)
		}
		return HashResult{}, fmt.Errorf("%w: %q", ErrEntryNotFound, entryName)
	}

	for _, e := range info.Entries {
		if _, ok := aesStrength(e.EncryptionType); ok {
			return ExtractZIPAES(zipPath, "")
		}
	}
	return ExtractZipCrypto(zipPath, "")
}

// zipCryptoHeaderLength 是传统加密写在数据最前面的 12 字节加密头。
const zipCryptoHeaderLength = 12

// zipCryptoPayloadLimit 是 hashcat 单条目数据段的上限（module 里 MAX_DATA）。
// 超过这个量级基本会被拒，先给用户一条提示。
const zipCryptoPayloadLimit = 1 << 20

// zipCryptoMode 把压缩方法映射成 (hashcat 模式号, $pkzip2$ 里的 compression_type)。
//
// 只有 Store 和 Deflate 能进 17xxx 段：hashcat 的 17200 校验 compression_type
// 必须是 8（Deflate），17210 对应 0（Store）。Deflate64 / bzip2 / LZMA / PPMd
// 这类压缩方法没有对应的模式，硬拼出来的哈希一定会 No hashes loaded，所以
// 这里直接报错，让界面给出明确原因。
func zipCryptoMode(e zipservice.Entry) (mode, compType int, err error) {
	switch e.Method {
	case 8:
		return ModeZipCryptoDeflate, 8, nil
	case 0:
		return ModeZipCryptoStore, 0, nil
	}
	return 0, 0, fmt.Errorf("%w: 条目 %q 的压缩方法是 %s（%d）",
		ErrUnsupportedCompression, e.Name, e.Compression, e.Method)
}

// pickZipCryptoEntry 选择目标条目：指定名称时精确匹配，否则取第一个 ZipCrypto 条目。
func pickZipCryptoEntry(entries []zipservice.Entry, name string) (zipservice.Entry, error) {
	if name != "" {
		for _, e := range entries {
			if e.Name != name {
				continue
			}
			if e.EncryptionType != "ZipCrypto" {
				return zipservice.Entry{}, fmt.Errorf("%w: %q 的加密类型为 %q",
					ErrNotZipCryptoEntry, e.Name, e.EncryptionType)
			}
			return e, nil
		}
		return zipservice.Entry{}, fmt.Errorf("%w: %q", ErrEntryNotFound, name)
	}
	for _, e := range entries {
		if e.EncryptionType == "ZipCrypto" {
			return e, nil
		}
	}
	if len(entries) == 0 {
		return zipservice.Entry{}, fmt.Errorf("%w: 归档中没有条目", ErrNoZipCryptoEntry)
	}
	return zipservice.Entry{}, fmt.Errorf("%w: 共 %d 个条目，全部不是 ZipCrypto 加密",
		ErrNoZipCryptoEntry, len(entries))
}

// readZipCryptoPayload 读出条目的原始存储字节，同时返回本地文件头里的
// DOS 修改时间、「数据相对本地文件头的偏移」和本地 CRC。
//
// 偏移必须以**本地文件头**为准：Zip64、对齐填充都会让扩展字段长度和中央
// 目录里记的不一样，用中央目录的值会让数据整体错位。
func readZipCryptoPayload(zipPath string, e zipservice.Entry) ([]byte, uint16, uint32, uint32, error) {
	f, err := os.Open(zipPath)
	if err != nil {
		return nil, 0, 0, 0, err
	}
	defer f.Close()

	st, err := f.Stat()
	if err != nil {
		return nil, 0, 0, 0, err
	}

	var lfh [localHeaderLength]byte
	if _, err := f.ReadAt(lfh[:], int64(e.LocalHeaderOffset)); err != nil {
		return nil, 0, 0, 0, fmt.Errorf("%w: 读取本地文件头失败: %v", ErrBadZipCryptoData, err)
	}
	if binary.LittleEndian.Uint32(lfh[:]) != sigLocalHeader {
		return nil, 0, 0, 0, fmt.Errorf("%w: 本地文件头签名错误（偏移 %d）",
			ErrBadZipCryptoData, e.LocalHeaderOffset)
	}

	// 本地文件头的第 10–11 字节是 DOS 修改时间，hashcat 的
	// checksum_from_timestamp 就是它。
	dosTime := binary.LittleEndian.Uint16(lfh[10:])
	localCRC := binary.LittleEndian.Uint32(lfh[14:])
	nameLen := int64(binary.LittleEndian.Uint16(lfh[26:]))
	extraLen := int64(binary.LittleEndian.Uint16(lfh[28:]))
	dataOff := int64(e.LocalHeaderOffset) + localHeaderLength + nameLen + extraLen

	if dataOff < 0 || dataOff+int64(e.CompressedSize) > st.Size() {
		return nil, 0, 0, 0, fmt.Errorf("%w: 条目 %q 的数据超出文件末尾", ErrBadZipCryptoData, e.Name)
	}
	payload := make([]byte, e.CompressedSize)
	if _, err := f.ReadAt(payload, dataOff); err != nil {
		return nil, 0, 0, 0, fmt.Errorf("%w: 读取条目数据失败: %v", ErrBadZipCryptoData, err)
	}
	// additional_offset 就是这段「头之后、数据之前」的长度。
	return payload, dosTime, uint32(localHeaderLength + nameLen + extraLen), localCRC, nil
}

// pickAESEntry 选择目标条目：指定名称时精确匹配，否则取第一个 AES 条目。
func pickAESEntry(entries []zipservice.Entry, name string) (zipservice.Entry, error) {
	if name != "" {
		for _, e := range entries {
			if e.Name != name {
				continue
			}
			if _, ok := aesStrength(e.EncryptionType); !ok {
				return zipservice.Entry{}, fmt.Errorf("%w: %q 的加密类型为 %q",
					ErrNotAESEntry, e.Name, e.EncryptionType)
			}
			return e, nil
		}
		return zipservice.Entry{}, fmt.Errorf("%w: %q", ErrEntryNotFound, name)
	}
	for _, e := range entries {
		if _, ok := aesStrength(e.EncryptionType); ok {
			return e, nil
		}
	}
	if len(entries) == 0 {
		return zipservice.Entry{}, fmt.Errorf("%w: 归档中没有条目", ErrNoAESEntry)
	}
	return zipservice.Entry{}, fmt.Errorf("%w: 共 %d 个条目，全部不是 AES 加密",
		ErrNoAESEntry, len(entries))
}

// aesStrength 把加密类型名映射回强度值 1/2/3。
func aesStrength(encryptionType string) (int, bool) {
	switch encryptionType {
	case "AES-128":
		return 1, true
	case "AES-192":
		return 2, true
	case "AES-256":
		return 3, true
	}
	return 0, false
}

// readEntryPayload 按中央目录记录定位本地文件头，读出该条目的全部数据
// （盐 + 校验值 + 密文 + 认证码）。
func readEntryPayload(zipPath string, e zipservice.Entry) ([]byte, error) {
	f, err := os.Open(zipPath)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	st, err := f.Stat()
	if err != nil {
		return nil, err
	}

	var lfh [localHeaderLength]byte
	if _, err := f.ReadAt(lfh[:], int64(e.LocalHeaderOffset)); err != nil {
		return nil, fmt.Errorf("%w: 读取本地文件头失败: %v", ErrBadAESData, err)
	}
	if binary.LittleEndian.Uint32(lfh[:]) != sigLocalHeader {
		return nil, fmt.Errorf("%w: 本地文件头签名错误（偏移 %d）",
			ErrBadAESData, e.LocalHeaderOffset)
	}
	// 本地文件头的扩展字段长度可能与中央目录不同（Zip64、对齐填充），
	// 必须以本地文件头为准，否则数据起点会偏。
	nameLen := int64(binary.LittleEndian.Uint16(lfh[26:]))
	extraLen := int64(binary.LittleEndian.Uint16(lfh[28:]))
	dataOff := int64(e.LocalHeaderOffset) + localHeaderLength + nameLen + extraLen

	if dataOff < 0 || dataOff+int64(e.CompressedSize) > st.Size() {
		return nil, fmt.Errorf("%w: 条目 %q 的数据超出文件末尾", ErrBadAESData, e.Name)
	}
	payload := make([]byte, e.CompressedSize)
	if _, err := f.ReadAt(payload, dataOff); err != nil {
		return nil, fmt.Errorf("%w: 读取条目数据失败: %v", ErrBadAESData, err)
	}
	return payload, nil
}

// sigLocalHeader 是本地文件头签名 "PK\x03\x04"。
const sigLocalHeader = 0x04034b50

// ---------------------------------------------------------------------------
// 外部工具（john 的 2john 系列）
// ---------------------------------------------------------------------------

// johnTarget 描述一个 2john 工具的输出特征。
type johnTarget struct {
	format   string
	mode     int
	source   string
	keywords []string // 用于从工具路径判断类型
}

var johnTargets = []johnTarget{
	{format: FormatRAR5, mode: ModeRAR5, source: SourceRar2, keywords: []string{"rar2john"}},
	{format: Format7z, mode: Mode7z, source: Source7z2, keywords: []string{"7z2john", "7z2john"}},
}

// ExtractViaJohn 调用 john 的 rar2john / 7z2john 提取 RAR5 或 7z 的哈希。
//
// tool 由调用方从设置中取得；工具类型按文件名判断（含 "rar2john" → RAR5，
// 含 "7z2john" → 7z）。脚本形式（.pl / .py）会自动补上解释器。
func ExtractViaJohn(tool, archivePath string) (HashResult, error) {
	target, err := johnTargetFor(tool, archivePath)
	if err != nil {
		return HashResult{}, err
	}

	name, args := johnCommand(tool, archivePath)
	out, runErr := runCommand(name, args...)

	hash, ok := findHash(string(out), target.format)
	if !ok {
		if runErr != nil {
			return HashResult{}, fmt.Errorf("%w: %s 执行失败: %v", ErrNoHash,
				filepath.Base(tool), runErr)
		}
		return HashResult{}, fmt.Errorf("%w: %s 没有输出 %s 哈希",
			ErrNoHash, filepath.Base(tool), target.format)
	}
	return HashResult{
		Hash:   hash,
		Mode:   target.mode,
		Format: target.format,
		Source: target.source,
	}, nil
}

// johnTargetFor 根据工具路径判断目标类型，路径无法判断时退化为看归档扩展名。
func johnTargetFor(tool, archivePath string) (johnTarget, error) {
	base := strings.ToLower(filepath.Base(tool))
	for _, t := range johnTargets {
		for _, kw := range t.keywords {
			if strings.Contains(base, kw) {
				return t, nil
			}
		}
	}
	switch strings.ToLower(filepath.Ext(archivePath)) {
	case ".rar":
		return johnTargets[0], nil
	case ".7z":
		return johnTargets[1], nil
	}
	return johnTarget{}, fmt.Errorf("%w: %s", ErrUnknownTool, filepath.Base(tool))
}

// johnCommand 组装命令行。john 的 7z2john 通常以 Perl 脚本形式发布，
// 这种情形需要显式调用解释器。
func johnCommand(tool, archivePath string) (string, []string) {
	switch strings.ToLower(filepath.Ext(tool)) {
	case ".pl":
		return "perl", []string{tool, archivePath}
	case ".py":
		return "python", []string{tool, archivePath}
	}
	return tool, []string{archivePath}
}

// findHash 在工具输出里找到第一行有效哈希。
//
// john 的输出形如 "archive.rar:$rar5$16$..."，也可能夹带警告行，
// 因此逐行扫描、定位签名起始位置。
func findHash(out, format string) (string, bool) {
	sig, end := hashMarkers(format)
	if sig == "" {
		return "", false
	}
	for _, line := range strings.Split(out, "\n") {
		line = strings.TrimRight(line, "\r \t")
		idx := strings.Index(line, sig)
		if idx < 0 {
			continue
		}
		hash := line[idx:]
		// $zip2$ 之后 john 会追加 ":<file>:<base>:<path>" 的辅助信息，
		// 需要在结束标记处截断。$rar5$ / $7z$ 没有结束标记，整行都是哈希。
		if end != "" {
			if e := strings.Index(hash, end); e >= 0 {
				hash = hash[:e+len(end)]
			}
		}
		if hash != "" {
			return hash, true
		}
	}
	return "", false
}

// hashMarkers 返回某格式哈希的起始与结束标记（无结束标记时返回空串）。
func hashMarkers(format string) (sig, end string) {
	switch format {
	case FormatRAR5:
		return "$rar5$", ""
	case Format7z:
		return "$7z$", ""
	case FormatZIPAES:
		return "$zip2$", "$/zip2$"
	}
	return "", ""
}

// Extract7zNative 用内建实现提取 7z 的 $7z$ 哈希，不依赖 john 和 Perl。
//
// john 上游只发布 7z2john.pl（Perl 脚本），Windows 包里没有对应的 .exe，
// 所以这里直接解析 7z 容器：找到带 AES 编码器的数据流，取出 salt/iv/
// 迭代次数、加密数据和 CRC，拼成 hashcat -m 11600 认的格式。
//
// 支持的编码链：AES 单独、AES + LZMA1、AES + LZMA2。遇到 BCJ2、PPMd 这类
// 多输入编码器会返回明确错误，而不是给一个校验不过的哈希。
func Extract7zNative(archivePath string) (HashResult, error) {
	hash, err := sevenzip.ExtractHash(archivePath)
	if err != nil {
		return HashResult{}, err
	}
	return HashResult{
		Hash:   hash,
		Mode:   Mode7z,
		Format: Format7z,
		Source: SourceBuiltin,
	}, nil
}

// ---------------------------------------------------------------------------
// 7z2hashcat（外部脚本，7z 提哈希的备用路径）
// ---------------------------------------------------------------------------

// 7z2hashcat 相关的错误。
var (
	// ErrScriptMissing 表示 7z2hashcat 脚本本身找不到。
	ErrScriptMissing = errors.New("hashextract: 未找到 7z2hashcat 脚本")
	// ErrInterpreterMissing 表示运行脚本所需的解释器找不到。
	ErrInterpreterMissing = errors.New("hashextract: 未检测到脚本解释器")
	// ErrScriptFailed 表示脚本执行了但退出码非零。
	ErrScriptFailed = errors.New("hashextract: 7z2hashcat 执行失败")
)

// ExtractVia7z2Hashcat 调用 philsmd 的 7z2hashcat 提取 7z 的 $7z$ 哈希。
//
// 关于 7z2hashcat 的两个事实（和很多二手资料里写的不一样，这里以源码为准）：
//
//   - 它是 **Perl** 脚本（`#!/usr/bin/env perl`），不是 Python 脚本，依赖
//     Compress::Raw::Lzma——这个依赖正是为了解开「压缩但未加密」的头部。
//     上游同时提供 Windows 版 7z2hashcat.exe（自带依赖，不需要装 Perl）。
//   - 输出格式与 7z2john 不同：**每行一条哈希，没有 `filename:` 前缀**，
//     警告和错误全部走 stderr。所以不能套用 7z2john 的 `filename:hash` 解析，
//     而是逐行找以 `$7z$` 开头的行。
//
// interpreterPath 为空时按脚本后缀自动挑（.pl → perl，.py → python3/python）；
// 脚本是 .exe 或没有后缀时直接执行，不需要解释器。
func ExtractVia7z2Hashcat(archivePath, scriptPath, interpreterPath string) (HashResult, error) {
	script := strings.TrimSpace(scriptPath)
	if script == "" {
		return HashResult{}, fmt.Errorf("%w：请在设置里指定 7z2hashcat 的路径", ErrScriptMissing)
	}
	if _, err := os.Stat(script); err != nil {
		return HashResult{}, fmt.Errorf("%w：%s", ErrScriptMissing, script)
	}

	name, args, err := sevenZip2HashcatCommand(script, interpreterPath, archivePath)
	if err != nil {
		return HashResult{}, err
	}

	out, stderr, runErr := runScriptOutput(name, args...)
	hash, ok := find7z2HashcatHash(out)
	if !ok {
		// 脚本跑起来了但没吐哈希：把它的 stderr 原样带出去，让用户看到
		// 7z2hashcat 自己的诊断（比如「no AES data found」）。
		detail := strings.TrimSpace(stderr)
		if detail == "" {
			detail = "脚本没有输出任何内容"
		}
		if runErr != nil {
			return HashResult{}, fmt.Errorf("%w：%v\n%s", ErrScriptFailed, runErr, detail)
		}
		return HashResult{}, fmt.Errorf("%w：没有输出 $7z$ 哈希\n%s", ErrNoHash, detail)
	}
	return HashResult{
		Hash:   hash,
		Mode:   Mode7z,
		Format: Format7z,
		Source: Source7z2Hashcat,
	}, nil
}

// sevenZip2HashcatCommand 组装命令行：脚本 + 归档路径，需要解释器时插在最前面。
func sevenZip2HashcatCommand(script, interpreterPath, archivePath string) (string, []string, error) {
	interpreter := strings.TrimSpace(interpreterPath)
	switch strings.ToLower(filepath.Ext(script)) {
	case ".pl", ".py":
		if interpreter == "" {
			// 没配解释器就按后缀找，先 perl 后 python，别写死 python。
			candidates := []string{"perl"}
			if strings.ToLower(filepath.Ext(script)) == ".py" {
				candidates = []string{"python3", "python"}
			}
			for _, cand := range candidates {
				if p, lookErr := execLookPath(cand); lookErr == nil {
					interpreter = p
					break
				}
			}
		}
		if interpreter == "" {
			return "", nil, fmt.Errorf("%w：运行 %s 需要 Perl（.pl）或 Python 3（.py），"+
				"请安装或在设置里指定解释器路径", ErrInterpreterMissing, filepath.Base(script))
		}
		return interpreter, []string{script, archivePath}, nil
	}
	// .exe 或没有后缀：直接执行，配了解释器也不用。
	return script, []string{archivePath}, nil
}

// find7z2HashcatHash 从 7z2hashcat 的 stdout 里取第一条 $7z$ 哈希。
//
// 7z2hashcat 每行输出一条完整哈希，行首没有文件名前缀，行尾没有结束标记，
// 所以整行（去掉行尾空白）就是哈希本身。$7z$ 内部不再含换行，也不会出现
// 第二个 $7z$，因此不需要像 $zip2$ 那样找结束标记。
func find7z2HashcatHash(out string) (string, bool) {
	lines := strings.Split(out, "\n")

	// 主流形态：整行就是哈希。
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if !strings.HasPrefix(line, "$7z$") {
			continue
		}
		if hash, ok := clean7z2HashcatLine(line); ok {
			return hash, true
		}
	}

	// 兜底：某些包装脚本会在前面拼上文件名或日志前缀。只有在上面的严格匹配
	// 全军覆没时才退到「行内任意位置」，免得把日志里提到的哈希误当成结果。
	for _, line := range lines {
		line = strings.TrimSpace(line)
		idx := strings.Index(line, "$7z$")
		if idx <= 0 {
			continue
		}
		if hash, ok := clean7z2HashcatLine(line[idx:]); ok {
			return hash, true
		}
	}
	return "", false
}

// clean7z2HashcatLine 去掉哈希主体后面可能跟的说明文字。
func clean7z2HashcatLine(s string) (string, bool) {
	if idx := strings.IndexAny(s, " \t"); idx >= 0 {
		s = s[:idx]
	}
	if len(s) <= len("$7z$") {
		return "", false
	}
	return s, true
}
