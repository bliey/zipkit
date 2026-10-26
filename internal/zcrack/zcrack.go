// Package zcrack 实现 ZipCrypto（PKWARE 传统加密）纯数字密码的快速破解。
//
// 本包完全自包含：只依赖 Go 标准库，不依赖 Wails、不依赖任何外部程序，
// 也不需要 archive/zip 之外的第三方代码。ZIP 结构由本包自行解析（EOCD +
// 中央目录 + 本地文件头），因为标准库无法读取加密条目的原始密文。
//
// 基本用法：
//
//	res := zcrack.Crack(ctx, "secret.zip", "hello.txt", 6, 8)
//	if res.Err != nil { ... }
//	if res.Found { fmt.Println(res.Password) }
//
// 破解分两级校验：
//  1. 用候选密码解密 12 字节加密头，检查第 12 个字节是否等于 CRC32 的最高字节；
//  2. 对通过第一级的候选（约 1/256）解密全部压缩数据，解压后计算 CRC32，
//     与中央目录中的 CRC32 比对。第二级用于排除第一级的误报。
package zcrack

import (
	"compress/flate"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"hash/crc32"
	"io"
	"os"
	"runtime"
	"sync"
	"sync/atomic"
)

// maxPWLen 是允许的最大密码长度。纯数字暴力破解超过这个长度没有实际意义。
const maxPWLen = 20

// 破解过程中可能返回的错误。未找到密码不算错误。
var (
	// ErrEntryNotFound 表示中央目录中没有指定名称的条目。
	ErrEntryNotFound = errors.New("zcrack: 未找到指定条目")
	// ErrNotEncrypted 表示条目没有加密（GPBF bit 0 未置位）。
	ErrNotEncrypted = errors.New("zcrack: 条目未加密")
	// ErrNotZipCrypto 表示条目不是 ZipCrypto 加密（AES 或强加密），本包不适用。
	ErrNotZipCrypto = errors.New("zcrack: 该条目不是 ZipCrypto 加密（可能是 AES 或强加密），本包不适用")
	// ErrBadZip 表示 ZIP 结构损坏或不是合法的 ZIP 文件。
	ErrBadZip = errors.New("zcrack: 无效的 ZIP 文件")
	// ErrInvalidRange 表示密码长度范围非法。
	ErrInvalidRange = errors.New("zcrack: 密码长度范围无效")
	// ErrUnsupportedMethod 表示压缩方法不是 Store(0) 或 Deflate(8)。
	ErrUnsupportedMethod = errors.New("zcrack: 不支持的压缩方法")
	// ErrZip64Unsupported 表示归档使用了 Zip64 扩展结构。
	ErrZip64Unsupported = errors.New("zcrack: 暂不支持 Zip64 归档")
)

// Result 表示一次破解的结果。
type Result struct {
	Password string // 找到的密码；未找到时为空
	Found    bool
	Err      error // 解析错误、文件错误等；未找到不算错误
}

// Entry 描述 ZIP 中央目录中的一个条目。
type Entry struct {
	Name              string
	LocalHeaderOffset uint64
	CompressedSize    uint64 // 含 12 字节加密头
	UncompressedSize  uint64 // 原始大小；0 表示未知（仅用于收紧二级校验的边界）
	CRC32             uint32
	GPFlags           uint16
	Method            uint16
}

// Options 是 CrackWithOptions / CrackEntryWithOptions 的参数。
type Options struct {
	MinLen  int // 密码最小长度（含）
	MaxLen  int // 密码最大长度（含）
	Workers int // 并发 worker 数；0 表示 runtime.GOMAXPROCS(0)，1 表示单核
}

// ---------------------------------------------------------------------------
// ZipCrypto 密钥流
// ---------------------------------------------------------------------------

// keys 是 ZipCrypto 的三元密钥状态。
type keys struct {
	k0, k1, k2 uint32
}

var initKeys = keys{0x12345678, 0x23456789, 0x34567890}

// crcTable 是标准 CRC-32（IEEE 802.3，多项式 0xEDB88320）查找表，
// ZipCrypto 的密钥更新直接复用它。
var crcTable [256]uint32

func init() {
	for i := 0; i < 256; i++ {
		c := uint32(i)
		for j := 0; j < 8; j++ {
			if c&1 != 0 {
				c = 0xEDB88320 ^ (c >> 1)
			} else {
				c >>= 1
			}
		}
		crcTable[i] = c
	}
}

// updateKeys 读入一个明文字节 b，更新三元密钥。
// 返回值而不是指针，便于编译器把状态放在寄存器里。
func updateKeys(k0, k1, k2 uint32, b byte) (uint32, uint32, uint32) {
	k0 = crcTable[(k0^uint32(b))&0xff] ^ (k0 >> 8)
	k1 = (k1+k0&0xff)*134775813 + 1
	k2 = crcTable[(k2^uint32(byte(k1>>24)))&0xff] ^ (k2 >> 8)
	return k0, k1, k2
}

// update 读入一个 0..9 的数字，更新密钥状态。
func (k keys) update(digit byte) keys {
	k0, k1, k2 := updateKeys(k.k0, k.k1, k.k2, '0'+digit)
	return keys{k0, k1, k2}
}

// decryptByte 返回密钥流的下一个字节。
func decryptByte(k2 uint32) byte {
	t := uint32(uint16(k2) | 2)
	return byte((t * (t ^ 1)) >> 8)
}

// ---------------------------------------------------------------------------
// 公开 API
// ---------------------------------------------------------------------------

// Crack 对指定 ZIP 中的某个加密条目进行纯数字密码破解。
//
// zipPath: ZIP 文件路径
// entryName: 中央目录中该条目的文件名（精确匹配）
// minLen, maxLen: 密码长度范围（含两端），通常为 6 和 8
//
// 并发度默认为 runtime.GOMAXPROCS(0)；需要单核行为时用 CrackWithOptions
// 并设置 Workers: 1。
func Crack(ctx context.Context, zipPath, entryName string, minLen, maxLen int) Result {
	return CrackWithOptions(ctx, zipPath, entryName, Options{MinLen: minLen, MaxLen: maxLen})
}

// CrackWithOptions 与 Crack 相同，但可以指定并发度。
func CrackWithOptions(ctx context.Context, zipPath, entryName string, opts Options) Result {
	o, err := opts.normalize()
	if err != nil {
		return Result{Err: err}
	}
	f, err := os.Open(zipPath)
	if err != nil {
		return Result{Err: err}
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil {
		return Result{Err: err}
	}
	e, err := findEntry(f, st.Size(), entryName)
	if err != nil {
		return Result{Err: err}
	}
	c, err := newCracker(f, e)
	if err != nil {
		return Result{Err: err}
	}
	return c.crack(ctx, o)
}

// CrackEntry 用已解析的 Entry 信息进行破解，避免重复解析 ZIP 中央目录。
func CrackEntry(ctx context.Context, zipPath string, entry Entry, minLen, maxLen int) Result {
	return CrackEntryWithOptions(ctx, zipPath, entry, Options{MinLen: minLen, MaxLen: maxLen})
}

// CrackEntryWithOptions 与 CrackEntry 相同，但可以指定并发度。
func CrackEntryWithOptions(ctx context.Context, zipPath string, entry Entry, opts Options) Result {
	o, err := opts.normalize()
	if err != nil {
		return Result{Err: err}
	}
	f, err := os.Open(zipPath)
	if err != nil {
		return Result{Err: err}
	}
	defer f.Close()
	c, err := newCracker(f, entry)
	if err != nil {
		return Result{Err: err}
	}
	return c.crack(ctx, o)
}

// InspectEntry 解析 ZIP 并返回指定名称的条目信息。
func InspectEntry(zipPath, entryName string) (Entry, error) {
	f, err := os.Open(zipPath)
	if err != nil {
		return Entry{}, err
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil {
		return Entry{}, err
	}
	return findEntry(f, st.Size(), entryName)
}

// ListEntries 返回 ZIP 中央目录中的所有条目。
func ListEntries(zipPath string) ([]Entry, error) {
	f, err := os.Open(zipPath)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil {
		return nil, err
	}
	var out []Entry
	err = walkEntries(f, st.Size(), func(e Entry) bool {
		out = append(out, e)
		return false
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (o Options) normalize() (Options, error) {
	if o.MinLen < 0 || o.MaxLen < o.MinLen {
		return o, fmt.Errorf("%w: minLen=%d maxLen=%d", ErrInvalidRange, o.MinLen, o.MaxLen)
	}
	if o.MaxLen > maxPWLen {
		return o, fmt.Errorf("%w: maxLen 不能超过 %d", ErrInvalidRange, maxPWLen)
	}
	if o.Workers <= 0 {
		o.Workers = runtime.GOMAXPROCS(0)
	}
	if o.Workers > 64 {
		o.Workers = 64
	}
	return o, nil
}

// ---------------------------------------------------------------------------
// ZIP 结构解析（本包独立实现的最小版本）
// ---------------------------------------------------------------------------

const (
	lfhSig  = 0x04034b50
	cdSig   = 0x02014b50
	eocdSig = 0x06054b50

	eocdLen   = 22
	maxTail   = eocdLen + 0xffff // EOCD 最大长度（含 64KiB 注释）
	zip64Mark = 0xffffffff
)

// findEOCD 从文件尾部向前搜索 End Of Central Directory 记录，返回其偏移。
func findEOCD(f *os.File, size int64) (int64, error) {
	if size < eocdLen {
		return 0, fmt.Errorf("%w: 文件长度 %d 不足", ErrBadZip, size)
	}
	tailLen := int64(maxTail)
	if tailLen > size {
		tailLen = size
	}
	buf := make([]byte, tailLen)
	if _, err := f.ReadAt(buf, size-tailLen); err != nil {
		return 0, fmt.Errorf("%w: 读取文件尾部失败: %v", ErrBadZip, err)
	}
	for i := len(buf) - eocdLen; i >= 0; i-- {
		if binary.LittleEndian.Uint32(buf[i:]) != eocdSig {
			continue
		}
		commentLen := int(binary.LittleEndian.Uint16(buf[i+20:]))
		if i+eocdLen+commentLen > len(buf) {
			continue // 注释长度与文件尾不符，可能是数据里碰巧出现的签名
		}
		return size - tailLen + int64(i), nil
	}
	return 0, fmt.Errorf("%w: 未找到 EOCD 记录", ErrBadZip)
}

// walkEntries 遍历中央目录，fn 返回 true 时提前结束。
func walkEntries(f *os.File, size int64, fn func(Entry) bool) error {
	eocdOff, err := findEOCD(f, size)
	if err != nil {
		return err
	}
	var eocd [eocdLen]byte
	if _, err := f.ReadAt(eocd[:], eocdOff); err != nil {
		return fmt.Errorf("%w: 读取 EOCD 失败: %v", ErrBadZip, err)
	}
	total := int(binary.LittleEndian.Uint16(eocd[10:]))
	cdSize := binary.LittleEndian.Uint32(eocd[12:])
	cdOff := binary.LittleEndian.Uint32(eocd[16:])
	if cdOff == zip64Mark || cdSize == zip64Mark || total == 0xffff {
		return ErrZip64Unsupported
	}
	if int64(cdOff)+int64(cdSize) > size {
		return fmt.Errorf("%w: 中央目录越界", ErrBadZip)
	}
	cd := make([]byte, cdSize)
	if _, err := f.ReadAt(cd, int64(cdOff)); err != nil {
		return fmt.Errorf("%w: 读取中央目录失败: %v", ErrBadZip, err)
	}

	p := 0
	for i := 0; i < total; i++ {
		if p+46 > len(cd) {
			return fmt.Errorf("%w: 中央目录条目被截断", ErrBadZip)
		}
		if binary.LittleEndian.Uint32(cd[p:]) != cdSig {
			return fmt.Errorf("%w: 中央目录签名错误（偏移 %d）", ErrBadZip, p)
		}
		e := Entry{
			GPFlags:           binary.LittleEndian.Uint16(cd[p+8:]),
			Method:            binary.LittleEndian.Uint16(cd[p+10:]),
			CRC32:             binary.LittleEndian.Uint32(cd[p+16:]),
			CompressedSize:    uint64(binary.LittleEndian.Uint32(cd[p+20:])),
			UncompressedSize:  uint64(binary.LittleEndian.Uint32(cd[p+24:])),
			LocalHeaderOffset: uint64(binary.LittleEndian.Uint32(cd[p+42:])),
		}
		nameLen := int(binary.LittleEndian.Uint16(cd[p+28:]))
		extraLen := int(binary.LittleEndian.Uint16(cd[p+30:]))
		commentLen := int(binary.LittleEndian.Uint16(cd[p+32:]))
		next := p + 46 + nameLen + extraLen + commentLen
		if next > len(cd) {
			return fmt.Errorf("%w: 中央目录条目被截断", ErrBadZip)
		}
		e.Name = string(cd[p+46 : p+46+nameLen])
		if e.CompressedSize == zip64Mark || e.LocalHeaderOffset == zip64Mark {
			return ErrZip64Unsupported
		}
		if fn(e) {
			return nil
		}
		p = next
	}
	return nil
}

// findEntry 在中央目录中按名称精确查找条目。
func findEntry(f *os.File, size int64, name string) (Entry, error) {
	var (
		found Entry
		ok    bool
	)
	err := walkEntries(f, size, func(e Entry) bool {
		if e.Name == name {
			found, ok = e, true
			return true
		}
		return false
	})
	if err != nil {
		return Entry{}, err
	}
	if !ok {
		return Entry{}, fmt.Errorf("%w: %q", ErrEntryNotFound, name)
	}
	return found, nil
}

// ---------------------------------------------------------------------------
// cracker：一次破解任务的只读上下文
// ---------------------------------------------------------------------------

type cracker struct {
	f       *os.File
	hdrOff  int64    // 12 字节加密头的文件偏移
	hdr     [12]byte // 加密头密文
	check   byte     // 校验字节：CRC32 最高字节
	check2  byte     // 备用校验字节（数据描述符时可能是 DOS 时间高字节）
	dataLen int      // 加密数据长度（不含 12 字节头）
	usize   int64    // 原始大小，<=0 表示未知
	method  uint16
	crc     uint32

	// 加密数据只在所有 worker 之间共享一份（只读），惰性加载。
	once    sync.Once
	payload []byte
	dataErr error
}

func newCracker(f *os.File, e Entry) (*cracker, error) {
	switch {
	case e.GPFlags&0x0001 == 0:
		return nil, fmt.Errorf("%w: %q", ErrNotEncrypted, e.Name)
	case e.GPFlags&0x0040 != 0:
		return nil, fmt.Errorf("%w: 条目 %q 使用了强加密", ErrNotZipCrypto, e.Name)
	case e.Method == 99:
		return nil, fmt.Errorf("%w: 条目 %q 使用 AES 加密", ErrNotZipCrypto, e.Name)
	case e.Method != 0 && e.Method != 8:
		return nil, fmt.Errorf("%w: 条目 %q 的压缩方法为 %d", ErrUnsupportedMethod, e.Name, e.Method)
	case e.CompressedSize < 12:
		return nil, fmt.Errorf("%w: 条目 %q 的压缩长度 %d 小于 12 字节加密头", ErrBadZip, e.Name, e.CompressedSize)
	}

	var lfh [30]byte
	if _, err := f.ReadAt(lfh[:], int64(e.LocalHeaderOffset)); err != nil {
		return nil, fmt.Errorf("%w: 读取本地文件头失败: %v", ErrBadZip, err)
	}
	if binary.LittleEndian.Uint32(lfh[:]) != lfhSig {
		return nil, fmt.Errorf("%w: 本地文件头签名错误（偏移 %d）", ErrBadZip, e.LocalHeaderOffset)
	}
	nameLen := int64(binary.LittleEndian.Uint16(lfh[26:]))
	extraLen := int64(binary.LittleEndian.Uint16(lfh[28:]))
	hdrOff := int64(e.LocalHeaderOffset) + 30 + nameLen + extraLen

	st, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if hdrOff < 0 || hdrOff+int64(e.CompressedSize) > st.Size() {
		return nil, fmt.Errorf("%w: 条目 %q 的数据超出文件末尾", ErrBadZip, e.Name)
	}

	c := &cracker{
		f:       f,
		hdrOff:  hdrOff,
		check:   byte(e.CRC32 >> 24),
		check2:  byte(e.CRC32 >> 24),
		dataLen: int(e.CompressedSize) - 12,
		usize:   int64(e.UncompressedSize),
		method:  e.Method,
		crc:     e.CRC32,
	}
	if _, err := f.ReadAt(c.hdr[:], hdrOff); err != nil {
		return nil, fmt.Errorf("%w: 读取加密头失败: %v", ErrBadZip, err)
	}
	// GPBF bit 3（数据描述符）置位时，PKWARE 规范允许把加密头最后字节写成
	// DOS 修改时间的高字节，而不是 CRC 的高字节。两种都接受，误报由 CRC 二级校验兜底。
	if e.GPFlags&0x0008 != 0 {
		c.check2 = byte(binary.LittleEndian.Uint16(lfh[10:]) >> 8)
	}
	return c, nil
}

// ---------------------------------------------------------------------------
// 破解主流程
// ---------------------------------------------------------------------------

type unit struct {
	prefix []byte // 前 1~2 位数字，各 worker 独立枚举
	length int
}

// buildUnits 把搜索空间切成以数字前缀为单位的工作块，便于并行。
//
// 前缀取 1~2 位，剩下的低位由 DFS 枚举；最后两位由叶子分组统一处理（见 search）。
// 这样每个工作块的候选数至少是 100，足够 16 个 worker 分负载。
//
// 每一位都必须枚举 '0'..'9'，**包括首位**。纯数字密码允许前导零，而且实际
// 很常见（日期、编号、手机号后六位、各种系统生成的 PIN）。曾经这里首位只
// 从 '1' 开始，等于静默丢掉 10% 的搜索空间：6 位密码里所有 0 开头的候选
// （10 万个）根本不会被尝试，表现为「hashcat 能解出来、本包解不出来」。
func buildUnits(minLen, maxLen int) []unit {
	var us []unit
	for l := minLen; l <= maxLen; l++ {
		switch {
		case l == 0:
			us = append(us, unit{nil, 0})
		case l == 1:
			// 1 位：10 个工作块，每个就是一个候选。
			for d := byte('0'); d <= '9'; d++ {
				us = append(us, unit{[]byte{d}, 1})
			}
		case l == 2:
			// 2 位：100 个工作块，每个就是一个候选。
			for a := byte('0'); a <= '9'; a++ {
				for b := byte('0'); b <= '9'; b++ {
					us = append(us, unit{[]byte{a, b}, 2})
				}
			}
		case l == 3:
			// 3 位：前缀 1 位（叶子层需要留 2 位给 checkLeaf），10 个工作块。
			for a := byte('0'); a <= '9'; a++ {
				us = append(us, unit{[]byte{a}, 3})
			}
		default:
			// 4 位及以上：前缀 2 位，100 个工作块。
			for a := byte('0'); a <= '9'; a++ {
				for b := byte('0'); b <= '9'; b++ {
					us = append(us, unit{[]byte{a, b}, l})
				}
			}
		}
	}
	return us
}

func (c *cracker) crack(ctx context.Context, opts Options) Result {
	if err := ctx.Err(); err != nil {
		return Result{Err: err}
	}
	units := buildUnits(opts.MinLen, opts.MaxLen)
	if len(units) == 0 {
		return Result{}
	}

	var (
		stop atomic.Bool
		mu   sync.Mutex
		res  Result
		done bool
	)
	setRes := func(r Result) {
		mu.Lock()
		if !done {
			done, res = true, r
		}
		mu.Unlock()
		stop.Store(true)
	}

	workers := opts.Workers
	if workers > len(units) {
		workers = len(units)
	}
	if workers < 1 {
		workers = 1
	}

	var next atomic.Int64
	next.Store(-1)
	var wg sync.WaitGroup
	wg.Add(workers)
	for i := 0; i < workers; i++ {
		go func() {
			defer wg.Done()
			w := c.newWorker()
			for {
				if stop.Load() {
					return
				}
				if err := ctx.Err(); err != nil {
					setRes(Result{Err: err})
					return
				}
				n := int(next.Add(1))
				if n >= len(units) {
					return
				}
				pw, ok, err := w.search(ctx, &stop, units[n].prefix, units[n].length)
				if err != nil {
					setRes(Result{Err: err})
					return
				}
				if ok {
					setRes(Result{Password: pw, Found: true})
					return
				}
			}
		}()
	}
	wg.Wait()

	mu.Lock()
	defer mu.Unlock()
	if res.Found || res.Err != nil {
		return res
	}
	if err := ctx.Err(); err != nil {
		return Result{Err: err}
	}
	return Result{}
}

// ---------------------------------------------------------------------------
// worker：可复用的工作缓冲区与枚举循环
// ---------------------------------------------------------------------------

type worker struct {
	c      *cracker
	hdr    [12]byte
	check  byte
	check2 byte

	digits [maxPWLen]byte
	states [maxPWLen + 1]keys

	// 二级校验用。明文不落地：解压时按需从密文流式解密，
	// 因此每个 worker 只需一个固定大小的读缓冲，内存不随条目大小×worker 数膨胀。
	dr  decryptReader
	fl  io.ReadCloser
	flr flate.Resetter
	buf []byte
}

// decryptReader 把密文按需解密成明文流，供 flate 直接读取。
// 同时实现 io.ByteReader，避免 flate 再套一层 bufio.Reader（那会每次 Reset 都分配）。
type decryptReader struct {
	payload    []byte
	off        int
	k0, k1, k2 uint32
}

func (r *decryptReader) reset(payload []byte, k0, k1, k2 uint32) {
	r.payload, r.off, r.k0, r.k1, r.k2 = payload, 0, k0, k1, k2
}

func (r *decryptReader) Read(p []byte) (int, error) {
	rem := len(r.payload) - r.off
	if rem == 0 {
		return 0, io.EOF
	}
	if len(p) > rem {
		p = p[:rem]
	}
	k0, k1, k2 := r.k0, r.k1, r.k2
	for i := 0; i < len(p); i++ {
		c := r.payload[r.off+i] ^ decryptByte(k2)
		k0, k1, k2 = updateKeys(k0, k1, k2, c)
		p[i] = c
	}
	r.off += len(p)
	r.k0, r.k1, r.k2 = k0, k1, k2
	return len(p), nil
}

func (r *decryptReader) ReadByte() (byte, error) {
	if r.off >= len(r.payload) {
		return 0, io.EOF
	}
	c := r.payload[r.off] ^ decryptByte(r.k2)
	r.k0, r.k1, r.k2 = updateKeys(r.k0, r.k1, r.k2, c)
	r.off++
	return c, nil
}

func (c *cracker) newWorker() *worker {
	return &worker{c: c, hdr: c.hdr, check: c.check, check2: c.check2}
}

// search 从 prefix 给定的前缀出发，枚举长度 length 的所有数字补全。
//
// 枚举顺序为深度优先、非递归：states[i] 保存"前 i 位数字处理完后"的密钥状态，
// 因此每一位只做一次 updateKeys，前缀状态在所有后继候选间共享。
// 最低两位交给 checkLeaf 一次处理 100 个候选（4 路交错），以填满 CPU 的指令级并行。
func (w *worker) search(ctx context.Context, stop *atomic.Bool, prefix []byte, length int) (string, bool, error) {
	d := &w.digits
	st := &w.states

	st[0] = initKeys
	for i := 0; i < len(prefix); i++ {
		d[i] = prefix[i]
		st[i+1] = st[i].update(prefix[i] - '0')
	}
	if len(prefix) >= length {
		return w.tryOne(st[length], d[:length])
	}

	leaf := length - 2 // 最后两位的位置
	depth := len(prefix)
	d[depth] = '0'
	for {
		if depth < leaf {
			st[depth+1] = st[depth].update(d[depth] - '0')
			depth++
			d[depth] = '0'
			continue
		}

		// 到达叶子层：st[leaf] 是"前 leaf 位"处理完后的状态。
		// 每轮 100 个候选耗时约 2.5µs，在这里检查取消足够及时。
		if err := ctx.Err(); err != nil {
			return "", false, err
		}
		if stop.Load() {
			return "", false, nil
		}
		if pw, ok, err := w.checkLeaf(st[leaf], d, leaf, length); ok || err != nil {
			return pw, ok, err
		}

		// 回溯到下一个候选前缀；退出固定前缀范围即本工作块枚举完毕。
		pos := leaf - 1
		for {
			if pos < len(prefix) {
				return "", false, nil
			}
			if d[pos] < '9' {
				d[pos]++
				break
			}
			d[pos] = '0'
			pos--
		}
		depth = pos
	}
}

// checkLeaf 枚举最后两位数字的全部 100 种组合。
//
// 四个候选的密钥链互不依赖，交错计算可以让 CPU 在等待查表/乘法的延迟时
// 同时推进另外三条链，实测把单候选耗时从 ~72ns 降到 ~25ns。
func (w *worker) checkLeaf(parent keys, d *[maxPWLen]byte, leaf, length int) (string, bool, error) {
	hdr := &w.hdr
	check, check2 := w.check, w.check2
	for g := 0; g < 25; g++ {
		i := g * 4
		s0 := parent.update(byte(i / 10)).update(byte(i % 10))
		s1 := parent.update(byte((i + 1) / 10)).update(byte((i + 1) % 10))
		s2 := parent.update(byte((i + 2) / 10)).update(byte((i + 2) % 10))
		s3 := parent.update(byte((i + 3) / 10)).update(byte((i + 3) % 10))

		k0a, k1a, k2a := s0.k0, s0.k1, s0.k2
		k0b, k1b, k2b := s1.k0, s1.k1, s1.k2
		k0c, k1c, k2c := s2.k0, s2.k1, s2.k2
		k0d, k1d, k2d := s3.k0, s3.k1, s3.k2

		var la, lb, lc, ld byte
		for j := 0; j < 12; j++ {
			h := hdr[j]
			la = h ^ decryptByte(k2a)
			lb = h ^ decryptByte(k2b)
			lc = h ^ decryptByte(k2c)
			ld = h ^ decryptByte(k2d)
			k0a, k1a, k2a = updateKeys(k0a, k1a, k2a, la)
			k0b, k1b, k2b = updateKeys(k0b, k1b, k2b, lb)
			k0c, k1c, k2c = updateKeys(k0c, k1c, k2c, lc)
			k0d, k1d, k2d = updateKeys(k0d, k1d, k2d, ld)
		}

		if la == check || la == check2 {
			if ok, err := w.verify(k0a, k1a, k2a); err != nil {
				return "", false, err
			} else if ok {
				return w.hit(d, leaf, length, i)
			}
		}
		if lb == check || lb == check2 {
			if ok, err := w.verify(k0b, k1b, k2b); err != nil {
				return "", false, err
			} else if ok {
				return w.hit(d, leaf, length, i+1)
			}
		}
		if lc == check || lc == check2 {
			if ok, err := w.verify(k0c, k1c, k2c); err != nil {
				return "", false, err
			} else if ok {
				return w.hit(d, leaf, length, i+2)
			}
		}
		if ld == check || ld == check2 {
			if ok, err := w.verify(k0d, k1d, k2d); err != nil {
				return "", false, err
			} else if ok {
				return w.hit(d, leaf, length, i+3)
			}
		}
	}
	return "", false, nil
}

// hit 把命中的最后两位写回数字缓冲区，并生成密码字符串（仅命中时分配）。
func (w *worker) hit(d *[maxPWLen]byte, leaf, length, idx int) (string, bool, error) {
	d[leaf] = byte('0' + idx/10)
	d[leaf+1] = byte('0' + idx%10)
	return string(d[:length]), true, nil
}

// tryOne 校验单个候选密码（用于空密码与 1~2 位的短密码）。
func (w *worker) tryOne(st keys, pw []byte) (string, bool, error) {
	k0, k1, k2 := st.k0, st.k1, st.k2
	var last byte
	for i := 0; i < 12; i++ {
		last = w.hdr[i] ^ decryptByte(k2)
		k0, k1, k2 = updateKeys(k0, k1, k2, last)
	}
	if last != w.check && last != w.check2 {
		return "", false, nil
	}
	ok, err := w.verify(k0, k1, k2)
	if err != nil {
		return "", false, err
	}
	if !ok {
		return "", false, nil
	}
	return string(pw), true, nil
}

// data 惰性读取加密数据，所有 worker 共享同一份只读副本。
func (c *cracker) data() ([]byte, error) {
	c.once.Do(func() {
		buf := make([]byte, c.dataLen)
		if _, err := c.f.ReadAt(buf, c.hdrOff+12); err != nil {
			c.dataErr = fmt.Errorf("zcrack: 读取加密数据失败: %w", err)
			return
		}
		c.payload = buf
	})
	return c.payload, c.dataErr
}

// verify 是第二级校验：解密全部数据并比对 CRC32。
//
// 注意：条目的 CRC32 是针对"解压后"的完整数据计算的，因此对前 N 字节做局部
// CRC 与条目 CRC 永远无法相等。这里按压缩方法分别处理：
//   - Store(0)：解密后即为原始数据，直接算 CRC；
//   - Deflate(8)：解密后解压，边解压边算 CRC。
//
// 只有完整校验通过才算命中，从而排除第一级 1/256 的误报。
func (w *worker) verify(k0, k1, k2 uint32) (bool, error) {
	if w.c.dataLen <= 0 {
		// 空文件没有数据可供校验，只能信任校验字节。
		return true, nil
	}
	payload, err := w.c.data()
	if err != nil {
		return false, err
	}
	w.dr.reset(payload, k0, k1, k2)
	switch w.c.method {
	case 0:
		return w.crcAll() == w.c.crc, nil
	case 8:
		return w.inflateCRC(), nil
	}
	return false, nil
}

// crcAll 读完整个解密流并计算 CRC32（Store 方法使用）。
func (w *worker) crcAll() uint32 {
	if w.buf == nil {
		w.buf = make([]byte, 32*1024)
	}
	var sum uint32
	for {
		n, err := w.dr.Read(w.buf)
		if n > 0 {
			sum = crc32.Update(sum, crc32.IEEETable, w.buf[:n])
		}
		if err != nil {
			return sum
		}
	}
}

// inflateCRC 边解压边算 CRC32，与条目 CRC 比对。缓冲区全部复用。
func (w *worker) inflateCRC() bool {
	if w.fl == nil {
		rc := flate.NewReader(&w.dr)
		r, ok := rc.(flate.Resetter)
		if !ok {
			return false
		}
		w.fl, w.flr = rc, r
		n := 32 * 1024
		if lim := w.inflateLimit(); lim+1 < int64(n) {
			n = int(lim) + 1
		}
		w.buf = make([]byte, n)
	} else if err := w.flr.Reset(&w.dr, nil); err != nil {
		return false
	}

	limit := w.inflateLimit()
	var (
		sum   uint32
		total int64
	)
	for {
		n, err := w.fl.Read(w.buf)
		if n > 0 {
			sum = crc32.Update(sum, crc32.IEEETable, w.buf[:n])
			total += int64(n)
			if total > limit {
				return false
			}
		}
		if err == io.EOF {
			break
		}
		if err != nil {
			return false
		}
	}
	if w.c.usize > 0 && total != w.c.usize {
		return false
	}
	return sum == w.c.crc
}

// inflateLimit 返回单次解压允许产出的最大字节数。
func (w *worker) inflateLimit() int64 {
	limit := int64(w.c.dataLen)*1032 + 1024
	if w.c.usize > 0 && w.c.usize < limit {
		limit = w.c.usize
	}
	return limit
}
