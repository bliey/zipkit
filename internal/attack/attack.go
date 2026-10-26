// Package attack 封装 bkcrack 的已知明文攻击（known plaintext attack）。
//
// 它只做三件事：
//
//  1. Precheck：在真正调用 bkcrack 之前，比较加密条目与明文的压缩方式、
//     CRC32 与原始大小，把「大概率会失败」的组合提前指出来；
//  2. Run：跑 bkcrack 恢复内部密钥，实时把输出推给界面；
//  3. Decrypt / DecryptEntry：用恢复出的密钥解密整个包或单个条目。
//
// 所有外部命令都用参数数组传给 exec.Command，不经过 shell：文件名里的
// 空格、中文、& 和引号都不需要转义，也不会被解释成命令。
package attack

import (
	"bufio"
	"bytes"
	"compress/flate"
	"context"
	"errors"
	"fmt"
	"hash/crc32"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/bliey/zipkit/internal/executil"
	"github.com/bliey/zipkit/internal/zipservice"
)

// 包级错误，调用方用 errors.Is 判断。
var (
	// ErrKeysNotFound 表示 bkcrack 跑完了但没找到密钥（明文对不上）。
	ErrKeysNotFound = errors.New("bkcrack 未能恢复密钥")
	// ErrCancelled 表示用户点了「停止」。
	ErrCancelled = errors.New("attack: 已取消")
)

// maxRawBytes 限制保留的原始输出大小。bkcrack 的进度是回车刷新的，几万个
// 进度点能刷出上百 KB，没必要全留着——失败时给用户看最后几行就够了。
const maxRawBytes = 256 << 10

// minUsefulPlaintext 是 bkcrack 恢复密钥通常需要的已知明文字节数。低于这个
// 数量不阻止攻击，只在预检里提醒一句——有些场景（偏移为 0、结构已知）确实
// 能用更短的明文碰运气。
const minUsefulPlaintext = 12

// PrecheckResult 是调用 bkcrack 之前的对齐检查结果。
//
// Precheck 只是「提前告诉用户可能会失败」，不阻止继续：明文的形态很杂
// （截断的前缀、不同压缩软件生成的数据流），机器判断不可能覆盖全部情况。
type PrecheckResult struct {
	OK                bool     `json:"ok"`
	CipherCompression string   `json:"cipherCompression"`
	PlainCompression  string   `json:"plainCompression"`
	CipherCRC32       uint32   `json:"cipherCRC32"`
	PlainCRC32        uint32   `json:"plainCRC32"`
	CipherSize        uint64   `json:"cipherSize"`
	PlainSize         uint64   `json:"plainSize"`
	Issues            []string `json:"issues"`
	// Notes 是「通过检查但要提醒一句」的内容，例如十六进制明文模式下无法
	// 预检对齐。Issues 只在未通过时展示，Notes 通过与否都展示。
	Notes []string `json:"notes"`
	// HexMode 表示这次预检走的是十六进制明文，三项比对都不适用。
	HexMode bool `json:"hexMode"`
}

// AttackOptions 描述一次明文攻击。
type AttackOptions struct {
	EncryptedZip string `json:"encryptedZip"`
	CipherEntry  string `json:"cipherEntry"`
	// PlainPath 既可以是独立文件，也可以是明文 ZIP，取决于 PlainIsZip。
	PlainPath  string `json:"plainPath"`
	PlainIsZip bool   `json:"plainIsZip"`
	// PlainEntry 只在 PlainIsZip 为 true 时有意义。
	PlainEntry string `json:"plainEntry"`
	// HexPlaintext 非空时走 bkcrack -x，PlainPath 被忽略。
	// 只接受十六进制字符，长度必须为偶数。
	HexPlaintext string `json:"hexPlaintext"`
	// HexOffset 是明文在密文中的起始偏移，默认 0。
	HexOffset int64 `json:"hexOffset"`
}

// AttackResult 是一次攻击的结果。Keys 是三组 8 位十六进制。
type AttackResult struct {
	Keys [3]string `json:"keys"`
	Raw  string    `json:"raw"`
	Err  error     `json:"-"`
}

// ------------------------------------------------------------------ Precheck

// Precheck 按明文形式自动判断：plainEntry 非空就当明文 ZIP 处理，否则当
// 独立文件。服务层有明确的单选按钮，用 PrecheckForm 指定形式更稳妥。
func Precheck(encryptedZip, cipherEntry, plainPath, plainEntry string) PrecheckResult {
	return PrecheckForm(encryptedZip, cipherEntry, plainPath, plainEntry, strings.TrimSpace(plainEntry) != "")
}

// PrecheckForm 显式指定明文形式。
func PrecheckForm(encryptedZip, cipherEntry, plainPath, plainEntry string, plainIsZip bool) PrecheckResult {
	var res PrecheckResult

	cipher, err := findEntry(encryptedZip, cipherEntry)
	if err != nil {
		res.Issues = append(res.Issues, err.Error())
		return res
	}
	res.CipherCompression = cipher.Compression
	res.CipherCRC32 = cipher.CRC32
	res.CipherSize = cipher.UncompressedSize

	if plainIsZip {
		return precheckZip(res, cipher, plainPath, plainEntry)
	}
	return precheckFile(res, cipher, plainPath)
}

// PrecheckHex 是十六进制明文模式下的预检。
//
// 没有完整明文，压缩方式 / CRC32 / 大小三项都无从比对，所以直接放行，只附
// 一条提醒：对齐对不对得用户自己确认（偏移量、字节序列）。
func PrecheckHex(encryptedZip, cipherEntry, hexPlaintext string, offset int64) (PrecheckResult, error) {
	if strings.TrimSpace(encryptedZip) == "" {
		return PrecheckResult{}, errors.New("attack: 没有指定加密压缩包")
	}
	if strings.TrimSpace(cipherEntry) == "" {
		return PrecheckResult{}, errors.New("attack: 没有指定目标条目")
	}
	hex, err := NormalizeHex(hexPlaintext)
	if err != nil {
		return PrecheckResult{}, err
	}
	if offset < 0 {
		return PrecheckResult{}, errors.New("attack: 偏移量不能是负数")
	}

	res := PrecheckResult{OK: true, HexMode: true}
	cipher, err := findEntry(encryptedZip, cipherEntry)
	if err != nil {
		res.OK = false
		res.Issues = append(res.Issues, err.Error())
		return res, nil
	}
	res.CipherCompression = cipher.Compression
	res.CipherCRC32 = cipher.CRC32
	res.CipherSize = cipher.UncompressedSize
	res.Notes = append(res.Notes,
		fmt.Sprintf("十六进制明文模式下无法预检对齐，请确认偏移和字节正确（当前偏移 %d，%d 字节）", offset, len(hex)/2))
	if len(hex)/2 < minUsefulPlaintext {
		res.Notes = append(res.Notes, fmt.Sprintf(
			"只有 %d 字节，bkcrack 通常需要至少 %d 字节已知明文才能恢复密钥；建议补上文件头之后的更多字节",
			len(hex)/2, minUsefulPlaintext))
	}
	if cipher.Compression == "Deflate" {
		res.Notes = append(res.Notes, "加密条目是 Deflate：给的必须是压缩后的字节流，不是原始文件的开头")
	}
	return res, nil
}

// NormalizeHex 校验并规范化十六进制明文字符串。
//
// 用户在输入框里可能带空格（"89 50 4E 47"）、0x 前缀或者全角字符，这里
// 统一去掉分隔符、转小写，再确认长度是偶数。bkcrack 的 -x 不接受带空格
// 的字符串，所以这一步是必须的。
func NormalizeHex(raw string) (string, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return "", errors.New("attack: 没有填写十六进制明文")
	}
	raw = strings.TrimPrefix(strings.TrimPrefix(raw, "0x"), "0X")

	var b strings.Builder
	b.Grow(len(raw))
	for _, r := range raw {
		switch {
		case r >= '0' && r <= '9', r >= 'a' && r <= 'f', r >= 'A' && r <= 'F':
			b.WriteRune(r)
		case r == ' ', r == '\t', r == '\n', r == '\r', r == '-', r == ':':
			// 分隔符，忽略
		default:
			return "", fmt.Errorf("attack: 十六进制明文里有非法字符 %q", r)
		}
	}

	hex := strings.ToLower(b.String())
	if hex == "" {
		return "", errors.New("attack: 没有填写十六进制明文")
	}
	if len(hex)%2 != 0 {
		return "", fmt.Errorf("attack: 十六进制明文必须是偶数个字符（当前 %d 个）", len(hex))
	}
	return hex, nil
}

// precheckFile 处理「独立文件」这种明文形式。
//
// 独立文件对应的是原始数据，只能和 Store 条目对齐：Deflate 条目在压缩包里
// 存的是压缩后的字节流，拿原始文件去比对必然对不上。
func precheckFile(res PrecheckResult, cipher zipservice.Entry, plainPath string) PrecheckResult {
	st, err := os.Stat(plainPath)
	if err != nil {
		res.Issues = append(res.Issues, fmt.Sprintf("读不到明文文件：%v", err))
		return res
	}
	if st.IsDir() {
		res.Issues = append(res.Issues, "明文路径是一个目录，需要选择具体文件")
		return res
	}

	res.PlainSize = uint64(st.Size())
	if cipher.Compression == "Store" {
		res.PlainCompression = "Store"
	} else {
		res.PlainCompression = "Unknown"
	}

	switch cipher.Compression {
	case "Store":
	case "Deflate":
		res.Issues = append(res.Issues, "加密条目是 Deflate，明文必须提供压缩后的字节流，不能直接给原始文件")
		return res
	default:
		res.Issues = append(res.Issues, fmt.Sprintf("加密条目的压缩方式 %q 不支持明文攻击", cipher.Compression))
		return res
	}

	if res.PlainSize != cipher.UncompressedSize {
		res.Issues = append(res.Issues, fmt.Sprintf(
			"文件大小 %d 字节与加密条目的原始大小 %d 字节不一致（如果只提供前一部分明文，可以忽略这条）",
			res.PlainSize, cipher.UncompressedSize))
	}

	res.OK = len(res.Issues) == 0
	return res
}

// precheckZip 处理「明文 ZIP」这种明文形式：三项都要比——压缩方式、CRC32、
// 原始大小。只比文件名或大小是不够的，压缩方式不同照样解不出密钥。
func precheckZip(res PrecheckResult, cipher zipservice.Entry, plainZip, plainEntry string) PrecheckResult {
	plain, err := findEntry(plainZip, plainEntry)
	if err != nil {
		res.Issues = append(res.Issues, err.Error())
		return res
	}

	res.PlainCompression = plain.Compression
	res.PlainCRC32 = plain.CRC32
	res.PlainSize = plain.UncompressedSize

	if cipher.Compression != plain.Compression {
		res.Issues = append(res.Issues, fmt.Sprintf("加密条目为 %s，明文条目为 %s",
			cipher.Compression, plain.Compression))
	}
	if cipher.CRC32 != plain.CRC32 {
		res.Issues = append(res.Issues, fmt.Sprintf("CRC32 不一致（加密 %08x，明文 %08x）",
			cipher.CRC32, plain.CRC32))
	}
	if cipher.UncompressedSize != plain.UncompressedSize {
		res.Issues = append(res.Issues, fmt.Sprintf("原始大小不一致（加密 %d 字节，明文 %d 字节）",
			cipher.UncompressedSize, plain.UncompressedSize))
	}

	res.OK = len(res.Issues) == 0
	return res
}

// findEntry 读 ZIP 中央目录并取出指定条目；name 为空时取第一个条目。
func findEntry(zipPath, name string) (zipservice.Entry, error) {
	if strings.TrimSpace(zipPath) == "" {
		return zipservice.Entry{}, errors.New("没有指定压缩包路径")
	}
	info, err := zipservice.Inspect(zipPath)
	if err != nil {
		return zipservice.Entry{}, fmt.Errorf("读取 %s 失败：%v", filepath.Base(zipPath), err)
	}
	return pickEntry(info, name)
}

func pickEntry(info *zipservice.ZipInfo, name string) (zipservice.Entry, error) {
	name = strings.TrimSpace(name)
	if name == "" {
		if len(info.Entries) == 0 {
			return zipservice.Entry{}, fmt.Errorf("%s 里没有条目", filepath.Base(info.Path))
		}
		return info.Entries[0], nil
	}
	for _, e := range info.Entries {
		if e.Name == name {
			return e, nil
		}
	}
	// 有些工具会改写大小写或路径分隔符，宽松匹配一次再报错。
	for _, e := range info.Entries {
		if strings.EqualFold(e.Name, name) {
			return e, nil
		}
	}
	return zipservice.Entry{}, fmt.Errorf("%s 里没有条目 %q%s",
		filepath.Base(info.Path), name, sampleNames(info.Entries))
}

func sampleNames(entries []zipservice.Entry) string {
	if len(entries) == 0 {
		return ""
	}
	names := make([]string, 0, 3)
	for i, e := range entries {
		if i >= 3 {
			break
		}
		names = append(names, e.Name)
	}
	return "（例如：" + strings.Join(names, "、") + "）"
}

// ----------------------------------------------------------------------- Run

// Run 跑一次明文攻击。onLog 会收到 bkcrack 的每一行输出（stderr 带
// [stderr] 前缀），界面靠它做实时日志。
func Run(ctx context.Context, opts AttackOptions, onLog func(string)) AttackResult {
	var res AttackResult

	if err := validateOptions(opts); err != nil {
		res.Err = err
		return res
	}
	exe, err := ResolveBkcrack()
	if err != nil {
		res.Err = err
		return res
	}

	args := attackArgs(opts)
	if onLog != nil {
		onLog("$ " + filepath.Base(exe) + " " + strings.Join(quoteArgs(args), " "))
	}

	raw, keys, err := runStreaming(ctx, exe, args, onLog)
	res.Raw = raw
	// 拿到密钥就算成功：bkcrack 有时会在找到密钥后以非 0 退出（比如
	// 收尾写日志失败），那不影响我们手里的密钥。
	if keys != ([3]string{}) {
		res.Keys = keys
		return res
	}
	res.Err = classifyRun(raw, keys, err)
	return res
}

// classifyRun 把 bkcrack 的输出与退出状态翻译成对用户有意义的错误。
//
// 「找不到密钥」是最常见的结果，bkcrack 会正常退出并打印
// `Could not find the keys.`；这时候给用户看「退出码 0」毫无意义，应该
// 明确说密钥没恢复出来。
func classifyRun(raw string, keys [3]string, runErr error) error {
	if keys != ([3]string{}) {
		return nil
	}
	if errors.Is(runErr, ErrCancelled) {
		return runErr
	}
	if strings.Contains(raw, "Could not find the keys") {
		return ErrKeysNotFound
	}
	if runErr != nil {
		return runErr
	}
	return ErrKeysNotFound
}

func validateOptions(opts AttackOptions) error {
	if strings.TrimSpace(opts.EncryptedZip) == "" {
		return errors.New("attack: 没有指定加密压缩包")
	}
	if strings.TrimSpace(opts.CipherEntry) == "" {
		return errors.New("attack: 没有指定目标条目")
	}
	// -x 与 -p 互斥：两种明文形式同时填只会让 bkcrack 的行为变得难以解释。
	if strings.TrimSpace(opts.HexPlaintext) != "" {
		if strings.TrimSpace(opts.PlainPath) != "" {
			return errors.New("attack: 十六进制明文与明文文件只能选一种")
		}
		if _, err := NormalizeHex(opts.HexPlaintext); err != nil {
			return err
		}
		if opts.HexOffset < 0 {
			return errors.New("attack: 偏移量不能是负数")
		}
		return nil
	}
	if strings.TrimSpace(opts.PlainPath) == "" {
		return errors.New("attack: 没有指定明文")
	}
	if opts.PlainIsZip && strings.TrimSpace(opts.PlainEntry) == "" {
		return errors.New("attack: 明文 ZIP 模式下必须指定明文条目名")
	}
	return nil
}

// attackArgs 构造 bkcrack 的攻击参数。每个参数独立一项，文件名里的空格
// 与中文原样传递。
//
// 十六进制模式：bkcrack -C <zip> -c <entry> -x <offset> <hex>
// 注意 hex 里不能带空格，NormalizeHex 已经保证这一点。
func attackArgs(opts AttackOptions) []string {
	args := []string{"-C", opts.EncryptedZip, "-c", opts.CipherEntry}

	if hex, err := NormalizeHex(opts.HexPlaintext); err == nil {
		return append(args, "-x", strconv.FormatInt(opts.HexOffset, 10), hex)
	}

	if opts.PlainIsZip {
		args = append(args, "-P", opts.PlainPath, "-p", opts.PlainEntry)
	} else {
		args = append(args, "-p", opts.PlainPath)
	}
	return args
}

// quoteArgs 只用于把命令回显到日志里；真正执行时用的是未加引号的数组。
func quoteArgs(args []string) []string {
	out := make([]string, len(args))
	for i, a := range args {
		if a == "" || strings.ContainsAny(a, " \t\"'&|<>") {
			out[i] = `"` + a + `"`
			continue
		}
		out[i] = a
	}
	return out
}

// ------------------------------------------------------------------- Decrypt

// Decrypt 用恢复出的密钥把整个包重新写一份到 outputZip。
//
// newPassword 为空时用 -D 生成无密码包（直接去掉加密标记）；非空时用
// -U 换成新密码。之所以不用「-U 后面省略密码」的写法：那会让 bkcrack
// 转去读标准输入，进程挂在那里等输入，界面看起来就是卡死。
func Decrypt(ctx context.Context, encryptedZip, keys, outputZip, newPassword string, onLog func(string)) error {
	if strings.TrimSpace(outputZip) == "" {
		return errors.New("attack: 没有指定输出路径")
	}
	return runDecrypt(ctx, encryptedZip, keys, func(keyArgs []string) []string {
		args := append([]string{"-C", encryptedZip, "-k"}, keyArgs...)
		if strings.TrimSpace(newPassword) == "" {
			return append(args, "-D", outputZip)
		}
		return append(args, "-U", outputZip, newPassword)
	}, outputZip, onLog)
}

// DecryptEntry 用恢复出的密钥只解出目标条目，写到 outputPath。
func DecryptEntry(ctx context.Context, encryptedZip, keys, entryName, outputPath string, onLog func(string)) error {
	if strings.TrimSpace(entryName) == "" {
		return errors.New("attack: 没有指定条目名")
	}
	if strings.TrimSpace(outputPath) == "" {
		return errors.New("attack: 没有指定输出路径")
	}

	err := runDecrypt(ctx, encryptedZip, keys, func(keyArgs []string) []string {
		args := append([]string{"-C", encryptedZip, "-k"}, keyArgs...)
		return append(args, "-c", entryName, "-d", outputPath)
	}, outputPath, onLog)
	if err != nil {
		return err
	}
	return maybeDecompress(encryptedZip, entryName, outputPath, onLog)
}

// runDecrypt 是两个解密入口共用的骨架：解析密钥、拼参数、跑进程、确认
// 输出文件真的生成了。
func runDecrypt(ctx context.Context, encryptedZip, keys string, buildArgs func([]string) []string, outputPath string, onLog func(string)) error {
	if strings.TrimSpace(encryptedZip) == "" {
		return errors.New("attack: 没有指定加密压缩包")
	}
	keyArgs, err := splitKeys(keys)
	if err != nil {
		return err
	}
	exe, err := ResolveBkcrack()
	if err != nil {
		return err
	}

	args := buildArgs(keyArgs)
	if onLog != nil {
		onLog("$ " + filepath.Base(exe) + " " + strings.Join(quoteArgs(args), " "))
	}
	if _, _, err := runStreaming(ctx, exe, args, onLog); err != nil {
		return err
	}

	if _, statErr := os.Stat(outputPath); statErr != nil {
		return fmt.Errorf("attack: bkcrack 没有生成 %s", outputPath)
	}
	return nil
}

// splitKeys 把 "853a600f cacad6c6 f0a084a4" 拆成三个独立参数。
//
// bkcrack 的 -k 收三个参数（-k X Y Z）。整串一起传会变成「一个」参数，
// bkcrack 解析失败后报的错跟密钥无关，很难看出是调用方的问题。
func splitKeys(keys string) ([]string, error) {
	fields := strings.Fields(keys)
	if len(fields) != 3 {
		return nil, fmt.Errorf("attack: 密钥需要三组十六进制，实际拿到 %d 组", len(fields))
	}
	for _, f := range fields {
		if len(f) != 8 {
			return nil, fmt.Errorf("attack: 密钥 %q 不是 8 位十六进制", f)
		}
		if _, err := parseHex32(f); err != nil {
			return nil, fmt.Errorf("attack: 密钥 %q 不是十六进制", f)
		}
	}
	return fields, nil
}

func parseHex32(s string) (uint32, error) {
	var v uint32
	for i := 0; i < len(s); i++ {
		c := s[i]
		var d uint32
		switch {
		case c >= '0' && c <= '9':
			d = uint32(c - '0')
		case c >= 'a' && c <= 'f':
			d = uint32(c-'a') + 10
		case c >= 'A' && c <= 'F':
			d = uint32(c-'A') + 10
		default:
			return 0, fmt.Errorf("非十六进制字符 %q", c)
		}
		v = v<<4 | d
	}
	return v, nil
}

// maybeDecompress 处理一个容易忽略的细节：bkcrack -d 写出的是「解密后的
// 条目数据」，对 Deflate 条目来说仍然是压缩流。用户点「只解出目标条目」
// 想要的是原始文件，所以这里按条目声明的压缩方式再解一层。
func maybeDecompress(encryptedZip, entryName, outputPath string, onLog func(string)) error {
	entry, err := findEntry(encryptedZip, entryName)
	if err != nil {
		return nil // 查不到条目就保持 bkcrack 的原始输出
	}
	if entry.Compression != "Deflate" {
		return nil
	}

	data, err := os.ReadFile(outputPath)
	if err != nil {
		return err
	}
	r := flate.NewReader(bytes.NewReader(data))
	out, err := io.ReadAll(r)
	r.Close()
	if err != nil {
		if onLog != nil {
			onLog(fmt.Sprintf("[zipkit] 条目是 Deflate，但解压失败（%v），保留压缩后的字节", err))
		}
		return nil
	}

	if err := os.WriteFile(outputPath, out, 0o644); err != nil {
		return err
	}
	if onLog != nil {
		onLog(fmt.Sprintf("[zipkit] 条目是 Deflate，已解压为原始文件（%d 字节）", len(out)))
		if got, want := crc32.ChecksumIEEE(out), entry.CRC32; got != want {
			onLog(fmt.Sprintf("[zipkit] 警告：解出的内容 CRC32 %08x 与条目记录 %08x 不一致", got, want))
		}
	}
	return nil
}

// ---------------------------------------------------------------- 进程与输出

// collector 收集原始输出并从中解析密钥。stdout / stderr 两个 goroutine
// 同时往里写，所以全程加锁。
type collector struct {
	mu   sync.Mutex
	raw  strings.Builder
	keys [3]string
}

func (c *collector) add(line string) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.raw.Len() < maxRawBytes {
		c.raw.WriteString(line)
		c.raw.WriteByte('\n')
	}
	if c.keys != ([3]string{}) {
		return
	}
	if k, ok := parseKeys(line); ok {
		c.keys = k
	}
}

func (c *collector) snapshot() (string, [3]string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.raw.String(), c.keys
}

var (
	// 单独成行的三组密钥（bkcrack 收尾时输出）。
	keysLineRe = regexp.MustCompile(`^([0-9a-fA-F]{8}) ([0-9a-fA-F]{8}) ([0-9a-fA-F]{8})$`)
	// 同一行里带 Keys 前缀的形式（进度条刚刷完时会出现）。
	keysInlineRe = regexp.MustCompile(`Keys:?\s+([0-9a-fA-F]{8}) ([0-9a-fA-F]{8}) ([0-9a-fA-F]{8})`)
	// 终端控制序列（bkcrack 用 \x1b[1K 擦掉进度行）。
	ansiRe = regexp.MustCompile("\x1b\\[[0-9;?]*[A-Za-z]")
)

// parseKeys 从一行输出里解析三组密钥。
//
// 不能用「第 N 行就是密钥」这种写法：bkcrack 不同版本的输出行数不一样，
// 进度刷新也会改变行数，只有十六进制的形状是稳定的。
func parseKeys(line string) ([3]string, bool) {
	if m := keysLineRe.FindStringSubmatch(line); m != nil {
		return [3]string{strings.ToLower(m[1]), strings.ToLower(m[2]), strings.ToLower(m[3])}, true
	}
	if m := keysInlineRe.FindStringSubmatch(line); m != nil {
		return [3]string{strings.ToLower(m[1]), strings.ToLower(m[2]), strings.ToLower(m[3])}, true
	}
	return [3]string{}, false
}

// splitLines 同时按 \n 和 \r 切分。bkcrack 的进度是回车刷新的，只按 \n
// 切会把几万个进度点挤成一行，日志里根本没法看。
func splitLines(data []byte, atEOF bool) (int, []byte, error) {
	if atEOF && len(data) == 0 {
		return 0, nil, nil
	}
	if i := bytes.IndexAny(data, "\r\n"); i >= 0 {
		return i + 1, data[:i], nil
	}
	if atEOF {
		return len(data), data, nil
	}
	return 0, nil, nil
}

// pump 逐行读取一路输出：清洗控制字符、记进 collector、推给界面。
func pump(r io.Reader, prefix string, c *collector, onLog func(string)) {
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 64<<10), 1<<20)
	sc.Split(splitLines)

	for sc.Scan() {
		line := strings.TrimSpace(ansiRe.ReplaceAllString(sc.Text(), ""))
		if line == "" {
			continue
		}
		c.add(line)
		if onLog != nil {
			onLog(prefix + line)
		}
	}
}

// runStreaming 跑一个 bkcrack 进程并实时读取输出。
//
// 这里刻意不用 cmd.Output() / CombinedOutput()：那要等进程退出才拿到全部
// 输出，攻击期间界面一片空白，用户会以为卡死了。
func runStreaming(ctx context.Context, exe string, args []string, onLog func(string)) (string, [3]string, error) {
	cmd := executil.CommandContext(ctx, exe, args...)
	// 显式给一个空 stdin：万一某个参数组合让 bkcrack 想读标准输入，
	// 它会立刻读到 EOF 而不是挂在那里等。
	cmd.Stdin = strings.NewReader("")

	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return "", [3]string{}, fmt.Errorf("attack: 接管 bkcrack 输出失败：%v", err)
	}
	stderr, err := cmd.StderrPipe()
	if err != nil {
		return "", [3]string{}, fmt.Errorf("attack: 接管 bkcrack 错误输出失败：%v", err)
	}

	if err := cmd.Start(); err != nil {
		return "", [3]string{}, fmt.Errorf("attack: 启动 bkcrack 失败：%v", err)
	}
	unregister := registerCommand(cmd)
	defer unregister()

	var c collector
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		pump(stdout, "", &c, onLog)
	}()
	go func() {
		defer wg.Done()
		pump(stderr, "[stderr] ", &c, onLog)
	}()
	wg.Wait()

	waitErr := cmd.Wait()
	raw, keys := c.snapshot()

	if ctx.Err() != nil || killed.Load() {
		return raw, keys, ErrCancelled
	}
	if waitErr != nil {
		// 统一格式：工具名 + 退出码 + 输出的前 5 行。「exit status 1」本身
		// 对用户没有任何信息量，bkcrack 自己说的话才是关键。
		code := -1
		var ee *exec.ExitError
		if errors.As(waitErr, &ee) {
			code = ee.ExitCode()
		}
		tail := lastLines(raw, 5)
		if len(tail) > 0 {
			return raw, keys, fmt.Errorf("bkcrack 退出码 %d\n%s", code, indentLines(tail))
		}
		return raw, keys, fmt.Errorf("bkcrack 退出码 %d：%v", code, waitErr)
	}
	return raw, keys, nil
}

// indentLines 把几行输出缩进两格，方便贴在错误信息里阅读。
func indentLines(lines []string) string {
	out := make([]string, 0, len(lines))
	for _, line := range lines {
		out = append(out, "  "+line)
	}
	return strings.Join(out, "\n")
}

// lastMeaningfulLine 取最后一条非进度行，用来解释 bkcrack 为什么退出。
func lastMeaningfulLine(raw string) string {
	lines := lastLines(raw, 1)
	if len(lines) == 0 {
		return ""
	}
	return lines[len(lines)-1]
}

var (
	procMu  sync.Mutex
	procCmd *exec.Cmd
	// killed 记录「这次进程是被 Kill 停掉的」。光看 ctx 不够：调用方可能
	// 只调 Kill 没取消 context，那种情况也应该算用户主动停止。
	killed atomic.Bool
)

// registerCommand 登记当前在跑的进程，返回注销函数。
func registerCommand(cmd *exec.Cmd) func() {
	killed.Store(false)
	procMu.Lock()
	procCmd = cmd
	procMu.Unlock()

	return func() {
		procMu.Lock()
		if procCmd == cmd {
			procCmd = nil
		}
		procMu.Unlock()
	}
}

// Kill 立刻终止正在跑的 bkcrack 进程，返回被终止的进程数。
//
// 只取消 context 是不够的：exec.CommandContext 要等到下一次检查点才动手，
// 而 bkcrack 在 Z 值搜索里可能连续跑很久都不看 context。用户点「停止」
// 必须当场生效。
func Kill() int {
	procMu.Lock()
	cmd := procCmd
	procMu.Unlock()

	if cmd == nil || cmd.Process == nil {
		return 0
	}
	if err := cmd.Process.Kill(); err != nil {
		return 0
	}
	killed.Store(true)
	return 1
}
