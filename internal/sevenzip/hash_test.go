package sevenzip

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"hash/crc32"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

// testdata 下的样本都由 7z.exe a -p1234 生成，内容是一个 13 字节的文本文件
// "hello zipkit\n"，四种形态分别覆盖：
//
//	aes-lzma2.7z    默认参数（LZMA2）+ 加密头
//	aes-lzma1.7z    -m0=lzma（LZMA1）+ 加密头
//	aes-copy.7z     -mx=0（Store/copy，dataType=0，哈希没有尾部两个字段）
//	plain-header.7z -mhe=off（头不加密，只有数据流加密）
//	plain-copy.7z   -mhe=off -mx=0
//
// 另外两个是「多条目 + 头部被压缩」的样本，内容是两个小文本文件，用来覆盖
// 7-Zip 在条目数 ≥ 2 且头部未加密时的默认行为（kEncodedHeader，0x17）：
//
//	multi-mhe-off.7z     -mhe=off，头部 LZMA2 压缩（NextHeader 只有 34 字节）
//	multi-mhe-off-raw.7z -mhe=off -mhc=off，头部明文（NextHeader 182 字节）
//
// 两者内容、压缩参数完全一致，只有头部的存放方式不同，所以数据流的 CRC
// 必须相同——这是「解出的头部确实指到了同一段数据」的硬证据。
//
// 固定样本的好处是哈希里的 salt/iv/CRC 全都不变，可以当黄金值做回归。
const testPassword = "1234"

func extractFile(t *testing.T, name string) string {
	t.Helper()
	hash, err := ExtractHash(filepath.Join("testdata", name))
	if err != nil {
		t.Fatalf("ExtractHash(%s): %v", name, err)
	}
	return hash
}

// TestExtractHashGolden 锁住四种形态的完整 $7z$ 字符串。
func TestExtractHashGolden(t *testing.T) {
	want := map[string]string{
		"aes-lzma2.7z": "$7z$0$19$0$$16$37a13c734496126afb36b13b582a1fa0$561336347$112$98$" +
			"8714e97029dd741f1e5f470bcc7cf0abdb7112114027bc6d605554abccb434acf5415e1f8154216d6ac48cbb3d679d814f264c511605bea636d19cd95137ad48d379448f80d9c609dd6fb5aeafffb353a79199423eb5a8acd8bdee4f18911754cf46bbf10e37cfe7b6c816e7cbf82e0a",
		"aes-lzma1.7z": "$7z$0$19$0$$16$a187f3043d94068eeb3ca197ade8a373$2703523876$128$114$" +
			"c8dbbdecfff7c64407bd9da8c5c8b246753ec13c058f34e44c4068b460032a31541c8d51c1651e5e255d6396aa0b5c568fcb7f951bed73a938cde1d6db4f68a59860e16c5387c5db593f9f01dbba75517c58ec43027bc19cb87c03daa2474f7195e6a52656f342bad3d21146c4ba0f1da2e2f8e655bbe0a5477643552f58e352",
		"aes-copy.7z": "$7z$0$19$0$$16$54aa59266e0752562afa3e22d6718a4c$693620215$112$98$" +
			"5c35f885962d0d59b3a27ac2c1977ad49449194f619b2b0549c734c18a4e8f6032e277f9cd74fb5b930495b0c8505a8b5956835a7ff8727e6f03c47c83e93c4605d2eda50bb300a59305366c5b5e6a9e2fab08bd001d50eac8e9833cb333919143b480c912e91609686bc1dde05af77b",
		"plain-header.7z": "$7z$2$19$0$$16$65b532be92fe0d5a79eae09598b1a29c$2656730354$32$17$" +
			"bad6728547ab464e4ca83832d3f3daf58bd6dcff1d868a913da1bf48067e998c$13$00",
		"plain-copy.7z": "$7z$0$19$0$$16$fa938c08a3f277e7c86b741db3d9c2d2$2656730354$16$13$" +
			"65f36ded627efa8c1181e75d874ed3b1",
		// 多条目 + 头部被压缩。修复前这两个样本里 multi-mhe-off.7z 会报
		// 「归档里没有 AES 加密的数据流」——它和 plain-header.7z 的差别只在于
		// 条目数是 2，7-Zip 因此把头部压缩了。
		"multi-mhe-off.7z": "$7z$2$19$0$$16$10b158af4c401a32a7c798fff11dccc0$2656730354$48$48$" +
			"ddff1436db4dbb84460a6955cd7dc4e036255014c4385ba7a69e5f65a043c1f6474e33314bdd183ac59b9dd1f5b5998c$13$00",
		"multi-mhe-off-raw.7z": "$7z$2$19$0$$16$a8cc7da6ebbc53308c0fd9c4803183c9$2656730354$48$48$" +
			"993b52f80fea0b5e3a8728a37ae36f91faef1a308df26973be37c8571e361921861a146e5f63184f1c89b88850492ef8$13$00",
	}
	for name, expected := range want {
		if got := extractFile(t, name); got != expected {
			t.Errorf("%s 哈希变了：\n got %s\nwant %s", name, got, expected)
		}
	}
}

// TestExtractHashEncodedHeader 覆盖「数据加密、头部只压缩不加密」这条路径。
//
// 这是 7-Zip 的默认行为：条目数 ≥ 2 时头部会被 LZMA 压缩，于是 NextHeader
// 的第一个字节是 kEncodedHeader(0x17)，而它的 StreamsInfo 描述的是**头部**
// 这条流，不是文件数据。早期实现直接在这条流里找 AES，必然落空，用户看到
// 的就是「归档里没有 AES 加密的数据流」。
func TestExtractHashEncodedHeader(t *testing.T) {
	// 先确认样本真的是 0x17，否则这个测试就失去意义了。
	raw := mustRead(t, filepath.Join("testdata", "multi-mhe-off.7z"))
	nextOff := binary.LittleEndian.Uint64(raw[12:20])
	nextSize := binary.LittleEndian.Uint64(raw[20:28])
	start := int64(sigHdrSize) + int64(nextOff)
	if start+int64(nextSize) > int64(len(raw)) {
		t.Fatal("样本头部越界")
	}
	if got := raw[start]; got != idEncodedHeader {
		t.Fatalf("样本的头部类型是 0x%02x，期望 0x%02x（kEncodedHeader）", got, idEncodedHeader)
	}
	// 头部被压缩后应该明显小于明文头部的 182 字节。
	if nextSize >= 100 {
		t.Fatalf("样本头部有 %d 字节，看起来没有被压缩", nextSize)
	}

	compressed := extractFile(t, "multi-mhe-off.7z")
	plain := extractFile(t, "multi-mhe-off-raw.7z")

	// 两条路径指向同一段数据：CRC、dataType、dataLen 必须一致。
	cf := strings.Split(compressed, "$")
	pf := strings.Split(plain, "$")
	for _, idx := range []int{2, 8, 9, 10} {
		if cf[idx] != pf[idx] {
			t.Errorf("第 %d 个字段不一致：压缩头部=%q 明文头部=%q", idx, cf[idx], pf[idx])
		}
	}
	// iv 是每次创建归档时随机生成的，本来就该不同——如果相同，说明两个样本
	// 其实是同一个文件。（7-Zip 默认不带 salt，所以 saltLen 恒为 0，比 iv 才有意义。）
	if cf[7] == pf[7] {
		t.Error("两个样本的 iv 相同，样本可能被覆盖成同一个文件")
	}
	if cf[2] == "0" {
		t.Error("dataType 是 0，说明 AES 后面没有压缩器，与预期不符")
	}

	// 光「结构对」还不够：用真实密码解密再解压，必须还原出两个文件的原始
	// 内容（solid 归档的 folder 输出就是各文件内容的拼接）。这一步同时验证
	// 了密文起点、KDF、iv、dataType 和 coderAttrs 全都指对了。
	iv, _ := hex.DecodeString(cf[7])
	data, _ := hex.DecodeString(cf[11])
	attrs, _ := hex.DecodeString(cf[13])
	unpackLen := uint64(mustInt(t, cf[10]))

	blk, err := aes.NewCipher(derive7zKey(utf16LE(testPassword), uint8(mustInt(t, cf[3]))))
	if err != nil {
		t.Fatal(err)
	}
	plainBuf := make([]byte, len(data))
	cipher.NewCBCDecrypter(blk, iv).CryptBlocks(plainBuf, data)

	got, err := decodeLZMA2(plainBuf, attrs, unpackLen)
	if err != nil {
		t.Fatalf("解密后的数据解不开：%v", err)
	}
	const want = "hello zipkit\nsecond file in the same folder\n"
	if string(got) != want {
		t.Fatalf("解出的明文不对：\n got %q\nwant %q", got, want)
	}
}

// TestLZMA2DictCap 锁住 LZMA2 字典大小属性的换算，以及「不超过解出长度」的收敛。
func TestLZMA2DictCap(t *testing.T) {
	cases := []struct {
		prop byte
		out  uint64
		want int
	}{
		{0, 0, 4096},           // (2|0) << 11，低于下限时抬到 MinDictCap
		{1, 0, 6144},           // (2|1) << 11
		{16, 0, 1 << 20},       // (2|0) << 19
		{40, 0, 1<<32 - 1},     // 规范里的特例
		{41, 0, 4096},          // 越界属性退回下限
		{16, 100, 4096},        // 声明 1 MiB，但只解出 100 字节 → 抬到下限
		{16, 1 << 20, 1 << 20}, // 正好相等
		{16, 8 << 20, 1 << 20}, // 解出长度更大时不放大
	}
	for _, tc := range cases {
		if got := lzma2DictCap(tc.prop, tc.out); got != tc.want {
			t.Errorf("lzma2DictCap(%d, %d) = %d，期望 %d", tc.prop, tc.out, got, tc.want)
		}
	}
}

// TestExtractHashShape 检查 $7z$ 各字段的数量、取值域和前后一致性。
// 不做黄金比对，改动实现时也能兜住结构性问题。
func TestExtractHashShape(t *testing.T) {
	for _, name := range []string{
		"aes-lzma2.7z", "aes-lzma1.7z", "aes-copy.7z", "plain-header.7z", "plain-copy.7z",
		"multi-mhe-off.7z", "multi-mhe-off-raw.7z",
	} {
		name := name
		t.Run(name, func(t *testing.T) {
			hash := extractFile(t, name)
			if !strings.HasPrefix(hash, "$7z$") {
				t.Fatalf("前缀不是 $7z$：%s", hash)
			}
			f := strings.Split(hash, "$")
			// f[0] 是空串（hash 以 $ 开头），f[1] 是 "7z"。
			if len(f) < 12 {
				t.Fatalf("字段太少：%d，%s", len(f), hash)
			}
			dataType := mustInt(t, f[2])
			cycles := mustInt(t, f[3])
			saltLen := mustInt(t, f[4])
			salt := f[5]
			ivLen := mustInt(t, f[6])
			iv := f[7]
			crc := mustUint32(t, f[8])
			dataLen := mustInt(t, f[9])
			unpackLen := mustInt(t, f[10])
			data := f[11]

			if dataType < 0 || dataType > 255 {
				t.Errorf("dataType 越界：%d", dataType)
			}
			// 7z 的迭代指数是 19 位左右，这里只兜一个合理区间，防止读错字节。
			if cycles < 1 || cycles > 24 {
				t.Errorf("cost 不合理：%d", cycles)
			}
			if saltLen != len(salt)/2 {
				t.Errorf("saltLen=%d 与 salt 长度 %d 不符", saltLen, len(salt)/2)
			}
			if ivLen != len(iv)/2 {
				t.Errorf("ivLen=%d 与 iv 长度 %d 不符", ivLen, len(iv)/2)
			}
			if ivLen != 16 {
				t.Errorf("iv 应补零到 16 字节，实际 %d", ivLen)
			}
			if dataLen != len(data)/2 {
				t.Errorf("dataLen=%d 与 data 长度 %d 不符", dataLen, len(data)/2)
			}
			if dataLen == 0 || dataLen%16 != 0 {
				t.Errorf("dataLen 必须是 16 的正整数倍，实际 %d", dataLen)
			}
			if unpackLen <= 0 || unpackLen > dataLen {
				t.Errorf("unpackLen 应在 (0, dataLen] 内，实际 %d / %d", unpackLen, dataLen)
			}
			if crc == 0 {
				t.Errorf("CRC 为 0，大概率没读到")
			}
			// dataType 0（明文）和 128（截断）没有尾部字段，其它都有。
			if dataType == 0 || dataType == 128 {
				if len(f) != 12 {
					t.Errorf("dataType=%d 不该有尾部字段，实际 %d 段：%s", dataType, len(f), hash)
				}
			} else if len(f) != 14 {
				t.Errorf("dataType=%d 应带 crcLen/coderAttrs 两段，实际 %d 段：%s", dataType, len(f), hash)
			}
		})
	}
}

// TestExtractHashMatchesCiphertext 用真实密码解密，验证：
//   - 密钥派生（滚动拼接的 SHA-256）没写错；
//   - dataLen 指向的密文位置正确（解出来是有意义的明文而不是垃圾）；
//   - dataType=0 时 CRC 就是明文 CRC。
//
// 这一步是整条链路上唯一能"自证"的检查：哈希格式对不对，最终由 hashcat 说了算；
// 但密文位置和 KDF 对不对，只有解一次才知道。
//
// 注意 -mhe=on 的三个样本目标不是文件内容，而是被加密的**头**：头一加密，
// 不先解密就列不出文件，所以 7z2john 也是拿头流当目标。解开后应该是
// idHeader(0x01) + idMainStreamsInfo(0x04) 开头的一段 NextHeader。
func TestExtractHashMatchesCiphertext(t *testing.T) {
	cases := []struct {
		name string
		// encryptedHeader 表示这个样本的头是加密的，解出来应是 NextHeader。
		encryptedHeader bool
	}{
		{"aes-lzma2.7z", true},
		{"aes-lzma1.7z", true},
		{"aes-copy.7z", true},
		{"plain-header.7z", false},
		{"plain-copy.7z", false},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			raw, err := os.ReadFile(filepath.Join("testdata", tc.name))
			if err != nil {
				t.Fatal(err)
			}
			f := strings.Split(extractFile(t, tc.name), "$")
			dataType := mustInt(t, f[2])
			cycles := uint8(mustInt(t, f[3]))
			iv, _ := hex.DecodeString(f[7])
			dataLen := mustInt(t, f[9])
			unpackLen := mustInt(t, f[10])
			data, _ := hex.DecodeString(f[11])

			// 哈希里的密文必须是文件里的连续一段，且长度与 dataLen 一致。
			idx := strings.Index(hex.EncodeToString(raw), f[11])
			if idx < 0 || idx%2 != 0 {
				t.Fatalf("密文没有原样出现在文件里")
			}
			if len(data) != dataLen {
				t.Fatalf("dataLen=%d 与密文长度 %d 不符", dataLen, len(data))
			}

			key := derive7zKey(utf16LE(testPassword), cycles)
			blk, err := aes.NewCipher(key)
			if err != nil {
				t.Fatal(err)
			}
			out := make([]byte, len(data))
			cipher.NewCBCDecrypter(blk, iv).CryptBlocks(out, data)

			if dataType != 0 {
				// LZMA1/LZMA2：CRC 是解压后算的，这里只兜"整段解错"——密钥或 iv
				// 错的时候，压缩流开头几乎必然是垃圾，这里只排除全零这种退化情况。
				if isAllZero(out) {
					t.Fatalf("解密结果全是零，KDF 或 iv 错了")
				}
				return
			}
			if got := crc32.ChecksumIEEE(out[:unpackLen]); got != mustUint32(t, f[8]) {
				t.Fatalf("CRC 不匹配：算出 %d，哈希里 %s", got, f[8])
			}
			if tc.encryptedHeader {
				if out[0] != 0x01 || out[1] != 0x04 {
					t.Fatalf("解出来不是 NextHeader：% x", out[:8])
				}
			} else if string(out[:unpackLen]) != "hello zipkit\n" {
				t.Fatalf("明文不匹配：%q", out[:unpackLen])
			}
		})
	}
}

func isAllZero(b []byte) bool {
	for _, c := range b {
		if c != 0 {
			return false
		}
	}
	return true
}

func TestExtractHashRejectsGarbage(t *testing.T) {
	dir := t.TempDir()
	full := mustRead(t, filepath.Join("testdata", "aes-lzma2.7z"))
	cases := map[string][]byte{
		"empty.7z": {},                             // 空文件
		"short.7z": []byte("not a 7z file at all"), // 连签名头都不够
		// 签名对、后面全零：过得了签名检查，过不了 nextOffset 校验。
		"magic.7z": append([]byte("7z\xbc\xaf\x27\x1c"), make([]byte, 64)...),
		"trunc.7z": full[:40], // 签名头被截断
	}
	for name, body := range cases {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, body, 0o644); err != nil {
			t.Fatal(err)
		}
		if _, err := ExtractHash(p); err == nil {
			t.Errorf("%s: 期望报错，实际成功", name)
		}
	}
	if _, err := ExtractHash(filepath.Join(dir, "does-not-exist.7z")); err == nil {
		t.Error("不存在的文件应报错")
	}
}

func mustRead(t *testing.T, p string) []byte {
	t.Helper()
	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func mustInt(t *testing.T, s string) int {
	t.Helper()
	n, err := strconv.Atoi(s)
	if err != nil {
		t.Fatalf("不是整数：%q", s)
	}
	return n
}

func mustUint32(t *testing.T, s string) uint32 {
	t.Helper()
	n, err := strconv.ParseUint(s, 10, 32)
	if err != nil {
		t.Fatalf("不是 uint32：%q", s)
	}
	return uint32(n)
}

func utf16LE(s string) []byte {
	out := make([]byte, 0, len(s)*2)
	for _, r := range s {
		out = append(out, byte(r), byte(r>>8))
	}
	return out
}

// derive7zKey 复刻 7z 的密钥派生：把 (密码 || 小端计数器) 反复喂给同一个
// SHA-256 上下文，而不是每轮 sha256(上一轮摘要)。
func derive7zKey(pw []byte, cycles uint8) []byte {
	h := sha256.New()
	var ctr [8]byte
	for i := uint32(0); i < 1<<cycles; i++ {
		h.Write(pw)
		binary.LittleEndian.PutUint64(ctr[:], uint64(i))
		h.Write(ctr[:])
	}
	return h.Sum(nil)
}
