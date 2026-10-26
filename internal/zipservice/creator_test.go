package zipservice

import (
	"bytes"
	"encoding/binary"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// 说明：指纹表来自 ziptool 的 KNOWN_HEADERS，判定依据是本地文件头的前 10 字节
// （签名 + version needed + GPBF + 压缩方法）。这里的 fixture 直接按这 10 字节
// 的期望值构造，而不是用各家软件现做一个包——本机没有 360压缩 / Bandizip /
// WinRAR / 2345 好压，伪造「由某软件生成」的样本没有意义，能验证的契约是
// 「给定这 10 字节，返回这家厂商与这个置信度」。

// creatorCase 是一行指纹的测试用例。
type creatorCase struct {
	name       string
	gpbf       uint16
	method     uint16
	wantName   string
	wantConf   string
	wantInEvi  string
	skipReason string
}

func TestDetectCreatorFingerprints(t *testing.T) {
	cases := []creatorCase{
		{
			name:      "360压缩 / 7-Zip",
			gpbf:      0x0001,
			method:    8,
			wantName:  "360压缩 / 7-Zip",
			wantConf:  ConfidenceMedium,
			wantInEvi: "GPBF=0x0001",
		},
		{
			name:      "Bandizip（0x000B）",
			gpbf:      0x000B,
			method:    8,
			wantName:  "Bandizip",
			wantConf:  ConfidenceHigh,
			wantInEvi: "GPBF=0x000B",
		},
		{
			name:      "Bandizip / WinRAR（0x0009）",
			gpbf:      0x0009,
			method:    8,
			wantName:  "Bandizip / WinRAR",
			wantConf:  ConfidenceMedium,
			wantInEvi: "GPBF=0x0009",
		},
		{
			name:      "2345 好压",
			gpbf:      0x0801,
			method:    8,
			wantName:  "2345 好压",
			wantConf:  ConfidenceHigh,
			wantInEvi: "GPBF=0x0801",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			path := writeDetailFixture(t, "creator.zip", buildDetailZip([]dEntry{
				{name: "a.txt", method: tc.method, gpbf: tc.gpbf, data: []byte("hello")},
			}))

			got, err := DetectCreator(path)
			if err != nil {
				t.Fatalf("DetectCreator: %v", err)
			}
			if got.Name != tc.wantName {
				t.Errorf("Name = %q，want %q（依据：%s）", got.Name, tc.wantName, got.Evidence)
			}
			if got.Confidence != tc.wantConf {
				t.Errorf("Confidence = %q，want %q", got.Confidence, tc.wantConf)
			}
			if !strings.Contains(got.Evidence, tc.wantInEvi) {
				t.Errorf("Evidence 里应包含 %q，实际 %q", tc.wantInEvi, got.Evidence)
			}
		})
	}
}

// 退化行（GPBF=0 + Deflate）不能报厂商名：几乎所有工具都会写出这组字节。
func TestDetectCreatorDegenerateRowIsUnknown(t *testing.T) {
	path := writeDetailFixture(t, "plain.zip", buildDetailZip([]dEntry{
		{name: "a.txt", method: 8, gpbf: 0, data: []byte("hello")},
	}))

	got, err := DetectCreator(path)
	if err != nil {
		t.Fatalf("DetectCreator: %v", err)
	}
	if got.Name != CreatorUnknown {
		t.Errorf("Name = %q，want %q——默认组合不能盖厂商戳", got.Name, CreatorUnknown)
	}
	if got.Confidence != ConfidenceLow {
		t.Errorf("Confidence = %q，want %q", got.Confidence, ConfidenceLow)
	}
	if !strings.Contains(got.Evidence, "默认组合") {
		t.Errorf("Evidence 应说明为什么判不出来：%q", got.Evidence)
	}
}

// 指纹表只覆盖 Deflate；Store 的同款 GPBF 不能硬套，要老实报 Unknown。
func TestDetectCreatorStoreIsUnknown(t *testing.T) {
	path := writeDetailFixture(t, "store.zip", buildDetailZip([]dEntry{
		{name: "a.txt", method: 0, gpbf: 0x0001, data: []byte("hello")},
	}))

	got, err := DetectCreator(path)
	if err != nil {
		t.Fatalf("DetectCreator: %v", err)
	}
	if got.Name != CreatorUnknown || got.Confidence != ConfidenceUnknown {
		t.Errorf("got %q/%q，want Unknown/unknown", got.Name, got.Confidence)
	}
	if !strings.Contains(got.Evidence, "不在已知指纹表里") {
		t.Errorf("Evidence = %q", got.Evidence)
	}
}

// 第一个条目是目录时，要跳过它去看真正的内容条目。
func TestDetectCreatorSkipsDirectories(t *testing.T) {
	path := writeDetailFixture(t, "dirfirst.zip", buildDetailZip([]dEntry{
		// 目录条目的头部与内容条目不同，先命中它会得出错误结论。
		{name: "folder/", method: 0, gpbf: 0, data: nil},
		{name: "folder/a.txt", method: 8, gpbf: 0x000B, data: []byte("hello")},
	}))

	got, err := DetectCreator(path)
	if err != nil {
		t.Fatalf("DetectCreator: %v", err)
	}
	if got.Name != "Bandizip" {
		t.Errorf("Name = %q，want Bandizip（应跳过目录条目）", got.Name)
	}
}

// version made by 要翻成「版本（宿主系统）」，它是佐证信息而不是指纹。
func TestDetectCreatorVersionString(t *testing.T) {
	path := writeDetailFixture(t, "v.zip", buildDetailZip([]dEntry{
		{name: "a.txt", method: 8, gpbf: 0x000B, data: []byte("hello")},
	}))

	got, err := DetectCreator(path)
	if err != nil {
		t.Fatalf("DetectCreator: %v", err)
	}
	// buildDetailZip 写的是 0x031E = 版本 3.0、宿主 Unix。
	if !strings.HasPrefix(got.Version, "3.0") {
		t.Errorf("Version = %q，want 以 3.0 开头", got.Version)
	}
	if !strings.Contains(got.Version, "Unix") {
		t.Errorf("Version = %q，应带宿主系统", got.Version)
	}
	if !strings.Contains(got.Evidence, "version made by=") {
		t.Errorf("Evidence 应带上 version made by：%q", got.Evidence)
	}
}

func TestDetectCreatorEmptyZip(t *testing.T) {
	path := writeDetailFixture(t, "empty.zip", emptyZipBytes())
	got, err := DetectCreator(path)
	if err != nil {
		t.Fatalf("DetectCreator: %v", err)
	}
	if got.Name != CreatorUnknown || got.Confidence != ConfidenceUnknown {
		t.Errorf("got %q/%q，want Unknown/unknown", got.Name, got.Confidence)
	}
	if !strings.Contains(got.Evidence, "没有条目") {
		t.Errorf("Evidence = %q", got.Evidence)
	}
}

func TestDetectCreatorRejectsGarbage(t *testing.T) {
	dir := t.TempDir()

	notZip := filepath.Join(dir, "not.zip")
	if err := os.WriteFile(notZip, []byte("this is definitely not a zip file"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := DetectCreator(notZip); err == nil {
		t.Error("非 ZIP 文件应报错")
	}

	if _, err := DetectCreator(filepath.Join(dir, "missing.zip")); err == nil {
		t.Error("不存在的文件应报错")
	}
	if _, err := DetectCreator("   "); err == nil {
		t.Error("空路径应报错")
	}
}

// 中央目录可能在几百 KB 之后：识别必须按 EOCD 记录的偏移去 ReadAt，
// 而不是假设它紧跟在数据后面。
func TestDetectCreatorFarCentralDirectory(t *testing.T) {
	blob := buildDetailZip([]dEntry{
		{name: "big.bin", method: 8, gpbf: 0x000B, data: bytes.Repeat([]byte{0xAB}, 400<<10)},
	})
	path := writeDetailFixture(t, "far.zip", blob)

	got, err := DetectCreator(path)
	if err != nil {
		t.Fatalf("DetectCreator: %v", err)
	}
	if got.Name != "Bandizip" {
		t.Errorf("Name = %q", got.Name)
	}
}

func TestMatchCreatorFingerprint(t *testing.T) {
	// 每个指纹都能被自己命中，且不会串到别的行。
	// 遍历的是 KnownLocalHeaders —— 指纹字节只有这一份来源。
	for _, fp := range KnownLocalHeaders {
		got, ok := matchCreatorFingerprint(fp.Bytes)
		if !ok {
			t.Errorf("%s 没有命中自己", fp.Label)
			continue
		}
		if got.Label != fp.Label {
			t.Errorf("命中串行了：%s → %s", fp.Label, got.Label)
		}
		// 字节相同的那两行 Label 也相同，只能靠字节比。
		if !bytes.Equal(got.Bytes, fp.Bytes) {
			t.Errorf("%s 命中的字节对不上：% X vs % X", fp.Label, got.Bytes, fp.Bytes)
		}
	}
	// 长度不足时不应 panic。
	if _, ok := matchCreatorFingerprint([]byte{0x50, 0x4b}); ok {
		t.Error("不足 10 字节不应命中")
	}
	if _, ok := matchCreatorFingerprint(nil); ok {
		t.Error("nil 不应命中")
	}
}

// 指纹表新增一行却忘了标置信度时，DetectCreator 不能冒充 high。
func TestKnownLocalHeadersHaveConfidence(t *testing.T) {
	for _, fp := range KnownLocalHeaders {
		switch fp.confidence {
		case ConfidenceHigh, ConfidenceMedium, ConfidenceLow:
		default:
			t.Errorf("%s 的 confidence = %q，应为 high / medium / low", fp.Label, fp.confidence)
		}
		if strings.TrimSpace(fp.reason) == "" {
			t.Errorf("%s 缺少判定理由（reason）", fp.Label)
		}
	}
}

// 退化的那一行必须是「GPBF=0 + Deflate」，且只有它。
func TestDegenerateFingerprintIsDefaultCombo(t *testing.T) {
	var degenerate int
	for _, fp := range KnownLocalHeaders {
		if !fp.degenerate {
			continue
		}
		degenerate++
		if got := binary.LittleEndian.Uint16(fp.Bytes[6:8]); got != 0 {
			t.Errorf("%s 被标为退化，但 GPBF = 0x%04X，应为 0", fp.Label, got)
		}
		if got := binary.LittleEndian.Uint16(fp.Bytes[8:10]); got != 8 {
			t.Errorf("%s 被标为退化，但方法 = 0x%04X，应为 Deflate", fp.Label, got)
		}
		if fp.confidence != ConfidenceLow {
			t.Errorf("%s 是退化行，置信度应为 low，实际 %q", fp.Label, fp.confidence)
		}
	}
	if degenerate != 1 {
		t.Errorf("退化行应恰好 1 条，实际 %d", degenerate)
	}
}

func TestDescribeVersionMadeBy(t *testing.T) {
	cases := []struct {
		v    uint16
		want string
	}{
		{0x0000, ""},
		{0x0014, "2.0（FAT）"},
		{0x003F, "6.3（FAT）"},
		{0x031E, "3.0（Unix）"},
		{0x0A14, "2.0（NTFS）"},
		{0x7F14, "2.0"}, // 未知宿主系统时只给版本号
	}
	for _, c := range cases {
		if got := describeVersionMadeBy(c.v); got != c.want {
			t.Errorf("describeVersionMadeBy(0x%04X) = %q，want %q", c.v, got, c.want)
		}
	}
}
