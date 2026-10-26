package attack

import (
	"bytes"
	"encoding/binary"
	"hash/crc32"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/bliey/zipkit/internal/zipservice"
)

// 这一层只验证「一致性判定与文案」。指纹本身的识别正确性由
// zipservice 的 creator_test.go 负责，所以这里的 fixture 只需要能造出
// 指定 GPBF 的本地文件头。

// buildZip 造一个只有一个条目的最小 ZIP，GPBF 与压缩方法可控。
func buildZip(gpbf, method uint16) []byte {
	name := []byte("a.txt")
	data := []byte("hello zipkit")
	crc := crc32.ChecksumIEEE(data)

	var b bytes.Buffer
	w16 := func(v uint16) { _ = binary.Write(&b, binary.LittleEndian, v) }
	w32 := func(v uint32) { _ = binary.Write(&b, binary.LittleEndian, v) }

	// 本地文件头
	w32(0x04034b50)
	w16(20)
	w16(gpbf)
	w16(method)
	w16(0)
	w16(0)
	w32(crc)
	w32(uint32(len(data)))
	w32(uint32(len(data)))
	w16(uint16(len(name)))
	w16(0)
	b.Write(name)
	b.Write(data)

	cdStart := uint32(b.Len())
	// 中央目录
	w32(0x02014b50)
	w16(0x031E) // version made by：3.0 / Unix
	w16(20)     // version needed
	w16(gpbf)
	w16(method)
	w16(0)
	w16(0)
	w32(crc)
	w32(uint32(len(data)))
	w32(uint32(len(data)))
	w16(uint16(len(name)))
	w16(0)
	w16(0)
	w16(0)
	w16(0)
	w32(0)
	w32(0) // 本地文件头偏移
	b.Write(name)
	cdSize := uint32(b.Len()) - cdStart

	// EOCD
	w32(0x06054b50)
	w16(0)
	w16(0)
	w16(1)
	w16(1)
	w32(cdSize)
	w32(cdStart)
	w16(0)
	return b.Bytes()
}

// writeZip 把 blob 写到临时目录并返回路径。
func writeZip(t *testing.T, dir, name string, blob []byte) string {
	t.Helper()
	p := filepath.Join(dir, name)
	if err := os.WriteFile(p, blob, 0o644); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestDetectCreatorsRejectsEmptyInput(t *testing.T) {
	if _, err := DetectCreators("", "b.zip"); err == nil {
		t.Error("缺加密包应报错")
	}
	if _, err := DetectCreators("a.zip", ""); err == nil {
		t.Error("缺明文 ZIP 应报错")
	}
}

func TestDetectCreatorsMissingFile(t *testing.T) {
	dir := t.TempDir()
	_, err := DetectCreators(filepath.Join(dir, "nope.zip"), filepath.Join(dir, "nope2.zip"))
	if err == nil {
		t.Fatal("文件不存在应报错")
	}
	if !strings.Contains(err.Error(), "识别") {
		t.Errorf("错误信息应说明是哪一步失败：%v", err)
	}
}

// 两边都是 high 且软件名相同 → same。
func TestDetectCreatorsSame(t *testing.T) {
	dir := t.TempDir()
	blob := buildZip(0x000B, 8) // Bandizip 特征，high
	a := writeZip(t, dir, "enc.zip", blob)
	b := writeZip(t, dir, "plain.zip", blob)

	pair, err := DetectCreators(a, b)
	if err != nil {
		t.Fatalf("DetectCreators: %v", err)
	}
	if pair.Verdict != VerdictSame {
		t.Fatalf("Verdict = %q，want %q（enc=%+v plain=%+v）",
			pair.Verdict, VerdictSame, pair.Encrypted, pair.Plain)
	}
	if !strings.Contains(pair.Message, "一致") || !strings.Contains(pair.Message, "Bandizip") {
		t.Errorf("Message = %q", pair.Message)
	}
}

// 两边都是 high 但软件名不同 → differ，并且文案要点出双方名字。
func TestDetectCreatorsDiffer(t *testing.T) {
	dir := t.TempDir()
	a := writeZip(t, dir, "enc.zip", buildZip(0x000B, 8))   // Bandizip
	b := writeZip(t, dir, "plain.zip", buildZip(0x0801, 8)) // 2345 好压

	pair, err := DetectCreators(a, b)
	if err != nil {
		t.Fatalf("DetectCreators: %v", err)
	}
	if pair.Verdict != VerdictDiffer {
		t.Fatalf("Verdict = %q，want %q", pair.Verdict, VerdictDiffer)
	}
	if !strings.Contains(pair.Message, "Bandizip") || !strings.Contains(pair.Message, "2345 好压") {
		t.Errorf("Message 应写出双方来源：%q", pair.Message)
	}
	if !strings.Contains(pair.Message, "成功率可能较低") {
		t.Errorf("Message 应给出风险提示：%q", pair.Message)
	}
}

// 任一边是 medium → unsure，不下结论。
func TestDetectCreatorsUnsure(t *testing.T) {
	dir := t.TempDir()
	a := writeZip(t, dir, "enc.zip", buildZip(0x0001, 8))   // 360压缩 / 7-Zip，medium
	b := writeZip(t, dir, "plain.zip", buildZip(0x000B, 8)) // Bandizip，high

	pair, err := DetectCreators(a, b)
	if err != nil {
		t.Fatalf("DetectCreators: %v", err)
	}
	if pair.Verdict != VerdictUnsure {
		t.Fatalf("Verdict = %q，want %q", pair.Verdict, VerdictUnsure)
	}
	if !strings.Contains(pair.Message, "仅供参考") {
		t.Errorf("Message = %q", pair.Message)
	}
}

// 任一边认不出来 → unknown，同样不下结论。
func TestDetectCreatorsUnknownVerdict(t *testing.T) {
	dir := t.TempDir()
	a := writeZip(t, dir, "enc.zip", buildZip(0x0000, 8))   // 退化行 → Unknown/low
	b := writeZip(t, dir, "plain.zip", buildZip(0x000B, 8)) // Bandizip，high

	pair, err := DetectCreators(a, b)
	if err != nil {
		t.Fatalf("DetectCreators: %v", err)
	}
	if pair.Encrypted.Name != zipservice.CreatorUnknown {
		t.Errorf("Encrypted.Name = %q，want Unknown", pair.Encrypted.Name)
	}
	if pair.Verdict != VerdictUnknown {
		t.Fatalf("Verdict = %q，want %q", pair.Verdict, VerdictUnknown)
	}
	if !strings.Contains(pair.Message, "不做一致性判断") {
		t.Errorf("Message = %q", pair.Message)
	}
}

// 结论只是提示：即使 differ 也照样返回结果，不返回 error。
func TestDetectCreatorsNeverBlocks(t *testing.T) {
	dir := t.TempDir()
	a := writeZip(t, dir, "enc.zip", buildZip(0x000B, 8))
	b := writeZip(t, dir, "plain.zip", buildZip(0x0801, 8))

	pair, err := DetectCreators(a, b)
	if err != nil {
		t.Fatalf("differ 不应返回 error：%v", err)
	}
	if pair.Verdict != VerdictDiffer {
		t.Fatalf("Verdict = %q", pair.Verdict)
	}
}
