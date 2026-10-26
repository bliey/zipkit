//go:build ignore

// generate.go 生成 internal/zcrack/testdata 下的固定测试 ZIP。
//
// 标准库 archive/zip 只能读不能写 ZipCrypto，所以这里手写一份最小的 ZIP 写入器，
// 用它构造 ZipCrypto（传统加密）与 AES（仅头部字段，数据不可解）两类样本。
//
// 用法（在 internal/zcrack 目录下）：
//
//	go run testdata/generate.go
package main

import (
	"bytes"
	"compress/flate"
	"encoding/binary"
	"fmt"
	"hash/crc32"
	"log"
	"os"
	"path/filepath"
)

// ---------------------------------------------------------------------------
// ZipCrypto
// ---------------------------------------------------------------------------

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

type keys struct{ k0, k1, k2 uint32 }

func (k keys) update(b byte) keys {
	k0 := crcTable[(k.k0^uint32(b))&0xff] ^ (k.k0 >> 8)
	k1 := (k.k1+k0&0xff)*134775813 + 1
	k2 := crcTable[(k.k2^uint32(byte(k1>>24)))&0xff] ^ (k.k2 >> 8)
	return keys{k0, k1, k2}
}

func decryptByte(k2 uint32) byte {
	t := uint32(uint16(k2) | 2)
	return byte((t * (t ^ 1)) >> 8)
}

// encryptPayload 用 password 加密 payload，返回 12 字节头 + 密文。
// checkByte 是加密头第 12 个字节：一般是 CRC32 的最高字节，置了 GPBF bit 3
// （数据描述符）时按 PKWARE 规范应写 DOS 修改时间的高字节。
func encryptPayload(password string, checkByte byte, payload []byte) []byte {
	k := keys{0x12345678, 0x23456789, 0x34567890}
	for i := 0; i < len(password); i++ {
		k = k.update(password[i])
	}
	hdr := make([]byte, 12)
	for i := 0; i < 11; i++ {
		hdr[i] = byte(0x41 + i*7) // 确定性"随机"字节，便于复现
	}
	hdr[11] = checkByte

	out := make([]byte, 12+len(payload))
	for i := 0; i < 12; i++ {
		out[i] = hdr[i] ^ decryptByte(k.k2)
		k = k.update(hdr[i])
	}
	for i, p := range payload {
		out[12+i] = p ^ decryptByte(k.k2)
		k = k.update(p)
	}
	return out
}

// ---------------------------------------------------------------------------
// 最小 ZIP 写入器
// ---------------------------------------------------------------------------

type entry struct {
	name       string
	data       []byte
	password   string
	method     uint16 // 0=Store, 8=Deflate
	descriptor bool   // 置 GPBF bit 3（CRC 与长度放在数据描述符里）
	aes        bool   // 用 AES 头部字段（method=99），数据不可解
}

const (
	lfhSig  = 0x04034b50
	cdSig   = 0x02014b50
	eocdSig = 0x06054b50
	ddSig   = 0x08074b50

	modTime = 0x6000 // 12:00:00
	modDate = 0x5a21 // 2025-01-01
)

func deflate(data []byte) []byte {
	var buf bytes.Buffer
	w, err := flate.NewWriter(&buf, flate.DefaultCompression)
	if err != nil {
		log.Fatal(err)
	}
	if _, err := w.Write(data); err != nil {
		log.Fatal(err)
	}
	if err := w.Close(); err != nil {
		log.Fatal(err)
	}
	return buf.Bytes()
}

func buildZip(entries []entry) []byte {
	var body bytes.Buffer
	type cdRec struct {
		name   string
		flags  uint16
		method uint16
		crc    uint32
		csize  uint32
		usize  uint32
		off    uint32
		extra  []byte
	}
	var recs []cdRec

	for _, e := range entries {
		payload := e.data
		method := e.method
		if method == 8 {
			payload = deflate(e.data)
		}
		crc := crc32.ChecksumIEEE(e.data)
		var extra []byte
		flags := uint16(0)
		stored := payload

		if e.aes {
			flags |= 1
			method = 99
			// AES 扩展字段 0x9901: version(2) vendor(2) strength(1) method(2)
			extra = []byte{0x01, 0x99, 0x07, 0x00, 0x02, 0x00, 'A', 'E', 0x03, 0x08, 0x00}
			fake := make([]byte, 12+len(payload)+10)
			for i := range fake {
				fake[i] = byte(i*13 + 5)
			}
			stored = fake
		} else if e.password != "" {
			flags |= 1
			check := byte(crc >> 24)
			if e.descriptor {
				check = byte(modTime >> 8) // 规范：bit 3 置位时用 DOS 时间高字节
			}
			stored = encryptPayload(e.password, check, payload)
		}

		off := uint32(body.Len())
		lfhCRC, lfhCSize, lfhUSize := crc, uint32(len(stored)), uint32(len(e.data))
		if e.descriptor {
			flags |= 0x0008
			lfhCRC, lfhCSize, lfhUSize = 0, 0, 0
		}

		var lfh [30]byte
		binary.LittleEndian.PutUint32(lfh[0:], lfhSig)
		binary.LittleEndian.PutUint16(lfh[4:], 20)
		binary.LittleEndian.PutUint16(lfh[6:], flags)
		binary.LittleEndian.PutUint16(lfh[8:], method)
		binary.LittleEndian.PutUint16(lfh[10:], modTime)
		binary.LittleEndian.PutUint16(lfh[12:], modDate)
		binary.LittleEndian.PutUint32(lfh[14:], lfhCRC)
		binary.LittleEndian.PutUint32(lfh[18:], lfhCSize)
		binary.LittleEndian.PutUint32(lfh[22:], lfhUSize)
		binary.LittleEndian.PutUint16(lfh[26:], uint16(len(e.name)))
		binary.LittleEndian.PutUint16(lfh[28:], uint16(len(extra)))
		body.Write(lfh[:])
		body.WriteString(e.name)
		body.Write(extra)
		body.Write(stored)
		if e.descriptor {
			var dd [16]byte
			binary.LittleEndian.PutUint32(dd[0:], ddSig)
			binary.LittleEndian.PutUint32(dd[4:], crc)
			binary.LittleEndian.PutUint32(dd[8:], uint32(len(stored)))
			binary.LittleEndian.PutUint32(dd[12:], uint32(len(e.data)))
			body.Write(dd[:])
		}

		recs = append(recs, cdRec{e.name, flags, method, crc, uint32(len(stored)), uint32(len(e.data)), off, extra})
	}

	cdOff := uint32(body.Len())
	for _, r := range recs {
		var cd [46]byte
		binary.LittleEndian.PutUint32(cd[0:], cdSig)
		binary.LittleEndian.PutUint16(cd[4:], 20)
		binary.LittleEndian.PutUint16(cd[6:], 20)
		binary.LittleEndian.PutUint16(cd[8:], r.flags)
		binary.LittleEndian.PutUint16(cd[10:], r.method)
		binary.LittleEndian.PutUint16(cd[12:], modTime)
		binary.LittleEndian.PutUint16(cd[14:], modDate)
		binary.LittleEndian.PutUint32(cd[16:], r.crc)
		binary.LittleEndian.PutUint32(cd[20:], r.csize)
		binary.LittleEndian.PutUint32(cd[24:], r.usize)
		binary.LittleEndian.PutUint16(cd[28:], uint16(len(r.name)))
		binary.LittleEndian.PutUint16(cd[30:], uint16(len(r.extra)))
		binary.LittleEndian.PutUint32(cd[42:], r.off)
		body.Write(cd[:])
		body.WriteString(r.name)
		body.Write(r.extra)
	}
	cdSize := uint32(body.Len()) - cdOff

	var eocd [22]byte
	binary.LittleEndian.PutUint32(eocd[0:], eocdSig)
	binary.LittleEndian.PutUint16(eocd[8:], uint16(len(recs)))
	binary.LittleEndian.PutUint16(eocd[10:], uint16(len(recs)))
	binary.LittleEndian.PutUint32(eocd[12:], cdSize)
	binary.LittleEndian.PutUint32(eocd[16:], cdOff)
	body.Write(eocd[:])
	return body.Bytes()
}

// ---------------------------------------------------------------------------

var sampleText = []byte("The quick brown fox jumps over the lazy dog.\n" +
	"Pack my box with five dozen liquor jugs.\n" +
	"How vexingly quick daft zebras jump!\n" +
	"Sphinx of black quartz, judge my vow.\n" +
	"0123456789 abcdefghijklmnopqrstuvwxyz\n")

// bigText 生成约 300KB 的"类日志"文本，压缩后仍有上百 KB，
// 用来验证大条目下的破解耗时（每次误报都要解密整段数据）。
func bigText() []byte {
	var b bytes.Buffer
	words := []string{"alpha", "bravo", "charlie", "delta", "echo", "foxtrot",
		"golf", "hotel", "india", "juliett", "kilo", "lima", "mike", "november"}
	for i := 0; i < 6000; i++ {
		fmt.Fprintf(&b, "%04d %s %s %s %d\n", i, words[i%len(words)],
			words[(i*7)%len(words)], words[(i*13)%len(words)], i*i%9973)
	}
	return b.Bytes()
}

func main() {
	dir := filepath.Join("testdata")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		log.Fatal(err)
	}

	files := []struct {
		name string
		zip  []byte
	}{
		{"num6.zip", buildZip([]entry{{name: "hello.txt", data: sampleText, password: "123456", method: 8}})},
		{"num6_big.zip", buildZip([]entry{{name: "big.log", data: bigText(), password: "123456", method: 8}})},
		{"num7.zip", buildZip([]entry{{name: "hello.txt", data: sampleText, password: "7654321", method: 8}})},
		{"num8.zip", buildZip([]entry{{name: "hello.txt", data: sampleText, password: "88888888", method: 8}})},
		// 前导零样本：真实微信账单 ZIP 就是 052092 + 数据描述符。
		{"leadingzero6.zip", buildZip([]entry{{name: "hello.txt", data: sampleText, password: "052092", method: 8}})},
		{"leadingzero_desc6.zip", buildZip([]entry{{name: "hello.txt", data: sampleText, password: "052092", method: 8, descriptor: true}})},
		{"leadingzero_store6.zip", buildZip([]entry{{name: "hello.txt", data: sampleText, password: "012345", method: 0}})},
		{"allzero6.zip", buildZip([]entry{{name: "hello.txt", data: sampleText, password: "000000", method: 8}})},
		{"store6.zip", buildZip([]entry{{name: "hello.txt", data: sampleText, password: "123456", method: 0}})},
		{"descriptor6.zip", buildZip([]entry{{name: "hello.txt", data: sampleText, password: "123456", method: 8, descriptor: true}})},
		{"alpha6.zip", buildZip([]entry{{name: "hello.txt", data: sampleText, password: "abc123", method: 8}})},
		{"five6.zip", buildZip([]entry{{name: "hello.txt", data: sampleText, password: "12345", method: 8}})},
		{"aes.zip", buildZip([]entry{{name: "hello.txt", data: sampleText, password: "123456", method: 8, aes: true}})},
		{"multi.zip", buildZip([]entry{
			{name: "readme.txt", data: []byte("not encrypted\n"), method: 8},
			{name: "secret.txt", data: sampleText, password: "123456", method: 8},
		})},
	}

	for _, f := range files {
		p := filepath.Join(dir, f.name)
		if err := os.WriteFile(p, f.zip, 0o644); err != nil {
			log.Fatal(err)
		}
		fmt.Printf("wrote %s (%d bytes)\n", p, len(f.zip))
	}
}
