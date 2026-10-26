// 条目详情（展开视图）的单测。
//
// 分两层：
//   一、纯格式化层 frontend/entry-detail.js —— 不需要 DOM，直接 import 就能测。
//       重点钉住**偏移算术**：中央目录固定 46 字节、本地头固定 30 字节、
//       扩展字段的 TLV 起点、数据描述符的四种布局。
//   二、渲染层 app.js 的 renderEntryDetail —— 用假 DOM 跑一遍真实代码，
//       确认字段表能拼出来、不会因为改名/漏引入而 ReferenceError。
//
// fixture 的字段形状取自一次真实的 ZipService.ReadEntryDetail 输出
// （PascalCase、嵌入的 Entry 被摊平、[]byte 序列化成 base64），只是把文件名
// 换成了中性的 "docs/report.csv"，并相应调整了 NameLen 与各类长度。
//
//   node --test tests/entry-detail.test.mjs

import test from "node:test";
import assert from "node:assert/strict";
import path from "node:path";
import { pathToFileURL } from "node:url";

import {
  base64ToBytes,
  centralFieldRows,
  descriptorRows,
  extraFieldRows,
  extraNote,
  flagMeanings,
  fmtOffset,
  hex16,
  hex32,
  hexBytes,
  localFieldRows,
  methodText,
  nameText,
  sizeText,
  splitModified,
  versionMadeByText,
  versionNeededText,
  versionText,
} from "../frontend/entry-detail.js";

import {
  installDom,
  prepareAppModule,
  writeRuntimeStub,
} from "./dom-stub.mjs";

const ROOT = path.resolve(import.meta.dirname, "..");
const FRONTEND = path.join(ROOT, "frontend");

// ------------------------------------------------------------------ fixture

function detailFixture(overrides = {}) {
  const base = {
    // ---- 嵌入的 Entry（中央目录字段，和 Inspect 返回的一致）
    Name: "docs/report.csv",
    Compression: "Deflate",
    Method: 8,
    IsEncrypted: true,
    EncryptionType: "ZipCrypto",
    GPFlags: 2057, // 0x0809：加密 + 数据描述符 + UTF-8
    CRC32: 715130766,
    CompressedSize: 5470,
    UncompressedSize: 22487,
    LocalHeaderOffset: 96,
    IsFakeEncrypted: false,
    FakeEvidence: "",

    // ---- 详情独有字段
    NameEncoding: "utf-8",
    CentralOffset: 5827,
    CentralRecordLen: 85, // 46 + 15 + 24 + 0
    NameLen: 15,
    ExtraLen: 24,
    CommentLen: 0,
    VersionMadeBy: 798, // 0x031E → UNIX，3.0
    VersionNeeded: 20, // 2.0
    DiskStart: 0,
    InternalAttrs: 1,
    ExternalAttrs: 2176188416,
    ModTime: 36261, // 0x8DA5
    ModDate: 22403, // 0x5783
    Modified: "2023-12-03 17:45:10",
    ActualMethod: 8,
    CentralExtra: [
      { ID: 21589, Name: "扩展时间戳", Size: 5, Offset: 0, Data: "AyZObGU=" },
      { ID: 30837, Name: "Unix UID/GID", Size: 11, Offset: 9, Data: "AQQAAAAABAAAAAA=" },
    ],
    Flags: [
      { Bit: 1, Name: "加密" },
      { Bit: 8, Name: "使用数据描述符（CRC / 大小写在数据之后）" },
      { Bit: 2048, Name: "文件名与注释为 UTF-8" },
    ],
    Local: {
      Offset: 96,
      Version: 20,
      GPFlags: 2057,
      Method: 8,
      MethodName: "Deflate",
      ModTime: 36261,
      ModDate: 22403,
      Modified: "2023-12-03 17:45:10",
      CRC32: 715130766,
      CompressedSize: 5470,
      UncompressedSize: 22487,
      NameLen: 15,
      ExtraLen: 28,
      Name: "docs/report.csv",
      NameEncoding: "utf-8",
      Extra: [
        { ID: 21589, Name: "扩展时间戳", Size: 9, Offset: 0, Data: "AyZObGUmTmxl" },
        { ID: 30837, Name: "Unix UID/GID", Size: 11, Offset: 13, Data: "AQQAAAAABAAAAAA=" },
      ],
      Flags: [
        { Bit: 1, Name: "加密" },
        { Bit: 8, Name: "使用数据描述符（CRC / 大小写在数据之后）" },
        { Bit: 2048, Name: "文件名与注释为 UTF-8" },
      ],
      TotalLen: 73, // 30 + 15 + 28
    },
    LocalErr: "",
    Descriptor: {
      Offset: 5703,
      HasSignature: true,
      Zip64: false,
      CRC32: 715130766,
      CompressedSize: 5470,
      UncompressedSize: 22487,
      MatchesCentral: true,
    },
    Consistent: true,
  };
  return { ...base, ...overrides };
}

// rowOf 按字段名取一行，取不到就报清楚缺哪个字段。
function rowOf(rows, label) {
  const hit = rows.find((r) => r[0] === label);
  assert.ok(hit, `字段表里没有「${label}」，实际有：${rows.map((r) => r[0]).join(" / ")}`);
  return hit;
}

// ================================================== 一、基础格式化

test("fmtOffset：8 位大写十六进制，非法值给破折号", () => {
  assert.equal(fmtOffset(0), "0x00000000");
  assert.equal(fmtOffset(5827), "0x000016C3");
  assert.equal(fmtOffset(96), "0x00000060");
  assert.equal(fmtOffset(-1), "—");
  assert.equal(fmtOffset("abc"), "—");
  assert.equal(fmtOffset(null), "—");
});

test("hex16 / hex32：定宽大写，负数按位截断", () => {
  assert.equal(hex16(2057), "0x0809");
  assert.equal(hex16(0), "0x0000");
  assert.equal(hex16(0x1ffff), "0xFFFF");
  assert.equal(hex32(715130766), "0x2AA0078E");
  assert.equal(hex32(0), "0x00000000");
  assert.equal(hex32(0xffffffff), "0xFFFFFFFF");
});

test("sizeText：ZIP64 占位值要单独说明", () => {
  assert.equal(sizeText(0), "0 字节");
  assert.equal(sizeText(5470), "5470 字节");
  assert.equal(sizeText(0xffffffff), "0xFFFFFFFF（ZIP64 占位）");
  assert.equal(sizeText(-1), "—");
});

test("versionText 系列：版本号按「主 × 10 + 次」换算", () => {
  assert.equal(versionText(20), "2.0");
  assert.equal(versionText(45), "4.5");
  assert.equal(versionText(63), "6.3");
  assert.equal(versionNeededText(20), "0x0014（2.0）");

  // 0x031E：高字节 3 = UNIX，低字节 0x1E = 30 → 3.0
  assert.equal(versionMadeByText(798), "0x031E（UNIX，3.0）");
  // 0x0A63：高字节 10 = Windows NTFS，低字节 0x63 = 99 → 9.9
  assert.equal(versionMadeByText(0x0a63), "0x0A63（Windows NTFS，9.9）");
  // 未登记的主机号不能崩，要给出「主机 N」
  assert.equal(versionMadeByText(0x6300), "0x6300（主机 99，0.0）");
});

test("methodText / nameText / flagMeanings：空值都有兜底", () => {
  assert.equal(methodText(8, "Deflate"), "0x0008（Deflate）");
  assert.equal(methodText(99), "0x0063");
  assert.equal(nameText("a.txt", "ascii"), "a.txt");
  assert.equal(nameText("中文.txt", "utf-8"), "中文.txt（utf-8）");
  assert.equal(nameText("", "utf-8"), "(空)（utf-8）");
  assert.equal(flagMeanings([{ Name: "加密" }, { Name: "UTF-8" }]), "加密 / UTF-8");
  assert.equal(flagMeanings([]), "未置位");
  assert.equal(flagMeanings(null), "未置位");
});

test("splitModified：把 DOS 时间拆成日期与时间两段", () => {
  assert.deepEqual(splitModified("2023-12-03 17:45:10"), ["2023-12-03", "17:45:10"]);
  assert.deepEqual(splitModified("2023-12-03"), ["2023-12-03", ""]);
  assert.deepEqual(splitModified(""), ["", ""]);
  assert.deepEqual(splitModified(null), ["", ""]);
});

test("base64ToBytes / hexBytes：Go 的 []byte 走 base64", () => {
  assert.equal(base64ToBytes("").length, 0);
  assert.equal(base64ToBytes(null).length, 0);
  assert.deepEqual(Array.from(base64ToBytes("AyZObGU=")), [0x03, 0x26, 0x4e, 0x6c, 0x65]);

  assert.equal(hexBytes("AyZObGU="), "03 26 4E 6C 65");
  assert.equal(hexBytes(""), "—");
  assert.equal(hexBytes(null), "—");

  // 超过 limit 只显示前 limit 个字节，末尾补省略号
  const long = "AQQAAAAABAAAAAA="; // 11 字节
  assert.equal(hexBytes(long, 4), "01 04 00 00 …");
  assert.equal(hexBytes(long), "01 04 00 00 00 00 04 00 00 00 00");
});

// ================================================== 二、偏移算术

test("centralFieldRows：中央目录固定头 46 字节，各字段偏移必须对上", () => {
  const rows = centralFieldRows(detailFixture());
  const base = 5827;

  assert.equal(rowOf(rows, "签名")[1], fmtOffset(base));
  assert.equal(rowOf(rows, "版本（制作）")[1], fmtOffset(base + 4));
  assert.equal(rowOf(rows, "版本（解压所需）")[1], fmtOffset(base + 6));
  assert.equal(rowOf(rows, "通用位标志")[1], fmtOffset(base + 8));
  assert.equal(rowOf(rows, "压缩方法")[1], fmtOffset(base + 10));
  assert.equal(rowOf(rows, "修改时间")[1], fmtOffset(base + 12));
  assert.equal(rowOf(rows, "修改日期")[1], fmtOffset(base + 14));
  assert.equal(rowOf(rows, "CRC32")[1], fmtOffset(base + 16));
  assert.equal(rowOf(rows, "压缩后大小")[1], fmtOffset(base + 20));
  assert.equal(rowOf(rows, "原始大小")[1], fmtOffset(base + 24));
  assert.equal(rowOf(rows, "文件名长度")[1], fmtOffset(base + 28));
  assert.equal(rowOf(rows, "扩展字段长度")[1], fmtOffset(base + 30));
  assert.equal(rowOf(rows, "注释长度")[1], fmtOffset(base + 32));
  assert.equal(rowOf(rows, "起始磁盘号")[1], fmtOffset(base + 34));
  assert.equal(rowOf(rows, "内部属性")[1], fmtOffset(base + 36));
  assert.equal(rowOf(rows, "外部属性")[1], fmtOffset(base + 38));
  assert.equal(rowOf(rows, "本地头偏移")[1], fmtOffset(base + 42));

  // 可变部分紧跟在 46 字节固定头后面
  assert.equal(rowOf(rows, "文件名")[1], "0x000016F1"); // 5827 + 46
  assert.equal(rowOf(rows, "扩展字段")[1], "0x00001700"); // + 15 字节名字
  assert.equal(rowOf(rows, "注释")[1], "0x00001718"); // + 24 字节扩展字段
});

test("centralFieldRows：值列的内容也对", () => {
  const rows = centralFieldRows(detailFixture());

  assert.equal(rowOf(rows, "签名")[2], "50 4B 01 02");
  assert.equal(rowOf(rows, "版本（制作）")[2], "0x031E（UNIX，3.0）");
  assert.equal(rowOf(rows, "通用位标志")[2], "0x0809");
  assert.equal(rowOf(rows, "压缩方法")[2], "0x0008（Deflate）");
  assert.equal(rowOf(rows, "修改时间")[2], "0x8DA5（17:45:10）");
  assert.equal(rowOf(rows, "修改日期")[2], "0x5783（2023-12-03）");
  assert.equal(rowOf(rows, "CRC32")[2], "0x2AA0078E");
  assert.equal(rowOf(rows, "压缩后大小")[2], "5470 字节");
  assert.equal(rowOf(rows, "本地头偏移")[2], "0x00000060");
  assert.equal(rowOf(rows, "文件名")[2], "docs/report.csv（utf-8）");
  assert.equal(rowOf(rows, "扩展字段")[2], "2 个");
  assert.equal(rowOf(rows, "注释")[2], "无");
});

test("centralFieldRows：AES 条目要把真实方法单独标出来", () => {
  const rows = centralFieldRows(
    detailFixture({ Method: 99, Compression: "AES-256", ActualMethod: 8 }),
  );
  const method = rowOf(rows, "压缩方法")[2];
  assert.match(method, /0x0063/);
  assert.match(method, /真实方法 0x0008/);
});

test("localFieldRows：本地头固定部分 30 字节", () => {
  const detail = detailFixture();
  const rows = localFieldRows(detail.Local);
  const base = 96;

  assert.equal(rowOf(rows, "签名")[1], fmtOffset(base));
  assert.equal(rowOf(rows, "版本（解压所需）")[1], fmtOffset(base + 4));
  assert.equal(rowOf(rows, "通用位标志")[1], fmtOffset(base + 6));
  assert.equal(rowOf(rows, "压缩方法")[1], fmtOffset(base + 8));
  assert.equal(rowOf(rows, "修改时间")[1], fmtOffset(base + 10));
  assert.equal(rowOf(rows, "修改日期")[1], fmtOffset(base + 12));
  assert.equal(rowOf(rows, "CRC32")[1], fmtOffset(base + 14));
  assert.equal(rowOf(rows, "压缩后大小")[1], fmtOffset(base + 18));
  assert.equal(rowOf(rows, "原始大小")[1], fmtOffset(base + 22));
  assert.equal(rowOf(rows, "文件名长度")[1], fmtOffset(base + 26));
  assert.equal(rowOf(rows, "扩展字段长度")[1], fmtOffset(base + 28));

  assert.equal(rowOf(rows, "文件名")[1], "0x0000007E"); // 96 + 30
  assert.equal(rowOf(rows, "扩展字段")[1], "0x0000008D"); // + 15 字节名字
  assert.equal(rowOf(rows, "固定头长度")[2], "73 字节");
});

test("extraFieldRows：扩展字段偏移 = 记录起点 + 固定头 + 名字 + TLV 偏移", () => {
  const rows = extraFieldRows(detailFixture());

  assert.equal(rows.length, 4); // 中央 2 个 + 本地 2 个

  const central0 = rows[0];
  const central1 = rows[1];
  const local0 = rows[2];
  const local1 = rows[3];

  assert.equal(central0[0], "中央目录");
  assert.equal(central0[1], "0x5455"); // 0x5455 扩展时间戳
  assert.equal(central0[2], "扩展时间戳");
  assert.equal(central0[3], "0x00001700"); // 5827 + 46 + 15 + 0
  assert.equal(central0[4], "5 字节");
  assert.equal(central0[5], "03 26 4E 6C 65");

  assert.equal(central1[3], "0x00001709"); // 上一个 TLV 占 4 + 5 字节
  assert.equal(central1[2], "Unix UID/GID");

  assert.equal(local0[0], "本地文件头");
  assert.equal(local0[3], "0x0000008D"); // 96 + 30 + 15 + 0
  assert.equal(local1[3], "0x0000009A"); // 96 + 30 + 15 + 13
});

test("extraNote：没有扩展字段时给「无」", () => {
  assert.equal(extraNote(detailFixture()), "中央目录 2 个 · 本地文件头 2 个");
  assert.equal(
    extraNote(detailFixture({ CentralExtra: [], Local: null })),
    "无",
  );
});

test("descriptorRows：四种布局的偏移各不相同", () => {
  const base = 5703;

  // 带签名 + 32 位
  const signed32 = descriptorRows({
    Offset: base,
    HasSignature: true,
    Zip64: false,
    CRC32: 1,
    CompressedSize: 2,
    UncompressedSize: 3,
    MatchesCentral: true,
  });
  assert.equal(rowOf(signed32, "签名")[1], fmtOffset(base));
  assert.equal(rowOf(signed32, "CRC32")[1], fmtOffset(base + 4));
  assert.equal(rowOf(signed32, "压缩后大小")[1], fmtOffset(base + 8));
  assert.equal(rowOf(signed32, "原始大小")[1], fmtOffset(base + 12));
  assert.equal(rowOf(signed32, "布局")[2], "32 位");

  // 带签名 + 64 位
  const signed64 = descriptorRows({
    Offset: base,
    HasSignature: true,
    Zip64: true,
    CRC32: 1,
    CompressedSize: 2,
    UncompressedSize: 3,
    MatchesCentral: true,
  });
  assert.equal(rowOf(signed64, "CRC32")[1], fmtOffset(base + 4));
  assert.equal(rowOf(signed64, "压缩后大小")[1], fmtOffset(base + 8));
  assert.equal(rowOf(signed64, "原始大小")[1], fmtOffset(base + 16));
  assert.equal(rowOf(signed64, "布局")[2], "ZIP64（8 字节大小字段）");

  // 无签名 + 32 位
  const plain32 = descriptorRows({
    Offset: base,
    HasSignature: false,
    Zip64: false,
    CRC32: 1,
    CompressedSize: 2,
    UncompressedSize: 3,
    MatchesCentral: false,
  });
  assert.equal(rowOf(plain32, "签名")[2], "（无签名）");
  assert.equal(rowOf(plain32, "CRC32")[1], fmtOffset(base));
  assert.equal(rowOf(plain32, "原始大小")[1], fmtOffset(base + 8));
  assert.equal(rowOf(plain32, "与中央目录一致")[2], "否");
});

// ================================================== 三、渲染层

// 只加载一次：模块顶层会跑 init()。
let appPromise = null;

async function loadApp() {
  if (!appPromise) {
    installDom();
    const { dir, entry } = prepareAppModule(FRONTEND, [
      "state",
      "el",
      "renderEntryDetail",
      "detailStatus",
      "closeEntryDetail",
    ]);
    writeRuntimeStub(dir);
    appPromise = import(pathToFileURL(entry).href).then(async (mod) => {
      await new Promise((r) => setTimeout(r, 50));
      return mod;
    });
  }
  return appPromise;
}

// 把假 DOM 树摊平成文本列表，用来断言「该出现的东西出现了」。
function collectText(node, out = []) {
  if (!node) return out;
  if (typeof node.textContent === "string" && node.textContent) out.push(node.textContent);
  for (const child of node.children || []) collectText(child, out);
  return out;
}

// 桩里的 className 只是普通字符串属性，不会同步到 classList，两个都要看。
function collectByClass(node, className, out = []) {
  if (!node) return out;
  const byName = String(node.className || "")
    .split(/\s+/)
    .includes(className);
  const byList = node.classList && node.classList.contains(className);
  if (byName || byList) out.push(node);
  for (const child of node.children || []) collectByClass(child, className, out);
  return out;
}

test("renderEntryDetail：五段字段表都渲染出来", async () => {
  const mod = await loadApp();
  const frag = mod.renderEntryDetail(detailFixture());

  const texts = collectText(frag);
  const joined = texts.join("|");

  for (const title of [
    "中央目录记录",
    "本地文件头（LFH）",
    "扩展字段",
    "通用位标志（GPBF）",
    "数据描述符",
  ]) {
    assert.ok(joined.includes(title), `缺少「${title}」这一段`);
  }

  // 字段名与值都要出现
  assert.ok(joined.includes("本地头偏移"));
  assert.ok(joined.includes("0x00000060"));
  assert.ok(joined.includes("docs/report.csv（utf-8）"));
  assert.ok(joined.includes("0x2AA0078E"));
  assert.ok(joined.includes("查看本地文件头字节"));

  // 五个 section 卡片
  assert.equal(collectByClass(frag, "detail-section").length, 5);
});

test("renderEntryDetail：本地头读不到时降级成错误提示，不抛异常", async () => {
  const mod = await loadApp();
  const frag = mod.renderEntryDetail(
    detailFixture({ Local: null, LocalErr: "偏移 999999 超出文件末尾" }),
  );

  const joined = collectText(frag).join("|");
  assert.ok(joined.includes("偏移 999999 超出文件末尾"));
  // 本地头那段仍然是 5 个 section（换成一条提示）
  assert.equal(collectByClass(frag, "detail-section").length, 5);
});

test("renderEntryDetail：没有数据描述符时给说明而不是空表", async () => {
  const mod = await loadApp();
  const frag = mod.renderEntryDetail(detailFixture({ Descriptor: null }));

  const joined = collectText(frag).join("|");
  assert.ok(joined.includes("没有数据描述符"));
  assert.equal(collectByClass(frag, "detail-table").length, 4); // 少一张描述符表
});

test("detailStatus：伪加密与不一致都要给出警告", async () => {
  const mod = await loadApp();

  const ok = collectText(mod.detailStatus(detailFixture())).join("|");
  assert.ok(ok.includes("本地文件头与中央目录一致"));

  const bad = collectText(
    mod.detailStatus(
      detailFixture({
        Consistent: false,
        IsFakeEncrypted: true,
        FakeEvidence: "中央目录加密位为 1，本地文件头为 0",
      }),
    ),
  ).join("|");
  assert.ok(bad.includes("不一致"));
  assert.ok(bad.includes("疑似伪加密"));
  assert.ok(bad.includes("中央目录加密位为 1，本地文件头为 0"));
});
