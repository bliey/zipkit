// entry-detail.js —— 条目详情的「纯格式化」层。
//
// 这里只做两件事：把 ZipService.ReadEntryDetail 返回的结构体换算成
// 可以直接铺进表格的字符串，以及算出每个字段在文件里的绝对偏移。
//
// 为什么单独拆一个模块：
//   1. 这些函数没有 DOM、没有状态，可以在 Node 里直接跑单测（见
//      tests/entry-detail.test.mjs），不用搭一整套假 DOM；
//   2. 偏移算术是这一块最容易出错的地方（46 / 30 两个固定头长度、
//      扩展字段的 TLV 起点、数据描述符的四种布局），集中放一处好核对。
//
// 所有偏移都是**文件内绝对偏移**，和十六进制视图里的地址一致。

// ZIP 规范里 "version made by" 高字节记录制作该条目的主机系统。
const HOST_SYSTEMS = [
  "MS-DOS / FAT",
  "Amiga",
  "OpenVMS",
  "UNIX",
  "VM/CMS",
  "Atari ST",
  "OS/2 HPFS",
  "Macintosh",
  "Z-System",
  "CP/M",
  "Windows NTFS",
  "MVS",
  "VSE",
  "Acorn RISC",
  "VFAT",
  "MVS（alternate）",
  "BeOS",
  "Tandem",
  "OS/400",
  "OS X / Darwin",
];

// 中央目录记录固定部分 46 字节，本地文件头固定部分 30 字节。
export const CENTRAL_FIXED_LEN = 46;
export const LOCAL_FIXED_LEN = 30;

// ---------------------------------------------------------------- 基础格式

// fmtOffset 输出 0x 开头的 8 位大写十六进制偏移，和十六进制视图保持一致。
// 空值给破折号：Number(null) 是 0，不挡住的话会显示成 0x00000000，看着像真地址。
export function fmtOffset(value) {
  if (value === null || value === undefined || value === "") return "—";
  const n = Number(value);
  if (!Number.isFinite(n) || n < 0) return "—";
  return `0x${Math.trunc(n).toString(16).toUpperCase().padStart(8, "0")}`;
}

export function hex16(value) {
  const n = Number(value) & 0xffff;
  return `0x${n.toString(16).toUpperCase().padStart(4, "0")}`;
}

export function hex32(value) {
  const n = Number(value) >>> 0;
  return `0x${n.toString(16).toUpperCase().padStart(8, "0")}`;
}

// sizeText 把字节数写成十进制。0xFFFFFFFF 是 ZIP64 的占位值，
// 真实大小在 0x0001 扩展字段里，直接显示成 42 亿会让用户误解。
export function sizeText(value) {
  const n = Number(value);
  if (!Number.isFinite(n) || n < 0) return "—";
  if (n === 0xffffffff) return "0xFFFFFFFF（ZIP64 占位）";
  return `${n} 字节`;
}

export function methodText(code, name) {
  return name ? `${hex16(code)}（${name}）` : hex16(code);
}

// ZIP 的版本号是「主版本 × 10 + 次版本」：20 → 2.0，45 → 4.5。
export function versionText(version) {
  const n = Number(version) & 0xff;
  return `${Math.floor(n / 10)}.${n % 10}`;
}

export function versionNeededText(value) {
  const n = Number(value) || 0;
  return `${hex16(n)}（${versionText(n)}）`;
}

export function versionMadeByText(value) {
  const n = Number(value) || 0;
  const host = (n >> 8) & 0xff;
  const hostName = HOST_SYSTEMS[host] || `主机 ${host}`;
  return `${hex16(n)}（${hostName}，${versionText(n)}）`;
}

export function nameText(name, encoding) {
  const label = encoding && encoding !== "ascii" ? `（${encoding}）` : "";
  return `${name || "(空)"}${label}`;
}

export function flagMeanings(flags) {
  const list = Array.isArray(flags) ? flags : [];
  if (!list.length) return "未置位";
  return list.map((f) => f.Name).join(" / ");
}

// "2020-01-01 03:04:00" → ["2020-01-01", "03:04:00"]，解析失败时给空串。
export function splitModified(text) {
  const value = String(text || "").trim();
  if (!value) return ["", ""];
  const cut = value.indexOf(" ");
  if (cut < 0) return [value, ""];
  return [value.slice(0, cut), value.slice(cut + 1)];
}

export function base64ToBytes(source) {
  if (!source) return new Uint8Array(0);
  if (source instanceof Uint8Array) return source;
  if (Array.isArray(source)) return Uint8Array.from(source);

  const binary = atob(String(source));
  const out = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i += 1) {
    out[i] = binary.charCodeAt(i);
  }
  return out;
}

// ExtraField.Data 在 JSON 里是 base64（Go 的 []byte 就是这么序列化的），
// 这里统一转成十六进制串。太长只显示前 limit 个字节。
export function hexBytes(data, limit = 24) {
  const bytes = base64ToBytes(data);
  if (!bytes.length) return "—";
  const head = [];
  for (let i = 0; i < Math.min(bytes.length, limit); i += 1) {
    head.push(bytes[i].toString(16).toUpperCase().padStart(2, "0"));
  }
  return bytes.length > limit ? `${head.join(" ")} …` : head.join(" ");
}

// -------------------------------------------------------------- 字段行组装
//
// 每行都是 [字段名, 偏移, 值]，偏移一律是文件内绝对地址。

export function centralFieldRows(detail) {
  const base = Number(detail.CentralOffset) || 0;
  const at = (rel) => fmtOffset(base + rel);
  const extraRel = CENTRAL_FIXED_LEN + detail.NameLen;
  const commentRel = extraRel + detail.ExtraLen;
  const [date, time] = splitModified(detail.Modified);

  const method =
    detail.ActualMethod !== detail.Method
      ? `${methodText(detail.Method, detail.Compression)}，AES 封装内真实方法 ${hex16(detail.ActualMethod)}`
      : methodText(detail.Method, detail.Compression);

  return [
    ["签名", at(0), "50 4B 01 02"],
    ["版本（制作）", at(4), versionMadeByText(detail.VersionMadeBy)],
    ["版本（解压所需）", at(6), versionNeededText(detail.VersionNeeded)],
    ["通用位标志", at(8), hex16(detail.GPFlags)],
    ["压缩方法", at(10), method],
    ["修改时间", at(12), time ? `${hex16(detail.ModTime)}（${time}）` : hex16(detail.ModTime)],
    ["修改日期", at(14), date ? `${hex16(detail.ModDate)}（${date}）` : hex16(detail.ModDate)],
    ["CRC32", at(16), hex32(detail.CRC32)],
    ["压缩后大小", at(20), sizeText(detail.CompressedSize)],
    ["原始大小", at(24), sizeText(detail.UncompressedSize)],
    ["文件名长度", at(28), String(detail.NameLen)],
    ["扩展字段长度", at(30), String(detail.ExtraLen)],
    ["注释长度", at(32), String(detail.CommentLen)],
    ["起始磁盘号", at(34), String(detail.DiskStart)],
    ["内部属性", at(36), hex16(detail.InternalAttrs)],
    ["外部属性", at(38), hex32(detail.ExternalAttrs)],
    ["本地头偏移", at(42), fmtOffset(detail.LocalHeaderOffset)],
    ["文件名", at(CENTRAL_FIXED_LEN), nameText(detail.Name, detail.NameEncoding)],
    ["扩展字段", at(extraRel), detail.CentralExtra?.length ? `${detail.CentralExtra.length} 个` : "无"],
    ["注释", at(commentRel), detail.CommentLen ? `${detail.CommentLen} 字节` : "无"],
  ];
}

export function localFieldRows(local) {
  const base = Number(local.Offset) || 0;
  const at = (rel) => fmtOffset(base + rel);

  return [
    ["签名", at(0), "50 4B 03 04"],
    ["版本（解压所需）", at(4), versionNeededText(local.Version)],
    ["通用位标志", at(6), hex16(local.GPFlags)],
    ["压缩方法", at(8), methodText(local.Method, local.MethodName)],
    ["修改时间", at(10), hex16(local.ModTime)],
    ["修改日期", at(12), hex16(local.ModDate)],
    ["CRC32", at(14), hex32(local.CRC32)],
    ["压缩后大小", at(18), sizeText(local.CompressedSize)],
    ["原始大小", at(22), sizeText(local.UncompressedSize)],
    ["文件名长度", at(26), String(local.NameLen)],
    ["扩展字段长度", at(28), String(local.ExtraLen)],
    ["文件名", at(LOCAL_FIXED_LEN), nameText(local.Name, local.NameEncoding)],
    ["扩展字段", at(LOCAL_FIXED_LEN + local.NameLen), local.Extra?.length ? `${local.Extra.length} 个` : "无"],
    ["固定头长度", "—", `${local.TotalLen} 字节`],
  ];
}

export function extraNote(detail) {
  const central = detail.CentralExtra?.length || 0;
  const local = detail.Local?.Extra?.length || 0;
  if (!central && !local) return "无";
  return `中央目录 ${central} 个 · 本地文件头 ${local} 个`;
}

// 扩展字段的绝对偏移 = 记录起点 + 固定部分 + 文件名 + 该 TLV 在扩展块里的偏移。
// ExtraField.Offset 是相对于扩展块起点的，必须加上前面那些长度才对得上文件地址。
export function extraFieldRows(detail) {
  const rows = [];
  const collect = (where, base, fixedLen, nameLen, fields) => {
    for (const field of fields || []) {
      rows.push([
        where,
        hex16(field.ID),
        field.Name || "未登记",
        fmtOffset(Number(base) + fixedLen + nameLen + field.Offset),
        `${field.Size} 字节`,
        hexBytes(field.Data),
      ]);
    }
  };

  collect("中央目录", detail.CentralOffset, CENTRAL_FIXED_LEN, detail.NameLen, detail.CentralExtra);
  if (detail.Local) {
    collect("本地文件头", detail.Local.Offset, LOCAL_FIXED_LEN, detail.Local.NameLen, detail.Local.Extra);
  }
  return rows;
}

// 数据描述符有四种布局：带不带 0x08074B50 签名 × 32 位 / 64 位大小字段。
// 各字段的偏移随布局变化，所以必须按布局算，不能写死。
export function descriptorRows(d) {
  const base = Number(d.Offset) || 0;
  const at = (rel) => fmtOffset(base + rel);
  const sigLen = d.HasSignature ? 4 : 0;
  const sizeLen = d.Zip64 ? 8 : 4;

  return [
    ["签名", at(0), d.HasSignature ? "50 4B 07 08" : "（无签名）"],
    ["CRC32", at(sigLen), hex32(d.CRC32)],
    ["压缩后大小", at(sigLen + 4), sizeText(d.CompressedSize)],
    ["原始大小", at(sigLen + 4 + sizeLen), sizeText(d.UncompressedSize)],
    ["与中央目录一致", "—", d.MatchesCentral ? "是" : "否"],
    ["布局", "—", d.Zip64 ? "ZIP64（8 字节大小字段）" : "32 位"],
  ];
}
