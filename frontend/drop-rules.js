// 拖放规则表（纯函数，不碰 DOM、不改状态）。
//
// 拖放只有两种行为，没有第三种：
//   1. 正在等明文（明文攻击面板展开）→ 拖进来的文件填明文；
//   2. 其余一切情况 → 开始新流程（重置当前状态，1 个进单文件、≥2 个进批量）。
//
// 不再有「批量追加」「进行中忽略」这类中间态：用户主动拖文件进来，要么是
// 在给明文攻击喂明文，要么就是想重新开始。规则抽成纯函数是为了不启动
// WebView 就能把它测完（见 tests/drop-rules.test.mjs）。

// 拖放的两种结果。
export const DropAction = {
  Plaintext: "plaintext", // 填明文
  NewFlow: "new", // 开始新流程
};

// dropActionOf 把界面状态快照翻译成一条拖放行为。
//
// snapshot 字段（全部只读）：
//   awaitingPlaintext  是否在等明文（唯一开关，由 app.js 维护）
//   hasPlain           明文路径是否已填（决定要不要二次确认替换）
//   taskRunning        是否有任务在跑（决定要不要二次确认终止）
//   count              本次拖入的文件数
//
// 注意：awaitingPlaintext 为真时，任务不可能在跑——攻击一开始这个标志就
// 被强制置回 false，见 app.js 的 syncAwaitingPlaintext。
export function dropActionOf(snapshot) {
  const s = snapshot || {};
  const count = Number(s.count) || 0;

  if (s.awaitingPlaintext) {
    return {
      kind: DropAction.Plaintext,
      replace: Boolean(s.hasPlain),
      extraFiles: count > 1,
    };
  }
  return {
    kind: DropAction.NewFlow,
    terminate: Boolean(s.taskRunning),
  };
}

// dropHintText 返回拖放遮罩上的两行文案：标题 + 补充说明。
export function dropHintText(action) {
  if (action && action.kind === DropAction.Plaintext) {
    return {
      title: "松开以填入明文文件",
      hint: "明文只接受一个文件，加密文件和侦察结果都不会动",
    };
  }
  return {
    title: "松开以开始新流程",
    hint: "1 个进入单文件视图，≥2 个进入批量视图；当前状态会被清空",
  };
}

// zipLike / archiveLike 是扩展名判断。
//
// 不能复用 app.js 里的 archiveKindOf：它对未知扩展名一律返回 "zip"，
// 拿来做校验会把 .png 当成 ZIP。
const ZIP_EXTENSIONS = [".zip", ".zipx", ".jar", ".apk", ".docx", ".xlsx", ".odt"];

export function zipLike(path) {
  const lower = String(path || "").toLowerCase();
  return ZIP_EXTENSIONS.some((ext) => lower.endsWith(ext));
}

export function archiveLike(path) {
  const lower = String(path || "").toLowerCase();
  return zipLike(path) || lower.endsWith(".rar") || lower.endsWith(".7z");
}

export function archiveKind(path) {
  const lower = String(path || "").toLowerCase();
  if (lower.endsWith(".rar")) return "rar";
  if (lower.endsWith(".7z")) return "7z";
  return "zip";
}

// ---------------------------------------------------------------- 批量行状态

// 批量列表里「这一行为什么不进破解队列」的六种原因。
//
// 后端 FileInfo 只给 applicable / skipReason，信息不够区分「RAR 要单独处理」
// 和「拖进来一个 PNG」。这一层把路径和 skipReason 合起来判断，判断结果直接
// 决定列表里显示哪一行文字、能不能点。
export const FileNotice = {
  AES: "aes", // ZIP + AES：批量破解引擎不认，要进单文件视图走 GPU 恢复
  ARCHIVE: "archive", // RAR / 7z：整条批量链路只做 ZIP
  FAKE: "fake", // 伪加密：单文件视图里有「修复伪加密」
  PLAIN: "plain", // ZIP 但没加密，不需要密码
  NOTZIP: "notzip", // 压根不是压缩包
  OTHER: "other", // ZIP 但格式不受支持（ZIP64 / 强加密 / 没有 ZipCrypto 条目）
};

// fileNoticeOf 返回「不进队列」的原因；返回 null 表示可以直接进破解队列。
export function fileNoticeOf(file) {
  const f = file || {};
  if (f.err) return null;
  if (f.applicable) return null;

  const reason = String(f.skipReason || "");
  if (reason.includes("AES")) return FileNotice.AES;
  if (reason.includes("伪加密")) return FileNotice.FAKE;
  if (reason.includes("未加密")) return FileNotice.PLAIN;

  const kind = archiveKind(f.path);
  if (kind === "rar" || kind === "7z") return FileNotice.ARCHIVE;
  if (!zipLike(f.path)) return FileNotice.NOTZIP;
  return FileNotice.OTHER;
}

// noticeLabel 是括号里的那半句。
export function noticeLabel(notice) {
  switch (notice) {
    case FileNotice.AES:
      return "AES";
    case FileNotice.ARCHIVE:
      return "RAR/7z";
    case FileNotice.FAKE:
      return "伪加密";
    case FileNotice.PLAIN:
      return "未加密";
    case FileNotice.NOTZIP:
      return "非压缩包";
    default:
      return "不适用";
  }
}

// isSeparate 区分「需单独处理」和「已忽略」：
//   需单独处理 = 点进单文件视图还能做点事（GPU 恢复 / 修复伪加密），可点击；
//   已忽略     = 这个文件在 zipkit 里没有任何后续动作，置灰不可点击。
export function isSeparate(notice) {
  return (
    notice === FileNotice.AES ||
    notice === FileNotice.ARCHIVE ||
    notice === FileNotice.FAKE
  );
}

// ---------------------------------------------------------------- 目录展开

// 拖入文件夹时最多展开两层。
//
// 上限存在的意义是防手滑：把整个磁盘拖进来会瞬间产生几十万行。两层足够
// 覆盖「一个文件夹里放几个子文件夹」这种最常见的整理方式。
export const MAX_DROP_DEPTH = 2;

// expandDropPaths 把拖入的路径展开成文件列表。
//
// probe(path) 由调用方注入，返回 { isDir, dirs, files, err }。之所以做成
// 注入而不是直接读文件系统：这张表要能在没有 WebView、没有 Go 侧的情况下
// 用假目录树测完（见 tests/drop-rules.test.mjs）。
//
// 返回 { files, dirs, failed }：
//   files  展开后的文件路径（去重，保持原顺序）
//   dirs   被展开的目录
//   failed 读不出来的目录——调用方负责提示「无法读取目录：<名称>」，但不阻塞
//          其余文件
export async function expandDropPaths(paths, probe, maxDepth = MAX_DROP_DEPTH) {
  const out = { files: [], dirs: [], failed: [] };
  const seen = new Set();
  const add = (p) => {
    if (!p || seen.has(p)) return;
    seen.add(p);
    out.files.push(p);
  };

  const limit = Math.min(Math.max(1, Number(maxDepth) || MAX_DROP_DEPTH), MAX_DROP_DEPTH);

  async function walk(target, depth) {
    let res = null;
    try {
      res = await probe(target);
    } catch {
      res = null;
    }

    // 探测不出来就按文件处理：宁可多一行「已忽略」，也不要吞掉用户拖的东西。
    if (!res || !res.isDir) {
      add(target);
      return;
    }
    if (res.err) {
      out.failed.push(target);
      return;
    }
    if (depth === 1) out.dirs.push(target);
    for (const f of res.files || []) add(f);

    // 到了深度上限就不再往下走，但当前这层的文件已经收下了。
    if (depth >= limit) return;
    for (const d of res.dirs || []) {
      await walk(d, depth + 1);
    }
  }

  for (const p of paths || []) {
    if (!p) continue;
    await walk(p, 1);
  }
  return out;
}
