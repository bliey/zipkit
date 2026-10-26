// zipkit frontend — plain ES modules, no framework, no bundler.
//
// The Wails runtime is served by the asset server at /wails/runtime.js, so the
// page can call bound Go methods by name without any generated bindings.
//
// 两个视图共用同一份状态：
//   - 单文件视图（#report）沿用阶段 1 的中央目录 / 十六进制检查；
//   - 批量视图（#batch）负责多文件侦察、并行破解、进度与结果导出。
// 批量任务在 Go 侧跑，切到单文件详情不会中断，事件回来时照样更新状态。

import { Browser, Call, Clipboard, Dialogs, Events } from "/wails/runtime.js";
import {
  DropAction,
  dropActionOf,
  dropHintText,
  fileNoticeOf,
  noticeLabel,
  isSeparate,
  expandDropPaths,
} from "/drop-rules.js";
// 条目详情的纯格式化逻辑（偏移算术、字段值格式化）单独一层，可在 Node 里单测。
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
  localFieldRows,
} from "/entry-detail.js";

const ZIP_SERVICE = "github.com/bliey/zipkit/internal/zipservice.ZipService";
const BATCH_SERVICE = "github.com/bliey/zipkit/internal/batch.BatchService";
const UNZIP_SERVICE = "github.com/bliey/zipkit/internal/unzip.UnzipService";
const ATTACK_SERVICE = "github.com/bliey/zipkit/internal/attack.AttackService";
const GPU_SERVICE = "github.com/bliey/zipkit/internal/hashcat.HashcatService";
const SETTINGS_SERVICE = "github.com/bliey/zipkit/internal/settingservice.SettingsService";

const MAX_ENTRY_ROWS = 200;
const MAX_RESULT_ROWS = 200;
// 日志区最多保留 5000 行；超了先丢最早的 1000 行，连 DOM 节点一起删，
// 否则内存会一直涨。
const MAX_LOG_LINES = 5000;
const LOG_TRIM_CHUNK = 1000;
const LOCAL_HEADER_BYTES = 128;

// 常用文件头模板：只是填充，用户可以改。
const HEX_TEMPLATES = {
  png: "89504E470D0A1A0A",
  jpeg: "FFD8FF",
  pdf: "25504446",
  zip: "504B0304",
  gif89: "474946383961",
  gif87: "474946383761",
};

const el = {
  main: document.getElementById("main"),
  pick: document.getElementById("pick-btn"),
  status: document.getElementById("status"),
  settingsBtn: document.getElementById("settings-btn"),

  // 左上角 logo：点一下回到初始状态（清空一切、停掉所有任务）。
  brandHome: document.getElementById("brand-home"),
  // 顶部居中的短提示，3 秒自动消失。状态栏的文案可能马上被别的事件覆盖，
  // 「已恢复初始状态」这类一次性反馈放这里更稳。
  toast: document.getElementById("toast"),

  errorCard: document.getElementById("error-card"),
  errorTitle: document.getElementById("error-title"),
  errorDetail: document.getElementById("error-detail"),
  errorCopy: document.getElementById("error-copy"),
  errorClose: document.getElementById("error-close"),

  empty: document.getElementById("empty"),
  report: document.getElementById("report"),
  batch: document.getElementById("batch"),

  detailBar: document.getElementById("detail-bar"),
  detailBack: document.getElementById("detail-back"),
  detailHint: document.getElementById("detail-hint"),
  openFolder: document.getElementById("open-folder-btn"),
  toBatch: document.getElementById("to-batch-btn"),
  path: document.getElementById("file-path"),
  chips: document.getElementById("file-chips"),
  entryCard: document.getElementById("entry-card"),
  entryCount: document.getElementById("entry-count"),
  body: document.getElementById("entry-body"),
  more: document.getElementById("entry-more"),
  hexCard: document.getElementById("hex-card"),
  hexEntry: document.getElementById("hex-entry"),
  hexOffset: document.getElementById("hex-offset"),
  hexDump: document.getElementById("hex-dump"),

  fakeCard: document.getElementById("fake-card"),
  fakeTitle: document.getElementById("fake-title"),
  fakeSub: document.getElementById("fake-sub"),
  fakeFix: document.getElementById("fake-fix"),
  fakeResult: document.getElementById("fake-result"),
  fakeOutput: document.getElementById("fake-output"),
  fakeOpenFolder: document.getElementById("fake-open-folder"),

  plainCard: document.getElementById("plain-card"),
  plainSub: document.getElementById("plain-sub"),
  plainUnzip: document.getElementById("plain-unzip"),

  fileBody: document.getElementById("batch-file-body"),
  fileSummary: document.getElementById("batch-file-summary"),
  addFiles: document.getElementById("add-files-btn"),

  start: document.getElementById("batch-start"),
  stop: document.getElementById("batch-stop"),
  minLen: document.getElementById("min-len"),
  maxLen: document.getElementById("max-len"),
  concurrencyText: document.getElementById("concurrency-text"),
  concurrencyBtn: document.getElementById("concurrency-btn"),
  concurrencyEditor: document.getElementById("concurrency-editor"),
  concurrencyInput: document.getElementById("concurrency-input"),
  concurrencyApply: document.getElementById("concurrency-apply"),

  progressCard: document.getElementById("progress-card"),
  progressText: document.getElementById("progress-text"),
  progressPercent: document.getElementById("progress-percent"),
  progressFill: document.getElementById("progress-fill"),

  resultsCard: document.getElementById("results-card"),
  resultsBody: document.getElementById("results-body"),
  resultsNote: document.getElementById("results-note"),
  resultsFoot: document.getElementById("results-foot"),
  exportBtn: document.getElementById("export-btn"),

  unzipBtn: document.getElementById("unzip-btn"),
  unzipProgress: document.getElementById("unzip-progress"),
  unzipProgressText: document.getElementById("unzip-progress-text"),
  unzipProgressPercent: document.getElementById("unzip-progress-percent"),
  unzipProgressFill: document.getElementById("unzip-progress-fill"),
  unzipStop: document.getElementById("unzip-stop"),

  unzipModal: document.getElementById("unzip-modal"),
  unzipModalText: document.getElementById("unzip-modal-text"),
  unzipModalDir: document.getElementById("unzip-modal-dir"),
  unzipFlat: document.getElementById("unzip-flat"),
  unzipCancel: document.getElementById("unzip-cancel"),
  unzipConfirm: document.getElementById("unzip-confirm"),

  // 通用二次确认框（拖放替换文件 / 替换明文用）。
  confirmModal: document.getElementById("confirm-modal"),
  confirmTitle: document.getElementById("confirm-modal-title"),
  confirmText: document.getElementById("confirm-modal-text"),
  confirmOk: document.getElementById("confirm-ok"),
  confirmCancel: document.getElementById("confirm-cancel"),

  // 拖放遮罩上随状态变化的文案。
  dropOverlayTitle: document.getElementById("drop-overlay-title"),
  dropOverlayHint: document.getElementById("drop-overlay-hint"),

  sevenZipBanner: document.getElementById("sevenzip-banner"),
  sevenZipInput: document.getElementById("sevenzip-input"),
  sevenZipBrowse: document.getElementById("sevenzip-browse"),
  sevenZipSave: document.getElementById("sevenzip-save"),
  sevenZipRecheck: document.getElementById("sevenzip-recheck"),

  bkcrackBanner: document.getElementById("bkcrack-banner"),
  bkcrackInput: document.getElementById("bkcrack-input"),
  bkcrackBrowse: document.getElementById("bkcrack-browse"),
  bkcrackSave: document.getElementById("bkcrack-save"),
  bkcrackRecheck: document.getElementById("bkcrack-recheck"),

  attackCard: document.getElementById("attack-card"),
  attackTitle: document.getElementById("attack-title"),
  attackSub: document.getElementById("attack-sub"),
  attackOpen: document.getElementById("attack-open"),
  attackGpu: document.getElementById("attack-gpu"),
  attackDisabledHint: document.getElementById("attack-disabled-hint"),
  attackPanel: document.getElementById("attack-panel"),
  attackEntry: document.getElementById("attack-entry"),
  attackPlainPath: document.getElementById("attack-plain-path"),
  attackPlainPathField: document.getElementById("attack-plain-path-field"),
  attackPlainBrowse: document.getElementById("attack-plain-browse"),
  attackPlainEntryField: document.getElementById("attack-plain-entry-field"),
  attackPlainEntry: document.getElementById("attack-plain-entry"),
  attackHexFields: document.getElementById("attack-hex-fields"),
  attackHexText: document.getElementById("attack-hex-text"),
  attackHexOffset: document.getElementById("attack-hex-offset"),
  attackHexTemplate: document.getElementById("attack-hex-template"),
  attackPrecheck: document.getElementById("attack-precheck"),
  attackCreator: document.getElementById("attack-creator"),
  attackStart: document.getElementById("attack-start"),
  attackStop: document.getElementById("attack-stop"),
  attackWarn: document.getElementById("attack-warn"),
  attackLogCard: document.getElementById("attack-log-card"),
  attackLog: document.getElementById("attack-log"),
  attackLogCount: document.getElementById("attack-log-count"),
  attackResult: document.getElementById("attack-result"),
  attackKeys: document.getElementById("attack-keys"),
  attackCopyKeys: document.getElementById("attack-copy-keys"),
  attackDecryptZip: document.getElementById("attack-decrypt-zip"),
  attackDecryptEntry: document.getElementById("attack-decrypt-entry"),
  attackFail: document.getElementById("attack-fail"),
  attackFailText: document.getElementById("attack-fail-text"),
  attackFailRaw: document.getElementById("attack-fail-raw"),

  quickCrack: document.getElementById("quick-crack"),
  quickRangeBtn: document.getElementById("quick-range-btn"),
  quickRange: document.getElementById("quick-range"),
  quickMinLen: document.getElementById("quick-min-len"),
  quickMaxLen: document.getElementById("quick-max-len"),
  quickSlowHint: document.getElementById("quick-slow-hint"),
  quickResult: document.getElementById("quick-result"),
  quickPassword: document.getElementById("quick-password"),
  quickCopy: document.getElementById("quick-copy"),
  quickDecrypt: document.getElementById("quick-decrypt"),
  quickNote: document.getElementById("quick-note"),

  decryptModal: document.getElementById("decrypt-modal"),
  decryptOutput: document.getElementById("decrypt-output"),
  decryptBrowse: document.getElementById("decrypt-browse"),
  decryptPassword: document.getElementById("decrypt-password"),
  decryptCancel: document.getElementById("decrypt-cancel"),
  decryptConfirm: document.getElementById("decrypt-confirm"),

  hashcatBanner: document.getElementById("hashcat-banner"),
  hashcatInput: document.getElementById("hashcat-input"),
  hashcatBrowse: document.getElementById("hashcat-browse"),
  hashcatSave: document.getElementById("hashcat-save"),
  hashcatRecheck: document.getElementById("hashcat-recheck"),

  gpuCard: document.getElementById("gpu-card"),
  gpuTitle: document.getElementById("gpu-title"),
  gpuSub: document.getElementById("gpu-sub"),
  gpuOpen: document.getElementById("gpu-open"),
  gpuDisabledHint: document.getElementById("gpu-disabled-hint"),
  gpuJohnHint: document.getElementById("gpu-john-hint"),
  gpuJohnText: document.getElementById("gpu-john-text"),
  gpuJohnInput: document.getElementById("gpu-john-input"),
  gpuJohnBrowse: document.getElementById("gpu-john-browse"),
  gpuJohnSave: document.getElementById("gpu-john-save"),

  gpuPanel: document.getElementById("gpu-panel"),
  gpuEntryField: document.getElementById("gpu-entry-field"),
  gpuEntry: document.getElementById("gpu-entry"),
  gpuHash: document.getElementById("gpu-hash"),
  gpuHashToggle: document.getElementById("gpu-hash-toggle"),
  gpuMaskField: document.getElementById("gpu-mask-field"),
  gpuMask: document.getElementById("gpu-mask"),
  gpuMaskHelpBtn: document.getElementById("gpu-mask-help-btn"),
  maskHelp: document.getElementById("mask-help"),
  gpuCharsetField: document.getElementById("gpu-charset-field"),
  gpuCharset: document.getElementById("gpu-charset"),
  gpuLenField: document.getElementById("gpu-len-field"),
  gpuMinLen: document.getElementById("gpu-min-len"),
  gpuMaxLen: document.getElementById("gpu-max-len"),
  gpuWordlistField: document.getElementById("gpu-wordlist-field"),
  gpuWordlist: document.getElementById("gpu-wordlist"),
  gpuWordlistBrowse: document.getElementById("gpu-wordlist-browse"),

  gpuStart: document.getElementById("gpu-start"),
  gpuStop: document.getElementById("gpu-stop"),
  gpuWarn: document.getElementById("gpu-warn"),

  gpuProgressCard: document.getElementById("gpu-progress-card"),
  gpuProgressFill: document.getElementById("gpu-progress-fill"),
  gpuStatus: document.getElementById("gpu-status"),
  gpuSpeed: document.getElementById("gpu-speed"),
  gpuProgress: document.getElementById("gpu-progress"),
  gpuEta: document.getElementById("gpu-eta"),

  gpuLogCard: document.getElementById("gpu-log-card"),
  gpuLog: document.getElementById("gpu-log"),
  gpuLogCount: document.getElementById("gpu-log-count"),

  gpuResult: document.getElementById("gpu-result"),
  gpuPassword: document.getElementById("gpu-password"),
  gpuCopyPassword: document.getElementById("gpu-copy-password"),
  gpuDecrypt: document.getElementById("gpu-decrypt"),

  gpuFail: document.getElementById("gpu-fail"),
  gpuFailText: document.getElementById("gpu-fail-text"),
  gpuFailRaw: document.getElementById("gpu-fail-raw"),

  settingsModal: document.getElementById("settings-modal"),
  settingsPath: document.getElementById("settings-path"),
  settingsTools: document.getElementById("settings-tools"),
  settingsBatchConcurrency: document.getElementById("settings-batch-concurrency"),
  settingsBatchHint: document.getElementById("settings-batch-hint"),
  settingsUnzipConcurrency: document.getElementById("settings-unzip-concurrency"),
  settingsExportDir: document.getElementById("settings-export-dir"),
  settingsExportBrowse: document.getElementById("settings-export-browse"),
  settingsExportSave: document.getElementById("settings-export-save"),
  settingsRecheck: document.getElementById("settings-recheck"),
  settingsClose: document.getElementById("settings-close"),

  aboutVersion: document.getElementById("about-version"),
  aboutRepo: document.getElementById("about-repo"),
  aboutBuiltin: document.getElementById("about-builtin"),
  aboutBuiltinError: document.getElementById("about-builtin-error"),
  sponsorQr: document.getElementById("sponsor-qr"),
};

const state = {
  view: "empty", // empty | single | batch
  path: "",
  activeName: "",
  detailFromBatch: false,

  // 条目详情缓存：按条目名存 ReadEntryDetail 的结果。展开→收起→再展开
  // 不用重复读盘；换文件时统一清空（见 resetForNewFlow / loadSingle）。
  detailCache: new Map(),

  // 掩码帮助面板是否展开。放在顶层而不是 state.gpu 里：换文件时
  // state.gpu 会重新填充，而这里要求整个会话内都记住。
  maskHelpOpen: false,

  // currentFile 是「当前文件」的统一视图：不管密码/密钥是从批量破解、明文
  // 攻击还是 hashcat 来的，都写到这里，「解密文件」只认这一份。
  currentFile: {
    path: "",
    info: null,
    keys: "",
    password: "",
    outputDir: "",
    source: "", // batch | attack | gpu | quick | plain
  },

  // 伪加密（阶段 6）。fake.output 是修复后生成的新文件。
  fake: {
    detected: false,
    count: 0,
    fixing: false,
    output: "",
  },

  // 设置面板。
  settings: {
    open: false,
    snapshot: null,
    tools: [], // [{kind,label,hint,path,available,resolved,message}]
    defaultExportDir: "",
  },

  // 「快速弱密码检测」的结果。
  quick: {
    running: false,
    password: "",
  },

  files: [],
  fileRows: new Map(),
  inspecting: 0,
  inspectToken: 0,

  results: [],
  sortKey: null, // null 表示按到达顺序
  sortDir: 1,

  batch: {
    running: false,
    finished: false,
    cancelled: false,
    // muted 为真时忽略 batch-result / batch-error / batch-done：恢复初始状态
    // 或开新流程后，上一批的迟到事件不该再往新界面上写东西。
    muted: false,
    total: 0,
    completed: 0,
    startedAt: 0,
    minLen: 6,
    maxLen: 8,
    concurrency: 2,
    numCPU: 1,
  },

  // 解压（阶段 3.5）。unzipByPath 是每个结果文件当前的解压状态。
  unzip: {
    running: false,
    finished: false,
    cancelled: false,
    available: false,
    sevenZipPath: "",
    layout: "per-zip",
    rootDir: "",
    total: 0, // 参与解压的文件数
    completed: 0,
    succeeded: 0,
    failed: 0,
    skippedResults: 0, // 没参与解压的结果数（AES / 未找到密码）
    skippedExisting: 0, // 目标目录里已存在、被跳过的文件数
    startedAt: 0,
    current: "",
  },
  unzipByPath: new Map(),

  // 明文攻击（阶段 4）。只在单文件视图里可用。
  info: null, // 当前文件的侦察结果，攻击面板要从里面挑 ZipCrypto 条目
  attack: {
    available: false,
    bkcrackPath: "",
    open: false,
    running: false,
    zipEntries: [], // 可攻击的 ZipCrypto 条目
    keys: "",
    plainIsZip: false,
    plainZipEntries: [],
    precheck: null,
    logLines: 0,
  },

  // GPU 恢复（阶段 5）。hashcat 是外部依赖，缺失时这条链路整体禁用。
  archiveKind: "", // "zip" | "rar" | "7z"
  gpu: {
    available: false,
    hashcatPath: "",
    rar2john: false,
    rar2johnPath: "",
    sevenZip2john: false,
    sevenZip2johnPath: "",
    johnKind: "", // "rar2john" | "7z2john"
    open: false,
    running: false,
    result: null, // 最近一次提取出的 HashResult
    hashExpanded: false,
    entries: [],
    // manual = GPU 卡片是被明文攻击卡片的第三个按钮临时展开的，
    // 收起面板时要一起收回去。
    manual: false,
    password: "",
    logLines: 0,
  },
};

// 待确认的解压任务：确认框弹出到用户点「开始解压」之间先存在这里。
let pendingUnzip = null;

// --------------------------------------------------------------------- utils

function setStatus(text, isError = false) {
  el.status.textContent = text || "";
  el.status.classList.toggle("error", Boolean(isError));
}

// -------------------------------------------------------------- 顶部短提示

// showToast 在界面顶部显示一条 3 秒后自动消失的提示。
//
// 和状态栏的区别：状态栏会被后续事件立刻覆盖（比如清空之后紧跟着一批
// batch-* 事件），而「已恢复初始状态」这种一次性反馈必须让人真看到。
let toastTimer = 0;

function showToast(text, ms = 3000) {
  if (!el.toast) return;
  el.toast.textContent = text || "";
  show(el.toast, true);
  if (toastTimer) clearTimeout(toastTimer);
  toastTimer = setTimeout(() => {
    toastTimer = 0;
    show(el.toast, false);
  }, ms);
}

// ------------------------------------------------------------- 统一错误卡片

// showErrorCard 是全局的错误展示：红色边框 + 可复制的完整信息。
// 外部工具失败时错误文本里已经带了「工具名 + 退出码 + 前 5 行输出」，
// 用户点一下就能复制下来反馈。
function showErrorCard(title, detail) {
  el.errorTitle.textContent = title || "出错了";
  el.errorDetail.textContent = detail || "";
  show(el.errorCard, true);
}

function hideErrorCard() {
  show(el.errorCard, false);
  el.errorDetail.textContent = "";
}

async function copyErrorText() {
  const text = `${el.errorTitle.textContent}\n${el.errorDetail.textContent}`.trim();
  if (!text) return;
  try {
    await Clipboard.SetText(text);
    setStatus("已复制错误信息");
  } catch (err) {
    setStatus(`复制失败：${describeError(err)}`, true);
  }
}

// failWith 同时更新状态栏与错误卡片，失败路径统一走这里。
function failWith(title, err) {
  const detail = describeError(err);
  setStatus(`${title}：${detail}`, true);
  showErrorCard(title, detail);
}

function show(node, visible) {
  if (!node) return;
  node.classList.toggle("hidden", !visible);
}

function formatBytes(value) {
  const n = typeof value === "number" ? value : Number(value);
  if (!Number.isFinite(n) || n < 0) return "—";
  const units = ["B", "KB", "MB", "GB", "TB", "PB"];
  let v = n;
  let i = 0;
  while (v >= 1024 && i < units.length - 1) {
    v /= 1024;
    i += 1;
  }
  const digits = i === 0 ? 0 : v < 10 ? 2 : 1;
  return `${v.toFixed(digits)} ${units[i]}`;
}

function formatSeconds(seconds) {
  if (!Number.isFinite(seconds) || seconds < 0) return "—";
  if (seconds < 1) return "< 1 秒";
  if (seconds < 60) return `${Math.round(seconds)} 秒`;
  const m = Math.floor(seconds / 60);
  const s = Math.round(seconds % 60);
  return s === 0 ? `${m} 分` : `${m} 分 ${s} 秒`;
}

function baseName(path) {
  const text = String(path || "");
  const cut = Math.max(text.lastIndexOf("/"), text.lastIndexOf("\\"));
  return cut >= 0 ? text.slice(cut + 1) : text;
}

function describeError(err) {
  if (!err) return "未知错误";
  if (typeof err === "string") return err;
  // Wails 把 Go 的 error 转成 {message} 或直接给字符串；多行内容要原样保留，
  // 错误卡片里那几行「退出码 + stderr」正是排查的关键。
  const text = err.message || String(err);
  return text.replace(/\s+$/, "");
}

function badgeClass(type) {
  if (type === "ZipCrypto") return "badge crypto";
  if (type && type.startsWith("AES")) return "badge aes";
  if (type === "None") return "badge none";
  return "badge unknown";
}

function badgeText(type) {
  return type === "None" ? "未加密" : type || "未知";
}

function clampInt(raw, min, max, fallback) {
  const n = Number.parseInt(String(raw), 10);
  if (!Number.isFinite(n)) return fallback;
  return Math.min(max, Math.max(min, n));
}

// --------------------------------------------------------------- 长度范围
//
// 界面里有三处「最小位数 – 最大位数」：快速弱密码检测、批量破解、显卡暴力。
// 三处的控件结构与校验逻辑必须完全一致，所以只留这一份实现：
//
//   readLengthRange(minEl, maxEl, defMin, defMax, edited)
//
// 规则（三处相同，只有默认值不同）：
//   · 两个框都限制在 1–12，超出自动收敛；
//   · 保证 minLen ≤ maxLen，靠 edited 判断是哪个框触发的联动修正；
//   · 非法输入（空、非数字）回退到上一次的合法值，不弹窗。
//
// 12 位是纯数字暴力在 Go 原生实现下还算能忍的边界（10^12 已经是极限），
// 再往上必须上显卡，所以三处统一封顶 12。
const LEN_MIN = 1;
const LEN_MAX = 12;

// clampLen 把输入收敛到 1–12；空或非数字返回 null，交给调用方回退。
function clampLen(raw) {
  const n = Number.parseInt(String(raw).trim(), 10);
  if (!Number.isFinite(n)) return null;
  return Math.min(LEN_MAX, Math.max(LEN_MIN, n));
}

// readLengthRange 读取并校正一对位数输入框，返回 { minLen, maxLen }。
//
// edited 是刚被改过的那一侧（"min" / "max" / undefined）：
//   改最小值把它抬过了最大值 → 最大值跟随抬上去；
//   改最大值把它压到了最小值下面 → 最小值跟着降下来。
// 这样用户「想试 9 位」和「只想试到 7 位」两种意图都不会被抹掉。
function readLengthRange(minEl, maxEl, defMin, defMax, edited) {
  const rawMin = clampLen(minEl.value);
  const rawMax = clampLen(maxEl.value);

  let minLen = rawMin === null ? clampLen(minEl.dataset.last) : rawMin;
  let maxLen = rawMax === null ? clampLen(maxEl.dataset.last) : rawMax;
  if (minLen === null) minLen = defMin;
  if (maxLen === null) maxLen = defMax;

  if (edited === "min" && minLen > maxLen) {
    maxLen = minLen;
  } else if (edited === "max" && maxLen < minLen) {
    minLen = maxLen;
  } else if (minLen > maxLen) {
    maxLen = minLen;
  }

  minEl.value = String(minLen);
  maxEl.value = String(maxLen);
  minEl.dataset.last = String(minLen);
  maxEl.dataset.last = String(maxLen);
  return { minLen, maxLen };
}

// bindLengthRange 给一对位数输入框挂上统一的失焦校正。
//
// 只监听 change：它在值被提交（失焦或回车）时触发，正好符合「失焦后校正」；
// 输入过程中不动用户的按键，避免边打字边被改数字。onInput 用来做实时提示
// （例如快速检测的「位数偏大会变慢」），不影响校正。
function bindLengthRange(minEl, maxEl, { defMin, defMax, onInput } = {}) {
  if (!minEl || !maxEl) return;
  minEl.dataset.last = String(clampInt(minEl.value, LEN_MIN, LEN_MAX, defMin));
  maxEl.dataset.last = String(clampInt(maxEl.value, LEN_MIN, LEN_MAX, defMax));

  const sync = (edited) => {
    const { minLen, maxLen } = readLengthRange(minEl, maxEl, defMin, defMax, edited);
    if (typeof onInput === "function") onInput({ minLen, maxLen });
  };

  minEl.addEventListener("change", () => sync("min"));
  maxEl.addEventListener("change", () => sync("max"));
}

// -------------------------------------------------------------------- routing

// 统一的文件选择：始终请求多选。返回的可能是 string（个别平台/版本
// 只回单个路径），统一交给 normalizePaths 处理。
function chooseFiles(title) {
  return Dialogs.OpenFile({
    Title: title || "选择 ZIP 文件（可多选）",
    CanChooseFiles: true,
    CanChooseDirectories: false,
    AllowsMultipleSelection: true,
    Filters: [
      { DisplayName: "压缩包（ZIP / RAR / 7z）", Pattern: "*.zip;*.zipx;*.jar;*.apk;*.docx;*.xlsx;*.odt;*.rar;*.7z" },
      { DisplayName: "所有文件", Pattern: "*.*" },
    ],
  });
}

async function pickFiles() {
  if (state.batch.running || state.unzip.running) return;
  if (state.attack.running) {
    setStatus("明文攻击进行中，先停止再换文件", true);
    return;
  }
  el.pick.disabled = true;
  try {
    const paths = normalizePaths(await chooseFiles());
    if (paths.length === 0) {
      setStatus("");
      return;
    }
    await openSelection(paths);
  } catch (err) {
    setStatus(`打开失败：${describeError(err)}`, true);
  } finally {
    el.pick.disabled = state.batch.running;
  }
}

function normalizePaths(selected) {
  if (!selected) return [];
  if (typeof selected === "string") return selected ? [selected] : [];
  if (Array.isArray(selected)) {
    return selected.filter((p) => typeof p === "string" && p.length > 0);
  }
  return [];
}

// 选中 1 个文件走单文件视图，2 个及以上走批量视图。
//
// 这是「开新流程」的落点：进来之前先把上一条流程的状态清干净，所以拖放、
// 「选择文件」、恢复初始状态之后的重新开始，走的都是同一条路。
async function openSelection(paths) {
  if (!paths || paths.length === 0) return;
  resetForNewFlow();

  if (paths.length === 1) {
    await showSingle(paths[0], false);
    return;
  }
  showBatch(paths);
}

// resetForNewFlow 把界面恢复到「什么都没选」。
//
// 注意顺序：先重置各面板与状态，再让调用方决定进单文件还是批量。
// 批量列表里的文件条目、结果、进度条都由 resetBatchView 清。
function resetForNewFlow() {
  resetBatchView();

  state.view = "empty";
  state.path = "";
  state.activeName = "";
  state.info = null;
  state.detailFromBatch = false;
  state.detailCache.clear();
  state.currentFile.path = "";
  state.currentFile.info = null;
  state.currentFile.password = "";
  state.currentFile.keys = "";
  state.currentFile.outputDir = "";
  state.currentFile.source = "";

  state.fake.detected = false;
  state.fake.count = 0;
  state.fake.fixing = false;
  state.fake.output = "";
  show(el.fakeCard, false);
  show(el.fakeResult, false);

  resetAttackState();
  resetGpuState();
  hideErrorCard();
  show(el.report, false);
  show(el.empty, true);
  refreshControls();
}

// resetToInitial 是左上角 logo 的点击行为：回到「未选择文件」。
//
// 有任务在跑时先问一句再动——直接清空会把后台还在跑的破解/解压晾在那里，
// 事件回来时又往空列表里写，界面就乱了。所以顺序固定为：
// 确认 → 真的把任务停掉（等它们停下）→ 清空界面 → 提示。
async function resetToInitial() {
  if (!isTaskRunning() && state.view === "empty") {
    // 已经在初始状态，不弹确认，也不做无谓的重置。
    showToast("已在初始状态");
    return;
  }

  if (isTaskRunning()) {
    const ok = await askConfirm({
      title: "恢复初始状态",
      text: "当前任务进行中，是否终止并恢复初始状态？",
      okText: "终止并恢复",
    });
    if (!ok) return;
    await terminateRunningTasks();
  }

  resetForNewFlow();
  setStatus("");
  showToast("已恢复初始状态");
}

// ------------------------------------------------------------------ 单文件视图

async function showSingle(path, fromBatch) {
  state.view = "single";
  state.detailFromBatch = Boolean(fromBatch);

  show(el.empty, false);
  show(el.batch, false);
  show(el.report, true);
  show(el.detailBar, state.detailFromBatch);
  resetAttackState();
  resetGpuState();
  refreshControls();

  await load(path);
  refreshDetailActions();
}

// refreshDetailActions 控制详情返回条上「打开所在文件夹」的显隐：
// 只有这个文件确实解压成功、并且拿到了输出目录才显示。
function refreshDetailActions() {
  if (!el.openFolder) return;
  const entry = state.unzipByPath.get(state.path);
  const canOpen = Boolean(entry && entry.status === "done" && entry.outputDir);
  show(el.openFolder, canOpen);
  el.openFolder.title = canOpen ? entry.outputDir : "";
}

// applyKnownPassword 从批量结果里把已经破解出的密码带进当前文件，
// 从结果列表点进来就不用重新跑一遍。
function applyKnownPassword(path) {
  if (state.currentFile.password) return;
  const hit = state.results.find(
    (r) => r.path === path && r.kind === "found" && r.password,
  );
  if (!hit) return;
  state.currentFile.password = hit.password;
  state.currentFile.source = "batch";
}

async function load(path) {
  setStatus("解析中…");
  show(el.hexCard, false);
  hideErrorCard();

  state.archiveKind = archiveKindOf(path);
  if (state.archiveKind !== "zip") {
    loadArchive(path);
    return;
  }

  let info;
  try {
    info = await Call.ByName(`${ZIP_SERVICE}.Inspect`, path);
  } catch (err) {
    setStatus(`解析失败：${describeError(err)}`, true);
    show(el.report, false);
    show(el.attackCard, false);
    show(el.gpuCard, false);
    show(el.empty, true);
    return;
  }

  if (!info) {
    setStatus("解析结果为空", true);
    return;
  }

  state.path = info.Path || path;
  state.activeName = "";
  // 详情是按「文件 + 条目名」算出来的，换文件必须整份作废。
  state.detailCache.clear();
  // 换了文件就把上一份的密码/密钥/输出目录清掉，避免张冠李戴。
  if (state.currentFile.path !== state.path) {
    state.currentFile.password = "";
    state.currentFile.keys = "";
    state.currentFile.outputDir = "";
    state.currentFile.source = "";
  }
  state.currentFile.path = state.path;
  state.currentFile.info = info;
  applyKnownPassword(state.path);

  renderSummary(info);
  renderTable(info);
  show(el.entryCard, true);
  state.info = info;
  renderFakeCard(info);
  renderPlainCard(info);
  renderAttackCard(info);
  renderGpuCard(info);
  applyRecommendationPriority();
  refreshDetailHint();
  show(el.empty, false);
  show(el.report, true);
  setStatus(`已解析 ${info.EntryCount} 个条目`);
  refreshControls();
}

// RAR5 / 7z 不是 ZIP：做不了中央目录侦察，但仍然可以提哈希交给 hashcat。
function loadArchive(path) {
  const kind = state.archiveKind;
  hideErrorCard();
  const label = kind === "rar" ? "RAR5" : "7z";

  state.path = path;
  state.info = null;
  state.activeName = "";

  if (state.currentFile.path !== path) {
    state.currentFile.password = "";
    state.currentFile.keys = "";
    state.currentFile.outputDir = "";
    state.currentFile.source = "";
  }
  state.currentFile.path = path;
  state.currentFile.info = null;
  applyKnownPassword(path);

  renderSummary({
    Path: path,
    FileSize: 0,
    Format: label,
    EncryptionType: "加密",
    EntryCount: 0,
    Entries: [],
  });
  show(el.entryCard, false);
  renderFakeCard(null);
  renderPlainCard(null);
  renderAttackCard(null);
  renderGpuCard(null);
  applyRecommendationPriority();
  refreshDetailHint();

  show(el.empty, false);
  show(el.report, true);
  setStatus(`已载入 ${label} 归档（只支持 GPU 恢复，不做 ZIP 结构侦察）`);
  refreshControls();
}

// archiveKindOf 按扩展名判断归档类型，其余一律当 ZIP 处理。
function archiveKindOf(path) {
  const lower = String(path || "").toLowerCase();
  if (lower.endsWith(".rar")) return "rar";
  if (lower.endsWith(".7z")) return "7z";
  return "zip";
}

function backToBatch() {
  if (state.view !== "single" || !state.detailFromBatch) return;
  // 从「需单独处理」那一行进来的：回去时把它标成「已处理」，用户能看出
  // 这个文件已经看过了。已找到 / 未找到的行不动，那些状态更有信息量。
  markFileHandled(state.path);
  focusBatchView();
  setStatus(
    state.batch.running
      ? `批量破解中：已完成 ${state.batch.completed} / ${state.batch.total}`
      : `批量完成：已完成 ${state.batch.completed} / ${state.batch.total}`,
  );
}

// markFileHandled 把「需单独处理」改成「已处理」。只改这一种状态：
// 已经破解过的文件（已找到 / 未找到）不该被覆盖。
function markFileHandled(path) {
  const file = state.files.find((f) => f.path === path);
  if (!file || file.status !== "separate") return;
  file.status = "handled";
  updateFileRow(file);
  updateFileSummary();
}

// ------------------------------------------------------------------ rendering

function renderSummary(info) {
  el.path.textContent = info.Path;
  el.path.title = info.Path;

  el.chips.textContent = "";
  if (info.FileSize > 0) {
    addChip("大小", formatBytes(info.FileSize), String(info.FileSize) + " 字节");
  }
  addChip("格式", info.Format);
  addChip("加密", info.EncryptionType === "None" ? "未加密" : info.EncryptionType);
  addChip("条目数", String(info.EntryCount));

  if (info.IsFakeEncrypted) {
    const chip = document.createElement("span");
    chip.className = "chip warn";
    chip.textContent = `疑似伪加密（${info.FakeCount || 0} 个条目，可修复）`;
    chip.title = "这些条目只在中央目录写了加密标记，数据本身没加密。可以用「修复伪加密」另存一份免密可解压的新文件。";
    el.chips.appendChild(chip);
  }
}

function addChip(key, value, title) {
  const chip = document.createElement("span");
  chip.className = "chip";

  const k = document.createElement("span");
  k.className = "k";
  k.textContent = key;

  const v = document.createElement("span");
  v.className = "v";
  v.textContent = value;
  if (title) v.title = title;

  chip.append(k, v);
  el.chips.appendChild(chip);
}

function renderTable(info) {
  const entries = info.Entries || [];
  const total = Math.max(info.EntryCount || 0, entries.length);
  const shown = entries.slice(0, MAX_ENTRY_ROWS);

  el.body.textContent = "";
  el.entryCount.textContent = total > 0 ? `共 ${total} 个` : "";

  if (shown.length === 0) {
    const row = document.createElement("tr");
    const cell = document.createElement("td");
    cell.colSpan = 6;
    cell.className = "empty-row";
    cell.textContent = "这个压缩包里没有条目。";
    row.appendChild(cell);
    el.body.appendChild(row);
    show(el.more, false);
    return;
  }

  const frag = document.createDocumentFragment();
  for (const entry of shown) {
    frag.appendChild(renderRow(entry));
  }
  el.body.appendChild(frag);

  const remaining = total - shown.length;
  if (remaining > 0) {
    el.more.textContent = `… 还有 ${remaining} 个条目（为保持界面流畅，只渲染前 ${MAX_ENTRY_ROWS} 行）`;
    show(el.more, true);
  } else {
    show(el.more, false);
  }
}

function renderRow(entry) {
  const row = document.createElement("tr");

  const nameCell = document.createElement("td");
  const button = document.createElement("button");
  button.type = "button";
  button.className = "name-btn entry-toggle";
  button.textContent = entry.Name || "(未命名)";
  button.title = "展开条目详情（中央目录 / 本地文件头 / 扩展字段）";
  button.addEventListener("click", () => toggleEntryDetail(entry, button, row));
  nameCell.appendChild(button);

  const methodCell = document.createElement("td");
  const method = document.createElement("span");
  method.className = "method";
  method.textContent = entry.Compression;
  method.title = `方法码 ${entry.Method}`;
  methodCell.appendChild(method);

  const encCell = document.createElement("td");
  const badge = document.createElement("span");
  if (entry.IsFakeEncrypted) {
    // 伪加密条目单独一种样式，和真 ZipCrypto 区分开，免得用户以为要密码。
    badge.className = "badge fake";
    badge.textContent = "ZipCrypto（疑似伪加密）";
    badge.title = entry.FakeEvidence || "中央目录加密位为 1，本地文件头加密位为 0";
  } else {
    badge.className = badgeClass(entry.EncryptionType);
    badge.textContent = badgeText(entry.EncryptionType);
    if (entry.FakeEvidence) badge.title = entry.FakeEvidence;
  }
  encCell.appendChild(badge);

  const crcCell = document.createElement("td");
  crcCell.className = "col-num";
  crcCell.textContent = hex32(entry.CRC32);

  const sizeCell = document.createElement("td");
  sizeCell.className = "col-num";
  sizeCell.textContent = formatBytes(entry.UncompressedSize);
  sizeCell.title = `${entry.UncompressedSize} 字节`;

  const packedCell = document.createElement("td");
  packedCell.className = "col-num";
  packedCell.textContent = formatBytes(entry.CompressedSize);
  packedCell.title = `${entry.CompressedSize} 字节`;

  row.append(nameCell, methodCell, encCell, crcCell, sizeCell, packedCell);
  return row;
}

// ------------------------------------------------------------------ hex dump

// selectEntry 只做一件事：把某个条目的本地文件头画到十六进制视图里。
// 展开/收起的高亮状态由 toggleEntryDetail 管，这里不再碰 .name-btn 的
// active 类——否则展开详情时会把高亮从文件名上抹掉。
async function selectEntry(entry) {
  state.activeName = entry.Name;

  el.hexEntry.textContent = entry.Name;
  el.hexOffset.textContent = `LFH @ 0x${Number(entry.LocalHeaderOffset)
    .toString(16)
    .toUpperCase()
    .padStart(8, "0")}`;
  show(el.hexCard, true);

  let bytes;
  try {
    const raw = await Call.ByName(
      `${ZIP_SERVICE}.ReadLocalHeader`,
      state.path,
      entry.LocalHeaderOffset,
      LOCAL_HEADER_BYTES,
    );
    bytes = base64ToBytes(raw);
  } catch (err) {
    el.hexDump.textContent = `读取本地文件头失败：${describeError(err)}`;
    return;
  }

  renderHex(bytes);
  el.hexCard.scrollIntoView({ behavior: "smooth", block: "nearest" });
}

function renderHex(bytes) {
  el.hexDump.textContent = "";

  if (!bytes.length) {
    el.hexDump.textContent = "没有可显示的字节。";
    return;
  }

  const frag = document.createDocumentFragment();
  for (let offset = 0; offset < bytes.length; offset += 16) {
    const slice = bytes.subarray(offset, offset + 16);

    const row = document.createElement("div");
    row.className = "hex-row";

    const off = document.createElement("span");
    off.className = "hex-off";
    off.textContent = offset.toString(16).padStart(8, "0");

    const hex = document.createElement("span");
    hex.className = "hex-bytes";

    const ascii = document.createElement("span");
    ascii.className = "hex-ascii";

    for (let i = 0; i < slice.length; i += 1) {
      const absolute = offset + i;
      const byte = slice[i];

      const cell = document.createElement("span");
      cell.className = "hb";
      if (i === 8) cell.classList.add("gap");
      if (absolute <= 3) cell.classList.add("hl-sig");
      else if (absolute === 6 || absolute === 7) cell.classList.add("hl-gpbf");
      cell.textContent = byte.toString(16).toUpperCase().padStart(2, "0");
      hex.appendChild(cell);

      if (byte >= 0x20 && byte <= 0x7e) {
        ascii.appendChild(document.createTextNode(String.fromCharCode(byte)));
      } else {
        const dot = document.createElement("span");
        dot.className = "dot";
        dot.textContent = ".";
        ascii.appendChild(dot);
      }
    }

    row.append(off, hex, ascii);
    frag.appendChild(row);
  }

  el.hexDump.appendChild(frag);
}

// ------------------------------------------------------------------ 条目详情
//
// 点条目名展开一块「字段对照表」：中央目录记录 / 本地文件头（LFH）/
// 扩展字段 / 通用位标志 / 数据描述符。
//
// 数据来自 ZipService.ReadEntryDetail —— Go 侧已经把字节解析成结构体，
// 前端只负责排版，不重复解析。同一时刻只展开一个条目：既省内存，也让
// 「字段偏移」始终对得上下面那块十六进制视图。

function closeEntryDetail() {
  for (const node of el.body.querySelectorAll(".detail-row")) node.remove();
  for (const btn of el.body.querySelectorAll(".entry-toggle.active")) {
    btn.classList.remove("active");
  }
}

async function toggleEntryDetail(entry, button, row) {
  const next = row.nextElementSibling;
  if (next && next.classList.contains("detail-row")) {
    closeEntryDetail();
    if (state.activeName === entry.Name) state.activeName = "";
    return;
  }

  closeEntryDetail();

  const detailRow = document.createElement("tr");
  detailRow.className = "detail-row";
  const cell = document.createElement("td");
  cell.className = "detail-cell";
  cell.colSpan = 6;
  const box = document.createElement("div");
  box.className = "entry-detail";
  box.textContent = "正在解析条目结构…";
  cell.appendChild(box);
  detailRow.appendChild(cell);
  // 详情行紧跟在条目行下面，表格结构保持合法（colspan 铺满 6 列）。
  row.parentNode.insertBefore(detailRow, row.nextSibling);

  button.classList.add("active");
  state.activeName = entry.Name;

  let detail = state.detailCache.get(entry.Name);
  if (!detail) {
    try {
      detail = await Call.ByName(
        `${ZIP_SERVICE}.ReadEntryDetail`,
        state.path,
        entry.Name,
      );
    } catch (err) {
      box.className = "entry-detail detail-error";
      box.textContent = `解析条目详情失败：${describeError(err)}`;
      return;
    }
    if (detail) state.detailCache.set(entry.Name, detail);
  }

  if (!detail) {
    box.className = "entry-detail detail-error";
    box.textContent = "没有拿到这个条目的详情。";
    return;
  }

  box.className = "entry-detail";
  box.textContent = "";
  box.appendChild(renderEntryDetail(detail));
}

function renderEntryDetail(detail) {
  const frag = document.createDocumentFragment();
  frag.appendChild(detailStatus(detail));

  const grid = document.createElement("div");
  grid.className = "detail-grid";

  grid.appendChild(
    detailSection(
      "中央目录记录",
      `${fmtOffset(detail.CentralOffset)} · ${detail.CentralRecordLen} 字节`,
      detailTable(["字段", "偏移", "值"], centralFieldRows(detail)),
    ),
  );

  if (detail.Local) {
    grid.appendChild(
      detailSection(
        "本地文件头（LFH）",
        `${fmtOffset(detail.Local.Offset)} · ${detail.Local.TotalLen} 字节`,
        detailTable(["字段", "偏移", "值"], localFieldRows(detail.Local)),
      ),
    );
  } else {
    grid.appendChild(
      detailSection(
        "本地文件头（LFH）",
        "",
        detailNotice(detail.LocalErr || "没有读到本地文件头", "bad"),
      ),
    );
  }

  // 扩展字段是 6 列（位置 / ID / 名称 / 偏移 / 长度 / 数据），挤在半栏里
  // 会换行到没法看，单独占满整行。
  const extraSection = detailSection(
    "扩展字段",
    extraNote(detail),
    extraFieldTable(detail),
  );
  extraSection.classList.add("detail-section-wide");
  grid.appendChild(extraSection);

  grid.appendChild(
    detailSection(
      "通用位标志（GPBF）",
      "",
      flagTable(detail),
    ),
  );

  grid.appendChild(
    detailSection(
      "数据描述符",
      detail.Descriptor ? fmtOffset(detail.Descriptor.Offset) : "无",
      descriptorTable(detail),
    ),
  );

  frag.appendChild(grid);

  // 本地文件头读不到时没有字节可看，按钮就不给了。
  if (detail.Local) {
    const actions = document.createElement("div");
    actions.className = "detail-actions";
    const hexBtn = document.createElement("button");
    hexBtn.type = "button";
    hexBtn.className = "btn-ghost";
    hexBtn.textContent = "查看本地文件头字节";
    hexBtn.addEventListener("click", () => selectEntry(detail.Entry));
    actions.appendChild(hexBtn);
    frag.appendChild(actions);
  }

  return frag;
}

// detailStatus 是详情顶部的一行结论：一致性、伪加密、数据描述符、时间。
function detailStatus(detail) {
  const wrap = document.createElement("div");
  wrap.className = "detail-status";

  const add = (text, kind, title) => {
    const node = document.createElement("span");
    node.className = `detail-note ${kind}`;
    node.textContent = text;
    if (title) node.title = title;
    wrap.appendChild(node);
  };

  if (detail.Local) {
    if (detail.Consistent) {
      add("本地文件头与中央目录一致", "ok");
    } else {
      add(
        "本地文件头与中央目录不一致",
        "warn",
        "可能是伪加密，也可能文件被改过。逐项对比下面两张字段表即可定位。",
      );
    }
  } else if (detail.LocalErr) {
    add(`本地文件头读取失败：${detail.LocalErr}`, "bad");
  }

  if (detail.IsFakeEncrypted) {
    add(`疑似伪加密：${detail.FakeEvidence || "中央目录加密位为 1，本地文件头为 0"}`, "warn");
  }

  if (detail.Descriptor) {
    add(
      detail.Descriptor.MatchesCentral ? "有数据描述符（与中央目录一致）" : "有数据描述符（与中央目录不符）",
      detail.Descriptor.MatchesCentral ? "info" : "warn",
      "GPBF bit 3 置位时，CRC 与大小写在条目数据之后。",
    );
  }

  if (detail.Modified) {
    add(`修改时间 ${detail.Modified}`, "info");
  }

  return wrap;
}

function detailSection(title, note, body) {
  const section = document.createElement("section");
  section.className = "detail-section";

  const head = document.createElement("div");
  head.className = "detail-section-head";
  const h = document.createElement("h3");
  h.textContent = title;
  head.appendChild(h);
  if (note) {
    const n = document.createElement("span");
    n.className = "detail-section-note mono";
    n.textContent = note;
    n.title = note;
    head.appendChild(n);
  }

  section.append(head, body);
  return section;
}

// detailTable 接受 [字段, 偏移, 值] 这样的二维数组。单元格可以直接给字符串，
// 也可以给 {text, className, title} —— 只有需要额外样式时才用后者。
function detailTable(headers, rows, extraClass) {
  const table = document.createElement("table");
  table.className = extraClass ? `detail-table ${extraClass}` : "detail-table";

  const thead = document.createElement("thead");
  const headRow = document.createElement("tr");
  for (const label of headers) {
    const th = document.createElement("th");
    th.textContent = label;
    headRow.appendChild(th);
  }
  thead.appendChild(headRow);

  const tbody = document.createElement("tbody");
  for (const row of rows) {
    const tr = document.createElement("tr");
    for (let i = 0; i < row.length; i += 1) {
      const td = document.createElement("td");
      const value = row[i];
      if (value && typeof value === "object") {
        td.textContent = value.text ?? "";
        if (value.className) td.className = value.className;
        if (value.title) td.title = value.title;
      } else {
        td.textContent = value == null ? "" : String(value);
        td.className = i === 0 ? "k" : i === 1 ? "off" : "val";
      }
      tr.appendChild(td);
    }
    tbody.appendChild(tr);
  }

  table.append(thead, tbody);
  return table;
}

function detailNotice(text, kind) {
  const node = document.createElement("p");
  node.className = `detail-notice ${kind || ""}`.trim();
  node.textContent = text;
  return node;
}

function extraFieldTable(detail) {
  const rows = extraFieldRows(detail);
  if (!rows.length) {
    return detailNotice("这个条目没有扩展字段。");
  }
  return detailTable(["位置", "ID", "名称", "偏移", "长度", "数据"], rows, "extra-table");
}

// 中央目录与本地文件头的 GPBF 并排放，伪加密在这里一眼就能看出来：
// 中央目录说 0x0001（加密），本地文件头却是 0x0000。
function flagTable(detail) {
  const rows = [["中央目录", hex16(detail.GPFlags), flagMeanings(detail.Flags)]];
  if (detail.Local) {
    rows.push(["本地文件头", hex16(detail.Local.GPFlags), flagMeanings(detail.Local.Flags)]);
  }
  return detailTable(["来源", "值", "含义"], rows);
}

function descriptorTable(detail) {
  const d = detail.Descriptor;
  if (!d) {
    return detailNotice(
      "没有数据描述符。GPBF bit 3 未置位时，CRC 与大小直接写在本地文件头里。",
    );
  }
  return detailTable(["字段", "偏移", "值"], descriptorRows(d));
}

// ------------------------------------------------------------------ 批量视图

function showBatch(paths) {
  state.view = "batch";
  state.detailFromBatch = false;

  show(el.empty, false);
  show(el.report, false);
  show(el.batch, true);
  show(el.detailBar, false);

  resetBatchView();

  state.files = paths.map(makeFileEntry);
  for (const file of state.files) {
    updateFileRow(file);
  }
  updateFileSummary();

  // 侦察也要排队：否则开新批次的同时拖入文件，两批侦察会互相顶掉 token，
  // 先开的那批永远停在「侦察中…」。
  const snapshot = state.files.slice();
  scheduleAppend(async () => {
    await inspectFiles(snapshot, nextInspectToken());
    if (state.view === "batch") {
      setStatus(batchOutcomeText(), batchCounts().waiting === 0);
    }
  });
  setStatus(`已选择 ${paths.length} 个文件，正在侦察…`);
}

function nextInspectToken() {
  const token = state.inspectToken + 1;
  state.inspectToken = token;
  return token;
}

function makeFileEntry(path) {
  return {
    path,
    name: baseName(path),
    size: -1,
    encryptionType: "",
    format: "",
    entryCount: 0,
    applicable: false,
    entryName: "",
    skipReason: "",
    err: "",
    status: "inspecting",
    // notice 是「不进破解队列的原因」，见 drop-rules.js 的 FileNotice。
    // 空字符串表示可以直接进队列。
    notice: "",
  };
}

// ---------------------------------------------------------------- 追加队列

// 侦察是串行的：一批没跑完就再塞一批，后一批的 inspectToken 会让前一批的
// 结果全部作废，那些行永远停在「侦察中…」。所以这里用队列代替「忙就丢弃」：
// 新文件永远排进队列，当前批次完成后自动处理。
let appendJobs = [];
let appendBusy = false;

// scheduleAppend 把一个侦察任务排进队列，返回「该任务完成」的 Promise。
function scheduleAppend(job) {
  let settle;
  const done = new Promise((resolve, reject) => {
    settle = { resolve, reject };
  });
  appendJobs.push({ job, ...settle });
  drainAppendQueue();
  return done;
}

async function drainAppendQueue() {
  if (appendBusy) return;
  appendBusy = true;
  updateFileSummary();

  try {
    while (appendJobs.length > 0) {
      const item = appendJobs.shift();
      try {
        item.resolve(await item.job());
      } catch (err) {
        item.reject(err);
      }
    }
  } finally {
    appendBusy = false;
    updateFileSummary();
    refreshControls();
  }
}

function pendingAppendCount() {
  return appendJobs.length;
}

// clearAppendQueue 丢掉还没开始的追加任务。
//
// 只在换批次（resetBatchView）时调用：那些任务属于上一批，继续跑会把刚清空
// 的列表又填回去。任务本身 resolve 掉，等它的调用方不会悬着。
function clearAppendQueue() {
  const dropped = appendJobs;
  appendJobs = [];
  for (const item of dropped) {
    item.resolve({ added: [], duplicates: [] });
  }
}

// 把一批路径追加到当前文件列表并侦察。
//
// 「+ 添加文件」、拖放、「加入批量」共用这一份逻辑，差别只在调用方怎么
// 组织提示语。返回 { added, duplicates }，added 是真正新加进来的条目。
//
// 去重键是**完整路径**：同名不同目录的两个文件都要留下来。
async function appendToBatch(paths) {
  const fresh = [];
  const duplicates = [];
  for (const path of paths) {
    if (!path) continue;
    const exists =
      state.files.some((f) => f.path === path) || fresh.some((p) => p === path);
    if (exists) {
      duplicates.push(path);
    } else {
      fresh.push(path);
    }
  }
  if (fresh.length === 0) return { added: [], duplicates };

  // 上一轮已经跑完时，追加文件意味着重新组一批：清掉旧结果，避免
  // 进度条和结果列表对不上。
  if (state.batch.finished) {
    resetResults();
    state.batch.finished = false;
    state.batch.cancelled = false;
    state.batch.completed = 0;
    state.batch.total = 0;
    show(el.progressCard, false);
    show(el.resultsCard, false);
    show(el.exportBtn, false);
  }

  const added = fresh.map(makeFileEntry);
  state.files.push(...added);
  for (const file of added) {
    updateFileRow(file);
  }
  updateFileSummary();

  await inspectFiles(added, nextInspectToken());
  return { added, duplicates };
}

// batchCounts 把当前文件列表按「能不能进破解队列」分桶。
function batchCounts() {
  const counts = { total: state.files.length, waiting: 0, separate: 0, ignored: 0, error: 0 };
  for (const file of state.files) {
    if (file.status === "error") counts.error += 1;
    else if (file.status === "waiting") counts.waiting += 1;
    else if (file.status === "separate" || file.status === "handled") counts.separate += 1;
    else counts.ignored += 1;
  }
  return counts;
}

// batchSkipReason 是「这个文件为什么不参与破解」，写进结果列表的那一行。
//
// 和文件列表里的状态文案同源（都来自 noticeLabel），只是句式不同：
// 文件列表用「需单独处理（AES）」，结果列表用「跳过（需单独处理：AES）」。
function batchSkipReason(file) {
  if (file.status === "error") return "解析失败";
  if (file.status === "handled") return `需单独处理：${noticeLabel(file.notice)}`;
  if (file.status === "separate") return `需单独处理：${noticeLabel(file.notice)}`;
  return noticeLabel(file.notice);
}

// appendOutcomeText 是追加完成后的汇总语：
// 「已加入 8 个文件，2 个需单独处理，1 个已忽略，共 11 个」。
function appendOutcomeText(added, duplicates) {
  const parts = [];
  if (added.length === 0) {
    parts.push("这些文件已经在列表里了");
  } else {
    parts.push(`已加入 ${added.length} 个文件`);
    const separate = added.filter((f) => f.status === "separate").length;
    const ignored = added.filter((f) => f.status === "ignored").length;
    const errors = added.filter((f) => f.status === "error").length;
    if (separate > 0) parts.push(`${separate} 个需单独处理`);
    if (ignored > 0) parts.push(`${ignored} 个已忽略`);
    if (errors > 0) parts.push(`${errors} 个解析失败`);
    parts.push(`共 ${state.files.length} 个`);
  }
  for (const path of duplicates || []) {
    parts.push(`已跳过重复文件：${path}`);
  }
  return parts.join("，");
}

// batchOutcomeText 是「这批文件现在能做什么」的一句话总结。
function batchOutcomeText() {
  const c = batchCounts();
  if (c.total === 0) return "";
  if (c.waiting === 0 && c.separate === 0) {
    return "没有可处理的压缩包（批量破解只支持 ZipCrypto 加密的 ZIP）";
  }
  const parts = [`${c.total} 个文件`];
  parts.push(c.waiting > 0 ? `${c.waiting} 个等待破解` : "0 个等待破解");
  if (c.separate > 0) parts.push(`${c.separate} 个需单独处理`);
  if (c.ignored > 0) parts.push(`${c.ignored} 个已忽略`);
  if (c.error > 0) parts.push(`${c.error} 个解析失败`);
  return parts.join(" · ");
}


// 往当前批次里追加文件。即使当前平台的对话框只支持单选，也能一个一个
// 加进来组成批量任务。
async function addFiles() {
  if (state.batch.running) return;
  el.addFiles.disabled = true;

  try {
    const paths = normalizePaths(await chooseFiles("添加压缩包"));
    if (paths.length === 0) return;

    const { added, duplicates } = await scheduleAppend(() => appendToBatch(paths));
    setStatus(appendOutcomeText(added, duplicates));
  } catch (err) {
    setStatus(`添加失败：${describeError(err)}`, true);
  } finally {
    refreshControls();
  }
}

// 单文件视图里的「加入批量」：把当前正在看的这个文件塞进批量列表。
// 这是多选对话框或拖放不可用时的兜底入口，保证任何平台都能组出批量任务。
async function addCurrentToBatch() {
  if (state.batch.running) {
    setStatus("批量进行中，等这批跑完再加文件", true);
    return;
  }

  const path = state.path;
  if (!path) return;

  // 从批量结果点进来的：文件本来就在列表里，切回去就行。
  if (state.detailFromBatch) {
    backToBatch();
    return;
  }

  // 已经在列表里（或列表是上一轮跑完的残留）：直接展示现有批次。
  if (state.files.some((f) => f.path === path) && !state.batch.finished) {
    focusBatchView();
    setStatus(`这个文件已在批量列表里，共 ${state.files.length} 个文件`);
    return;
  }

  if (state.files.length === 0 || state.batch.finished) {
    showBatch([path]);
    setStatus(`已把 ${baseName(path)} 放入批量列表，可继续添加文件`);
    return;
  }

  focusBatchView();
  try {
    const { added } = await scheduleAppend(() => appendToBatch([path]));
    if (added.length > 0) {
      setStatus(`已加入 ${baseName(path)}，共 ${state.files.length} 个文件`);
    }
  } catch (err) {
    setStatus(`加入失败：${describeError(err)}`, true);
  } finally {
    refreshControls();
  }
}

// 只切视图，不动数据：从单文件视图回到已有的批量视图。
function focusBatchView() {
  state.view = "batch";
  state.detailFromBatch = false;
  show(el.empty, false);
  show(el.report, false);
  show(el.batch, true);
  show(el.detailBar, false);
  updateProgress();
  refreshControls();
}

function resetBatchView() {
  state.files = [];
  state.fileRows.clear();
  state.inspecting = 0;
  state.results = [];
  state.sortKey = null;
  state.sortDir = 1;
  clearAppendQueue();

  el.fileBody.textContent = "";
  el.resultsBody.textContent = "";
  el.fileSummary.textContent = "";
  el.resultsNote.textContent = "";
  el.resultsFoot.textContent = "";
  el.resultsFoot.classList.add("hidden");

  state.batch.running = false;
  state.batch.finished = false;
  state.batch.cancelled = false;
  state.batch.total = 0;
  state.batch.completed = 0;
  state.batch.startedAt = 0;

  show(el.progressCard, false);
  show(el.resultsCard, false);
  show(el.exportBtn, false);
  hideConcurrencyEditor();
  updateSortIndicators();
  updateProgress();
  refreshControls();
}

// 侦察逐行进行：每完成一个就更新对应行，用户能立刻看到哪些文件会被跳过。
//
// 不做整批重绘：只在每个文件回来时更新它自己那一行，最后再统一刷新汇总。
async function inspectFiles(files, token) {
  state.inspecting = files.length;
  updateFileSummary();
  refreshControls();

  for (const file of files) {
    if (token !== state.inspectToken) return;

    try {
      const info = await Call.ByName(`${BATCH_SERVICE}.InspectFile`, file.path);
      // 等待期间用户可能已经换了一批文件，这一批的结果直接丢弃。
      if (token !== state.inspectToken) return;
      applyFileInfo(file, info || {});
    } catch (err) {
      if (token !== state.inspectToken) return;
      file.status = "error";
      file.err = describeError(err);
    }

    state.inspecting = Math.max(0, state.inspecting - 1);
    updateFileRow(file);
    updateFileSummary();
    refreshControls();
  }

  if (token !== state.inspectToken) return;

  state.inspecting = 0;
  updateFileSummary();
  refreshControls();
}

function applyFileInfo(file, info) {
  file.name = info.name || file.name;
  file.size = typeof info.size === "number" ? info.size : -1;
  file.format = info.format || "";
  file.encryptionType = info.encryptionType || "";
  file.entryCount = info.entryCount || 0;
  file.applicable = Boolean(info.applicable);
  file.entryName = info.entryName || "";
  file.skipReason = info.skipReason || "";
  file.err = info.err || "";

  if (file.err) {
    file.status = "error";
    file.notice = "";
    return;
  }
  if (file.applicable) {
    file.status = "waiting";
    file.notice = "";
    return;
  }

  // 不能破解的分两种：点进单文件视图还能做点事的（需单独处理，可点击），
  // 和做什么都没用的（已忽略，置灰）。判断依据见 drop-rules.js。
  file.notice = fileNoticeOf(file) || "";
  file.status = isSeparate(file.notice) ? "separate" : "ignored";
}

function ensureFileRow(file) {
  const existing = state.fileRows.get(file.path);
  if (existing) return existing;

  const tr = document.createElement("tr");

  const nameCell = document.createElement("td");
  const nameBtn = document.createElement("button");
  nameBtn.type = "button";
  nameBtn.className = "name-btn";
  nameBtn.textContent = file.name;
  nameBtn.title = file.path;
  // 点击时再看状态：行建好之后状态还会变（侦察中 → 已忽略 / 需单独处理）。
  // 「已忽略」的文件不跳转，但给一句说明——按钮直接 disabled 就没有反馈了。
  nameBtn.addEventListener("click", () => {
    if (file.status === "ignored") {
      setStatus(
        `${file.name} 已忽略（${noticeLabel(file.notice)}），在 zipkit 里没有可做的后续处理`,
        true,
      );
      return;
    }
    showSingle(file.path, true);
  });
  nameCell.appendChild(nameBtn);

  const encCell = document.createElement("td");
  const badge = document.createElement("span");
  badge.className = "badge unknown";
  badge.textContent = "侦察中…";
  encCell.appendChild(badge);

  const sizeCell = document.createElement("td");
  sizeCell.className = "col-num";
  sizeCell.textContent = "—";

  const statusCell = document.createElement("td");
  const status = document.createElement("span");
  status.className = "file-status";
  statusCell.appendChild(status);

  tr.append(nameCell, encCell, sizeCell, statusCell);
  el.fileBody.appendChild(tr);

  const refs = { tr, nameBtn, badge, sizeCell, status };
  state.fileRows.set(file.path, refs);
  return refs;
}

// fileBadgeText 决定「加密类型」那一列显示什么。
//
// 不是 ZIP 的文件没有加密类型可言，但显示一个「—」用户看不出它是什么，
// 所以这里退化成格式名。
function fileBadgeText(file) {
  if (file.encryptionType) return null; // 交给 badgeClass/badgeText
  if (file.status === "inspecting") return "侦察中…";
  if (file.notice === "archive") return archiveKindOf(file.path) === "rar" ? "RAR" : "7z";
  if (file.notice === "notzip") return "非压缩包";
  if (file.notice === "plain") return "无";
  return "—";
}

function updateFileRow(file) {
  const refs = ensureFileRow(file);

  refs.nameBtn.textContent = file.name;
  refs.nameBtn.title = file.path;

  if (file.encryptionType) {
    refs.badge.className = badgeClass(file.encryptionType);
    refs.badge.textContent = badgeText(file.encryptionType);
  } else {
    refs.badge.className = "badge unknown";
    refs.badge.textContent = fileBadgeText(file);
  }

  refs.sizeCell.textContent = file.size >= 0 ? formatBytes(file.size) : "—";
  refs.status.textContent = fileStatusText(file);
  refs.status.className = `file-status s-${file.status}`;
  refs.status.title = file.err || file.skipReason || "";

  refs.tr.classList.toggle("row-skip", file.status === "ignored" || file.status === "error");
  refs.tr.classList.toggle("row-crypto", file.status === "waiting" || file.applicable);
  refs.tr.classList.toggle("row-ignored", file.status === "ignored");
  refs.nameBtn.classList.toggle("name-btn-muted", file.status === "ignored");
}

function fileStatusText(file) {
  switch (file.status) {
    case "inspecting":
      return "侦察中…";
    case "waiting":
      return "等待";
    case "separate":
      return `需单独处理（${noticeLabel(file.notice)}）`;
    case "handled":
      return "已处理";
    case "ignored":
      return `已忽略（${noticeLabel(file.notice)}）`;
    case "found":
      return "已找到";
    case "miss":
      return "未找到";
    case "error":
      return "错误";
    case "unfinished":
      return "未完成";
    default:
      return "等待";
  }
}

function updateFileSummary() {
  const total = state.files.length;
  if (total === 0) {
    el.fileSummary.textContent = "";
    return;
  }

  // 侦察中优先显示进度：追加进来的文件一行行变状态时，用户需要知道还有
  // 多少个没解析完，而不是看一个一直在变的统计。
  if (state.inspecting > 0) {
    const queued = pendingAppendCount();
    el.fileSummary.textContent =
      queued > 0
        ? `正在解析 ${state.inspecting} 个文件…（还有 ${queued} 批在排队）`
        : `正在解析 ${state.inspecting} 个文件…`;
    return;
  }

  const c = batchCounts();
  const parts = [`${c.total} 个文件`, `${c.waiting} 个等待破解`];
  if (c.separate > 0) parts.push(`${c.separate} 个需单独处理`);
  if (c.ignored > 0) parts.push(`${c.ignored} 个已忽略`);
  if (c.error > 0) parts.push(`${c.error} 个错误`);
  el.fileSummary.textContent = parts.join(" · ");
}

// ------------------------------------------------------------------ 控制条

function refreshControls() {
  const running = state.batch.running;
  const unzipping = state.unzip.running;
  const attacking = state.attack.running;
  const recovering = state.gpu.running;
  const inspecting = state.inspecting > 0;
  const hasApplicable = state.files.some((f) => f.applicable);
  const busy = running || unzipping || attacking || recovering;

  el.pick.disabled = busy;
  el.start.disabled = busy || inspecting || !hasApplicable;
  el.start.textContent = running ? "破解中…" : inspecting ? "侦察中…" : "开始批量破解";
  el.start.title = hasApplicable ? "" : "没有可处理的压缩包（只支持 ZipCrypto 加密的 ZIP）";

  if (el.addFiles) {
    // 侦察中也能继续加：新文件会排进队列，当前这批解析完自动接上。
    el.addFiles.disabled = busy;
    el.addFiles.title = running
      ? "批量进行中不能修改文件列表"
      : unzipping
        ? "解压进行中不能修改文件列表"
        : attacking
          ? "明文攻击进行中不能修改文件列表"
          : recovering
            ? "GPU 恢复进行中不能修改文件列表"
            : "选择更多文件加入这批";
  }

  // 「加入批量」只出现在单文件视图里，并且当前文件确实还不在批量列表中。
  // 批量破解只处理 ZIP，RAR / 7z 单文件视图下不提供该入口。
  if (el.toBatch) {
    const showToBatch =
      state.view === "single" &&
      !state.detailFromBatch &&
      !busy &&
      state.archiveKind === "zip" &&
      Boolean(state.path);
    show(el.toBatch, showToBatch);
    el.toBatch.disabled = busy;
  }

  // 「解压全部已破解文件」要等批量破解结束、并且确实有文件拿到密码才可用。
  if (el.unzipBtn) {
    const visible = state.batch.finished && hasFoundResults();
    show(el.unzipBtn, visible);
    el.unzipBtn.disabled = !visible || busy || !state.unzip.available;
    el.unzipBtn.title = !state.unzip.available
      ? "未检测到 7z，无法解压"
      : unzipping
        ? "解压进行中"
        : "用找到的密码把这些压缩包解压出来";
  }

  show(el.stop, running);
  el.stop.disabled = false;
  el.stop.textContent = "停止";

  el.minLen.disabled = running;
  el.maxLen.disabled = running;
  el.concurrencyBtn.disabled = running;

  if (running) hideConcurrencyEditor();

  // 拖放语义完全由界面状态决定，所以状态一变就刷新遮罩文案与是否可放下。
  updateDropHint();
}

// 批量破解的默认长度范围。和快速检测一样默认 6–8：批量场景里更长的纯数字
// 用原生实现基本跑不完，用户真要试可以自己往右拖到 12。
const BATCH_MIN_DEFAULT = 6;
const BATCH_MAX_DEFAULT = 8;

// readRange 读取批量破解的长度范围。校验与联动全部交给 readLengthRange，
// 这里只多做一件事：把结果写回 state.batch。
function readRange(edited) {
  const { minLen, maxLen } = readLengthRange(
    el.minLen,
    el.maxLen,
    BATCH_MIN_DEFAULT,
    BATCH_MAX_DEFAULT,
    edited,
  );
  state.batch.minLen = minLen;
  state.batch.maxLen = maxLen;
  return { minLen, maxLen };
}

function updateConcurrencyText() {
  const b = state.batch;
  el.concurrencyText.textContent = `使用 ${b.concurrency} 个核心并行处理`;
  el.concurrencyText.title = `1 – ${b.numCPU}，默认 ${Math.max(2, b.numCPU - 1)}`;
}

function toggleConcurrencyEditor() {
  const hidden = el.concurrencyEditor.classList.contains("hidden");
  if (hidden) {
    el.concurrencyInput.value = String(state.batch.concurrency);
    el.concurrencyInput.max = String(state.batch.numCPU);
    show(el.concurrencyEditor, true);
    el.concurrencyInput.focus();
    el.concurrencyInput.select();
  } else {
    hideConcurrencyEditor();
  }
}

function hideConcurrencyEditor() {
  show(el.concurrencyEditor, false);
}

async function applyConcurrency() {
  const n = clampInt(el.concurrencyInput.value, 1, state.batch.numCPU, state.batch.concurrency);
  try {
    const applied = await Call.ByName(`${BATCH_SERVICE}.SetConcurrency`, n);
    state.batch.concurrency = typeof applied === "number" ? applied : n;
    updateConcurrencyText();
    hideConcurrencyEditor();
    setStatus(`并发数已设为 ${state.batch.concurrency}`);
  } catch (err) {
    setStatus(`设置并发数失败：${describeError(err)}`, true);
  }
}

async function startBatch() {
  if (state.batch.running || state.inspecting > 0) return;
  if (state.unzip.running) {
    setStatus("解压进行中，先停止解压再重新破解", true);
    return;
  }
  if (state.attack.running) {
    setStatus("明文攻击进行中，先停止攻击再开始批量破解", true);
    return;
  }
  if (state.files.length === 0) return;

  const { minLen, maxLen } = readRange();

  // 只把「等待」的文件交给后端：RAR / 7z / AES / 非压缩包都留在列表里，
  // 在结果区各占一行「跳过（…）」，用户才知道它们去哪了。
  const queued = state.files.filter((f) => f.status === "waiting" && f.applicable);
  const paths = queued.map((f) => f.path);
  if (paths.length === 0) {
    setStatus("没有可处理的压缩包（批量破解只支持 ZipCrypto 加密的 ZIP）", true);
    return;
  }

  const b = state.batch;

  resetResults();
  show(el.progressCard, true);
  show(el.resultsCard, true);
  renderResultsPlaceholder();

  b.running = true;
  b.finished = false;
  b.cancelled = false;
  b.muted = false; // 新批次开始了，之前的静音到此为止
  b.total = paths.length;
  b.completed = 0;
  b.startedAt = Date.now();

  for (const file of state.files) {
    if (file.status === "waiting" || file.status === "found" || file.status === "miss") {
      file.status = "waiting";
      file.err = "";
    }
    updateFileRow(file);
  }

  // 不参与破解的文件也写进结果列表，顺序和文件列表一致。
  for (const file of state.files) {
    if (file.status === "waiting") continue;
    addResult({
      seq: state.results.length,
      path: file.path,
      name: file.name,
      kind: "skip",
      reason: batchSkipReason(file),
      minLen,
      maxLen,
    });
  }

  refreshControls();
  updateProgress();
  setStatus(
    `批量破解中：${paths.length} 个文件，${minLen}–${maxLen} 位纯数字` +
      (state.files.length > paths.length
        ? `（另有 ${state.files.length - paths.length} 个不参与）`
        : ""),
  );

  try {
    await Call.ByName(`${BATCH_SERVICE}.StartBatch`, paths, minLen, maxLen);
  } catch (err) {
    b.running = false;
    b.finished = true;
    refreshControls();
    updateProgress();

    if (b.cancelled) {
      // 侦察阶段就被停止：Go 侧没有真正启动批次，也不会有 batch-done。
      setStatus("已停止");
      if (state.results.length > 0) show(el.exportBtn, true);
      return;
    }
    setStatus(`启动失败：${describeError(err)}`, true);
  }
}

async function stopBatch() {
  if (!state.batch.running) return;
  state.batch.cancelled = true;
  el.stop.disabled = true;
  el.stop.textContent = "正在停止…";
  setStatus("正在停止批量任务…");

  try {
    await Call.ByName(`${BATCH_SERVICE}.StopBatch`);
  } catch (err) {
    setStatus(`停止失败：${describeError(err)}`, true);
    el.stop.disabled = false;
    el.stop.textContent = "停止";
  }
}

// ------------------------------------------------------------------ 进度

function updateProgress() {
  const b = state.batch;
  const total = b.total || state.files.length;
  const completed = Math.min(b.completed, total || b.completed);
  const pct = total > 0 ? Math.min(100, Math.round((completed / total) * 100)) : 0;

  el.progressFill.style.width = `${pct}%`;
  el.progressPercent.textContent = `${pct}%`;

  const parts = [`已完成 ${completed} / ${total}`];
  if (completed > 0 && b.startedAt > 0) {
    const elapsed = (Date.now() - b.startedAt) / 1000;
    const avg = elapsed / completed;
    parts.push(`平均 ${avg < 0.1 ? "< 0.1" : avg.toFixed(1)} 秒/文件`);

    const remaining = Math.max(0, total - completed);
    if (b.running && remaining > 0) {
      parts.push(`预计剩余：${formatSeconds(avg * remaining)}`);
    } else if (!b.running) {
      parts.push(`总耗时 ${formatSeconds(elapsed)}`);
    }
  }
  el.progressText.textContent = parts.join("  ·  ");
}

// ------------------------------------------------------------------ 结果列表

function resetResults() {
  state.results = [];
  state.sortKey = null;
  state.sortDir = 1;
  el.resultsBody.textContent = "";
  el.resultsNote.textContent = "";
  el.resultsFoot.textContent = "";
  el.resultsFoot.classList.add("hidden");
  show(el.exportBtn, false);
  show(el.unzipBtn, false);
  updateSortIndicators();
  resetUnzipState();
}

// resetUnzipState 把解压相关的状态清干净：换了一批文件、或者重新开始破解时，
// 上一轮的解压结果就不该再挂在界面上了。
function resetUnzipState() {
  const u = state.unzip;
  u.running = false;
  u.finished = false;
  u.cancelled = false;
  u.rootDir = "";
  u.total = 0;
  u.completed = 0;
  u.succeeded = 0;
  u.failed = 0;
  u.skippedResults = 0;
  u.skippedExisting = 0;
  u.startedAt = 0;
  u.current = "";

  state.unzipByPath.clear();
  show(el.unzipProgress, false);
  show(el.unzipStop, false);
}

function renderResultsPlaceholder() {
  if (state.results.length > 0) return;
  el.resultsBody.textContent = "";
  const row = document.createElement("tr");
  const cell = document.createElement("td");
  cell.colSpan = 4;
  cell.className = "empty-row";
  cell.textContent = "等待第一个结果…";
  row.appendChild(cell);
  el.resultsBody.appendChild(row);
}

function onBatchResult(data) {
  if (!data || state.batch.muted) return;
  const kind = data.skipped ? "skip" : data.found ? "found" : "miss";
  const file = state.files.find((f) => f.path === data.path);
  if (file) {
    if (kind === "skip") {
      // 正常情况下不会走到这里（只提交「等待」的文件），但后端仍然可能
      // 在侦察阶段改判，这里按同一套原因表落状态，避免行停在「等待」。
      file.notice = fileNoticeOf({ path: file.path, skipReason: data.skipReason }) || "other";
      file.status = isSeparate(file.notice) ? "separate" : "ignored";
    } else {
      file.status = kind === "found" ? "found" : "miss";
    }
    updateFileRow(file);
  }

  // 批量破解到的密码也写进统一视图，从结果列表点进去就能直接解密。
  if (kind === "found" && data.password && state.currentFile.path === data.path) {
    state.currentFile.password = data.password;
    state.currentFile.source = "batch";
  }

  addResult({
    seq: state.results.length,
    path: data.path,
    name: data.name || baseName(data.path),
    kind,
    password: data.password || "",
    reason: data.skipReason || "",
    minLen: state.batch.minLen,
    maxLen: state.batch.maxLen,
  });

  state.batch.completed += 1;
  updateProgress();
  updateFileSummary();
}

function onBatchError(data) {
  if (!data || state.batch.muted) return;
  const file = state.files.find((f) => f.path === data.path);
  if (file) {
    file.status = "error";
    file.err = data.message || "解析失败";
    updateFileRow(file);
  }

  addResult({
    seq: state.results.length,
    path: data.path,
    name: data.name || baseName(data.path),
    kind: "error",
    message: data.message || "未知错误",
    minLen: state.batch.minLen,
    maxLen: state.batch.maxLen,
  });

  state.batch.completed += 1;
  updateProgress();
  updateFileSummary();
}

function onBatchDone(data) {
  if (state.batch.muted) return;
  const b = state.batch;
  b.running = false;
  b.finished = true;
  b.cancelled = Boolean(data && data.cancelled);

  if (data && Number.isFinite(data.completed)) {
    b.completed = Math.max(b.completed, data.completed);
  }
  if (data && Number.isFinite(data.total) && data.total > 0) {
    b.total = data.total;
  }

  for (const file of state.files) {
    if (file.status === "waiting" && !b.cancelled) {
      file.status = "unfinished";
    }
    updateFileRow(file);
  }

  refreshControls();
  updateProgress();
  updateFileSummary();
  el.stop.textContent = "停止";
  el.stop.disabled = false;

  if (state.results.length > 0) {
    show(el.exportBtn, true);
  }
  // refreshControls 里按「批次已结束 + 有密码 + 7z 可用」决定解压按钮的状态。
  refreshControls();

  setStatus(
    b.cancelled
      ? `已停止：完成 ${b.completed} / ${b.total}`
      : `批量完成：${b.completed} / ${b.total}`,
    false,
  );
}

function addResult(result) {
  state.results.push(result);

  if (state.sortKey === null) {
    if (state.results.length === 1) {
      el.resultsBody.textContent = "";
    }
    el.resultsBody.appendChild(createResultRow(result));

    // DOM 只保留最近 MAX_RESULT_ROWS 行；完整数据仍在 state.results 里，
    // 导出 CSV 时不会丢。
    while (el.resultsBody.children.length > MAX_RESULT_ROWS) {
      el.resultsBody.removeChild(el.resultsBody.firstElementChild);
    }
  } else {
    renderResults();
  }

  updateResultsNote();
}

function createResultRow(result) {
  const tr = document.createElement("tr");
  tr.dataset.path = result.path;

  const nameCell = document.createElement("td");
  const nameBtn = document.createElement("button");
  nameBtn.type = "button";
  nameBtn.className = "name-btn";
  nameBtn.textContent = result.name;
  nameBtn.title = result.path;
  nameBtn.addEventListener("click", () => showSingle(result.path, true));
  nameCell.appendChild(nameBtn);

  const valueCell = document.createElement("td");
  valueCell.className = "result-cell";

  if (result.kind === "found") {
    valueCell.appendChild(document.createTextNode("密码："));
    const code = document.createElement("code");
    code.className = "password";
    code.textContent = result.password;
    valueCell.appendChild(code);
  } else if (result.kind === "skip") {
    valueCell.textContent = `跳过（${result.reason || "不适用"}）`;
  } else if (result.kind === "miss") {
    valueCell.textContent = `未找到（${result.minLen}–${result.maxLen} 位纯数字内无匹配）`;
  } else {
    valueCell.textContent = `错误：${result.message || "未知错误"}`;
  }

  const unzipCell = document.createElement("td");
  unzipCell.className = "unzip-cell";
  renderUnzipCell(unzipCell, result);

  const copyCell = document.createElement("td");
  copyCell.className = "col-copy";
  if (result.kind === "found") {
    const copyBtn = document.createElement("button");
    copyBtn.type = "button";
    copyBtn.className = "copy-btn";
    copyBtn.textContent = "复制";
    copyBtn.title = "复制密码";
    copyBtn.addEventListener("click", () => copyPassword(result.password, copyBtn));
    copyCell.appendChild(copyBtn);
  }

  tr.append(nameCell, valueCell, unzipCell, copyCell);
  tr.classList.add(`result-${result.kind}`);
  tr._unzipCell = unzipCell;
  return tr;
}

async function copyPassword(password, button) {
  try {
    await Clipboard.SetText(password);
    button.textContent = "已复制";
    button.classList.add("copied");
    window.setTimeout(() => {
      button.textContent = "复制";
      button.classList.remove("copied");
    }, 1200);
  } catch (err) {
    setStatus(`复制失败：${describeError(err)}`, true);
  }
}

function sortedResults() {
  const rows = state.results.slice();
  if (state.sortKey === null) return rows;

  const key = state.sortKey;
  const dir = state.sortDir;
  const rank = { found: 0, miss: 1, skip: 2, error: 3 };
  const unzipRank = { done: 0, failed: 1, running: 2, pending: 3, skipped: 4, cancelled: 5 };

  rows.sort((a, b) => {
    let cmp;
    if (key === "name") {
      cmp = a.name.localeCompare(b.name, "zh-CN");
    } else if (key === "unzip") {
      const ea = state.unzipByPath.get(a.path);
      const eb = state.unzipByPath.get(b.path);
      cmp = (unzipRank[ea?.status] ?? 9) - (unzipRank[eb?.status] ?? 9);
      if (cmp === 0) cmp = a.name.localeCompare(b.name, "zh-CN");
    } else {
      cmp = (rank[a.kind] ?? 9) - (rank[b.kind] ?? 9);
      if (cmp === 0) cmp = a.name.localeCompare(b.name, "zh-CN");
    }
    if (cmp === 0) cmp = a.seq - b.seq;
    return cmp * dir;
  });
  return rows;
}

function renderResults() {
  el.resultsBody.textContent = "";
  if (state.results.length === 0) {
    renderResultsPlaceholder();
    return;
  }

  const rows = sortedResults();
  const visible = state.sortKey === null ? rows.slice(-MAX_RESULT_ROWS) : rows.slice(0, MAX_RESULT_ROWS);

  const frag = document.createDocumentFragment();
  for (const result of visible) {
    frag.appendChild(createResultRow(result));
  }
  el.resultsBody.appendChild(frag);
  updateResultsNote();
}

function updateResultsNote() {
  const total = state.results.length;
  el.resultsNote.textContent = total > 0 ? `共 ${total} 条` : "";

  const hidden = total - Math.min(total, MAX_RESULT_ROWS);
  if (hidden > 0) {
    const scope = state.sortKey === null ? `最近 ${MAX_RESULT_ROWS} 条` : `前 ${MAX_RESULT_ROWS} 条`;
    el.resultsFoot.textContent = `界面只显示${scope}，导出 CSV 仍包含全部 ${total} 条。`;
    show(el.resultsFoot, true);
  } else {
    show(el.resultsFoot, false);
  }
}

function updateSortIndicators() {
  for (const th of el.resultsCard.querySelectorAll("th.sortable")) {
    const active = th.dataset.sort === state.sortKey;
    th.classList.toggle("sorted-asc", active && state.sortDir === 1);
    th.classList.toggle("sorted-desc", active && state.sortDir === -1);
    const ind = th.querySelector(".sort-ind");
    if (ind) ind.textContent = active ? (state.sortDir === 1 ? "▲" : "▼") : "";
  }
}

function toggleSort(key) {
  if (state.sortKey === key) {
    state.sortDir *= -1;
  } else {
    state.sortKey = key;
    state.sortDir = 1;
  }
  updateSortIndicators();
  renderResults();
}

function resultStatusLabel(result) {
  switch (result.kind) {
    case "found":
      return "已找到";
    case "miss":
      return "未找到";
    case "skip":
      return "跳过";
    default:
      return "错误";
  }
}

function resultDetail(result) {
  switch (result.kind) {
    case "found":
      return result.password;
    case "miss":
      return `${result.minLen}–${result.maxLen} 位纯数字内无匹配`;
    case "skip":
      return result.reason || "不适用";
    default:
      return result.message || "未知错误";
  }
}

async function exportCSV() {
  if (state.results.length === 0) return;

  let target;
  try {
    target = await Dialogs.SaveFile({
      Title: "导出批量结果",
      Filename: "zipkit-batch.csv",
      Filters: [{ DisplayName: "CSV 文件", Pattern: "*.csv" }],
    });
  } catch (err) {
    setStatus(`打开保存对话框失败：${describeError(err)}`, true);
    return;
  }
  if (!target) return;

  const rows = sortedResults().map((result) => ({
    name: result.name,
    status: resultStatusLabel(result),
    detail: resultDetail(result),
  }));

  try {
    await Call.ByName(`${BATCH_SERVICE}.ExportCSV`, target, rows);
    setStatus(`已导出 ${rows.length} 条结果到 ${target}`);
  } catch (err) {
    setStatus(`导出失败：${describeError(err)}`, true);
  }
}

// ------------------------------------------------------------------ 批量解压

// 只有「找到密码」的结果能解压。AES、未找到密码、破解失败的文件不进 Job
// 列表，在界面上标成「跳过解压」。
function hasFoundResults() {
  return state.results.some((r) => r.kind === "found" && r.password);
}

function buildUnzipJobs() {
  return state.results
    .filter((r) => r.kind === "found" && r.password)
    .map((r) => ({ ZipPath: r.path, Password: r.password, OutputDir: "", EntryName: "" }));
}

async function chooseExportDir() {
  // 浏览器预览 / 自动化验证里没有原生目录对话框，允许外部预置一个目录。
  // 桌面端不会设置这个全局变量，行为完全不受影响。
  if (typeof window.__ZIPKIT_TEST_DIR__ === "string" && window.__ZIPKIT_TEST_DIR__) {
    return window.__ZIPKIT_TEST_DIR__;
  }

  const picked = await Dialogs.OpenFile({
    Title: "选择导出根目录",
    CanChooseFiles: false,
    CanChooseDirectories: true,
    AllowsMultipleSelection: false,
    // 设置里配了默认导出目录的话，对话框直接从这里起步。
    DefaultDirectory: state.settings.defaultExportDir || "",
  });
  return normalizePaths(picked)[0] || "";
}

async function startUnzipFlow() {
  if (state.unzip.running || state.batch.running) return;
  if (!state.unzip.available) {
    setStatus("未检测到 7z，无法解压。请先安装 7-Zip 或指定 7z 路径", true);
    return;
  }

  const jobs = buildUnzipJobs();
  if (jobs.length === 0) {
    setStatus("没有已找到密码的文件可以解压", true);
    return;
  }

  let dir;
  try {
    dir = await chooseExportDir();
  } catch (err) {
    setStatus(`选择导出目录失败：${describeError(err)}`, true);
    return;
  }
  if (!dir) return;

  pendingUnzip = { jobs, dir };
  showUnzipConfirm(jobs, dir);
}

function showUnzipConfirm(jobs, dir) {
  const total = state.results.length;
  const skipped = total - jobs.length;

  el.unzipModalText.textContent =
    `将解压 ${jobs.length} 个文件到下面这个目录。` +
    `本次共有 ${total} 条结果，其中 ${jobs.length} 个文件已找到密码，${skipped} 个文件被跳过。`;
  el.unzipModalDir.textContent = dir;
  el.unzipFlat.checked = state.unzip.layout === "flat";
  show(el.unzipModal, true);
  el.unzipConfirm.focus();
}

function hideUnzipModal() {
  pendingUnzip = null;
  show(el.unzipModal, false);
}

async function confirmUnzip() {
  const pending = pendingUnzip;
  if (!pending) return;
  hideUnzipModal();

  const layout = el.unzipFlat.checked ? "flat" : "per-zip";
  state.unzip.layout = layout;
  try {
    await Call.ByName(`${UNZIP_SERVICE}.SetLayout`, layout);
  } catch (err) {
    // 布局存不下来不影响本次解压，服务端会用配置里的默认值。
    console.warn("保存解压布局失败", err);
  }

  // 每行先准备好解压状态：能找到密码的是「等待解压」，其余是「跳过解压」。
  state.unzipByPath.clear();
  for (const result of state.results) {
    if (result.kind === "found" && result.password) {
      state.unzipByPath.set(result.path, {
        status: "pending",
        outputDir: "",
        extracted: 0,
        failed: 0,
        skippedExisting: 0,
        message: "",
      });
    } else {
      state.unzipByPath.set(result.path, {
        status: "skipped",
        outputDir: "",
        extracted: 0,
        failed: 0,
        skippedExisting: 0,
        message: unzipSkipReason(result),
      });
    }
  }
  renderResults();

  const u = state.unzip;
  u.running = true;
  u.finished = false;
  u.cancelled = false;
  u.rootDir = pending.dir;
  u.total = pending.jobs.length;
  u.completed = 0;
  u.succeeded = 0;
  u.failed = 0;
  u.skippedResults = state.results.length - pending.jobs.length;
  u.skippedExisting = 0;
  u.startedAt = Date.now();
  u.current = "";

  // 底部切成解压进度视图。
  show(el.progressCard, false);
  show(el.unzipProgress, true);
  show(el.unzipStop, true);
  el.unzipStop.disabled = false;
  el.unzipStop.textContent = "停止";
  updateUnzipProgress();
  refreshControls();

  try {
    await Call.ByName(`${UNZIP_SERVICE}.StartUnzip`, pending.jobs, pending.dir);
    setStatus(`解压中：${pending.jobs.length} 个文件 → ${pending.dir}`);
  } catch (err) {
    u.running = false;
    u.finished = true;
    show(el.unzipStop, false);
    refreshControls();
    setStatus(`启动解压失败：${describeError(err)}`, true);
  }
}

function unzipSkipReason(result) {
  if (result.kind === "skip") return result.reason || "不适用";
  if (result.kind === "miss") return "未找到密码";
  if (result.kind === "error") return "破解失败";
  return "没有密码";
}

function onUnzipStart(data) {
  if (!data) return;
  state.unzip.current = data.name || baseName(data.path);

  const entry = state.unzipByPath.get(data.path);
  // 事件来自不同 goroutine，start 有可能比 result 晚到。只在「还没开始」时
  // 才把它标成解压中，否则会把已经出结果的行又改回「解压中…」。
  if (entry && entry.status === "pending") {
    entry.status = "running";
    refreshUnzipRow(data.path);
  }
  updateUnzipProgress();
}

// applyUnzipResult 把一条结果写进 state 并刷新对应的行。
// count 为 false 时只同步数据、不累加计数（收尾对账用）。
function applyUnzipResult(data, count) {
  const entry = state.unzipByPath.get(data.path) || {};
  entry.status = data.cancelled ? "cancelled" : data.err ? "failed" : "done";
  entry.outputDir = data.outputDir || "";
  entry.extracted = Number(data.extracted) || 0;
  entry.failed = Number(data.failed) || 0;
  entry.skippedExisting = Number(data.skipped) || 0;
  entry.message = data.err || "";
  state.unzipByPath.set(data.path, entry);
  refreshUnzipRow(data.path);

  if (!count) return;
  const u = state.unzip;
  if (!data.cancelled) u.completed += 1;
  if (data.cancelled) {
    // 取消的不计入成功/失败，界面靠「已完成 x / y」的差值体现。
  } else if (data.err) {
    u.failed += 1;
  } else {
    u.succeeded += 1;
  }
}

function onUnzipResult(data) {
  if (!data) return;
  applyUnzipResult(data, true);
  updateUnzipProgress();
}

function onUnzipDone(data) {
  const u = state.unzip;
  u.running = false;
  u.finished = true;
  u.cancelled = Boolean(data && data.cancelled);

  if (data) {
    if (Number.isFinite(data.completed)) u.completed = Math.max(u.completed, data.completed);
    if (Number.isFinite(data.succeeded)) u.succeeded = data.succeeded;
    if (Number.isFinite(data.failed)) u.failed = data.failed;
    if (Number.isFinite(data.skipped)) u.skippedExisting = data.skipped;
  }

  show(el.unzipStop, false);
  el.unzipStop.disabled = false;
  el.unzipStop.textContent = "停止";
  updateUnzipProgress();
  refreshControls();

  const parts = [u.cancelled ? "解压已停止" : "解压完成"];
  parts.push(`成功 ${u.succeeded}`);
  if (u.failed > 0) parts.push(`失败 ${u.failed}`);
  if (u.skippedResults > 0) parts.push(`跳过 ${u.skippedResults}`);
  if (u.skippedExisting > 0) parts.push(`${u.skippedExisting} 个已存在文件未覆盖`);
  setStatus(parts.join("  ·  "), u.failed > 0);

  // 事件可能比 done 晚到，向 Go 要一份最终结果对账，保证每一行都和实际一致。
  reconcileUnzipResults();
}

async function reconcileUnzipResults() {
  try {
    const rows = await Call.ByName(`${UNZIP_SERVICE}.Snapshot`);
    if (Array.isArray(rows)) {
      for (const row of rows) {
        if (row && row.path) applyUnzipResult(row, false);
      }
    }
  } catch (err) {
    console.warn("同步解压结果失败", err);
  }
  renderResults();
}

function updateUnzipProgress() {
  const u = state.unzip;
  const total = u.total;
  const completed = Math.min(u.completed, total || u.completed);
  const pct = total > 0 ? Math.min(100, Math.round((completed / total) * 100)) : 0;

  el.unzipProgressFill.style.width = `${pct}%`;
  el.unzipProgressPercent.textContent = `${pct}%`;

  const parts = [`已完成 ${completed} / ${total}`, `成功 ${u.succeeded}`];
  if (u.failed > 0) parts.push(`失败 ${u.failed}`);
  if (u.skippedResults > 0) parts.push(`跳过 ${u.skippedResults}`);
  if (u.running && u.current) parts.push(`当前：${u.current}`);
  el.unzipProgressText.textContent = parts.join("  ·  ");
}

// renderUnzipCell 只负责渲染一个「解压状态」单元格。
function renderUnzipCell(cell, result) {
  cell.textContent = "";
  cell.className = "unzip-cell";

  const entry = state.unzipByPath.get(result.path);
  if (!entry) {
    cell.textContent = "—";
    return;
  }

  cell.classList.add(`unzip-${entry.status}`);

  if (entry.status === "done") {
    const dirLabel = baseName(entry.outputDir) || "输出目录";
    let text;
    if (entry.extracted > 0) {
      text = `已解压（${entry.extracted} 个文件 → ${dirLabel}/）`;
      if (entry.skippedExisting > 0) text += `，跳过 ${entry.skippedExisting} 个已存在文件`;
    } else {
      // 一个都没解出来、但目标目录里全都有：这是「跳过」而不是「解压了 0 个」。
      text = `已跳过（${entry.skippedExisting} 个已存在文件 → ${dirLabel}/）`;
    }
    cell.textContent = text;

    if (entry.outputDir) {
      const openBtn = document.createElement("button");
      openBtn.type = "button";
      openBtn.className = "btn-ghost unzip-open-btn";
      openBtn.textContent = "打开";
      openBtn.title = entry.outputDir;
      openBtn.addEventListener("click", () => openOutputDir(entry.outputDir));
      cell.appendChild(openBtn);
    }
    return;
  }

  if (entry.status === "failed") {
    cell.textContent = entry.message || "解压失败";
    return;
  }
  if (entry.status === "skipped") {
    cell.textContent = `跳过解压（${entry.message || "不适用"}）`;
    return;
  }
  if (entry.status === "running") {
    cell.textContent = "解压中…";
    return;
  }
  if (entry.status === "cancelled") {
    cell.textContent = "未解压（已停止）";
    return;
  }
  cell.textContent = "等待解压";
}

function refreshUnzipRow(path) {
  for (const tr of el.resultsBody.children) {
    if (tr.dataset.path !== path || !tr._unzipCell) continue;
    const result = state.results.find((r) => r.path === path);
    if (result) renderUnzipCell(tr._unzipCell, result);
    return;
  }
}

async function openOutputDir(dir) {
  if (!dir) return;
  try {
    await Call.ByName(`${UNZIP_SERVICE}.OpenOutputDir`, dir);
    setStatus(`已打开 ${dir}`);
  } catch (err) {
    setStatus(`打开目录失败：${describeError(err)}`, true);
  }
}

async function stopUnzip() {
  if (!state.unzip.running) return;
  el.unzipStop.disabled = true;
  el.unzipStop.textContent = "正在停止…";
  setStatus("正在停止解压…");

  try {
    await Call.ByName(`${UNZIP_SERVICE}.StopUnzip`);
  } catch (err) {
    setStatus(`停止失败：${describeError(err)}`, true);
    el.unzipStop.disabled = false;
    el.unzipStop.textContent = "停止";
  }
}

// ------------------------------------------------------------------ 7z 检测

async function checkSevenZip() {
  try {
    const status = await Call.ByName(`${UNZIP_SERVICE}.SevenZip`);
    applySevenZipStatus(status);
  } catch (err) {
    applySevenZipStatus({ available: false });
  }
}

function applySevenZipStatus(status) {
  const available = Boolean(status && status.available);
  state.unzip.available = available;
  state.unzip.sevenZipPath = (status && status.path) || "";

  show(el.sevenZipBanner, !available);
  if (!available) {
    el.sevenZipInput.value = state.unzip.sevenZipPath;
  }
  refreshControls();
}

async function saveSevenZipPath() {
  const value = el.sevenZipInput.value.trim();
  try {
    const status = await Call.ByName(`${UNZIP_SERVICE}.SetSevenZipPath`, value);
    applySevenZipStatus(status);
    if (status && status.available) {
      setStatus(`7z 已就绪：${status.path}`);
    } else {
      setStatus("这个路径不能用，仍未检测到 7z", true);
    }
  } catch (err) {
    setStatus(`保存 7z 路径失败：${describeError(err)}`, true);
  }
}

async function browseSevenZip() {
  try {
    const picked = await Dialogs.OpenFile({
      Title: "选择 7z 可执行文件",
      CanChooseFiles: true,
      CanChooseDirectories: false,
      AllowsMultipleSelection: false,
      Filters: [
        { DisplayName: "可执行文件", Pattern: "*.exe;7z;7za;7zr" },
        { DisplayName: "所有文件", Pattern: "*.*" },
      ],
    });
    const path = normalizePaths(picked)[0];
    if (!path) return;
    el.sevenZipInput.value = path;
    await saveSevenZipPath();
  } catch (err) {
    setStatus(`选择 7z 失败：${describeError(err)}`, true);
  }
}

// ------------------------------------------------------------------ 明文攻击

// 明文攻击只在单文件视图里出现：批量模式一次处理几十个文件，没有「挑一个
// 已知明文」的语境。从批量结果点进详情后，卡片照常按这个文件显示。

// ------------------------------------------------------- 推荐卡片与优先级

// recommendationOf 按优先级判断当前文件该显示哪张推荐卡片：
//
//	1 fake      伪加密            → 修复伪加密
//	2 zipcrypto 全是 ZipCrypto    → 明文攻击 + 快速弱密码检测
//	3 mixed     混合              → 明文攻击 + GPU 恢复
//	4 gpu       全 AES / RAR5 / 7z → GPU 恢复
//	5 plain     全未加密          → 直接解压
//
// 只显示第一个匹配项：伪加密的文件绝不能再露出明文攻击入口，否则用户点了
// 只会白等一场。
function recommendationOf(info) {
  if (state.archiveKind === "rar" || state.archiveKind === "7z") return "gpu";

  const entries = (info && info.Entries) || [];
  if (!info) return "";
  if (info.IsFakeEncrypted) return "fake";
  if (entries.length === 0) return "";

  const zipcrypto = entries.filter((e) => e.EncryptionType === "ZipCrypto");
  const aes = entries.filter(isAesEntry);

  if (zipcrypto.length > 0) return aes.length > 0 ? "mixed" : "zipcrypto";
  if (aes.length > 0) return "gpu";
  if (entries.every((e) => !e.IsEncrypted)) return "plain";
  return "";
}

function applyRecommendationPriority() {
  const level = recommendationOf(state.info);

  show(el.fakeCard, level === "fake");
  show(el.attackCard, level === "zipcrypto" || level === "mixed");
  show(el.gpuCard, level === "gpu" || level === "mixed");
  show(el.plainCard, level === "plain");

  if (level !== "zipcrypto" && level !== "mixed") closeAttackPanel();
  if (level !== "gpu" && level !== "mixed") closeGpuPanel();
}

// ------------------------------------------------------------- 伪加密修复

function renderFakeCard(info) {
  const fake = Boolean(info && info.IsFakeEncrypted);
  state.fake.detected = fake;
  state.fake.count = (info && info.FakeCount) || 0;

  if (!fake) {
    show(el.fakeCard, false);
    show(el.fakeResult, false);
    state.fake.output = "";
    updateDropHint();
    return;
  }

  const names = ((info && info.Entries) || [])
    .filter((e) => e.IsFakeEncrypted)
    .map((e) => e.Name);
  const sample = names.slice(0, 3).join("、");
  const more = names.length > 3 ? ` 等 ${names.length} 个` : "";

  el.fakeTitle.textContent = "检测到疑似伪加密";
  el.fakeSub.textContent =
    `${state.fake.count} 个条目只改了中央目录的加密标记，数据本身没加密` +
    (sample ? `（${sample}${more}）` : "") +
    "。修复会另存一份新文件，原文件不动。";
  show(el.fakeCard, true);
  show(el.fakeResult, false);
}

async function fixFakeEncryption() {
  if (state.fake.fixing || !state.fake.detected) return;

  let output;
  try {
    output = await pickSavePath(
      "保存修复后的文件",
      baseName(siblingPath(state.path, "_已修复.zip")),
      [{ DisplayName: "ZIP 压缩包", Pattern: "*.zip" }],
    );
  } catch (err) {
    failWith("选择输出路径失败", err);
    return;
  }
  if (!output) return;

  state.fake.fixing = true;
  el.fakeFix.disabled = true;
  el.fakeFix.textContent = "修复中…";
  setStatus("正在修复伪加密…");
  hideErrorCard();

  try {
    const res = await Call.ByName(`${ZIP_SERVICE}.FixFakeEncryption`, state.path, output);
    const fixedPath = (res && res.outputPath) || output;
    state.fake.output = fixedPath;
    state.currentFile.outputDir = dirOf(fixedPath);

    el.fakeOutput.textContent = fixedPath;
    el.fakeOutput.title = fixedPath;
    show(el.fakeResult, true);
    updateDropHint();
    setStatus(`已修复 ${res.fixedCount} 个条目，新文件：${fixedPath}`);
  } catch (err) {
    failWith("修复伪加密失败", err);
  } finally {
    state.fake.fixing = false;
    el.fakeFix.disabled = false;
    el.fakeFix.textContent = "修复伪加密";
  }
}

// ------------------------------------------------------------- 未加密文件

function renderPlainCard(info) {
  const entries = (info && info.Entries) || [];
  const plain = entries.length > 0 && entries.every((e) => !e.IsEncrypted);
  if (!plain) {
    show(el.plainCard, false);
    return;
  }
  el.plainSub.textContent = `共 ${entries.length} 个条目，都没有加密，不需要密码。`;
  show(el.plainCard, true);
}

async function unzipPlainFile() {
  const dir = await chooseExportDir();
  if (!dir) {
    setStatus("没有选择导出目录");
    return;
  }
  setStatus("正在解压…");
  el.plainUnzip.disabled = true;
  try {
    const res = await Call.ByName(`${GPU_SERVICE}.DecryptFile`, state.path, "", dir);
    state.currentFile.outputDir = dir;
    const parts = [`解出 ${res.extracted} 个文件`];
    if (res.skipped) parts.push(`跳过 ${res.skipped} 个`);
    if (res.failed) parts.push(`失败 ${res.failed} 个`);
    setStatus(`${parts.join("，")}：${dir}`);
    refreshDetailActions();
  } catch (err) {
    failWith("解压失败", err);
  } finally {
    el.plainUnzip.disabled = false;
  }
}

// ------------------------------------------------------- 快速弱密码检测

// 快速检测的位数范围默认 6–8：1–5 位几乎秒出，真正常见的弱口令集中在 6–8。
// 上下限本身由 readLengthRange 统一管（1–12），这里只留默认值。
const QUICK_MIN_DEFAULT = 6;
const QUICK_MAX_DEFAULT = 8;
// 从这个位数开始提醒「原生实现会慢」。
const QUICK_SLOW_FROM = 10;

// readQuickRange 读取并校正位数输入框，返回 { minLen, maxLen }。
// 校验逻辑与批量破解、显卡暴力共用 readLengthRange。
function readQuickRange(edited) {
  const { minLen, maxLen } = readLengthRange(
    el.quickMinLen,
    el.quickMaxLen,
    QUICK_MIN_DEFAULT,
    QUICK_MAX_DEFAULT,
    edited,
  );
  updateQuickSlowHint(maxLen);
  return { minLen, maxLen };
}

// updateQuickSlowHint 控制黄色提示：位数上限到 10 位以上才提示慢。
function updateQuickSlowHint(maxLen) {
  show(el.quickSlowHint, maxLen >= QUICK_SLOW_FROM);
}

// toggleQuickRange 展开/收起位数设置。▾ 就是「快速弱密码检测」的位数入口。
function toggleQuickRange() {
  const closed = el.quickRange.classList.contains("hidden");
  show(el.quickRange, closed);
  el.quickRangeBtn.setAttribute("aria-expanded", closed ? "true" : "false");
  if (closed) {
    readQuickRange();
    el.quickMinLen.focus();
    el.quickMinLen.select();
  }
}

async function quickCrack() {
  if (state.quick.running || state.attack.running) return;

  const { minLen, maxLen } = readQuickRange();

  state.quick.running = true;
  el.quickCrack.disabled = true;
  el.quickRangeBtn.disabled = true;
  el.quickCrack.textContent = "检测中…";
  setStatus(`正在检测 ${minLen}–${maxLen} 位纯数字密码…`);
  hideErrorCard();

  try {
    const res = await Call.ByName(`${BATCH_SERVICE}.CrackOne`, state.path, minLen, maxLen);
    const seconds = ((res.elapsedMs || 0) / 1000).toFixed(1);

    if (res.err) {
      failWith("快速检测失败", res.err);
      return;
    }
    if (res.skip) {
      el.quickPassword.textContent = "—";
      el.quickNote.textContent = `跳过：${res.skip}`;
      show(el.quickResult, true);
      setStatus(`跳过：${res.skip}`, true);
      return;
    }

    if (res.found) {
      state.quick.password = res.password;
      state.currentFile.password = res.password;
      state.currentFile.source = "quick";
      el.quickPassword.textContent = res.password;
      el.quickNote.textContent = `${minLen}–${maxLen} 位纯数字，用时 ${seconds}s`;
      show(el.quickResult, true);
      setStatus(`已找到密码：${res.password}`);
    } else {
      el.quickPassword.textContent = "（未找到）";
      el.quickNote.textContent = `${minLen}–${maxLen} 位纯数字内没有匹配，用时 ${seconds}s。可以再试明文攻击或显卡加速破解。`;
      show(el.quickResult, true);
      setStatus("快速检测没有找到密码", true);
    }
  } catch (err) {
    failWith("快速检测失败", err);
  } finally {
    state.quick.running = false;
    el.quickCrack.disabled = false;
    el.quickRangeBtn.disabled = false;
    el.quickCrack.textContent = "快速弱密码检测";
    refreshControls();
  }
}

// --------------------------------------------------------- 统一解密入口

// decryptCurrentFile 是「解密文件」的唯一实现：密码来自 currentFile，
// 不管它是批量破解、快速检测还是 hashcat 拿到的。底层仍然是 7z。
async function decryptCurrentFile() {
  const password = state.currentFile.password;
  if (!password) {
    setStatus("还没有拿到密码", true);
    return;
  }
  const archive = state.currentFile.path || state.path;
  const dir = await chooseExportDir();
  if (!dir) {
    setStatus("没有选择导出目录");
    return;
  }

  setStatus("正在解密…");
  try {
    const res = await Call.ByName(`${GPU_SERVICE}.DecryptFile`, archive, password, dir);
    state.currentFile.outputDir = dir;
    const parts = [`解出 ${res.extracted} 个文件`];
    if (res.skipped) parts.push(`跳过 ${res.skipped} 个`);
    if (res.failed) parts.push(`失败 ${res.failed} 个`);
    setStatus(`${parts.join("，")}：${dir}`);
    refreshDetailActions();
  } catch (err) {
    failWith("解密失败", err);
  }
}

// dirOf 取路径的父目录（兼容 / 和 \）。
function dirOf(path) {
  const cut = Math.max(String(path).lastIndexOf("/"), String(path).lastIndexOf("\\"));
  return cut > 0 ? String(path).slice(0, cut) : "";
}

// refreshDetailHint 在批量详情页顶部说明「这个文件为什么要单独处理」。
function refreshDetailHint() {
  if (!el.detailHint) return;
  if (!state.detailFromBatch) {
    show(el.detailHint, false);
    return;
  }

  const kind = state.archiveKind;
  const level = recommendationOf(state.info);
  let text = "";

  if (kind === "rar" || kind === "7z") {
    text = "这个归档需要单独处理（提取哈希 → hashcat），处理完点左上角返回批量视图";
  } else if (level === "gpu" || level === "mixed") {
    text = "包含 AES 条目，需要单独处理（GPU 恢复），处理完点左上角返回批量视图";
  } else if (level === "fake") {
    text = "这是伪加密文件，修复后才能直接解压；处理完点左上角返回批量视图";
  }

  el.detailHint.textContent = text;
  show(el.detailHint, Boolean(text));
}

function resetAttackState() {
  const a = state.attack;
  a.open = false;
  a.zipEntries = [];
  a.keys = "";
  a.precheck = null;
  a.plainZipEntries = [];

  show(el.attackCard, false);
  show(el.attackPanel, false);
  show(el.attackLogCard, false);
  show(el.attackResult, false);
  show(el.attackFail, false);
  show(el.attackPrecheck, false);
  hideCreatorCompare();
  show(el.attackWarn, false);

  el.attackLog.textContent = "";
  el.attackLogCount.textContent = "";
  el.attackPlainPath.value = "";
  el.attackPlainPath.title = "";
  el.attackPlainEntry.textContent = "";
  el.attackOpen.textContent = "开始明文攻击";
  show(el.quickResult, false);
  state.quick.password = "";
  state.attack.logLines = 0;

  // 位数设置面板收起，但输入框里的值留着（那是用户的偏好，换文件不该丢）。
  show(el.quickRange, false);
  el.quickRangeBtn.setAttribute("aria-expanded", "false");
  show(el.quickSlowHint, false);

  setPlainMode("file");
  setAttackRunning(false);
}

function renderAttackCard(info) {
  // RAR5 / 7z 没有 ZipCrypto 可言，整张卡片收起来。
  if (!info) {
    show(el.attackCard, false);
    closeAttackPanel();
    return;
  }
  const entries = ((info && info.Entries) || []).filter((e) => e.EncryptionType === "ZipCrypto");
  const total = ((info && info.Entries) || []).length;
  state.attack.zipEntries = entries;

  show(el.attackCard, true);

  if (entries.length === 0) {
    // 全是 AES 时 GPU 卡片会给出更准确的说明，这张卡片就不用再占地方了。
    if (((info && info.Entries) || []).some(isAesEntry)) {
      show(el.attackCard, false);
      closeAttackPanel();
      return;
    }
    el.attackTitle.textContent = "此文件不适用明文攻击";
    el.attackSub.textContent =
      total === 0
        ? "这个压缩包里没有条目。"
        : "没有 ZipCrypto 条目（全是 AES 或未加密）。明文攻击只能恢复 ZipCrypto 的密钥。";
    show(el.attackOpen, false);
    show(el.attackDisabledHint, false);
    closeAttackPanel();
    return;
  }

  const others = total - entries.length;
  el.attackTitle.textContent = others > 0 ? "部分条目可明文攻击" : "可尝试明文攻击";
  el.attackSub.textContent =
    others > 0
      ? `${entries.length} 个 ZipCrypto 条目可以尝试，另外 ${others} 个是 AES / 未加密，不在候选里。`
      : `共 ${entries.length} 个 ZipCrypto 条目。如果手上有压缩前的原始文件（或另存的一份明文 ZIP），可以用 bkcrack 恢复密钥。`;

  // 快速弱密码检测只对 ZipCrypto 有意义（AES 走 GPU 恢复），
  // 而且伪加密文件压根不该出现这张卡片——推荐优先级已经在外面拦住了。
  const level = recommendationOf(info);
  const canQuick = level === "zipcrypto" || level === "mixed";
  show(el.quickCrack, canQuick);
  el.quickCrack.disabled = state.quick.running || state.attack.running;
  if (!canQuick) show(el.quickResult, false);

  const available = state.attack.available;
  show(el.attackOpen, true);
  el.attackOpen.disabled = !available || state.attack.running;
  el.attackOpen.title = available ? "" : "未找到 bkcrack，请在设置中指定路径";
  show(el.attackDisabledHint, !available);

  // 第三个按钮：显卡加速破解。它和「快速弱密码检测」「开始明文攻击」一样只
  // 出现在 ZipCrypto 卡片上，但走的是 hashcat 那条完全不同的路——前面两个
  // 按钮作用于这里的 ZipCrypto 条目，这个按钮让用户在面板里挑条目。
  show(el.attackGpu, true);
  applyGpuAvailability();

  fillAttackEntries(entries);
}

function fillAttackEntries(entries) {
  const previous = el.attackEntry.value;
  el.attackEntry.textContent = "";

  for (const entry of entries) {
    const option = document.createElement("option");
    option.value = entry.Name;
    option.textContent = `${entry.Name}（${entry.Compression}，${formatBytes(entry.UncompressedSize)}）`;
    el.attackEntry.appendChild(option);
  }
  if (entries.some((e) => e.Name === previous)) {
    el.attackEntry.value = previous;
  }
}

function toggleAttackPanel() {
  if (state.attack.open) {
    closeAttackPanel();
    return;
  }
  state.attack.open = true;
  show(el.attackPanel, true);
  el.attackOpen.textContent = "收起攻击面板";
  el.attackEntry.focus();
  updateDropHint();
}

function closeAttackPanel() {
  state.attack.open = false;
  show(el.attackPanel, false);
  if (el.attackOpen && !state.attack.running) {
    el.attackOpen.textContent = "开始明文攻击";
  }
  updateDropHint();
}

function setPlainMode(mode) {
  const isZip = mode === "zip";
  const isHex = mode === "hex";
  state.attack.plainIsZip = isZip;

  for (const radio of document.querySelectorAll('input[name="attack-plain-mode"]')) {
    radio.checked = radio.value === mode;
  }
  show(el.attackPlainEntryField, isZip);
  show(el.attackPlainPathField, !isHex);
  show(el.attackHexFields, isHex);
  // 十六进制模式下不接受拖入，提示文案要跟着变。
  updateDropHint();
}

function currentPlainMode() {
  const checked = document.querySelector('input[name="attack-plain-mode"]:checked');
  return checked ? checked.value : "file";
}

// 切换明文形式时清掉已选路径：三种形式是完全不同的东西，留着上一次的路径
// 只会让人误以为已经选好了。
function onPlainModeChange() {
  if (state.attack.running) return;
  setPlainMode(currentPlainMode());
  el.attackPlainPath.value = "";
  el.attackPlainPath.title = "";
  el.attackPlainEntry.textContent = "";
  state.attack.plainZipEntries = [];
  hidePrecheck();
  hideCreatorCompare();
}

// ------------------------------------------------------ 十六进制明文输入

// normalizeHexInput 只保留十六进制字符，并按每 2 位加一个空格。
// bkcrack 的 -x 不接受带空格的字符串，提交前会再清一次。
function normalizeHexInput(raw) {
  const clean = String(raw || "")
    .replace(/[^0-9a-fA-F]/g, "")
    .toUpperCase();
  return clean.replace(/(.{2})/g, "$1 ").trim();
}

// parseHexOffset 接受十进制或 0x 前缀的十六进制。
function parseHexOffset(raw) {
  const text = String(raw || "").trim();
  if (!text) return 0;
  if (/^0x/i.test(text)) {
    const value = Number.parseInt(text.slice(2), 16);
    if (!Number.isFinite(value) || value < 0) throw new Error("偏移量不是合法的十六进制数");
    return value;
  }
  const value = Number.parseInt(text, 10);
  if (!Number.isFinite(value) || value < 0) throw new Error("偏移量必须是 0 或正整数");
  return value;
}

function onHexInput() {
  const caretAtEnd =
    el.attackHexText.selectionStart === el.attackHexText.value.length;
  const formatted = normalizeHexInput(el.attackHexText.value);
  if (formatted !== el.attackHexText.value) {
    el.attackHexText.value = formatted;
    if (caretAtEnd) el.attackHexText.setSelectionRange(formatted.length, formatted.length);
  }
}

function applyHexTemplate() {
  const key = el.attackHexTemplate.value;
  if (!key || !HEX_TEMPLATES[key]) return;
  el.attackHexText.value = normalizeHexInput(HEX_TEMPLATES[key]);
  if (!el.attackHexOffset.value.trim()) el.attackHexOffset.value = "0";
  hidePrecheck();
  void runPrecheck();
}

// hexPlaintextForSubmit 去掉所有空格，bkcrack 只认紧凑的十六进制串。
function hexPlaintextForSubmit() {
  return normalizeHexInput(el.attackHexText.value).replace(/\s+/g, "");
}

async function browsePlainFile() {
  if (state.attack.running) return;

  const isZip = currentPlainMode() === "zip";
  try {
    const path = await pickPlainPath(isZip);
    if (!path) return;
    await setPlaintext(path);
  } catch (err) {
    setStatus(`选择明文失败：${describeError(err)}`, true);
  }
}

// setPlaintext 是「填入明文路径」的唯一入口：按钮选择和拖放都走这里，
// 两条路径才不会逐渐漂移。它只负责写路径、加载明文 ZIP 的条目、跑预检，
// 不改界面状态（面板本来就是开着的）。
async function setPlaintext(path) {
  if (state.attack.running) return false;
  if (!path) return false;

  const isZip = currentPlainMode() === "zip";
  el.attackPlainPath.value = path;
  el.attackPlainPath.title = path;

  if (isZip) {
    const ok = await loadPlainZipEntries(path);
    if (!ok) return false;
  } else {
    el.attackPlainEntry.textContent = "";
    state.attack.plainZipEntries = [];
  }

  await runPrecheck();
  return true;
}

// pickPlainPath 打开文件对话框选明文。__ZIPKIT_TEST_PLAIN__ 是无头测试用的
// 逃生口：CDP 点不动原生对话框，只能让页面直接拿到路径。
async function pickPlainPath(isZip) {
  if (window.__ZIPKIT_TEST_PLAIN__) {
    return String(window.__ZIPKIT_TEST_PLAIN__);
  }

  const picked = await Dialogs.OpenFile({
    Title: isZip ? "选择明文 ZIP（内含已知明文条目）" : "选择已知明文文件",
    CanChooseFiles: true,
    CanChooseDirectories: false,
    AllowsMultipleSelection: false,
    Filters: isZip
      ? [
          { DisplayName: "ZIP 压缩包", Pattern: "*.zip;*.zipx" },
          { DisplayName: "所有文件", Pattern: "*.*" },
        ]
      : [{ DisplayName: "所有文件", Pattern: "*.*" }],
  });
  return normalizePaths(picked)[0];
}

// 明文 ZIP 的条目列表：Precheck 和「明文条目名」下拉框都要用。
async function loadPlainZipEntries(path) {
  try {
    const info = await Call.ByName(`${ZIP_SERVICE}.Inspect`, path);
    const entries = (info && info.Entries) || [];
    state.attack.plainZipEntries = entries;

    el.attackPlainEntry.textContent = "";
    for (const entry of entries) {
      const option = document.createElement("option");
      option.value = entry.Name;
      option.textContent = `${entry.Name}（${entry.Compression}）`;
      el.attackPlainEntry.appendChild(option);
    }
    return true;
  } catch (err) {
    state.attack.plainZipEntries = [];
    el.attackPlainEntry.textContent = "";
    showPrecheckError(`这个文件不是可读的 ZIP：${describeError(err)}`);
    return false;
  }
}

async function runPrecheck() {
  const mode = currentPlainMode();
  const cipherEntry = el.attackEntry.value;

  // 来源对比只对「明文 ZIP」模式有意义：独立文件与十六进制模式没有第二个
  // ZIP，比来源无从谈起，所以其他模式要立刻收起来。
  if (mode !== "zip") hideCreatorCompare();

  if (!cipherEntry) {
    hidePrecheck();
    return;
  }

  // 十六进制模式：没有完整明文，三项比对不适用，后端直接放行并给提醒。
  if (mode === "hex") {
    const hex = hexPlaintextForSubmit();
    if (!hex) {
      hidePrecheck();
      return;
    }
    let offset = 0;
    try {
      offset = parseHexOffset(el.attackHexOffset.value);
    } catch (err) {
      showPrecheckError(describeError(err));
      return;
    }
    try {
      const res = await Call.ByName(
        `${ATTACK_SERVICE}.PrecheckHex`,
        state.path,
        cipherEntry,
        hex,
        offset,
      );
      state.attack.precheck = res || null;
      resetAttackOutputs();
      renderPrecheck(res);
    } catch (err) {
      showPrecheckError(describeError(err));
    }
    return;
  }

  const plainPath = el.attackPlainPath.value.trim();
  if (!plainPath) {
    hidePrecheck();
    return;
  }

  const plainIsZip = mode === "zip";
  if (plainIsZip) {
    // 来源对比只看两个 ZIP 的结构，不依赖「明文条目名」选没选，所以放在
    // 条目校验之前——用户刚选完文件就能看到结论。
    void runCreatorCompare(plainPath);
  }
  const plainEntry = plainIsZip ? el.attackPlainEntry.value : "";
  if (plainIsZip && !plainEntry) {
    hidePrecheck();
    return;
  }

  try {
    const res = await Call.ByName(
      `${ATTACK_SERVICE}.Precheck`,
      state.path,
      cipherEntry,
      plainPath,
      plainEntry,
      plainIsZip,
    );
    state.attack.precheck = res || null;
    resetAttackOutputs();
    renderPrecheck(res);
  } catch (err) {
    showPrecheckError(describeError(err));
  }
}

// resetAttackOutputs 清掉上一次的攻击结果：参数变了，旧密钥就不再适用。
function resetAttackOutputs() {
  state.attack.keys = "";
  clearAttackLog();
  show(el.attackLogCard, false);
  show(el.attackResult, false);
  show(el.attackFail, false);
}

// ------------------------------------------------------------ 来源对比（明文 ZIP）

// 置信度 → 界面文案。
const CREATOR_CONFIDENCE_LABELS = {
  high: "高",
  medium: "中",
  low: "低",
  unknown: "未知",
};

// 结论 → 样式类。
const CREATOR_VERDICT_CLASS = {
  same: "ok",
  differ: "warn",
  unsure: "muted",
  unknown: "muted",
};

// runCreatorCompare 识别加密包与明文 ZIP 各自由什么软件创建。
//
// 这是辅助信息：失败不影响 Precheck，也不影响「开始攻击」——所以出错时
// 只在原地留一行灰字说明，不弹错误卡片。
async function runCreatorCompare(plainPath) {
  const cipherEntry = el.attackEntry.value;
  if (!state.path || !plainPath) {
    hideCreatorCompare();
    return;
  }

  try {
    const pair = await Call.ByName(`${ATTACK_SERVICE}.DetectCreators`, state.path, plainPath);
    renderCreatorCompare(pair);
  } catch (err) {
    renderCreatorCompareNotice(`来源对比不可用：${describeError(err)}`);
  }
}

function hideCreatorCompare() {
  if (!el.attackCreator) return;
  el.attackCreator.textContent = "";
  show(el.attackCreator, false);
}

// renderCreatorCompareNotice 只显示一行灰字，用于「算不出来」的情形。
function renderCreatorCompareNotice(text) {
  if (!el.attackCreator) return;
  el.attackCreator.textContent = "";

  const head = document.createElement("div");
  head.className = "creator-head";
  head.textContent = "来源对比";

  const line = document.createElement("p");
  line.className = "creator-notice";
  line.textContent = text;

  el.attackCreator.append(head, line);
  show(el.attackCreator, true);
}

// renderCreatorCompare 画「加密文件 / 明文文件 / 结论」三段。
function renderCreatorCompare(pair) {
  if (!pair || !pair.encrypted || !pair.plain) {
    hideCreatorCompare();
    return;
  }

  el.attackCreator.textContent = "";

  const head = document.createElement("div");
  head.className = "creator-head";
  head.textContent = "来源对比";
  el.attackCreator.appendChild(head);

  const files = document.createElement("div");
  files.className = "creator-files";
  files.append(
    creatorFileBlock("加密文件", state.path, pair.encrypted),
    creatorFileBlock("明文文件", el.attackPlainPath.value.trim(), pair.plain),
  );
  el.attackCreator.appendChild(files);

  const verdict = document.createElement("p");
  verdict.className = `creator-verdict ${CREATOR_VERDICT_CLASS[pair.verdict] || "muted"}`;
  verdict.textContent = pair.message || "";
  el.attackCreator.appendChild(verdict);

  show(el.attackCreator, true);
}

// creatorFileBlock 画一个文件的识别结果与依据。
function creatorFileBlock(label, path, creator) {
  const box = document.createElement("div");
  box.className = "creator-file";

  const title = document.createElement("p");
  title.className = "creator-file-title";
  const name = document.createElement("span");
  name.className = "creator-file-name mono";
  name.textContent = baseName(path || "");
  name.title = path || "";
  title.append(document.createTextNode(`${label}：`), name);

  const result = document.createElement("p");
  result.className = "creator-file-result";
  const confidence = creator.confidence || "unknown";
  result.textContent =
    `识别结果：${creator.name || "Unknown"}` +
    `（置信度：${CREATOR_CONFIDENCE_LABELS[confidence] || confidence}）`;
  if (creator.version) {
    result.textContent += ` · version made by ${creator.version}`;
  }

  const evidence = document.createElement("p");
  evidence.className = "creator-file-evidence";
  evidence.textContent = `依据：${creator.evidence || "—"}`;

  box.append(title, result, evidence);
  return box;
}

function hidePrecheck() {
  state.attack.precheck = null;
  el.attackPrecheck.textContent = "";
  show(el.attackPrecheck, false);
  show(el.attackWarn, false);
}

function showPrecheckError(message) {
  state.attack.precheck = null;
  el.attackPrecheck.textContent = "";

  const line = document.createElement("p");
  line.className = "precheck-bad";
  line.textContent = `预检失败：${message}`;
  el.attackPrecheck.appendChild(line);

  show(el.attackPrecheck, true);
  show(el.attackWarn, true);
}

function hex8(value) {
  return (Number(value) >>> 0).toString(16).padStart(8, "0");
}

function renderPrecheck(res) {
  el.attackPrecheck.textContent = "";
  if (!res) {
    hidePrecheck();
    return;
  }

  const ok = Boolean(res.ok);

  const head = document.createElement("p");
  head.className = ok ? "precheck-ok" : "precheck-bad";
  head.textContent = ok ? "✓ 检查通过" : "⚠ 预检未通过";
  el.attackPrecheck.appendChild(head);

  const facts = document.createElement("p");
  facts.className = "precheck-facts mono";
  facts.textContent = ok
    ? `${res.cipherCompression} · CRC32 ${hex8(res.cipherCRC32)} · ${res.cipherSize} 字节`
    : `加密：${res.cipherCompression} / CRC32 ${hex8(res.cipherCRC32)} / ${res.cipherSize} 字节\n` +
      `明文：${res.plainCompression} / CRC32 ${hex8(res.plainCRC32)} / ${res.plainSize} 字节`;
  el.attackPrecheck.appendChild(facts);

  if (!ok && Array.isArray(res.issues) && res.issues.length > 0) {
    const list = document.createElement("ul");
    list.className = "precheck-issues";
    for (const issue of res.issues) {
      const item = document.createElement("li");
      item.textContent = issue;
      list.appendChild(item);
    }
    el.attackPrecheck.appendChild(list);

    const hint = document.createElement("p");
    hint.className = "muted precheck-hint";
    hint.textContent =
      "可尝试直接攻击，但成功率较低。常见原因：明文与原包由不同压缩软件生成，或压缩方式不匹配。";
    el.attackPrecheck.appendChild(hint);
  }

  // Notes 是「通过也要提醒一句」的内容：十六进制模式下没法比对三项，
  // 只能靠用户自己确认偏移和字节。
  const notes = Array.isArray(res.notes) ? res.notes : [];
  if (notes.length > 0) {
    const list = document.createElement("ul");
    list.className = "precheck-notes";
    for (const note of notes) {
      const item = document.createElement("li");
      item.textContent = note;
      list.appendChild(item);
    }
    el.attackPrecheck.appendChild(list);
  }

  show(el.attackPrecheck, true);
  show(el.attackWarn, !ok);
}

function clearAttackLog() {
  el.attackLog.textContent = "";
  el.attackLogCount.textContent = "";
  state.attack.logLines = 0;
}

// 按行数裁剪日志节点：从最早的节点开始摘，直到摘掉的文本行数达到 count。
// 按节点内的换行符计行，避免一条多行日志被当成一行少摘了。
function trimLogNodes(container, count) {
  let removed = 0;
  while (removed < count && container.firstChild) {
    const node = container.firstChild;
    const text = node.textContent || "";
    const lines = text.split("\n").length - 1;
    container.removeChild(node);
    removed += lines > 0 ? lines : 1;
  }
  return removed;
}

function appendAttackLog(line) {
  const text = String(line == null ? "" : line);
  if (!text) return;

  // 用户往上翻看历史时不要抢滚动条，只有本来就在底部才自动跟随。
  const atBottom =
    el.attackLog.scrollTop + el.attackLog.clientHeight >= el.attackLog.scrollHeight - 8;

  el.attackLog.appendChild(document.createTextNode(text + "\n"));
  state.attack.logLines += 1;

  // 超上限时一次丢掉最早的 1000 行，并且真的把 DOM 节点摘掉——
  // 只计数不清节点的话，长跑任务的 DOM 会一直涨到把界面拖死。
  if (state.attack.logLines > MAX_LOG_LINES) {
    trimLogNodes(el.attackLog, LOG_TRIM_CHUNK);
    state.attack.logLines = Math.max(0, state.attack.logLines - LOG_TRIM_CHUNK);
  }
  el.attackLogCount.textContent = `${state.attack.logLines} 行`;

  if (atBottom) el.attackLog.scrollTop = el.attackLog.scrollHeight;
}

function setAttackRunning(running) {
  state.attack.running = running;

  show(el.attackStart, !running);
  show(el.attackStop, running);
  el.attackEntry.disabled = running;
  el.attackPlainBrowse.disabled = running;
  el.attackPlainEntry.disabled = running;
  el.attackDecryptZip.disabled = running;
  el.attackDecryptEntry.disabled = running;
  el.attackOpen.disabled = running || !state.attack.available;

  for (const radio of document.querySelectorAll('input[name="attack-plain-mode"]')) {
    radio.disabled = running;
  }

  // 攻击期间不许换文件：pick / 加入批量都跟着 disabled。
  refreshControls();
}

async function startAttack() {
  if (state.attack.running) return;

  const mode = currentPlainMode();
  const cipherEntry = el.attackEntry.value;
  if (!cipherEntry) {
    setStatus("先选择目标条目", true);
    return;
  }

  // 三种明文形式最终都归一到同一份参数，hex 模式不传 plainPath。
  const payload = {
    encryptedZip: state.path,
    cipherEntry,
    plainPath: "",
    plainIsZip: false,
    plainEntry: "",
    hexPlaintext: "",
    hexOffset: 0,
  };

  if (mode === "hex") {
    const hex = hexPlaintextForSubmit();
    if (!hex) {
      setStatus("先填写十六进制明文", true);
      el.attackHexText.focus();
      return;
    }
    let offset = 0;
    try {
      offset = parseHexOffset(el.attackHexOffset.value);
    } catch (err) {
      setStatus(describeError(err), true);
      el.attackHexOffset.focus();
      return;
    }
    payload.hexPlaintext = hex;
    payload.hexOffset = offset;
  } else {
    const plainPath = el.attackPlainPath.value.trim();
    if (!plainPath) {
      setStatus("先选择明文文件", true);
      return;
    }
    const plainIsZip = mode === "zip";
    const plainEntry = plainIsZip ? el.attackPlainEntry.value : "";
    if (plainIsZip && !plainEntry) {
      setStatus("明文 ZIP 里要指定一个条目", true);
      return;
    }
    payload.plainPath = plainPath;
    payload.plainIsZip = plainIsZip;
    payload.plainEntry = plainEntry;
  }

  hideErrorCard();
  clearAttackLog();
  show(el.attackResult, false);
  show(el.attackFail, false);
  show(el.attackLogCard, true);
  setAttackRunning(true);
  setStatus("明文攻击中…");

  // 先把这次提交的参数写一行到日志里：攻击参数写错时，用户能立刻看出
  // 是偏移错了还是字节数不够，而不用去猜 bkcrack 收到了什么。
  appendAttackLog(
    mode === "hex"
      ? `[zipkit] 十六进制明文：偏移 ${payload.hexOffset}，${payload.hexPlaintext.length / 2} 字节`
      : `[zipkit] 明文文件：${payload.plainPath}${payload.plainEntry ? `（条目 ${payload.plainEntry}）` : ""}`,
  );

  try {
    await Call.ByName(`${ATTACK_SERVICE}.StartAttack`, payload);
  } catch (err) {
    setAttackRunning(false);
    appendAttackLog(`[zipkit] 启动失败：${describeError(err)}`);
    setStatus(`启动攻击失败：${describeError(err)}`, true);
    failWith("明文攻击未能启动", err);
  }
}

async function stopAttack() {
  if (!state.attack.running) return;
  el.attackStop.disabled = true;
  el.attackStop.textContent = "正在停止…";
  setStatus("正在停止明文攻击…");

  try {
    await Call.ByName(`${ATTACK_SERVICE}.StopAttack`);
  } catch (err) {
    setStatus(`停止失败：${describeError(err)}`, true);
  } finally {
    el.attackStop.disabled = false;
    el.attackStop.textContent = "停止";
  }
}

function onAttackLog(data) {
  appendAttackLog(data && data.line);
}

function onAttackDone(data) {
  setAttackRunning(false);
  const result = data || {};

  if (result.ok) {
    state.attack.keys = result.keys || "";
    state.currentFile.keys = state.attack.keys;
    el.attackKeys.textContent = state.attack.keys;
    show(el.attackResult, true);
    show(el.attackFail, false);
    appendAttackLog(`[zipkit] 攻击成功，密钥：${state.attack.keys}`);
    setStatus(`已恢复密钥：${state.attack.keys}`);
    // 结果区在日志下方，攻击一结束就把视线带过去，免得用户以为没反应。
    el.attackResult.scrollIntoView({ behavior: "smooth", block: "nearest" });
    return;
  }

  if (result.cancelled) {
    appendAttackLog("[zipkit] 已停止");
    setStatus("已停止明文攻击");
    return;
  }

  const reason = String(result.err || "未知原因");
  const headline = reason.split("\n")[0];
  el.attackFailText.textContent = headline.includes("未能恢复密钥")
    ? "未能恢复密钥"
    : `未能恢复密钥：${headline}`;
  const tail = Array.isArray(result.tail) ? result.tail : [];
  el.attackFailRaw.textContent = tail.length > 0 ? tail.join("\n") : "（没有更多输出）";
  show(el.attackFail, true);
  show(el.attackResult, false);
  appendAttackLog(`[zipkit] 攻击失败：${headline}`);
  setStatus(`明文攻击失败：${headline}`, true);
  showErrorCard("明文攻击失败", [reason, ...tail].join("\n"));
  el.attackFail.scrollIntoView({ behavior: "smooth", block: "nearest" });
}

async function copyKeys() {
  const keys = state.attack.keys;
  if (!keys) return;
  try {
    await Clipboard.SetText(keys);
    setStatus(`已复制密钥：${keys}`);
  } catch (err) {
    setStatus(`复制失败：${describeError(err)}`, true);
  }
}

// --------------------------------------------------------------- 解密操作

function siblingPath(path, suffix) {
  const cut = Math.max(path.lastIndexOf("/"), path.lastIndexOf("\\"));
  const dir = cut >= 0 ? path.slice(0, cut + 1) : "";
  const name = cut >= 0 ? path.slice(cut + 1) : path;
  const stem = name.replace(/\.[^.]+$/, "");
  return `${dir}${stem}${suffix}`;
}

function openDecryptModal() {
  if (!state.attack.keys) return;
  el.decryptOutput.value = siblingPath(state.path, "_解密.zip");
  el.decryptPassword.value = "";
  show(el.decryptModal, true);
  el.decryptOutput.focus();
  el.decryptOutput.select();
}

function hideDecryptModal() {
  show(el.decryptModal, false);
}

async function browseDecryptOutput() {
  try {
    const path = await pickSavePath("选择输出 ZIP 的位置", baseName(el.decryptOutput.value) || "解密.zip", [
      { DisplayName: "ZIP 压缩包", Pattern: "*.zip" },
    ]);
    if (!path) return;
    el.decryptOutput.value = path;
  } catch (err) {
    setStatus(`选择输出路径失败：${describeError(err)}`, true);
  }
}

// pickSavePath 打开「另存为」对话框。同样留了 __ZIPKIT_TEST_SAVE__ 逃生口。
async function pickSavePath(title, filename, filters) {
  if (window.__ZIPKIT_TEST_SAVE__) {
    return String(window.__ZIPKIT_TEST_SAVE__);
  }
  const picked = await Dialogs.SaveFile({ Title: title, Filename: filename, Filters: filters });
  return normalizePaths(picked)[0];
}

async function confirmDecrypt() {
  const output = el.decryptOutput.value.trim();
  if (!output) {
    setStatus("先填写输出路径", true);
    return;
  }
  if (!state.attack.keys) return;

  el.decryptConfirm.disabled = true;
  el.decryptConfirm.textContent = "解密中…";
  setStatus("正在解密整个包…");

  try {
    await Call.ByName(
      `${ATTACK_SERVICE}.DecryptWithKeys`,
      state.path,
      state.attack.keys,
      output,
      el.decryptPassword.value,
    );
    hideDecryptModal();
    appendAttackLog(`[zipkit] 已生成 ${baseName(output)}`);
    setStatus(`已生成 ${baseName(output)}`);
  } catch (err) {
    setStatus(`解密失败：${describeError(err)}`, true);
  } finally {
    el.decryptConfirm.disabled = false;
    el.decryptConfirm.textContent = "开始解密";
  }
}

async function decryptEntry() {
  const entryName = el.attackEntry.value;
  if (!state.attack.keys || !entryName) return;

  let output;
  try {
    output = await pickSavePath("保存解出的条目", baseName(entryName), [
      { DisplayName: "所有文件", Pattern: "*.*" },
    ]);
  } catch (err) {
    setStatus(`选择保存位置失败：${describeError(err)}`, true);
    return;
  }
  if (!output) return;

  el.attackDecryptEntry.disabled = true;
  el.attackDecryptEntry.textContent = "解出中…";
  setStatus(`正在解出 ${baseName(entryName)}…`);

  try {
    await Call.ByName(
      `${ATTACK_SERVICE}.DecryptEntryWithKeys`,
      state.path,
      state.attack.keys,
      entryName,
      output,
    );
    appendAttackLog(`[zipkit] 已生成 ${baseName(output)}`);
    setStatus(`已生成 ${baseName(output)}`);
  } catch (err) {
    setStatus(`解出条目失败：${describeError(err)}`, true);
  } finally {
    el.attackDecryptEntry.disabled = false;
    el.attackDecryptEntry.textContent = "只解出目标条目";
  }
}

// --------------------------------------------------------------- bkcrack 检测

async function checkBkcrack() {
  try {
    const status = await Call.ByName(`${ATTACK_SERVICE}.Bkcrack`);
    applyBkcrackStatus(status);
  } catch (err) {
    applyBkcrackStatus({ available: false });
  }
}

function applyBkcrackStatus(status) {
  const available = Boolean(status && status.available);
  state.attack.available = available;
  state.attack.bkcrackPath = (status && status.path) || "";

  show(el.bkcrackBanner, !available);
  if (!available) {
    el.bkcrackInput.value = state.attack.bkcrackPath;
  }

  // 卡片已经渲染过的话，按钮的可用状态要跟着变。
  if (state.info) {
    renderAttackCard(state.info);
    // 推荐优先级决定「哪张卡该露脸」，重渲染后要再收一次。
    applyRecommendationPriority();
  }
}

async function saveBkcrackPath() {
  const value = el.bkcrackInput.value.trim();
  try {
    const status = await Call.ByName(`${ATTACK_SERVICE}.SetBkcrackPath`, value);
    applyBkcrackStatus(status);
    if (status && status.available) {
      setStatus(`bkcrack 已就绪：${status.path}`);
    } else {
      setStatus("这个路径不能用，仍未找到 bkcrack", true);
    }
  } catch (err) {
    setStatus(`保存 bkcrack 路径失败：${describeError(err)}`, true);
  }
}

async function browseBkcrack() {
  try {
    const picked = await Dialogs.OpenFile({
      Title: "选择 bkcrack 可执行文件",
      CanChooseFiles: true,
      CanChooseDirectories: false,
      AllowsMultipleSelection: false,
      Filters: [
        { DisplayName: "可执行文件", Pattern: "*.exe;bkcrack" },
        { DisplayName: "所有文件", Pattern: "*.*" },
      ],
    });
    const path = normalizePaths(picked)[0];
    if (!path) return;
    el.bkcrackInput.value = path;
    await saveBkcrackPath();
  } catch (err) {
    setStatus(`选择 bkcrack 失败：${describeError(err)}`, true);
  }
}

// ------------------------------------------------------- GPU 恢复（hashcat）
//
// 与明文攻击并列的另一条路：ZipCrypto 可以靠 bkcrack 恢复密钥，AES / RAR5 / 7z
// 只能把哈希交给 hashcat 跑 GPU。两者互斥——一个条目要么是 ZipCrypto，
// 要么是 AES，所以同一张卡片不会同时给出两个入口。

const GPU_HASH_PREVIEW = 64;

// 暴力策略的默认长度范围 1–8：短密码先试，8 位是纯数字/小字符集还能跑完的量级。
// 上下限与另外两处一样受 readLengthRange 约束（1–12）。
const GPU_MIN_DEFAULT = 1;
const GPU_MAX_DEFAULT = 8;

function resetGpuState() {
  const g = state.gpu;
  g.open = false;
  g.result = null;
  g.hashExpanded = false;
  g.logLines = 0;
  g.password = "";
  g.johnKind = "";
  g.entries = [];
  // manual 记录「GPU 卡片是被明文攻击卡片的第三个按钮临时展开的」。
  g.manual = false;

  show(el.gpuCard, false);
  show(el.gpuPanel, false);
  show(el.gpuLogCard, false);
  show(el.gpuResult, false);
  show(el.gpuFail, false);
  show(el.gpuProgressCard, false);
  show(el.gpuJohnHint, false);
  show(el.gpuEntryField, false);
  el.gpuEntry.textContent = "";
  el.gpuEntry.value = "";

  el.gpuHash.textContent = "";
  el.gpuHash.classList.remove("expanded");
  show(el.gpuHashToggle, false);
  clearGpuLog();
  el.gpuPassword.textContent = "";
  el.gpuFailText.textContent = "";
  el.gpuFailRaw.textContent = "";
  resetGpuProgress();
  el.gpuOpen.textContent = "显卡加速破解";
  setGpuRunning(false);
}

function resetGpuProgress() {
  el.gpuProgressFill.style.width = "0%";
  el.gpuStatus.textContent = "—";
  el.gpuSpeed.textContent = "—";
  el.gpuProgress.textContent = "—";
  el.gpuEta.textContent = "—";
}

// renderGpuCard 按侦察结果决定这张卡片显不显示、标题写什么。
//   - 全 AES          → 「需要 GPU 加速恢复」
//   - AES + ZipCrypto → 「部分条目需要 GPU 恢复」，另一部分走上面的明文攻击
//   - RAR5 / 7z       → 无法明文攻击，只能提哈希
function renderGpuCard(info) {
  const kind = state.archiveKind;
  const entries = (info && info.Entries) || [];
  const aes = entries.filter((e) => isAesEntry(e));
  const zipcrypto = entries.filter((e) => e.EncryptionType === "ZipCrypto");

  // 下拉框里列的是「hashcat 能提哈希的条目」：AES 和 ZipCrypto 都算——混合
  // 文件里两者都在候选里，让用户自己挑。顺序沿用归档里的条目顺序，不重排。
  // RAR5 / 7z 的哈希是整包级的，没有条目可选，所以留空。
  const selectable =
    kind === "rar" || kind === "7z"
      ? []
      : entries.filter((e) => isAesEntry(e) || e.EncryptionType === "ZipCrypto");
  state.gpu.entries = selectable;
  fillGpuEntries(selectable);

  if (kind === "rar" || kind === "7z") {
    const label = kind === "rar" ? "RAR5" : "7z";
    el.gpuTitle.textContent = `需要 GPU 加速恢复（${label}）`;
    el.gpuSub.textContent = `${label} 不支持明文攻击。提取哈希后交给 hashcat 做字典 / 掩码 / 暴力恢复。`;
    state.gpu.johnKind = kind === "rar" ? "rar2john" : "7z2john";
    show(el.gpuCard, true);
    applyGpuAvailability();
    return;
  }

  if (aes.length === 0) {
    show(el.gpuCard, false);
    closeGpuPanel();
    return;
  }

  state.gpu.johnKind = "";

  if (zipcrypto.length > 0) {
    el.gpuTitle.textContent = "部分条目需要 GPU 恢复";
    el.gpuSub.textContent = `${aes.length} 个 AES 条目只能交给 hashcat；另外 ${zipcrypto.length} 个 ZipCrypto 条目可以走上面的明文攻击。`;
  } else {
    el.gpuTitle.textContent = "需要 GPU 加速恢复";
    el.gpuSub.textContent = `共 ${aes.length} 个 AES 条目（${summarizeAes(aes)}）。提取 $zip2$ 哈希后交给 hashcat 做字典 / 掩码 / 暴力恢复。`;
  }

  show(el.gpuCard, true);
  applyGpuAvailability();
}

function isAesEntry(entry) {
  return typeof entry.EncryptionType === "string" && entry.EncryptionType.startsWith("AES-");
}

function summarizeAes(entries) {
  const seen = [];
  for (const entry of entries) {
    if (!seen.includes(entry.EncryptionType)) seen.push(entry.EncryptionType);
  }
  return seen.join(" / ");
}

// fillGpuEntries 填充「目标条目」下拉框。
//
// 只有一个候选时整个字段收起来——多一次点击没有任何收益。混合文件（既有
// AES 又有 ZipCrypto）才会出现多个候选，这也是「点显卡加速破解让用户用下拉
// 框选择条目」那条要求的落点。
function fillGpuEntries(entries) {
  const previous = el.gpuEntry.value;
  el.gpuEntry.textContent = "";

  for (const entry of entries) {
    const option = document.createElement("option");
    option.value = entry.Name;
    option.textContent = `${entry.Name}（${entry.EncryptionType}，${formatBytes(entry.UncompressedSize)}）`;
    el.gpuEntry.appendChild(option);
  }
  // 保留上次选的条目；它不在新列表里（或本来没选）时落到第一个。
  const keep = entries.some((e) => e.Name === previous) ? previous : entries[0]?.Name || "";
  el.gpuEntry.value = keep;
  show(el.gpuEntryField, entries.length > 1);
}

// currentGpuEntry 返回下拉框当前选中的条目名；没有下拉框时返回空串，
// 后端会自己挑第一个能提哈希的条目。
function currentGpuEntry() {
  if (!el.gpuEntry || el.gpuEntryField.classList.contains("hidden")) return "";
  return el.gpuEntry.value || "";
}

// applyGpuAvailability 统一处理「缺 hashcat / 缺 john」时的按钮与提示。
//
// 两个入口共用这一份判断：GPU 卡片上的 #gpu-open，以及明文攻击卡片上的
// #attack-gpu。文案统一成「显卡加速破解」，但 tooltip 里必须出现 hashcat
// ——用户要能对上设置页里那个 hashcat 路径输入框。
const GPU_TOOLTIP =
  "使用 hashcat 调用 GPU 加速破解，适合快速弱密码检测未命中的情况。需要先在设置中配置 hashcat 路径。";
const GPU_MISSING_HINT = "未找到 hashcat，请在设置中指定路径";
const GPU_TOOLTIP_NO_HASHCAT = `${GPU_TOOLTIP}（当前未检测到 hashcat）`;

function applyGpuAvailability() {
  const g = state.gpu;
  const needJohn = g.johnKind !== "";
  const johnReady = needJohn
    ? g.johnKind === "rar2john"
      ? g.rar2john
      : g.sevenZip2john
    : true;

  const blocked = !g.available || !johnReady;
  el.gpuOpen.disabled = blocked || g.running;

  show(el.gpuDisabledHint, !g.available);
  if (!g.available) {
    el.gpuDisabledHint.textContent = GPU_MISSING_HINT;
    el.gpuOpen.title = GPU_TOOLTIP_NO_HASHCAT;
  } else if (!johnReady) {
    el.gpuOpen.title = `未找到 ${g.johnKind}，请安装 john 或在设置中指定路径`;
  } else {
    el.gpuOpen.title = GPU_TOOLTIP;
  }

  // 明文攻击卡片上的第三个按钮：缺 hashcat 时同样禁用，但 tooltip 不能没有
  // ——禁用状态下悬停仍要能看到「为什么不能点」。
  if (el.attackGpu) {
    const attackBlocked = !g.available || g.running;
    el.attackGpu.disabled = attackBlocked;
    el.attackGpu.title = g.available ? GPU_TOOLTIP : GPU_TOOLTIP_NO_HASHCAT;
  }

  // RAR5 / 7z 缺 john 工具时，直接给出可填路径的输入框。
  show(el.gpuJohnHint, needJohn && !johnReady);
  if (needJohn && !johnReady) {
    el.gpuJohnText.textContent = `未找到 ${g.johnKind}，请安装 john 或在下面指定路径。`;
    el.gpuJohnInput.placeholder = g.johnKind === "rar2john" ? "C:\\john\\run\\rar2john.exe" : "C:\\john\\run\\7z2john.pl";
    if (!el.gpuJohnInput.value) {
      el.gpuJohnInput.value = g.johnKind === "rar2john" ? g.rar2johnPath : g.sevenZip2johnPath;
    }
  }
}

function toggleGpuPanel() {
  if (state.gpu.open) {
    closeGpuPanel();
    return;
  }
  void openGpuPanel();
}

// openGpuFromAttackCard 是明文攻击卡片上第三个按钮「显卡加速破解」的行为。
//
// ZipCrypto 文件本来不显示 GPU 卡片（推荐优先级把那张卡留给了 AES / RAR5 /
// 7z），但三个按钮要平铺在同一张卡上，所以这里把 GPU 卡片临时展开再开面板。
// 「临时」记在 state.gpu.manual 上：收起面板时一起收回去，不留空卡片。
async function openGpuFromAttackCard() {
  const g = state.gpu;
  if (g.running) return;

  if (el.gpuCard.classList.contains("hidden")) {
    el.gpuTitle.textContent = "显卡加速破解（ZipCrypto）";
    el.gpuSub.textContent =
      "快速弱密码检测没命中时，把 ZipCrypto 哈希交给 hashcat 跑 GPU。";
    show(el.gpuCard, true);
    g.manual = true;
    applyGpuAvailability();
  }
  if (g.open) {
    closeGpuPanel();
    return;
  }
  await openGpuPanel();
}

// openGpuPanel 提取哈希并展开面板。提取失败时只在面板里报错，不弹窗。
async function openGpuPanel() {
  const g = state.gpu;
  if (g.running) return;

  state.gpu.open = true;
  show(el.gpuPanel, true);
  el.gpuOpen.textContent = "收起破解面板";
  show(el.gpuFail, false);
  show(el.gpuResult, false);
  updateDropHint();

  await extractGpuHash();
  el.gpuStart.focus();
}

function closeGpuPanel() {
  state.gpu.open = false;
  show(el.gpuPanel, false);
  if (state.gpu.manual) {
    // 从明文攻击卡片临时展开的那张卡：面板收起，卡片也跟着收起。
    state.gpu.manual = false;
    show(el.gpuCard, false);
  }
  updateDropHint();
  if (el.gpuOpen && !state.gpu.running) {
    el.gpuOpen.textContent = "显卡加速破解";
  }
}

// extractGpuHash 让后端按归档类型提取哈希（ZIP 自实现，RAR5/7z 走 john）。
//
// entryName 为空时由后端自己挑：ZIP 优先 AES，没有 AES 再退到 ZipCrypto。
async function extractGpuHash(entryName) {
  const target = entryName == null ? currentGpuEntry() : entryName;
  setStatus("提取哈希中…");
  try {
    const res = await Call.ByName(`${GPU_SERVICE}.Extract`, state.path, target);
    state.gpu.result = res || null;
    renderGpuHash(res);
    setStatus(`已提取 ${res.format} 哈希（hashcat -m ${res.mode}）`);
    return res;
  } catch (err) {
    state.gpu.result = null;
    el.gpuHash.textContent = "";
    show(el.gpuHashToggle, false);
    el.gpuFailText.textContent = `提取哈希失败：${describeError(err)}`;
    el.gpuFailRaw.textContent = "";
    show(el.gpuFail, true);
    setStatus(`提取哈希失败：${describeError(err)}`, true);
    return null;
  }
}

function renderGpuHash(res) {
  const hash = (res && res.hash) || "";
  state.gpu.hashExpanded = false;
  el.gpuHash.classList.remove("expanded");

  if (!hash) {
    el.gpuHash.textContent = "（空）";
    show(el.gpuHashToggle, false);
    return;
  }
  el.gpuHash.textContent =
    hash.length > GPU_HASH_PREVIEW ? `${hash.slice(0, GPU_HASH_PREVIEW)}…` : hash;
  el.gpuHash.title = `hashcat -m ${res.mode} ${res.format}`;
  show(el.gpuHashToggle, hash.length > GPU_HASH_PREVIEW);
  el.gpuHashToggle.textContent = "展开";
}

function toggleGpuHash() {
  const res = state.gpu.result;
  if (!res || !res.hash) return;
  state.gpu.hashExpanded = !state.gpu.hashExpanded;
  el.gpuHash.classList.toggle("expanded", state.gpu.hashExpanded);
  el.gpuHash.textContent = state.gpu.hashExpanded
    ? res.hash
    : `${res.hash.slice(0, GPU_HASH_PREVIEW)}…`;
  el.gpuHashToggle.textContent = state.gpu.hashExpanded ? "收起" : "展开";
}

// toggleMaskHelp 就地展开/收起掩码语法说明。不弹模态框，也不打断输入。
function toggleMaskHelp() {
  state.maskHelpOpen = !state.maskHelpOpen;
  applyMaskHelp();
}

// applyMaskHelp 把状态同步到界面上。打开面板时把焦点留在按钮上，
// 用户按 Tab 能直接进到输入框。
//
// 面板展开时整个掩码字段横跨整行：对照表放在半列里太挤，两列的宽度
// 正好够「占位符 / 含义 / 示例」三栏排开。
function applyMaskHelp() {
  const open = Boolean(state.maskHelpOpen);
  show(el.maskHelp, open);
  el.gpuMaskField.classList.toggle("mask-open", open);
  el.gpuMaskHelpBtn.setAttribute("aria-expanded", open ? "true" : "false");
}

function currentGpuStrategy() {
  const picked = document.querySelector('input[name="gpu-strategy"]:checked');
  return picked ? picked.value : "mask";
}

// onGpuStrategyChange 按策略切换字段显隐。
//
// 长度范围只在「暴力」下出现：字典的词表本身决定长度，掩码的位数也写在掩码里，
// 两者都不需要额外输入；掩码旁边另有一句指路说明，避免用户到处找长度设置。
function onGpuStrategyChange() {
  const kind = currentGpuStrategy();
  show(el.gpuWordlistField, kind === "dictionary");
  show(el.gpuMaskField, kind === "mask");
  show(el.gpuCharsetField, kind === "bruteforce");
  show(el.gpuLenField, kind === "bruteforce");
}

// buildGpuStrategy 把界面上的选择拼成后端 hashcat.Strategy。
// 字段名与 Go 结构体的 json tag 对齐：minLen / maxLen（不是 length）。
function buildGpuStrategy() {
  const kind = currentGpuStrategy();
  if (kind === "dictionary") {
    const wordlist = el.gpuWordlist.value.trim();
    if (!wordlist) throw new Error("先选择字典文件");
    return { kind, wordlist, mask: "", charset: "", minLen: 0, maxLen: 0 };
  }
  if (kind === "bruteforce") {
    const charset = el.gpuCharset.value.trim();
    if (!charset) throw new Error("先填写字符集");
    // 前端先按 1–12 校正一次；后端 hashcat.bruteforceRange 还会再校验一次，
    // 两边都不信任对方的输入。
    const { minLen, maxLen } = readLengthRange(
      el.gpuMinLen,
      el.gpuMaxLen,
      GPU_MIN_DEFAULT,
      GPU_MAX_DEFAULT,
    );
    if (minLen > maxLen) throw new Error("最小位数不能大于最大位数");
    return { kind, wordlist: "", mask: "", charset, minLen, maxLen };
  }
  const mask = el.gpuMask.value.trim();
  if (!mask) throw new Error("先填写掩码");
  return { kind, wordlist: "", mask, charset: "", minLen: 0, maxLen: 0 };
}

async function startGpuRun() {
  if (state.gpu.running) return;

  const res = state.gpu.result || (await extractGpuHash());
  if (!res) return;

  let strategy;
  try {
    strategy = buildGpuStrategy();
  } catch (err) {
    setStatus(describeError(err), true);
    return;
  }

  hideErrorCard();
  clearGpuLog();
  show(el.gpuResult, false);
  show(el.gpuFail, false);
  show(el.gpuLogCard, true);
  show(el.gpuProgressCard, true);
  resetGpuProgress();
  setGpuRunning(true);
  setStatus("hashcat 运行中…");

  try {
    await Call.ByName(`${GPU_SERVICE}.Start`, res.hash, res.mode, strategy);
  } catch (err) {
    setGpuRunning(false);
    appendGpuLog(`[zipkit] 启动失败：${describeError(err)}`);
    el.gpuFailText.textContent = `启动失败：${describeError(err)}`;
    el.gpuFailRaw.textContent = "";
    show(el.gpuFail, true);
    setStatus(`启动 hashcat 失败：${describeError(err)}`, true);
  }
}

async function stopGpuRun() {
  if (!state.gpu.running) return;
  el.gpuStop.disabled = true;
  el.gpuStop.textContent = "正在停止…";
  setStatus("正在停止 hashcat…");

  try {
    await Call.ByName(`${GPU_SERVICE}.StopHashcat`);
  } catch (err) {
    setStatus(`停止失败：${describeError(err)}`, true);
  } finally {
    el.gpuStop.disabled = false;
    el.gpuStop.textContent = "停止";
  }
}

function setGpuRunning(running) {
  state.gpu.running = running;

  show(el.gpuStart, !running);
  show(el.gpuStop, running);
  el.gpuOpen.disabled = running || !state.gpu.available;
  if (el.attackGpu) el.attackGpu.disabled = running || !state.gpu.available;
  el.gpuEntry.disabled = running;
  el.gpuMask.disabled = running;
  el.gpuCharset.disabled = running;
  el.gpuMinLen.disabled = running;
  el.gpuMaxLen.disabled = running;
  el.gpuWordlist.disabled = running;
  el.gpuWordlistBrowse.disabled = running;
  el.gpuHashToggle.disabled = running;
  el.gpuDecrypt.disabled = running;

  for (const radio of document.querySelectorAll('input[name="gpu-strategy"]')) {
    radio.disabled = running;
  }

  refreshControls();
}

function clearGpuLog() {
  el.gpuLog.textContent = "";
  el.gpuLogCount.textContent = "";
  state.gpu.logLines = 0;
}

function appendGpuLog(line) {
  const text = String(line == null ? "" : line);
  if (!text) return;

  const atBottom =
    el.gpuLog.scrollTop + el.gpuLog.clientHeight >= el.gpuLog.scrollHeight - 8;

  el.gpuLog.appendChild(document.createTextNode(text + "\n"));
  state.gpu.logLines += 1;

  if (state.gpu.logLines > MAX_LOG_LINES) {
    trimLogNodes(el.gpuLog, LOG_TRIM_CHUNK);
    state.gpu.logLines = Math.max(0, state.gpu.logLines - LOG_TRIM_CHUNK);
  }
  el.gpuLogCount.textContent = `${state.gpu.logLines} 行`;

  if (atBottom) el.gpuLog.scrollTop = el.gpuLog.scrollHeight;
}

function onGpuProgress(data) {
  if (!data) return;
  if (data.line) appendGpuLog(data.line);
  if (!data.status && !data.speed && !data.progress) return;

  if (data.status) el.gpuStatus.textContent = translateStatus(data.status);
  if (data.speed) el.gpuSpeed.textContent = data.speed;
  if (data.progress) {
    el.gpuProgress.textContent = data.progress;
    const percent = Number.parseFloat(data.progress);
    if (Number.isFinite(percent)) {
      el.gpuProgressFill.style.width = `${Math.max(0, Math.min(100, percent))}%`;
    }
  }
  if (data.eta) el.gpuEta.textContent = data.eta;
}

function translateStatus(status) {
  switch (status) {
    case "Running":
      return "运行中";
    case "Cracked":
      return "已破解";
    case "Exhausted":
      return "已穷尽";
    case "Aborted":
      return "已中止";
    case "Paused":
      return "已暂停";
    default:
      return status;
  }
}

function onGpuDone(data) {
  setGpuRunning(false);
  const result = data || {};

  if (result.ok) {
    state.gpu.password = result.password || "";
    // 成功的密码统一进 currentFile，后面「解密文件」只认这一份。
    state.currentFile.password = state.gpu.password;
    state.currentFile.source = "gpu";
    el.gpuPassword.textContent = state.gpu.password;
    show(el.gpuResult, true);
    show(el.gpuFail, false);
    el.gpuProgressFill.style.width = "100%";
    el.gpuStatus.textContent = "已破解";
    appendGpuLog(`[zipkit] 已恢复密码：${state.gpu.password}`);
    setStatus(`已恢复密码：${state.gpu.password}`);
    el.gpuResult.scrollIntoView({ behavior: "smooth", block: "nearest" });
    return;
  }

  if (result.cancelled) {
    el.gpuStatus.textContent = "已中止";
    appendGpuLog("[zipkit] 已停止");
    setStatus("已停止 hashcat");
    return;
  }

  const reason = String(result.err || "未知原因");
  // 失败详情是多行的（工具名 + 退出码 + 前几行输出），标题只留第一行。
  const reasonLines = reason
    .split("\n")
    .map((line) => line.trim())
    .filter(Boolean);
  const headline = reasonLines[0] || "未知原因";
  el.gpuFailText.textContent = headline.includes("未恢复密码")
    ? "未恢复密码"
    : `未恢复密码：${headline}`;
  // reason 里已经附了几行输出，tail 是同一份输出另一遍挑出来的，重复的行不再显示。
  const shown = new Set(reasonLines);
  const tail = (Array.isArray(result.tail) ? result.tail : []).filter(
    (line) => !shown.has(String(line).trim()),
  );
  const detail = [...reasonLines.slice(1), ...tail];
  el.gpuFailRaw.textContent = detail.length > 0 ? detail.join("\n") : "（没有更多输出）";
  show(el.gpuFail, true);
  show(el.gpuResult, false);
  el.gpuStatus.textContent = "已结束";
  appendGpuLog(`[zipkit] 未恢复密码：${headline}`);
  setStatus(`未恢复密码：${headline}`, true);
  showErrorCard("GPU 恢复失败", [reason, ...tail].join("\n"));
  el.gpuFail.scrollIntoView({ behavior: "smooth", block: "nearest" });
}

async function copyGpuPassword() {
  const password = state.gpu.password;
  if (!password) return;
  try {
    await Clipboard.SetText(password);
    setStatus(`已复制密码：${password}`);
  } catch (err) {
    setStatus(`复制失败：${describeError(err)}`, true);
  }
}

// decryptWithPassword 走统一解密入口，密码来自 currentFile。
async function decryptWithPassword() {
  if (!state.currentFile.password && state.gpu.password) {
    state.currentFile.password = state.gpu.password;
    state.currentFile.source = "gpu";
  }
  el.gpuDecrypt.disabled = true;
  try {
    await decryptCurrentFile();
  } finally {
    el.gpuDecrypt.disabled = false;
  }
}

async function browseGpuWordlist() {
  try {
    const picked = await Dialogs.OpenFile({
      Title: "选择字典文件",
      CanChooseFiles: true,
      CanChooseDirectories: false,
      AllowsMultipleSelection: false,
      Filters: [
        { DisplayName: "词表文件", Pattern: "*.txt;*.dict;*.lst" },
        { DisplayName: "所有文件", Pattern: "*.*" },
      ],
    });
    const path = normalizePaths(picked)[0];
    if (!path) return;
    el.gpuWordlist.value = path;
  } catch (err) {
    setStatus(`选择字典失败：${describeError(err)}`, true);
  }
}

// ------------------------------------------------------------ hashcat 检测

async function checkHashcat() {
  try {
    const status = await Call.ByName(`${GPU_SERVICE}.Tools`);
    applyHashcatTools(status);
  } catch (err) {
    applyHashcatTools(null);
  }
}

function applyHashcatTools(status) {
  const tools = status || {};
  const hashcat = tools.hashcat || {};
  const rar2john = tools.rar2john || {};
  const sevenZip2John = tools.sevenZip2John || {};

  state.gpu.available = Boolean(hashcat.available);
  state.gpu.hashcatPath = hashcat.path || "";
  state.gpu.rar2john = Boolean(rar2john.available);
  state.gpu.rar2johnPath = rar2john.path || "";
  state.gpu.sevenZip2john = Boolean(sevenZip2John.available);
  state.gpu.sevenZip2johnPath = sevenZip2John.path || "";

  show(el.hashcatBanner, !state.gpu.available);
  if (!state.gpu.available) {
    el.hashcatInput.value = state.gpu.hashcatPath;
  }

  // 卡片已经渲染过的话，按钮的可用状态要跟着变。
  if (el.gpuCard && (state.info || state.archiveKind)) {
    renderGpuCard(state.info);
    applyRecommendationPriority();
  }
}

async function saveHashcatPath() {
  const value = el.hashcatInput.value.trim();
  try {
    const status = await Call.ByName(`${GPU_SERVICE}.SetToolPath`, "hashcat", value);
    applyHashcatTools(status);
    if (status && status.hashcat && status.hashcat.available) {
      setStatus(`hashcat 已就绪：${status.hashcat.path}`);
    } else {
      setStatus("这个路径不能用，仍未找到 hashcat", true);
    }
  } catch (err) {
    setStatus(`保存 hashcat 路径失败：${describeError(err)}`, true);
  }
}

async function browseHashcat() {
  try {
    const picked = await Dialogs.OpenFile({
      Title: "选择 hashcat 可执行文件",
      CanChooseFiles: true,
      CanChooseDirectories: false,
      AllowsMultipleSelection: false,
      Filters: [
        { DisplayName: "可执行文件", Pattern: "*.exe;hashcat" },
        { DisplayName: "所有文件", Pattern: "*.*" },
      ],
    });
    const path = normalizePaths(picked)[0];
    if (!path) return;
    el.hashcatInput.value = path;
    await saveHashcatPath();
  } catch (err) {
    setStatus(`选择 hashcat 失败：${describeError(err)}`, true);
  }
}

// ------------------------------------------------------------ john 工具路径

async function saveJohnPath() {
  const kind = state.gpu.johnKind;
  if (!kind) return;

  const value = el.gpuJohnInput.value.trim();
  try {
    const status = await Call.ByName(`${GPU_SERVICE}.SetToolPath`, kind, value);
    applyHashcatTools(status);
    const tool = kind === "rar2john" ? status.rar2john : status.sevenZip2John;
    if (tool && tool.available) {
      setStatus(`${kind} 已就绪：${tool.path}`);
      await extractGpuHash();
    } else {
      setStatus("这个路径不能用，仍未找到 " + kind, true);
    }
  } catch (err) {
    setStatus(`保存 ${kind} 路径失败：${describeError(err)}`, true);
  }
}

async function browseJohnPath() {
  const kind = state.gpu.johnKind;
  if (!kind) return;

  try {
    const picked = await Dialogs.OpenFile({
      Title: `选择 ${kind}`,
      CanChooseFiles: true,
      CanChooseDirectories: false,
      AllowsMultipleSelection: false,
      Filters: [
        { DisplayName: "可执行文件 / 脚本", Pattern: "*.exe;*.pl;*.py;rar2john;7z2john" },
        { DisplayName: "所有文件", Pattern: "*.*" },
      ],
    });
    const path = normalizePaths(picked)[0];
    if (!path) return;
    el.gpuJohnInput.value = path;
    await saveJohnPath();
  } catch (err) {
    setStatus(`选择 ${kind} 失败：${describeError(err)}`, true);
  }
}

// ------------------------------------------------------------------ 设置面板

// 工具种类 → 文件选择对话框的过滤器。
const TOOL_FILTERS = {
  sevenzip: [{ DisplayName: "7z 可执行文件", Pattern: "7z.exe;7za.exe;7zz" }, { DisplayName: "所有文件", Pattern: "*.*" }],
  bkcrack: [{ DisplayName: "bkcrack 可执行文件", Pattern: "bkcrack.exe;bkcrack" }, { DisplayName: "所有文件", Pattern: "*.*" }],
  hashcat: [{ DisplayName: "hashcat 可执行文件", Pattern: "hashcat.exe;hashcat" }, { DisplayName: "所有文件", Pattern: "*.*" }],
  rar2john: [{ DisplayName: "rar2john", Pattern: "rar2john.exe;rar2john;*.py;*.pl" }, { DisplayName: "所有文件", Pattern: "*.*" }],
  "7z2john": [{ DisplayName: "7z2john", Pattern: "7z2john.pl;7z2john.py;7z2john.exe" }, { DisplayName: "所有文件", Pattern: "*.*" }],
  "7z2hashcat": [{ DisplayName: "7z2hashcat", Pattern: "7z2hashcat.pl;7z2hashcat.exe;7z2hashcat" }, { DisplayName: "所有文件", Pattern: "*.*" }],
  interpreter: [{ DisplayName: "解释器", Pattern: "perl.exe;python.exe;python3.exe;perl;python3;python" }, { DisplayName: "所有文件", Pattern: "*.*" }],
};

async function openSettings() {
  state.settings.open = true;
  show(el.settingsModal, true);
  el.settingsTools.textContent = "";
  el.settingsPath.textContent = "正在检测外部工具…";
  try {
    const snapshot = await Call.ByName(`${SETTINGS_SERVICE}.Snapshot`);
    renderSettings(snapshot);
  } catch (err) {
    failWith("读取设置失败", err);
    el.settingsPath.textContent = "";
  }
}

function closeSettings() {
  state.settings.open = false;
  show(el.settingsModal, false);
}

function renderSettings(snapshot) {
  if (!snapshot) return;
  state.settings.snapshot = snapshot;
  state.settings.tools = Array.isArray(snapshot.tools) ? snapshot.tools : [];
  state.settings.defaultExportDir = snapshot.defaultExportDir || "";

  el.settingsPath.textContent = snapshot.configPath
    ? `配置文件：${snapshot.configPath}`
    : "";
  el.settingsPath.title = snapshot.configPath || "";

  el.settingsTools.textContent = "";
  for (const tool of state.settings.tools) {
    el.settingsTools.appendChild(renderToolRow(tool));
  }

  const max = Math.max(1, snapshot.numCPU || 1);
  el.settingsBatchConcurrency.max = String(max);
  el.settingsBatchConcurrency.value = String(snapshot.batchConcurrency || max);
  el.settingsBatchHint.textContent = `1–${max}，本机 ${max} 核；默认 ${Math.max(2, max - 1)}`;

  el.settingsUnzipConcurrency.value = String(snapshot.unzipConcurrency || 3);
  el.settingsExportDir.value = snapshot.defaultExportDir || "";

  renderAbout(snapshot);

  // 工具状态变了，各功能入口的可用性也要跟着变。
  syncAvailabilityFromSettings();
}

// QR_IMAGES 是赞助二维码的静态资源。前端本地文件，不联网。
const QR_IMAGES = {
  alipay: "/assets/alipay.png",
  wechat: "/assets/wechat.png",
  paypal: "/assets/paypal.png",
};

// renderAbout 填充设置页底部的「关于与赞助」区块。
function renderAbout(snapshot) {
  el.aboutVersion.textContent = snapshot.version ? `v${snapshot.version}` : "";

  const builtin = Array.isArray(snapshot.builtin) ? snapshot.builtin : [];
  const ready = builtin.filter((item) => item.builtin);
  if (ready.length === 0) {
    el.aboutBuiltin.textContent = "无（需要手动配置工具路径）";
  } else {
    el.aboutBuiltin.textContent = ready
      .map((item) => `${BUILTIN_LABELS[item.kind] || item.kind} ${item.version}`)
      .join(" · ");
    el.aboutBuiltin.title = snapshot.builtinDir || "";
  }

  const err = snapshot.builtinError || "";
  show(el.aboutBuiltinError, err !== "");
  el.aboutBuiltinError.textContent = err ? `内置工具释放失败：${err}` : "";
}

// BUILTIN_LABELS 让「关于」里的工具名和设置页保持一致。
const BUILTIN_LABELS = {
  bkcrack: "bkcrack",
  sevenzip: "7-Zip",
  rar2john: "rar2john",
  "7z2john": "7z2john",
};

// showSponsorQr 显示某个收款码；传空则收起。同时只显示一个。
function showSponsorQr(kind) {
  const src = QR_IMAGES[kind];
  for (const link of document.querySelectorAll(".sponsor-link")) {
    link.classList.toggle("active", Boolean(src) && link.dataset.qr === kind);
  }
  if (!src) {
    show(el.sponsorQr, false);
    return;
  }
  el.sponsorQr.src = src;
  show(el.sponsorQr, true);
}

// openExternal 交给系统默认浏览器打开，避免在 webview 里跳走。
async function openExternal(url) {
  try {
    await Browser.OpenURL(url);
    setStatus("已在浏览器中打开");
  } catch (err) {
    setStatus(`打开链接失败：${describeError(err)}`, true);
  }
}

// renderToolStatus 把后端的四态归一化成一个状态标签。
//
// 用户关心的三态是：已内置（版本）/ 用户配置：路径 / 未找到；再补一个
// 「系统路径」覆盖「既没内置也没配置，但在 PATH 里找到了」这种真实情况。
// 自检失败（释放失败、起不来）优先级最高——必须先说清楚，否则用户会把
// 看到的「已内置」当成真的能用。
function renderToolStatus(tool) {
  const status = document.createElement("span");
  status.className = tool.available ? "tool-status ok" : "tool-status bad";
  status.dataset.state = stateOfTool(tool);

  if (tool.check === "not-runnable") {
    // 文件在、但起不来——光看「已内置」会以为一切正常，必须说清楚。
    status.textContent = "内置版本无法执行";
    status.title = tool.checkDetail || tool.message || "";
    return status;
  }
  if (tool.check === "release-failed") {
    status.textContent = "内置释放失败";
    status.title = tool.checkDetail || tool.message || "";
    return status;
  }

  switch (stateOfTool(tool)) {
    case "builtin":
      status.textContent = tool.native
        ? "已内置（程序内建实现）"
        : `已内置（${tool.builtinVersion || "内置"}）`;
      status.title = tool.resolved || tool.message || "";
      break;
    case "config":
      status.textContent = `用户配置：${shortPath(tool.resolved || tool.path)}`;
      status.title = tool.resolved || tool.path || "";
      break;
    case "auto":
      status.textContent = `系统路径：${shortPath(tool.resolved)}`;
      status.title = tool.resolved || "";
      break;
    default:
      status.textContent = tool.check === "not-embedded" ? "未内置" : "未找到";
      status.title = tool.message || "";
  }
  return status;
}

// stateOfTool 兜底：后端升级前拿到的快照里没有 state 字段。
function stateOfTool(tool) {
  if (tool.state) return tool.state;
  if (!tool.available) return "missing";
  if (tool.source === "builtin") return "builtin";
  if (tool.source === "config") return "config";
  return "auto";
}

// shortPath 把长路径缩成尾部一段，免得状态标签被挤成省略号。
function shortPath(path) {
  const text = String(path || "");
  if (text.length <= 44) return text;
  return `…${text.slice(-42)}`;
}

// restoreBuiltin 清掉用户配置的路径，改用随程序分发的内置副本。
async function restoreBuiltin(kind, button) {
  if (button) {
    button.disabled = true;
    button.textContent = "恢复中…";
  }
  hideErrorCard();
  try {
    const snapshot = await Call.ByName(`${SETTINGS_SERVICE}.RestoreBuiltin`, kind);
    renderSettings(snapshot);
    const tool = state.settings.tools.find((t) => t.kind === kind);
    setStatus(`${(tool && tool.label) || kind} 已恢复为内置版本`);
  } catch (err) {
    failWith("恢复内置版本失败", err);
  } finally {
    if (button) {
      button.disabled = false;
      button.textContent = "恢复为内置版本";
    }
  }
}

// renderToolRow 生成一行工具状态：状态点 + 名称 + 说明 + 路径输入 + 浏览/保存。
function renderToolRow(tool) {
  const row = document.createElement("div");
  row.className = "settings-tool";
  row.dataset.kind = tool.kind;

  const head = document.createElement("div");
  head.className = "settings-tool-head";

  const dot = document.createElement("span");
  dot.className = tool.available ? "tool-dot ok" : "tool-dot bad";

  const name = document.createElement("span");
  name.className = "settings-tool-name";
  name.textContent = tool.label;

  const hint = document.createElement("span");
  hint.className = "muted small";
  hint.textContent = tool.hint || "";

  const status = renderToolStatus(tool);

  head.append(dot, name, hint, status);

  const pathRow = document.createElement("div");
  pathRow.className = "path-row";

  const input = document.createElement("input");
  input.type = "text";
  input.className = "path-input mono";
  input.spellcheck = false;
  input.value = tool.path || "";
  input.placeholder = tool.available ? "留空则自动探测" : "未找到，请指定可执行文件路径";
  input.dataset.kind = tool.kind;

  const browse = document.createElement("button");
  browse.type = "button";
  browse.className = "btn-ghost";
  browse.textContent = "浏览…";
  browse.addEventListener("click", () => browseTool(tool.kind, input));

  const save = document.createElement("button");
  save.type = "button";
  save.className = "btn-ghost";
  save.textContent = "保存";
  save.addEventListener("click", () => saveToolPath(tool.kind, input, save));

  pathRow.append(input, browse, save);

  // 用户配了自己的路径、而程序里另有一份能用的副本时，给一个一键回退的入口。
  // 没有这个按钮的话，用户只能自己去把输入框清空再点保存——不是所有人都猜得到。
  if (tool.canRestore) {
    const restore = document.createElement("button");
    restore.type = "button";
    restore.className = "btn-ghost restore-builtin";
    restore.textContent = "恢复为内置版本";
    restore.title = `清除配置的路径，改用内置的 ${tool.builtinVersion || "副本"}`;
    restore.addEventListener("click", () => restoreBuiltin(tool.kind, restore));
    pathRow.append(restore);
  }

  row.append(head, pathRow);

  // 配置写错但已回退到内置版本时单独给一行提示：塞进状态文字会把它挤成省略号。
  if (tool.warning) {
    const warn = document.createElement("div");
    warn.className = "tool-warn";
    warn.textContent = `${tool.warning}，已回退到内置版本`;
    row.append(warn);
  }
  // 自检失败的具体原因（未嵌入 / 释放失败 / 无法执行）也单独列出来。
  if (!tool.available && tool.checkDetail) {
    const detail = document.createElement("div");
    detail.className = "tool-warn";
    detail.textContent = tool.checkDetail;
    row.append(detail);
  }
  return row;
}

async function saveToolPath(kind, input, button) {
  const value = (input.value || "").trim();
  if (button) {
    button.disabled = true;
    button.textContent = "保存中…";
  }
  hideErrorCard();
  try {
    const snapshot = await Call.ByName(`${SETTINGS_SERVICE}.SetPath`, kind, value);
    renderSettings(snapshot);
    const tool = state.settings.tools.find((t) => t.kind === kind);
    if (tool && tool.available) {
      setStatus(`${tool.label} 已就绪：${tool.resolved || value}`);
    } else if (value) {
      setStatus(`${kind} 未找到：${value}（清空后保存可恢复自动探测）`, true);
    } else {
      setStatus(`${kind} 未找到，已恢复自动探测`, true);
    }
  } catch (err) {
    failWith("保存工具路径失败", err);
  } finally {
    if (button) {
      button.disabled = false;
      button.textContent = "保存";
    }
  }
}

async function browseTool(kind, input) {
  try {
    const picked = await Dialogs.OpenFile({
      Title: `选择 ${kind}`,
      CanChooseFiles: true,
      CanChooseDirectories: false,
      AllowsMultipleSelection: false,
      Filters: TOOL_FILTERS[kind] || [{ DisplayName: "所有文件", Pattern: "*.*" }],
    });
    const path = normalizePaths(picked)[0];
    if (!path) return;
    input.value = path;
    const row = input.closest(".settings-tool");
    const button = row ? row.querySelector(".path-row .btn-ghost:last-child") : null;
    await saveToolPath(kind, input, button);
  } catch (err) {
    failWith(`选择 ${kind} 失败`, err);
  }
}

async function saveBatchConcurrency(raw) {
  const max = Math.max(1, (state.settings.snapshot && state.settings.snapshot.numCPU) || 1);
  const n = clampInt(raw, 1, max, max);
  try {
    const snapshot = await Call.ByName(`${SETTINGS_SERVICE}.SetBatchConcurrency`, n);
    renderSettings(snapshot);
    state.batch.concurrency = snapshot.batchConcurrency;
    updateConcurrencyText();
    setStatus(`批量破解并发数已改为 ${snapshot.batchConcurrency}`);
  } catch (err) {
    failWith("保存并发数失败", err);
  }
}

async function saveUnzipConcurrency(raw) {
  const n = clampInt(raw, 1, 8, 3);
  try {
    const snapshot = await Call.ByName(`${SETTINGS_SERVICE}.SetUnzipConcurrency`, n);
    renderSettings(snapshot);
    setStatus(`批量解压并发数已改为 ${snapshot.unzipConcurrency}`);
  } catch (err) {
    failWith("保存并发数失败", err);
  }
}

async function browseExportDir() {
  try {
    const picked = await Dialogs.OpenFile({
      Title: "选择默认导出目录",
      CanChooseFiles: false,
      CanChooseDirectories: true,
      AllowsMultipleSelection: false,
    });
    const path = normalizePaths(picked)[0];
    if (!path) return;
    el.settingsExportDir.value = path;
    await saveExportDir();
  } catch (err) {
    failWith("选择目录失败", err);
  }
}

async function saveExportDir() {
  const dir = (el.settingsExportDir.value || "").trim();
  try {
    const snapshot = await Call.ByName(`${SETTINGS_SERVICE}.SetDefaultExportDir`, dir);
    renderSettings(snapshot);
    setStatus(dir ? `默认导出目录：${dir}` : "已清除默认导出目录");
  } catch (err) {
    failWith("保存默认导出目录失败", err);
  }
}

async function recheckTools() {
  el.settingsRecheck.disabled = true;
  try {
    const snapshot = await Call.ByName(`${SETTINGS_SERVICE}.Recheck`);
    renderSettings(snapshot);
    const ok = state.settings.tools.filter((t) => t.available).length;
    setStatus(`已重新检测：${ok} / ${state.settings.tools.length} 个工具可用`);
  } catch (err) {
    failWith("重新检测失败", err);
  } finally {
    el.settingsRecheck.disabled = false;
  }
}

// syncAvailabilityFromSettings 把设置面板里的工具状态同步回各功能入口。
// 只改 UI 状态，不重新发请求——快照本身就是最新的。
function syncAvailabilityFromSettings() {
  const find = (kind) => state.settings.tools.find((t) => t.kind === kind);

  const sz = find("sevenzip");
  if (sz) {
    state.unzip.available = sz.available;
    state.unzip.sevenZipPath = sz.resolved || "";
    applySevenZipStatus({
      available: sz.available,
      path: sz.resolved || "",
      message: sz.message || "",
    });
  }

  const bk = find("bkcrack");
  if (bk) {
    applyBkcrackStatus({
      available: bk.available,
      path: bk.resolved || "",
      message: bk.message || "",
    });
  }

  const hc = find("hashcat");
  if (hc) {
    applyHashcatTools({
      hashcat: { available: hc.available, path: hc.resolved || "", message: hc.message || "" },
      rar2john: toolStatusOf(find("rar2john")),
      sevenZip2John: toolStatusOf(find("7z2john")),
    });
  }

  refreshControls();
}

function toolStatusOf(tool) {
  return {
    available: Boolean(tool && tool.available),
    path: (tool && tool.resolved) || "",
    message: (tool && tool.message) || "",
  };
}

// ------------------------------------------------------------------ 拖放

// 拖放只有两种行为，没有第三种：
//   isAwaitingPlaintext === true  → 拖进来的文件填明文；
//   isAwaitingPlaintext === false → 开始新流程（重置一切）。
//
// 这里刻意不做「按界面状态路由」：那种写法会不断长出新分支（批量追加、
// 进行中忽略、明文 ZIP 校验…），用户根本猜不到拖一下会发生什么。
//
// isAwaitingPlaintext 只有一个来源：明文攻击面板展开、且攻击没在跑。
// syncAwaitingPlaintext() 每轮 refreshControls 都会重算一次，所以任何
// 状态变化都不会让它漂在错的值上。

let isAwaitingPlaintext = false;

function syncAwaitingPlaintext() {
  // 攻击一开始就强制 false：攻击中不需要再喂明文。
  // 初始 / 单文件侦察完成 / 批量视图 / hashcat 面板 / 伪加密结果 / 解压中…
  // 这些状态的 attack.open 要么是 false，要么攻击在跑，所以一律 false。
  isAwaitingPlaintext = Boolean(state.attack.open) && !state.attack.running;
  return isAwaitingPlaintext;
}

// isTaskRunning 判断有没有需要先终止的后台任务。
function isTaskRunning() {
  return (
    state.batch.running ||
    state.unzip.running ||
    state.attack.running ||
    state.gpu.running
  );
}

// dropAction 把当前状态翻译成一条拖放行为（规则表在 drop-rules.js）。
function dropAction(count) {
  return dropActionOf({
    awaitingPlaintext: syncAwaitingPlaintext(),
    hasPlain: Boolean(el.attackPlainPath.value.trim()),
    taskRunning: isTaskRunning(),
    count,
  });
}

// updateDropHint 把当前行为写进遮罩文字。
function updateDropHint() {
  const text = dropHintText(dropAction(1));
  if (el.dropOverlayTitle) el.dropOverlayTitle.textContent = text.title;
  if (el.dropOverlayHint) el.dropOverlayHint.textContent = text.hint;
}

// onFilesDropped 是 Wails 运行时 files-dropped 事件的入口。
async function onFilesDropped(paths) {
  const list = normalizePaths(paths);
  if (list.length === 0) return;

  const action = dropAction(list.length);
  if (action.kind === DropAction.Plaintext) {
    await dropPlaintext(list, action);
    return;
  }
  await startNewFlow(list, action);
}

// dropPlaintext 处理「明文攻击面板展开时拖入文件」。
//
// 只取第一个文件，不做扩展名校验：明文本来就是「任意已知文件」，
// 是不是 ZIP 由 setPlaintext 自己判断（它会顺带把 ZIP 的条目列出来）。
async function dropPlaintext(paths, action) {
  const path = paths[0];

  if (paths.length > 1) {
    setStatus(`明文只接受一个文件，已取第一个：${baseName(path)}`, true);
  }

  // 已有明文时替换要二次确认：误拖一下就把选好的明文换掉，代价太大。
  if (action.replace) {
    const ok = await askConfirm({
      title: "替换明文文件",
      text: `当前明文是 ${baseName(el.attackPlainPath.value.trim())}，要替换成 ${baseName(path)} 吗？`,
      okText: "替换",
    });
    if (!ok) return;
  }

  try {
    await setPlaintext(path);
  } catch (err) {
    setStatus(`填入明文失败：${describeError(err)}`, true);
  }
}

// startNewFlow 开始新流程：先展开目录，任务在跑就先确认终止，再重置一切。
//
// 「先终止再清空」的顺序不能反：反了的话旧任务会继续往新界面上写事件。
async function startNewFlow(paths, action) {
  const expanded = await expandForDrop(paths);

  if (expanded.files.length === 0) {
    setStatus(
      expanded.failed.length > 0
        ? `无法读取目录：${baseName(expanded.failed[0])}`
        : "拖入的目录里没有文件",
      true,
    );
    return;
  }

  if (action.terminate) {
    const ok = await askConfirm({
      title: "终止当前任务",
      text: "当前任务进行中，是否终止并开始新流程？",
      okText: "终止并继续",
    });
    if (!ok) return;
    await terminateRunningTasks();
  }

  await openSelection(expanded.files);

  if (expanded.failed.length > 0) {
    setStatus(`无法读取目录：${baseName(expanded.failed[0])}`, true);
  }
}

// terminateRunningTasks 停掉所有在跑的任务，并等它们真的停下。
//
// stop* 只是发出停止请求，batch-done / unzip-done 之类的确认事件可能晚一拍，
// 所以这里除了 await 之外，还直接把 running 置回 false，保证随后的重置看到
// 的是「已停」。
async function terminateRunningTasks() {
  const jobs = [];
  if (state.batch.running) jobs.push(stopBatch());
  if (state.unzip.running) jobs.push(stopUnzip());
  if (state.attack.running) jobs.push(stopAttack());
  if (state.gpu.running) jobs.push(stopGpuRun());
  if (jobs.length > 0) {
    await Promise.allSettled(jobs);
  }

  state.batch.running = false;
  state.unzip.running = false;
  state.attack.running = false;
  state.gpu.running = false;

  // 旧批次的迟到事件不该再改界面（结果列表已经被清空了）。
  state.batch.muted = true;
  refreshControls();
}

// probeDropPath 是 expandDropPaths 的数据来源：问 Go 侧这个路径是文件还是
// 目录，是目录就把这一层列出来。
//
// 拿不到结果（老版本程序没有这个方法 / 调用失败）时按文件处理——宁可多
// 一行「已忽略」，也不要吞掉用户拖进来的东西。
async function probeDropPath(path) {
  try {
    const res = await Call.ByName(`${BATCH_SERVICE}.ListDir`, path);
    if (!res || typeof res.isDir !== "boolean") return { isDir: false };
    return res;
  } catch (err) {
    return { isDir: false };
  }
}

// expandForDrop 把拖入的路径展开成文件列表（文件夹最多展开两层）。
async function expandForDrop(paths) {
  try {
    return await expandDropPaths(paths, probeDropPath);
  } catch (err) {
    return { files: paths, dirs: [], failed: [] };
  }
}

// askConfirm 是统一的二次确认框，复用 unzip / decrypt 那套 modal 样式。
// 返回 Promise<boolean>：确定 true，取消 / Esc / 点背景 false。
let confirmResolver = null;

function askConfirm({ title, text, okText }) {
  // 上一个确认框还没关就又弹一个：按取消处理，避免 Promise 悬着。
  if (confirmResolver) {
    confirmResolver(false);
    confirmResolver = null;
  }

  el.confirmTitle.textContent = title || "确认";
  el.confirmText.textContent = text || "";
  el.confirmOk.textContent = okText || "确定";
  show(el.confirmModal, true);
  el.confirmOk.focus();

  return new Promise((resolve) => {
    confirmResolver = resolve;
  });
}

function closeConfirm(result) {
  if (!confirmResolver) return;
  const resolve = confirmResolver;
  confirmResolver = null;
  show(el.confirmModal, false);
  resolve(result);
}

// ---------------------------------------------------------------------- init

// 拖放由 Wails 运行时接管（它需要 WebView2 才能拿到真实路径）。运行时没
// 打开 enableFileDrop 时，拖入会静默失败——这里补一条明确的提示，免得
// 用户以为是自己拖错了地方。
//
// 拖放现在只有两种行为（填明文 / 开新流程），**没有**「不能放下」的状态，
// 所以 dropEffect 恒为 "copy"，不会再出现禁止光标。
function watchUnsupportedDrop() {
  const hasFiles = (event) =>
    Boolean(event.dataTransfer && Array.from(event.dataTransfer.types || []).includes("Files"));
  const runtimeHandlesDrop = () => window._wails?.flags?.enableFileDrop === true;

  document.addEventListener(
    "dragover",
    (event) => {
      if (!hasFiles(event) || runtimeHandlesDrop()) return;
      event.preventDefault();
      event.dataTransfer.dropEffect = "copy";
    },
    false,
  );

  document.addEventListener(
    "drop",
    (event) => {
      if (!hasFiles(event) || runtimeHandlesDrop()) return;
      event.preventDefault();
      setStatus("当前环境拿不到拖入文件的路径，请点右上角「选择 ZIP 文件」", true);
    },
    false,
  );
}

function bindEvents() {
  el.pick.addEventListener("click", pickFiles);
  el.addFiles.addEventListener("click", addFiles);
  // 左上角 logo：点一下回到初始状态（tooltip 在 HTML 的 title 上）。
  if (el.brandHome) el.brandHome.addEventListener("click", resetToInitial);
  if (el.toBatch) el.toBatch.addEventListener("click", addCurrentToBatch);
  el.detailBack.addEventListener("click", backToBatch);
  el.start.addEventListener("click", startBatch);
  el.stop.addEventListener("click", stopBatch);
  el.exportBtn.addEventListener("click", exportCSV);
  el.concurrencyBtn.addEventListener("click", toggleConcurrencyEditor);
  el.concurrencyApply.addEventListener("click", applyConcurrency);

  el.unzipBtn.addEventListener("click", startUnzipFlow);
  el.unzipStop.addEventListener("click", stopUnzip);
  el.unzipCancel.addEventListener("click", hideUnzipModal);
  el.unzipConfirm.addEventListener("click", confirmUnzip);
  el.unzipModal.addEventListener("click", (event) => {
    if (event.target === el.unzipModal) hideUnzipModal();
  });

  el.confirmOk.addEventListener("click", () => closeConfirm(true));
  el.confirmCancel.addEventListener("click", () => closeConfirm(false));
  el.confirmModal.addEventListener("click", (event) => {
    if (event.target === el.confirmModal) closeConfirm(false);
  });

  el.sevenZipSave.addEventListener("click", saveSevenZipPath);
  el.sevenZipBrowse.addEventListener("click", browseSevenZip);
  el.sevenZipRecheck.addEventListener("click", checkSevenZip);
  el.sevenZipInput.addEventListener("keydown", (event) => {
    if (event.key === "Enter") {
      event.preventDefault();
      saveSevenZipPath();
    }
  });

  el.bkcrackSave.addEventListener("click", saveBkcrackPath);
  el.bkcrackBrowse.addEventListener("click", browseBkcrack);
  el.bkcrackRecheck.addEventListener("click", checkBkcrack);

  el.hashcatRecheck.addEventListener("click", checkHashcat);
  el.hashcatSave.addEventListener("click", saveHashcatPath);
  el.hashcatBrowse.addEventListener("click", browseHashcat);

  el.gpuOpen.addEventListener("click", toggleGpuPanel);
  el.gpuStart.addEventListener("click", startGpuRun);
  el.gpuStop.addEventListener("click", stopGpuRun);
  el.gpuHashToggle.addEventListener("click", toggleGpuHash);
  el.gpuMaskHelpBtn.addEventListener("click", toggleMaskHelp);
  el.gpuWordlistBrowse.addEventListener("click", browseGpuWordlist);
  el.gpuCopyPassword.addEventListener("click", copyGpuPassword);
  el.gpuDecrypt.addEventListener("click", decryptWithPassword);
  el.gpuJohnSave.addEventListener("click", saveJohnPath);
  el.gpuJohnBrowse.addEventListener("click", browseJohnPath);
  // 换目标条目要重新提哈希：不同条目对应不同的 $zip2$ / $pkzip2$，
  // 也可能落在不同的模式号上（17200 vs 17210）。
  el.gpuEntry.addEventListener("change", () => {
    if (state.gpu.running) return;
    void extractGpuHash(el.gpuEntry.value);
  });
  for (const radio of document.querySelectorAll('input[name="gpu-strategy"]')) {
    radio.addEventListener("change", onGpuStrategyChange);
  }
  // 暴力策略的长度范围：与批量、快速检测共用同一套校正逻辑。
  bindLengthRange(el.gpuMinLen, el.gpuMaxLen, {
    defMin: GPU_MIN_DEFAULT,
    defMax: GPU_MAX_DEFAULT,
  });
  el.bkcrackInput.addEventListener("keydown", (event) => {
    if (event.key === "Enter") {
      event.preventDefault();
      saveBkcrackPath();
    }
  });

  el.attackOpen.addEventListener("click", toggleAttackPanel);
  el.attackGpu.addEventListener("click", openGpuFromAttackCard);
  el.attackPlainBrowse.addEventListener("click", browsePlainFile);
  el.attackEntry.addEventListener("change", runPrecheck);
  el.attackPlainEntry.addEventListener("change", runPrecheck);
  for (const radio of document.querySelectorAll('input[name="attack-plain-mode"]')) {
    radio.addEventListener("change", onPlainModeChange);
  }
  el.attackStart.addEventListener("click", startAttack);
  el.attackStop.addEventListener("click", stopAttack);
  el.attackCopyKeys.addEventListener("click", copyKeys);
  el.attackDecryptZip.addEventListener("click", openDecryptModal);
  el.attackDecryptEntry.addEventListener("click", decryptEntry);

  // 十六进制明文：输入即格式化，换条目/偏移重新预检。
  if (el.attackHexText) {
    el.attackHexText.addEventListener("input", onHexInput);
    el.attackHexText.addEventListener("change", runPrecheck);
  }
  if (el.attackHexOffset) {
    el.attackHexOffset.addEventListener("change", runPrecheck);
  }
  if (el.attackHexTemplate) {
    el.attackHexTemplate.addEventListener("change", applyHexTemplate);
  }

  // 伪加密修复 / 未加密直接解压 / 快速弱密码检测。
  if (el.fakeFix) el.fakeFix.addEventListener("click", fixFakeEncryption);
  if (el.fakeOpenFolder) {
    el.fakeOpenFolder.addEventListener("click", () => {
      if (state.fake.output) openOutputDir(dirOf(state.fake.output));
    });
  }
  if (el.plainUnzip) el.plainUnzip.addEventListener("click", unzipPlainFile);
  if (el.quickCrack) el.quickCrack.addEventListener("click", quickCrack);
  // ▾ 就是「快速弱密码检测」的位数入口，展开两个输入框。
  if (el.quickRangeBtn) el.quickRangeBtn.addEventListener("click", toggleQuickRange);
  // 三处「最小位数 – 最大位数」共用同一个绑定器：失焦校正、联动修正、
  // 非法输入回退都在 bindLengthRange 里，界面层不再各写一套。
  if (el.quickMinLen && el.quickMaxLen) {
    bindLengthRange(el.quickMinLen, el.quickMaxLen, {
      defMin: QUICK_MIN_DEFAULT,
      defMax: QUICK_MAX_DEFAULT,
      // 边打字边提示：位数上限到 10 位以上就提醒原生实现会慢。
      onInput: ({ maxLen }) => updateQuickSlowHint(maxLen),
    });
    // 输入过程中不校正数字，但提示要跟着走。
    const hint = () =>
      updateQuickSlowHint(clampInt(el.quickMaxLen.value, LEN_MIN, LEN_MAX, QUICK_MAX_DEFAULT));
    el.quickMinLen.addEventListener("input", hint);
    el.quickMaxLen.addEventListener("input", hint);
  }
  if (el.quickCopy) {
    el.quickCopy.addEventListener("click", async () => {
      if (!state.quick.password) return;
      try {
        await Clipboard.SetText(state.quick.password);
        setStatus(`已复制密码：${state.quick.password}`);
      } catch (err) {
        setStatus(`复制失败：${describeError(err)}`, true);
      }
    });
  }
  if (el.quickDecrypt) el.quickDecrypt.addEventListener("click", decryptCurrentFile);

  // 错误卡片。
  if (el.errorCopy) el.errorCopy.addEventListener("click", copyErrorText);
  if (el.errorClose) el.errorClose.addEventListener("click", hideErrorCard);

  // 设置面板。
  if (el.settingsBtn) el.settingsBtn.addEventListener("click", openSettings);
  if (el.settingsClose) el.settingsClose.addEventListener("click", closeSettings);
  if (el.settingsRecheck) el.settingsRecheck.addEventListener("click", recheckTools);
  if (el.settingsExportBrowse) el.settingsExportBrowse.addEventListener("click", browseExportDir);
  if (el.settingsExportSave) el.settingsExportSave.addEventListener("click", saveExportDir);
  if (el.settingsBatchConcurrency) {
    el.settingsBatchConcurrency.addEventListener("change", () => {
      saveBatchConcurrency(el.settingsBatchConcurrency.value);
    });
  }
  if (el.settingsUnzipConcurrency) {
    el.settingsUnzipConcurrency.addEventListener("change", () => {
      saveUnzipConcurrency(el.settingsUnzipConcurrency.value);
    });
  }
  if (el.settingsModal) {
    el.settingsModal.addEventListener("click", (event) => {
      if (event.target === el.settingsModal) closeSettings();
    });
  }

  // 赞助：点文字显示对应收款码，点别处收起；项目地址走系统浏览器。
  if (el.settingsModal) {
    el.settingsModal.addEventListener("click", (event) => {
      const target = event.target;
      if (!(target instanceof Element)) return;

      const link = target.closest("[data-qr]");
      if (link) {
        const kind = link.dataset.qr || "";
        // 再点一次同一个链接就收起，点别的直接换成那一张。
        const same = !el.sponsorQr.classList.contains("hidden") && link.classList.contains("active");
        showSponsorQr(same ? "" : kind);
        return;
      }
      if (!target.closest("#sponsor-qr")) showSponsorQr("");
    });
  }
  if (el.aboutRepo) {
    el.aboutRepo.addEventListener("click", (event) => {
      event.preventDefault();
      openExternal(el.aboutRepo.getAttribute("href") || "");
    });
  }
  if (el.settingsExportDir) {
    el.settingsExportDir.addEventListener("keydown", (event) => {
      if (event.key === "Enter") {
        event.preventDefault();
        saveExportDir();
      }
    });
  }

  el.decryptBrowse.addEventListener("click", browseDecryptOutput);
  el.decryptCancel.addEventListener("click", hideDecryptModal);
  el.decryptConfirm.addEventListener("click", confirmDecrypt);
  el.decryptModal.addEventListener("click", (event) => {
    if (event.target === el.decryptModal) hideDecryptModal();
  });

  if (el.openFolder) {
    el.openFolder.addEventListener("click", () => {
      const entry = state.unzipByPath.get(state.path);
      if (entry && entry.outputDir) openOutputDir(entry.outputDir);
    });
  }

  el.concurrencyInput.addEventListener("keydown", (event) => {
    if (event.key === "Enter") {
      event.preventDefault();
      applyConcurrency();
    } else if (event.key === "Escape") {
      hideConcurrencyEditor();
    }
  });

  document.addEventListener("keydown", (event) => {
    if (event.key !== "Escape") return;
    if (el.confirmModal && !el.confirmModal.classList.contains("hidden")) {
      closeConfirm(false);
      return;
    }
    if (el.settingsModal && !el.settingsModal.classList.contains("hidden")) {
      closeSettings();
      return;
    }
    if (!el.decryptModal.classList.contains("hidden")) {
      hideDecryptModal();
      return;
    }
    if (!el.unzipModal.classList.contains("hidden")) {
      hideUnzipModal();
    }
  });

  // 批量破解：校正后同步到 state，开始批量时直接用这份值。
  bindLengthRange(el.minLen, el.maxLen, {
    defMin: BATCH_MIN_DEFAULT,
    defMax: BATCH_MAX_DEFAULT,
    onInput: ({ minLen, maxLen }) => {
      state.batch.minLen = minLen;
      state.batch.maxLen = maxLen;
    },
  });

  for (const th of el.resultsCard.querySelectorAll("th.sortable")) {
    th.addEventListener("click", () => toggleSort(th.dataset.sort));
  }

  Events.On("batch-result", (event) => onBatchResult(event.data));
  Events.On("batch-error", (event) => onBatchError(event.data));
  Events.On("batch-done", (event) => onBatchDone(event.data));
  Events.On("unzip-start", (event) => onUnzipStart(event.data));
  Events.On("unzip-result", (event) => onUnzipResult(event.data));
  Events.On("unzip-done", (event) => onUnzipDone(event.data));
  Events.On("attack-log", (event) => onAttackLog(event.data));
  Events.On("attack-done", (event) => onAttackDone(event.data));
  Events.On("hashcat-progress", (event) => onGpuProgress(event.data));
  Events.On("hashcat-done", (event) => onGpuDone(event.data));
  Events.On("files-dropped", (event) => onFilesDropped(event.data));
}

async function loadDefaults() {
  try {
    const d = await Call.ByName(`${BATCH_SERVICE}.Defaults`);
    if (!d) return;
    state.batch.minLen = Number(d.minLen) || 6;
    state.batch.maxLen = Number(d.maxLen) || 8;
    state.batch.concurrency = Number(d.concurrency) || 2;
    state.batch.numCPU = Number(d.numCPU) || 1;

    el.minLen.value = String(state.batch.minLen);
    el.maxLen.value = String(state.batch.maxLen);
    el.minLen.dataset.last = String(state.batch.minLen);
    el.maxLen.dataset.last = String(state.batch.maxLen);
    // 后端 maxPasswordLen 是 20，但三处长度控件统一封顶 12（10^12 已是不可能
    // 跑完的量级，再往上必须上显卡）。这里不跟着后端放宽，否则会出现
    // 「HTML 允许 20、失焦又被改回 12」的诡异手感。
    el.minLen.max = String(LEN_MAX);
    el.maxLen.max = String(LEN_MAX);
    el.concurrencyInput.max = String(state.batch.numCPU);
    updateConcurrencyText();
  } catch (err) {
    // 拿不到默认值不影响单文件视图，用内置的 6–8 / 2 线程兜底。
    updateConcurrencyText();
  }
}

async function init() {
  bindEvents();
  applyMaskHelp();
  watchUnsupportedDrop();
  updateProgress();
  updateUnzipProgress();
  updateConcurrencyText();
  refreshControls();
  setStatus("");
  await loadDefaults();
  await checkSevenZip();
  await checkBkcrack();
  await checkHashcat();
}

init();
