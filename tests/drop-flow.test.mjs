// 拖放流程与单文件操作的端到端测试（无浏览器）。
//
// 做法：把 app.js 复制到临时目录，把裸导入换成桩（Wails 运行时、DOM），
// 再用一个够用的假 DOM 把整个模块跑起来（桩见 tests/dom-stub.mjs）。这样测的是**真实的 app.js**，
// 不是它的副本逻辑——路由、确认框、状态是否被改动，全都覆盖。
//
//   node --test tests/drop-flow.test.mjs
//
// 覆盖的是验收清单里的界面层行为；纯规则表另见 tests/drop-rules.test.mjs。

import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { pathToFileURL } from "node:url";
import {
  installDom,
  prepareAppModule as prepareAppModuleBase,
  writeRuntimeStub,
} from "./dom-stub.mjs";

const ROOT = path.resolve(import.meta.dirname, "..");
const FRONTEND = path.join(ROOT, "frontend");

// ----------------------------------------------------------------- DOM 桩
//
// 假 DOM 与「复制 app.js 并改写裸导入」这两件事已抽到 tests/dom-stub.mjs，
// 条目详情那边（entry-detail.test.mjs）用的是同一套。

// prepareAppModule 生成可导入的 app 副本，末尾补一行导出方便测试取用内部函数。
//
// Call.ByName 走 globalThis.__zipkitCall 这个钩子：默认返回 {}，测试需要
// 真实结果时再装一个假后端（见 installBackend）。
function prepareAppModule() {
  const { dir, entry } = prepareAppModuleBase(FRONTEND, [
    "state",
    "el",
    "onFilesDropped",
    "dropAction",
    "updateDropHint",
    "closeConfirm",
    "showBatch",
    "showSingle",
    "startBatch",
    "backToBatch",
    "appendToBatch",
    "resetForNewFlow",
    "resetToInitial",
    "terminateRunningTasks",
    "isTaskRunning",
    "renderAttackCard",
    "renderGpuCard",
    "applyGpuAvailability",
    "recommendationOf",
    "quickCrack",
    "readQuickRange",
    "toggleQuickRange",
    "openGpuFromAttackCard",
    "closeGpuPanel",
    "batchCounts",
    "fileStatusText",
  ]);
  writeRuntimeStub(dir);
  return entry;
}

// ------------------------------------------------------------------ 假后端

// inspectDelay 让侦察变慢，用来测并发拖入时会不会互相顶掉。
let inspectDelay = 0;

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

// installBackend 装一个只认路径的假后端：
//   files  路径 → 侦察结果（缺省当作「不支持的格式」）
//   dirs   路径 → 目录内容 { dirs, files }
//   calls  收集 StartBatch / CrackOne / Extract 收到的参数
function installBackend({ files = {}, dirs = {}, calls = {} } = {}) {
  inspectDelay = 0;
  globalThis.__zipkitCall = async (name, ...args) => {
    if (name.endsWith(".InspectFile")) {
      if (inspectDelay > 0) await sleep(inspectDelay);
      const p = args[0];
      const hit = files[p];
      if (hit) return { path: p, name: p.split(/[\\/]/).pop(), size: 2048, ...hit };
      return { path: p, name: p.split(/[\\/]/).pop(), applicable: false, skipReason: "不支持的格式" };
    }
    if (name.endsWith(".ListDir")) {
      const p = args[0];
      const hit = dirs[p];
      if (!hit) return { path: p, isDir: false, dirs: [], files: [] };
      return { path: p, isDir: true, dirs: hit.dirs || [], files: hit.files || [] };
    }
    if (name.endsWith(".Inspect")) {
      return { Path: args[0], Format: "ZIP", EntryCount: 0, Entries: [], EncryptionType: "None" };
    }
    if (name.endsWith(".StartBatch")) {
      calls.startBatch = args[0];
      return "batch-test";
    }
    if (name.endsWith(".CrackOne")) {
      calls.crackOne = args;
      return { found: false, elapsedMs: 12 };
    }
    if (name.endsWith(".Extract")) {
      calls.extract = args;
      return { hash: "$pkzip2$deadbeef*$/pkzip2$", mode: 17200, format: "ZIP-ZipCrypto" };
    }
    return {};
  };
  return calls;
}

function clearBackend() {
  globalThis.__zipkitCall = null;
  inspectDelay = 0;
}

// ZIP + ZipCrypto：能进破解队列。
const zipOk = { format: "ZIP", encryptionType: "ZipCrypto", entryCount: 2, applicable: true, entryName: "a.txt" };
// ZIP + AES：批量引擎不认，要单独处理。
const zipAes = { format: "ZIP", encryptionType: "AES-256", entryCount: 2, applicable: false, skipReason: "AES 加密" };
// 非压缩包。
const notZip = { applicable: false, skipReason: "不支持的格式" };

// resetBatch 把批量视图恢复到「空列表、可接收拖入」的状态。
function resetBatch(mod) {
  mod.state.view = "batch";
  mod.state.detailFromBatch = false;
  mod.state.files = [];
  mod.state.fileRows.clear();
  mod.state.results = [];
  mod.state.inspecting = 0;
  mod.state.batch.running = false;
  mod.state.batch.finished = false;
  mod.state.batch.cancelled = false;
  mod.state.batch.total = 0;
  mod.state.batch.completed = 0;
  mod.state.batch.muted = false;
  mod.state.path = "";
  mod.el.fileBody.children = [];
  mod.el.resultsBody.children = [];
}

// resetAll 把模块恢复到「刚启动」：没有任务、没有文件、没有面板。
function resetAll(mod) {
  mod.resetForNewFlow();
  mod.state.batch.running = false;
  mod.state.batch.muted = false;
  mod.state.unzip.running = false;
  mod.state.attack.running = false;
  mod.state.attack.open = false;
  mod.state.gpu.running = false;
  mod.state.gpu.open = false;
  mod.el.attackPlainPath.value = "";
  mod.el.attackEntry.value = "";
  mod.el.quickMinLen.value = "6";
  mod.el.quickMaxLen.value = "8";
  // dataset.last 是「上一次合法值」，非法输入时用它回退；跨用例必须一起重置，
  // 否则上一个用例留下的 9/9 会漏到下一个用例里。
  mod.el.quickMinLen.dataset.last = "6";
  mod.el.quickMaxLen.dataset.last = "8";
  mod.el.toast.textContent = "";
  mod.el.status.textContent = "";
  mod.updateDropHint();
}

// statusOf 读的是真实渲染出来的那一格文字，不是 state 里的原始字段。
function statusOf(mod, p) {
  const refs = mod.state.fileRows.get(p);
  return refs ? refs.status.textContent : "";
}

const hidden = (elm) => elm.classList.contains("hidden");
const tick = (ms = 10) => new Promise((r) => setTimeout(r, ms));

// 只加载一次：模块顶层会执行 init()，重复导入没有意义。
let appPromise = null;

async function loadApp() {
  if (!appPromise) {
    const { body, byId } = installDom();
    const entry = prepareAppModule();
    appPromise = import(pathToFileURL(entry).href).then(async (mod) => {
      // 等 init() 里那串 await 跑完。
      await new Promise((r) => setTimeout(r, 50));
      return { ...mod, body, byId };
    });
  }
  return appPromise;
}

// 明文形式是 radio，currentPlainMode() 直接读它；桩里用 querySelector 模拟。
function setPlainMode(mod, mode) {
  globalThis.document.querySelector = (sel) =>
    String(sel).includes("attack-plain-mode") ? { value: mode } : null;
  mod.updateDropHint();
}

// =========================================================== 一、拖放：二元

test("验收 1：初始状态拖入 2 个 ZIP，直接进批量视图", async () => {
  const mod = await loadApp();
  const { state, el, onFilesDropped } = mod;

  installBackend({ files: { "C:/tmp/a.zip": zipOk, "C:/tmp/b.zip": zipOk } });
  resetAll(mod);

  assert.equal(mod.dropAction(2).kind, "new");
  assert.equal(el.dropOverlayTitle.textContent, "松开以开始新流程");

  await onFilesDropped(["C:/tmp/a.zip", "C:/tmp/b.zip"]);
  await tick(20);

  assert.equal(state.view, "batch", "2 个文件必须进批量视图");
  assert.deepEqual(state.files.map((f) => f.path), ["C:/tmp/a.zip", "C:/tmp/b.zip"]);
  assert.equal(state.files.every((f) => f.status === "waiting"), true);

  clearBackend();
});

test("验收 1b：初始状态拖入 1 个 ZIP，进单文件视图", async () => {
  const mod = await loadApp();
  const { state, onFilesDropped } = mod;

  installBackend({ files: { "C:/tmp/one.zip": zipOk } });
  resetAll(mod);

  await onFilesDropped(["C:/tmp/one.zip"]);

  assert.equal(state.view, "single");
  assert.equal(state.path, "C:/tmp/one.zip");

  clearBackend();
});

test("验收 2：面板展开时拖入 1 个 PNG，只填明文，加密文件与侦察结果都不动", async () => {
  const mod = await loadApp();
  const { state, el, onFilesDropped } = mod;

  resetAll(mod);
  state.view = "single";
  state.path = "C:/tmp/cipher.zip";
  const infoBefore = { Entries: [{ Name: "a.txt", EncryptionType: "ZipCrypto" }] };
  state.info = infoBefore;
  state.attack.open = true;
  state.attack.running = false;
  setPlainMode(mod, "file");

  assert.equal(mod.dropAction(1).kind, "plaintext");
  assert.equal(el.dropOverlayTitle.textContent, "松开以填入明文文件");

  await onFilesDropped(["C:/tmp/known.png"]);

  assert.equal(el.attackPlainPath.value, "C:/tmp/known.png", "明文要填进去");
  assert.equal(state.path, "C:/tmp/cipher.zip", "加密文件不能被替换");
  assert.equal(state.info, infoBefore, "侦察结果不能被清掉");
  assert.equal(state.attack.open, true, "面板不能被关闭");
  assert.equal(state.view, "single");
});

test("验收 3：面板展开时拖入 2 个，只取第一个并提示「明文只接受一个文件」", async () => {
  const mod = await loadApp();
  const { el, onFilesDropped } = mod;

  resetAll(mod);
  mod.state.attack.open = true;
  setPlainMode(mod, "file");

  const action = mod.dropAction(2);
  assert.equal(action.kind, "plaintext");
  assert.equal(action.extraFiles, true);

  await onFilesDropped(["C:/tmp/first.png", "C:/tmp/second.png"]);

  assert.equal(el.attackPlainPath.value, "C:/tmp/first.png", "只认第一个");
  assert.match(el.status.textContent, /明文只接受一个文件/);
  assert.match(el.status.textContent, /first\.png/);
});

test("面板展开 + 已有明文：确认取消保持原样，确认后替换", async () => {
  const mod = await loadApp();
  const { el, onFilesDropped } = mod;

  resetAll(mod);
  mod.state.attack.open = true;
  setPlainMode(mod, "file");
  el.attackPlainPath.value = "C:/tmp/first.png";

  const cancel = onFilesDropped(["C:/tmp/second.png"]);
  await tick();
  assert.equal(hidden(el.confirmModal), false, "应弹出确认框");
  assert.match(el.confirmText.textContent, /first\.png/);
  assert.match(el.confirmText.textContent, /second\.png/);

  mod.closeConfirm(false);
  await cancel;
  assert.equal(el.attackPlainPath.value, "C:/tmp/first.png");

  const accept = onFilesDropped(["C:/tmp/second.png"]);
  await tick();
  mod.closeConfirm(true);
  await accept;
  assert.equal(el.attackPlainPath.value, "C:/tmp/second.png");
});

test("验收 4：收起面板后拖入，触发新流程而不是填明文", async () => {
  const mod = await loadApp();
  const { state, el, onFilesDropped } = mod;

  installBackend({ files: { "C:/tmp/x.zip": zipOk, "C:/tmp/y.zip": zipOk } });
  resetAll(mod);

  mod.state.attack.open = true;
  setPlainMode(mod, "file");
  el.attackPlainPath.value = "C:/tmp/keep.png";

  // 收起面板（等价于点「收起攻击面板」）
  state.attack.open = false;
  mod.updateDropHint();

  assert.equal(mod.dropAction(1).kind, "new");

  await onFilesDropped(["C:/tmp/x.zip", "C:/tmp/y.zip"]);

  assert.equal(state.view, "batch", "收起面板后拖入要开新流程");
  assert.equal(el.attackPlainPath.value, "", "明文路径要被清掉");

  clearBackend();
});

test("验收 5：攻击进行中拖入 → 弹确认 → 终止并开始新流程", async () => {
  const mod = await loadApp();
  const { state, el, onFilesDropped } = mod;

  const calls = installBackend({ files: { "C:/tmp/n1.zip": zipOk, "C:/tmp/n2.zip": zipOk } });
  resetAll(mod);
  state.view = "single";
  state.path = "C:/tmp/cipher.zip";
  state.attack.running = true;
  state.attack.open = true;

  // 攻击中 awaitingPlaintext 被强制 false，所以走的是开新流程。
  const action = mod.dropAction(2);
  assert.equal(action.kind, "new");
  assert.equal(action.terminate, true);

  const pending = onFilesDropped(["C:/tmp/n1.zip", "C:/tmp/n2.zip"]);
  await tick();
  assert.equal(hidden(el.confirmModal), false, "任务进行中要弹确认框");
  assert.match(el.confirmText.textContent, /当前任务进行中/);
  assert.match(el.confirmText.textContent, /终止并开始新流程/);

  mod.closeConfirm(true);
  await pending;

  assert.equal(state.attack.running, false, "任务要被终止");
  assert.equal(state.view, "batch", "终止后开始新流程");
  assert.equal(state.path, "");
  assert.deepEqual(state.files.map((f) => f.path), ["C:/tmp/n1.zip", "C:/tmp/n2.zip"]);
  assert.ok(calls.startBatch === undefined, "不该顺手开始破解");

  clearBackend();
});

test("验收 5b：确认框取消时，任务继续跑、界面不动", async () => {
  const mod = await loadApp();
  const { state, onFilesDropped } = mod;

  installBackend({ files: { "C:/tmp/n1.zip": zipOk } });
  resetAll(mod);
  state.view = "single";
  state.path = "C:/tmp/cipher.zip";
  state.attack.running = true;

  const pending = onFilesDropped(["C:/tmp/n1.zip"]);
  await tick();
  mod.closeConfirm(false);
  await pending;

  assert.equal(state.attack.running, true, "取消后任务不能被停");
  assert.equal(state.path, "C:/tmp/cipher.zip");
  assert.equal(state.view, "single");

  state.attack.running = false;
  clearBackend();
});

test("批量视图拖入：开新流程，不做追加", async () => {
  const mod = await loadApp();
  const { state, onFilesDropped } = mod;

  installBackend({ files: { "C:/tmp/old.zip": zipOk, "C:/tmp/new.zip": zipOk } });
  resetAll(mod);
  await mod.showBatch(["C:/tmp/old.zip"]);
  assert.equal(state.files.length, 1);

  await onFilesDropped(["C:/tmp/new.zip"]);

  assert.equal(state.view, "single", "1 个文件 → 单文件视图");
  assert.equal(state.path, "C:/tmp/new.zip");
  assert.deepEqual(state.files, [], "旧批次必须被清空，不是追加");

  clearBackend();
});

test("hashcat 面板展开时拖入：开新流程（只有明文攻击面板才算等明文）", async () => {
  const mod = await loadApp();
  const { state, onFilesDropped } = mod;

  installBackend({ files: { "C:/tmp/a.zip": zipOk, "C:/tmp/b.zip": zipOk } });
  resetAll(mod);
  state.view = "single";
  state.path = "C:/tmp/cipher.zip";
  state.gpu.open = true;

  assert.equal(mod.dropAction(1).kind, "new");

  await onFilesDropped(["C:/tmp/a.zip", "C:/tmp/b.zip"]);
  assert.equal(state.view, "batch");

  clearBackend();
});

test("伪加密结果展示中拖入：开新流程", async () => {
  const mod = await loadApp();
  const { state, onFilesDropped } = mod;

  installBackend({ files: { "C:/tmp/a.zip": zipOk } });
  resetAll(mod);
  state.view = "single";
  state.path = "C:/tmp/fake.zip";
  state.fake.detected = true;
  state.fake.output = "C:/tmp/fixed.zip";

  assert.equal(mod.dropAction(1).kind, "new");
  await onFilesDropped(["C:/tmp/a.zip"]);
  assert.equal(state.path, "C:/tmp/a.zip");
  assert.equal(state.fake.output, "", "新流程要清掉伪加密结果");

  clearBackend();
});

test("解压进行中拖入：弹确认后终止并开新流程", async () => {
  const mod = await loadApp();
  const { state, el, onFilesDropped } = mod;

  installBackend({ files: { "C:/tmp/a.zip": zipOk } });
  resetAll(mod);
  state.unzip.running = true;

  const pending = onFilesDropped(["C:/tmp/a.zip"]);
  await tick();
  assert.equal(hidden(el.confirmModal), false);
  mod.closeConfirm(true);
  await pending;

  assert.equal(state.unzip.running, false);
  assert.equal(state.view, "single");

  clearBackend();
});

test("拖入含 3 个 ZIP 的文件夹：全部进来；超过两层不再展开", async () => {
  const mod = await loadApp();
  const { state, onFilesDropped } = mod;

  installBackend({
    files: {
      "C:/tmp/dir/1.zip": zipOk,
      "C:/tmp/dir/2.zip": zipOk,
      "C:/tmp/dir/sub/3.zip": zipOk,
      "C:/tmp/dir/sub/deep/4.zip": zipOk,
    },
    dirs: {
      "C:/tmp/dir": { dirs: ["C:/tmp/dir/sub"], files: ["C:/tmp/dir/1.zip", "C:/tmp/dir/2.zip"] },
      "C:/tmp/dir/sub": { dirs: ["C:/tmp/dir/sub/deep"], files: ["C:/tmp/dir/sub/3.zip"] },
      "C:/tmp/dir/sub/deep": { dirs: [], files: ["C:/tmp/dir/sub/deep/4.zip"] },
    },
  });

  resetAll(mod);
  await onFilesDropped(["C:/tmp/dir"]);
  await tick(20);

  const paths = state.files.map((f) => f.path);
  assert.deepEqual(paths, ["C:/tmp/dir/1.zip", "C:/tmp/dir/2.zip", "C:/tmp/dir/sub/3.zip"]);
  assert.ok(!paths.includes("C:/tmp/dir/sub/deep/4.zip"), "第三层不该被展开");

  clearBackend();
});

test("目录读不出来时只提示，不阻塞其余文件", async () => {
  const mod = await loadApp();
  const { state, el, onFilesDropped } = mod;

  globalThis.__zipkitCall = async (name, ...args) => {
    if (name.endsWith(".ListDir")) {
      const p = args[0];
      if (p === "C:/tmp/locked") return { path: p, isDir: true, dirs: [], files: [], err: "拒绝访问" };
      return { path: p, isDir: false, dirs: [], files: [] };
    }
    if (name.endsWith(".InspectFile")) {
      return { path: args[0], name: "ok.zip", applicable: true, encryptionType: "ZipCrypto" };
    }
    return {};
  };

  resetAll(mod);
  await onFilesDropped(["C:/tmp/locked", "C:/tmp/ok.zip"]);
  await tick(20);

  // 只剩 1 个文件，所以走单文件视图；关键是它没被那个读不出来的目录拖累。
  assert.equal(state.view, "single");
  assert.equal(state.path, "C:/tmp/ok.zip");
  assert.match(el.status.textContent, /无法读取目录：locked/);

  clearBackend();
});

test("拖入空目录：只提示，不动当前状态", async () => {
  const mod = await loadApp();
  const { state, el, onFilesDropped } = mod;

  installBackend({ dirs: { "C:/tmp/empty": { dirs: [], files: [] } } });
  resetAll(mod);
  state.view = "single";
  state.path = "C:/tmp/keep.zip";

  await onFilesDropped(["C:/tmp/empty"]);

  assert.equal(state.path, "C:/tmp/keep.zip");
  assert.match(el.status.textContent, /目录里没有文件/);

  clearBackend();
});

test("并发拖入两批：不会互相顶掉侦察结果", async () => {
  const mod = await loadApp();
  const { state, onFilesDropped } = mod;

  installBackend({
    files: {
      "C:/tmp/a1.zip": zipOk,
      "C:/tmp/a2.zip": zipOk,
      "C:/tmp/b1.zip": zipOk,
      "C:/tmp/b2.zip": zipOk,
    },
  });
  resetAll(mod);
  inspectDelay = 15;

  const first = onFilesDropped(["C:/tmp/a1.zip", "C:/tmp/a2.zip"]);
  await tick(1);
  const second = onFilesDropped(["C:/tmp/b1.zip", "C:/tmp/b2.zip"]);
  await tick(1);
  await Promise.all([first, second]);
  await tick(80);

  assert.equal(state.view, "batch");
  assert.equal(state.files.length, 2, "后一次拖入是开新流程，覆盖前一批");
  assert.deepEqual(state.files.map((f) => f.path), ["C:/tmp/b1.zip", "C:/tmp/b2.zip"]);
  assert.equal(state.files.every((f) => f.status === "waiting"), true, "侦察结果要落到位");

  clearBackend();
});

// =========================================== 二、左上角图标：恢复初始状态

test("验收 6：初始状态下点图标，不弹确认，直接提示「已在初始状态」", async () => {
  const mod = await loadApp();
  const { state, el, resetToInitial } = mod;

  resetAll(mod);
  assert.equal(mod.isTaskRunning(), false);
  assert.equal(state.view, "empty");

  await resetToInitial();

  assert.equal(hidden(el.confirmModal), true, "初始状态不该弹确认框");
  assert.equal(el.toast.textContent, "已在初始状态");
  assert.equal(hidden(el.toast), false, "提示要显示出来");
});

test("验收 6b：有文件但没任务时点图标，直接恢复并提示「已恢复初始状态」", async () => {
  const mod = await loadApp();
  const { state, el, resetToInitial } = mod;

  installBackend({ files: { "C:/tmp/a.zip": zipOk } });
  resetAll(mod);
  await mod.showSingle("C:/tmp/a.zip", false);
  assert.equal(state.view, "single");

  await resetToInitial();

  assert.equal(hidden(el.confirmModal), true, "没有任务在跑就不弹确认");
  assert.equal(state.view, "empty");
  assert.equal(state.path, "");
  assert.equal(el.toast.textContent, "已恢复初始状态");
  assert.equal(hidden(el.report), true);
  assert.equal(hidden(el.empty), false);

  clearBackend();
});

test("验收 7：有任务进行中时点图标，先弹确认再终止并恢复", async () => {
  const mod = await loadApp();
  const { state, el, resetToInitial } = mod;

  installBackend({ files: { "C:/tmp/a.zip": zipOk, "C:/tmp/b.zip": zipOk } });
  resetAll(mod);
  await mod.showBatch(["C:/tmp/a.zip", "C:/tmp/b.zip"]);
  state.batch.running = true;
  state.batch.finished = true;

  const pending = resetToInitial();
  await tick();
  assert.equal(hidden(el.confirmModal), false, "任务进行中要弹确认");
  assert.match(el.confirmText.textContent, /当前任务进行中/);
  assert.match(el.confirmText.textContent, /终止并恢复初始状态/);

  mod.closeConfirm(true);
  await pending;

  assert.equal(state.batch.running, false, "任务要被终止");
  assert.equal(state.batch.muted, true, "旧批次的迟到事件要被静音");
  assert.equal(state.view, "empty");
  assert.deepEqual(state.files, [], "文件列表要清空");
  assert.deepEqual(state.results, [], "结果列表要清空");
  assert.equal(el.fileBody.children.length, 0);
  assert.equal(el.resultsBody.children.length, 0);
  assert.equal(el.toast.textContent, "已恢复初始状态");

  clearBackend();
});

test("验收 7b：图标确认框取消时什么都不做", async () => {
  const mod = await loadApp();
  const { state, resetToInitial } = mod;

  resetAll(mod);
  state.attack.running = true;
  state.view = "single";
  state.path = "C:/tmp/cipher.zip";

  const pending = resetToInitial();
  await tick();
  mod.closeConfirm(false);
  await pending;

  assert.equal(state.attack.running, true);
  assert.equal(state.view, "single");
  assert.equal(state.path, "C:/tmp/cipher.zip");

  state.attack.running = false;
});

test("恢复初始状态要清掉所有面板与提示", async () => {
  const mod = await loadApp();
  const { state, el, resetToInitial } = mod;

  installBackend({ files: { "C:/tmp/a.zip": zipOk } });
  resetAll(mod);
  await mod.showSingle("C:/tmp/a.zip", false);
  state.attack.open = true;
  state.gpu.open = true;
  state.fake.detected = true;
  state.quick.password = "123456";

  await resetToInitial();

  assert.equal(state.attack.open, false);
  assert.equal(state.gpu.open, false);
  assert.equal(state.fake.detected, false);
  assert.equal(state.quick.password, "");
  assert.equal(hidden(el.attackPanel), true);
  assert.equal(hidden(el.gpuPanel), true);
  assert.equal(hidden(el.attackResult), true);
  assert.equal(hidden(el.gpuResult), true);
  assert.equal(hidden(el.fakeCard), true);
  assert.equal(hidden(el.progressCard), true);
  assert.equal(hidden(el.resultsCard), true);
  assert.equal(hidden(el.errorCard), true);

  clearBackend();
});

// =============================== 三、单文件模式的三个按钮（ZipCrypto 卡片）

const zipCryptoInfo = {
  Entries: [
    { Name: "a.txt", EncryptionType: "ZipCrypto", Compression: "Deflate", UncompressedSize: 100, CompressedSize: 120 },
    { Name: "b.txt", EncryptionType: "ZipCrypto", Compression: "Store", UncompressedSize: 50, CompressedSize: 62 },
  ],
};

const mixedInfo = {
  Entries: [
    { Name: "a.txt", EncryptionType: "ZipCrypto", Compression: "Deflate", UncompressedSize: 100, CompressedSize: 120 },
    { Name: "c.txt", EncryptionType: "AES-256", Compression: "Deflate", UncompressedSize: 100, CompressedSize: 140 },
  ],
};

const aesInfo = {
  Entries: [
    { Name: "c.txt", EncryptionType: "AES-256", Compression: "Deflate", UncompressedSize: 100, CompressedSize: 140 },
  ],
};

// setupSingle 把界面摆成「单文件视图 + 指定侦察结果」。
function setupSingle(mod, info, kind = "zip") {
  mod.state.view = "single";
  mod.state.path = "C:/tmp/target.zip";
  mod.state.info = info;
  mod.state.archiveKind = kind;
  mod.state.attack.available = true;
  mod.state.attack.running = false;
  mod.el.attackEntry.value = "";
  mod.renderAttackCard(info);
  mod.renderGpuCard(info);
}

test("验收 8：ZipCrypto 文件有三个按钮，平铺不折叠", async () => {
  const mod = await loadApp();
  const { el } = mod;

  resetAll(mod);
  setupSingle(mod, zipCryptoInfo);

  assert.equal(hidden(el.attackCard), false, "卡片要显示");
  assert.equal(hidden(el.quickCrack), false, "① 快速弱密码检测");
  assert.equal(hidden(el.quickRangeBtn), false, "▾ 位数入口");
  assert.equal(hidden(el.attackOpen), false, "② 开始明文攻击");
  assert.equal(hidden(el.attackGpu), false, "③ 显卡加速破解");
});

test("验收 8b：AES 文件只有「显卡加速破解」一个按钮", async () => {
  const mod = await loadApp();
  const { el } = mod;

  resetAll(mod);
  setupSingle(mod, aesInfo);

  assert.equal(hidden(el.attackCard), true, "ZipCrypto 卡片不该出现");
  assert.equal(hidden(el.gpuCard), false, "GPU 卡片要出现");
  assert.equal(el.gpuOpen.textContent, "显卡加速破解");
});

test("验收 8c：混合文件三个按钮都在，快速检测与明文攻击只认 ZipCrypto 条目", async () => {
  const mod = await loadApp();
  const { el, state } = mod;

  resetAll(mod);
  setupSingle(mod, mixedInfo);

  assert.equal(hidden(el.attackCard), false);
  assert.equal(hidden(el.quickCrack), false);
  assert.equal(hidden(el.attackOpen), false);
  assert.equal(hidden(el.attackGpu), false);
  assert.equal(hidden(el.gpuCard), false, "混合文件两张卡都露脸");

  // 明文攻击的目标条目下拉框只列 ZipCrypto 条目。
  const names = el.attackEntry.children.map((o) => o.value);
  assert.deepEqual(names, ["a.txt"]);
  assert.equal(state.attack.zipEntries.length, 1);
});

test("验收 8d：混合文件点「显卡加速破解」，下拉框列出所有可攻击条目", async () => {
  const mod = await loadApp();
  const { el } = mod;

  const calls = installBackend({});
  resetAll(mod);
  setupSingle(mod, mixedInfo);

  await mod.openGpuFromAttackCard();

  assert.equal(hidden(el.gpuPanel), false, "面板要展开");
  assert.equal(hidden(el.gpuEntryField), false, "多候选时要出现目标条目下拉框");
  const names = el.gpuEntry.children.map((o) => o.value);
  assert.deepEqual(names, ["a.txt", "c.txt"], "ZipCrypto 和 AES 条目都要列出来");
  assert.equal(calls.extract[0], "C:/tmp/target.zip");
  assert.equal(calls.extract[1], "a.txt", "默认提交第一个条目");

  clearBackend();
});

test("验收 9：tooltip 原文包含 hashcat", async () => {
  const mod = await loadApp();
  const { el } = mod;

  resetAll(mod);
  mod.state.gpu.available = true;
  setupSingle(mod, zipCryptoInfo);

  const expected =
    "使用 hashcat 调用 GPU 加速破解，适合快速弱密码检测未命中的情况。需要先在设置中配置 hashcat 路径。";
  assert.equal(el.attackGpu.title, expected);
  assert.equal(el.gpuOpen.title, expected);
  assert.match(el.attackGpu.title, /hashcat/);

  mod.state.gpu.available = false;
});

test("验收 10：未配置 hashcat 时按钮禁用，tooltip 追加「（当前未检测到 hashcat）」", async () => {
  const mod = await loadApp();
  const { el } = mod;

  resetAll(mod);
  mod.state.gpu.available = false;
  setupSingle(mod, zipCryptoInfo);

  assert.equal(el.attackGpu.disabled, true, "没 hashcat 就不能点");
  assert.equal(el.gpuOpen.disabled, true);
  assert.match(el.attackGpu.title, /hashcat/);
  assert.match(el.attackGpu.title, /（当前未检测到 hashcat）$/);
  assert.equal(hidden(el.gpuDisabledHint), false, "缺 hashcat 的提示要显示");
  assert.equal(el.gpuDisabledHint.textContent, "未找到 hashcat，请在设置中指定路径");
});

// ------------------------------------------------- 快速检测的位数范围

test("验收 11：位数改成 4–6 后，破解范围就是 4–6", async () => {
  const mod = await loadApp();
  const { el, state } = mod;

  const calls = installBackend({});
  resetAll(mod);
  setupSingle(mod, zipCryptoInfo);

  el.quickMinLen.value = "4";
  el.quickMaxLen.value = "6";

  await mod.quickCrack();

  assert.deepEqual(calls.crackOne, ["C:/tmp/target.zip", 4, 6], "必须把 4 和 6 传给后端");
  assert.match(el.quickNote.textContent, /4–6 位/);

  clearBackend();
});

test("位数默认是 6–8", async () => {
  const mod = await loadApp();
  const { el } = mod;

  const calls = installBackend({});
  resetAll(mod);
  setupSingle(mod, zipCryptoInfo);

  // resetAll 把两个输入框恢复成 6 / 8
  assert.equal(el.quickMinLen.value, "6");
  assert.equal(el.quickMaxLen.value, "8");

  await mod.quickCrack();
  assert.deepEqual(calls.crackOne, ["C:/tmp/target.zip", 6, 8]);

  clearBackend();
});

test("位数越界要被夹到 1–12，且保证 min ≤ max", async () => {
  const mod = await loadApp();
  const { el } = mod;

  resetAll(mod);

  el.quickMinLen.value = "0";
  el.quickMaxLen.value = "99";
  assert.deepEqual(mod.readQuickRange(), { minLen: 1, maxLen: 12 });
  assert.equal(el.quickMinLen.value, "1");
  assert.equal(el.quickMaxLen.value, "12");

  // 最小位数比最大位数大时，把最大位数抬上去，而不是报错。
  el.quickMinLen.value = "9";
  el.quickMaxLen.value = "3";
  assert.deepEqual(mod.readQuickRange(), { minLen: 9, maxLen: 9 });

  // 非数字 / 空值：失焦后恢复「上一次的合法值」，不弹窗也不跳回默认值。
  el.quickMinLen.value = "abc";
  el.quickMaxLen.value = "";
  assert.deepEqual(mod.readQuickRange(), { minLen: 9, maxLen: 9 });
  assert.equal(el.quickMinLen.value, "9");
  assert.equal(el.quickMaxLen.value, "9");
});

test("位数设到 10 位以上时显示黄色提示", async () => {
  const mod = await loadApp();
  const { el } = mod;

  resetAll(mod);

  el.quickMaxLen.value = "9";
  mod.readQuickRange();
  assert.equal(hidden(el.quickSlowHint), true, "9 位还不提示");

  el.quickMaxLen.value = "10";
  mod.readQuickRange();
  assert.equal(hidden(el.quickSlowHint), false, "10 位要提示");

  el.quickMaxLen.value = "8";
  mod.readQuickRange();
  assert.equal(hidden(el.quickSlowHint), true);
});

test("▾ 展开 / 收起位数设置，并同步 aria-expanded", async () => {
  const mod = await loadApp();
  const { el } = mod;

  resetAll(mod);
  setupSingle(mod, zipCryptoInfo);

  assert.equal(hidden(el.quickRange), true);
  assert.equal(el.quickRangeBtn.getAttribute("aria-expanded"), "false");

  mod.toggleQuickRange();
  assert.equal(hidden(el.quickRange), false);
  assert.equal(el.quickRangeBtn.getAttribute("aria-expanded"), "true");

  mod.toggleQuickRange();
  assert.equal(hidden(el.quickRange), true);
  assert.equal(el.quickRangeBtn.getAttribute("aria-expanded"), "false");
});

test("换文件时位数面板收起，但输入框里的值保留", async () => {
  const mod = await loadApp();
  const { el } = mod;

  resetAll(mod);
  el.quickMinLen.value = "3";
  el.quickMaxLen.value = "5";
  mod.toggleQuickRange();
  assert.equal(hidden(el.quickRange), false);

  mod.resetForNewFlow();

  assert.equal(hidden(el.quickRange), true, "面板要收起");
  assert.equal(el.quickMinLen.value, "3", "值不能丢");
  assert.equal(el.quickMaxLen.value, "5");
});

// ------------------------------------------- 批量视图的基本行为（回归）

test("批量视图：5 ZIP + 2 RAR 显示 7 行，破解只提交 5 个 ZIP", async () => {
  const mod = await loadApp();
  const { state, onFilesDropped, startBatch } = mod;

  const files = {};
  const dropped = [];
  for (let i = 1; i <= 5; i += 1) {
    files[`C:/tmp/${i}.zip`] = zipOk;
    dropped.push(`C:/tmp/${i}.zip`);
  }
  for (let i = 1; i <= 2; i += 1) {
    files[`C:/tmp/${i}.rar`] = notZip;
    dropped.push(`C:/tmp/${i}.rar`);
  }
  const calls = installBackend({ files });

  resetAll(mod);
  await onFilesDropped(dropped);
  await tick(20);

  assert.equal(state.files.length, 7, "7 个文件都要显示出来");
  assert.equal(state.files.filter((f) => f.status === "waiting").length, 5);
  assert.equal(state.files.filter((f) => f.status === "separate").length, 2);
  assert.equal(statusOf(mod, "C:/tmp/1.rar"), "需单独处理（RAR/7z）");

  await startBatch();

  assert.deepEqual(
    calls.startBatch,
    ["C:/tmp/1.zip", "C:/tmp/2.zip", "C:/tmp/3.zip", "C:/tmp/4.zip", "C:/tmp/5.zip"],
    "只把等待中的 5 个 ZIP 交给后端",
  );
  assert.equal(state.batch.total, 5);

  const skipped = state.results.filter((r) => r.kind === "skip");
  assert.equal(skipped.length, 2, "RAR 在结果列表里各占一行");

  clearBackend();
});

test("批量视图：1 ZIP + 1 PNG，PNG 置灰不阻塞", async () => {
  const mod = await loadApp();
  const { state, onFilesDropped, startBatch } = mod;

  const calls = installBackend({
    files: { "C:/tmp/a.zip": zipOk, "C:/tmp/pic.png": notZip },
  });

  resetAll(mod);
  await onFilesDropped(["C:/tmp/a.zip", "C:/tmp/pic.png"]);
  await tick(20);

  assert.equal(state.files.length, 2);
  assert.equal(statusOf(mod, "C:/tmp/pic.png"), "已忽略（非压缩包）");

  const refs = state.fileRows.get("C:/tmp/pic.png");
  assert.equal(refs.tr.classList.contains("row-ignored"), true, "已忽略的行要置灰");

  await startBatch();
  assert.deepEqual(calls.startBatch, ["C:/tmp/a.zip"]);

  clearBackend();
});

test("批量视图：同名不同目录的两个文件都显示", async () => {
  const mod = await loadApp();
  const { state, onFilesDropped } = mod;

  installBackend({ files: { "C:/a/report.zip": zipOk, "C:/b/report.zip": zipOk } });

  resetAll(mod);
  await onFilesDropped(["C:/a/report.zip", "C:/b/report.zip"]);
  await tick(20);

  assert.deepEqual(state.files.map((f) => f.path), ["C:/a/report.zip", "C:/b/report.zip"]);

  clearBackend();
});

test("批量视图：需单独处理 → 单文件 → 返回批量，列表还在", async () => {
  const mod = await loadApp();
  const { state, onFilesDropped } = mod;

  installBackend({ files: { "C:/tmp/a.zip": zipOk, "C:/tmp/b.rar": notZip } });

  resetAll(mod);
  await onFilesDropped(["C:/tmp/a.zip", "C:/tmp/b.rar"]);
  await tick(20);
  const resultsBefore = state.results;

  assert.equal(statusOf(mod, "C:/tmp/b.rar"), "需单独处理（RAR/7z）");

  await mod.showSingle("C:/tmp/b.rar", true);
  assert.equal(state.view, "single");
  assert.equal(state.detailFromBatch, true);

  mod.backToBatch();
  assert.equal(state.view, "batch");
  assert.equal(state.files.length, 2, "批量列表不能被清空");
  assert.equal(state.results, resultsBefore, "批量结果不能被清空");
  assert.equal(statusOf(mod, "C:/tmp/b.rar"), "已处理");

  clearBackend();
});

test("全部是「已忽略」时才提示没有可处理的压缩包", async () => {
  const mod = await loadApp();
  const { state, el, onFilesDropped } = mod;

  installBackend({ files: { "C:/tmp/a.png": notZip, "C:/tmp/b.txt": notZip } });

  resetAll(mod);
  await onFilesDropped(["C:/tmp/a.png", "C:/tmp/b.txt"]);
  await tick(20);

  assert.equal(state.files.length, 2);
  assert.equal(state.files.every((f) => f.status === "ignored"), true);
  assert.match(el.fileSummary.textContent, /0 个等待破解/);

  assert.equal(el.start.disabled, true);
  assert.match(el.start.title, /没有可处理的压缩包/);

  clearBackend();
});

test("批量视图里的「+ 添加文件」仍然走追加（按钮入口，不是拖放）", async () => {
  const mod = await loadApp();
  const { state } = mod;

  installBackend({ files: { "C:/tmp/a.zip": zipOk, "C:/tmp/b.zip": zipOk } });

  resetAll(mod);
  await mod.showBatch(["C:/tmp/a.zip"]);
  assert.equal(state.files.length, 1);

  await mod.appendToBatch(["C:/tmp/b.zip"]);
  assert.deepEqual(state.files.map((f) => f.path), ["C:/tmp/a.zip", "C:/tmp/b.zip"]);

  // 同一个文件再加一次要被去重。
  const res = await mod.appendToBatch(["C:/tmp/b.zip"]);
  assert.equal(res.added.length, 0);
  assert.deepEqual(res.duplicates, ["C:/tmp/b.zip"]);

  clearBackend();
});

// ================================================= 静态结构（读 index.html）

// DOM 桩里没有真实 HTML，所以文案、id、属性这些只能直接读源文件来钉住。
const html = fs.readFileSync(path.join(FRONTEND, "index.html"), "utf8");

test("左上角 logo 是可点按钮，tooltip 是「返回初始状态」，引用的是 assets 里的图标", () => {
  assert.match(html, /<button id="brand-home"[^>]*title="返回初始状态"/);
  assert.match(html, /<img src="\/assets\/appicon\.png"/);
  // 图标必须放在 frontend/ 下才能被 //go:embed all:frontend 打进产物；
  // build/appicon.png 只用于生成平台图标，不在嵌入范围里。
  assert.ok(fs.existsSync(path.join(FRONTEND, "assets", "appicon.png")));
});

test("顶部短提示容器存在", () => {
  assert.match(html, /<div id="toast"/);
});

test("ZipCrypto 卡片：三按钮平铺 + ▾ 位数入口", () => {
  const card = html.slice(html.indexOf('id="attack-card"'), html.indexOf('id="attack-panel"'));
  assert.match(card, /id="quick-crack"[^>]*>快速弱密码检测</);
  assert.match(card, /id="quick-range-btn"[^>]*>▾</);
  assert.match(card, /id="attack-open"[^>]*>开始明文攻击</);
  assert.match(card, /id="attack-gpu"[^>]*>显卡加速破解</);
});

test("位数输入框：默认 6–8，范围 1–12", () => {
  assert.match(html, /id="quick-min-len"[^>]*min="1"[^>]*max="12"[^>]*value="6"/);
  assert.match(html, /id="quick-max-len"[^>]*min="1"[^>]*max="12"[^>]*value="8"/);
});

test("10 位以上的黄色提示文案在 HTML 里", () => {
  const m = html.match(/id="quick-slow-hint"[^>]*>([^<]+)</);
  assert.ok(m, "找不到 #quick-slow-hint");
  assert.match(m[1], /纯数字 10 位以上/);
  assert.match(m[1], /数分钟/);
  assert.match(m[1], /显卡加速破解/);
});

test("界面统一用「显卡加速破解」，hashcat 只留在 tooltip / 设置里", () => {
  // 按钮文案
  assert.equal((html.match(/>显卡加速破解</g) || []).length, 2, "两张卡各一个按钮");
  // 旧文案不能残留
  assert.ok(!html.includes("提取哈希并启动 hashcat"), "旧按钮文案要清掉");
  assert.ok(!html.includes("GPU 恢复</button>"), "按钮上不能写 GPU 恢复");
});

test("GPU 面板有目标条目下拉框", () => {
  assert.match(html, /id="gpu-entry-field"/);
  assert.match(html, /<select id="gpu-entry"/);
});
