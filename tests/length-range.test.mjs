// 「最小位数 – 最大位数」范围控件的单元测试（无浏览器）。
//
// 界面里三处长度输入（快速弱密码检测 / 批量破解 / 显卡暴力）必须表现完全一致，
// 所以这里把三处放在一起断言：同一组输入必须得到同一组结果，默认值各自不同，
// 上下限都是 1–12。做法与 drop-flow.test.mjs 相同：真 DOM 桩 + 真 app.js。
//
//   node --test tests/length-range.test.mjs

import test from "node:test";
import assert from "node:assert/strict";
import path from "node:path";
import { pathToFileURL } from "node:url";
import { installDom, prepareAppModule, writeRuntimeStub } from "./dom-stub.mjs";

const ROOT = path.resolve(import.meta.dirname, "..");
const FRONTEND = path.join(ROOT, "frontend");

let appPromise = null;

// loadApp 只加载一次：模块顶层会执行 init()，重复导入没有意义。
async function loadApp() {
  if (appPromise) return appPromise;
  installDom();
  const { dir, entry } = prepareAppModule(FRONTEND, [
    "el",
    "state",
    "LEN_MIN",
    "LEN_MAX",
    "BATCH_MIN_DEFAULT",
    "BATCH_MAX_DEFAULT",
    "QUICK_MIN_DEFAULT",
    "QUICK_MAX_DEFAULT",
    "GPU_MIN_DEFAULT",
    "GPU_MAX_DEFAULT",
    "clampLen",
    "readLengthRange",
    "bindLengthRange",
    "readRange",
    "readQuickRange",
    "buildGpuStrategy",
    "onGpuStrategyChange",
  ]);
  writeRuntimeStub(dir);
  appPromise = import(pathToFileURL(entry).href);
  return appPromise;
}

// setStrategy 让 currentGpuStrategy() 读到指定的策略值。
// 桩的 document.querySelector 恒返回 null，这里按需替换再还原。
function setStrategy(kind) {
  const original = globalThis.document.querySelector;
  globalThis.document.querySelector = (selector) =>
    String(selector).includes("gpu-strategy") ? { value: kind } : null;
  return () => {
    globalThis.document.querySelector = original;
  };
}

const hidden = (node) => node.classList.contains("hidden");

// 三处控件统一成「同一组输入 → 同一组输出」，用一张表驱动。
// 每项：[说明, 最小输入, 最大输入, edited, 期望 { minLen, maxLen }]
const SAME_CASES = [
  ["正常范围原样保留", "6", "8", undefined, { minLen: 6, maxLen: 8 }],
  ["下限低于 1 被抬到 1", "0", "8", "min", { minLen: 1, maxLen: 8 }],
  ["上限高于 12 被压到 12", "6", "13", "max", { minLen: 6, maxLen: 12 }],
  ["改最小值超过最大值时最大值跟随", "9", "3", "min", { minLen: 9, maxLen: 9 }],
  ["改最大值低于最小值时最小值跟随", "9", "3", "max", { minLen: 3, maxLen: 3 }],
  ["两端都越界同时收敛", "0", "99", undefined, { minLen: 1, maxLen: 12 }],
  ["单点范围", "7", "7", undefined, { minLen: 7, maxLen: 7 }],
];

test("三处长度控件共用同一套校验：同一组输入得到同一组结果", async () => {
  const mod = await loadApp();
  const { el } = mod;

  for (const [name, min, max, edited, want] of SAME_CASES) {
    // 快速弱密码检测
    el.quickMinLen.value = min;
    el.quickMaxLen.value = max;
    assert.deepEqual(mod.readQuickRange(edited), want, `快速检测：${name}`);

    // 批量破解
    el.minLen.value = min;
    el.maxLen.value = max;
    assert.deepEqual(mod.readRange(edited), want, `批量破解：${name}`);

    // 显卡暴力
    el.gpuMinLen.value = min;
    el.gpuMaxLen.value = max;
    assert.deepEqual(
      mod.readLengthRange(el.gpuMinLen, el.gpuMaxLen, mod.GPU_MIN_DEFAULT, mod.GPU_MAX_DEFAULT, edited),
      want,
      `显卡暴力：${name}`,
    );
  }
});

test("三处默认值分别是 6–8 / 6–8 / 1–8，上下限都是 1–12", async () => {
  const mod = await loadApp();
  const { el } = mod;

  assert.equal(mod.LEN_MIN, 1);
  assert.equal(mod.LEN_MAX, 12);

  assert.equal(mod.QUICK_MIN_DEFAULT, 6);
  assert.equal(mod.QUICK_MAX_DEFAULT, 8);
  assert.equal(mod.BATCH_MIN_DEFAULT, 6);
  assert.equal(mod.BATCH_MAX_DEFAULT, 8);
  assert.equal(mod.GPU_MIN_DEFAULT, 1);
  assert.equal(mod.GPU_MAX_DEFAULT, 8);

  // 输入框为空（等价于用户从没填过）时落回各自的默认值。
  el.quickMinLen.value = "";
  el.quickMaxLen.value = "";
  el.quickMinLen.dataset.last = "";
  el.quickMaxLen.dataset.last = "";
  assert.deepEqual(mod.readQuickRange(), { minLen: 6, maxLen: 8 });

  el.minLen.value = "";
  el.maxLen.value = "";
  el.minLen.dataset.last = "";
  el.maxLen.dataset.last = "";
  assert.deepEqual(mod.readRange(), { minLen: 6, maxLen: 8 });

  el.gpuMinLen.value = "";
  el.gpuMaxLen.value = "";
  el.gpuMinLen.dataset.last = "";
  el.gpuMaxLen.dataset.last = "";
  assert.deepEqual(
    mod.readLengthRange(el.gpuMinLen, el.gpuMaxLen, mod.GPU_MIN_DEFAULT, mod.GPU_MAX_DEFAULT),
    { minLen: 1, maxLen: 8 },
  );
});

test("非法输入失焦后恢复上一次合法值，不弹窗", async () => {
  const mod = await loadApp();
  const { el } = mod;

  // 先跑一次合法值，把「上一次合法值」写进 dataset.last。
  el.quickMinLen.value = "7";
  el.quickMaxLen.value = "9";
  assert.deepEqual(mod.readQuickRange("min"), { minLen: 7, maxLen: 9 });

  // 非数字 / 空值：回到 7 / 9，而不是跳回默认 6 / 8。
  // 注意 "8x" 这类带数字前缀的串会被 parseInt 读成 8，所以这里用纯非数字。
  el.quickMinLen.value = "abc";
  el.quickMaxLen.value = "x9";
  assert.deepEqual(mod.readQuickRange("min"), { minLen: 7, maxLen: 9 });
  assert.equal(el.quickMinLen.value, "7");
  assert.equal(el.quickMaxLen.value, "9");

  el.quickMinLen.value = "";
  el.quickMaxLen.value = "";
  assert.deepEqual(mod.readQuickRange(), { minLen: 7, maxLen: 9 });
});

test("clampLen 对边界与垃圾输入的处理", async () => {
  const mod = await loadApp();

  assert.equal(mod.clampLen("1"), 1);
  assert.equal(mod.clampLen("12"), 12);
  assert.equal(mod.clampLen("0"), 1);
  assert.equal(mod.clampLen("13"), 12);
  assert.equal(mod.clampLen("-5"), 1);
  assert.equal(mod.clampLen(" 6 "), 6);
  assert.equal(mod.clampLen("6.9"), 6);
  assert.equal(mod.clampLen(""), null);
  assert.equal(mod.clampLen("abc"), null);
  assert.equal(mod.clampLen(undefined), null);
});

test("buildGpuStrategy：暴力策略把 minLen / maxLen 传给后端", async () => {
  const mod = await loadApp();
  const { el } = mod;

  const restore = setStrategy("bruteforce");
  try {
    el.gpuCharset.value = "0123456789";
    el.gpuMinLen.value = "6";
    el.gpuMaxLen.value = "8";
    assert.deepEqual(mod.buildGpuStrategy(), {
      kind: "bruteforce",
      wordlist: "",
      mask: "",
      charset: "0123456789",
      minLen: 6,
      maxLen: 8,
    });

    // 字段名必须是 minLen / maxLen，不能再出现旧的 length。
    const st = mod.buildGpuStrategy();
    assert.equal("length" in st, false, "不能残留单值 length 字段");

    // 越界输入在构造策略时就被夹住。
    el.gpuMinLen.value = "0";
    el.gpuMaxLen.value = "99";
    assert.deepEqual(mod.buildGpuStrategy(), {
      kind: "bruteforce",
      wordlist: "",
      mask: "",
      charset: "0123456789",
      minLen: 1,
      maxLen: 12,
    });

    // 字符集为空时明确报错，而不是把空串发给 hashcat。
    el.gpuCharset.value = "   ";
    assert.throws(() => mod.buildGpuStrategy(), /字符集/);
  } finally {
    restore();
  }
});

test("buildGpuStrategy：掩码与字典不带长度范围", async () => {
  const mod = await loadApp();
  const { el } = mod;

  let restore = setStrategy("mask");
  try {
    el.gpuMask.value = "?d?d?d?d?d?d";
    assert.deepEqual(mod.buildGpuStrategy(), {
      kind: "mask",
      wordlist: "",
      mask: "?d?d?d?d?d?d",
      charset: "",
      minLen: 0,
      maxLen: 0,
    });
  } finally {
    restore();
  }

  restore = setStrategy("dictionary");
  try {
    el.gpuWordlist.value = "C:/tmp/rockyou.txt";
    assert.deepEqual(mod.buildGpuStrategy(), {
      kind: "dictionary",
      wordlist: "C:/tmp/rockyou.txt",
      mask: "",
      charset: "",
      minLen: 0,
      maxLen: 0,
    });
  } finally {
    restore();
  }
});

test("长度范围只在暴力策略下出现，掩码策略下隐藏", async () => {
  const mod = await loadApp();
  const { el } = mod;

  let restore = setStrategy("bruteforce");
  try {
    mod.onGpuStrategyChange();
    assert.equal(hidden(el.gpuLenField), false, "暴力策略要显示长度范围");
    assert.equal(hidden(el.gpuCharsetField), false);
    assert.equal(hidden(el.gpuMaskField), true);
  } finally {
    restore();
  }

  restore = setStrategy("mask");
  try {
    mod.onGpuStrategyChange();
    assert.equal(hidden(el.gpuLenField), true, "掩码策略要隐藏长度范围");
    assert.equal(hidden(el.gpuMaskField), false);
    assert.equal(hidden(el.gpuCharsetField), true);
  } finally {
    restore();
  }
});

test("bindLengthRange 在 change 时校正并回调", async () => {
  const mod = await loadApp();
  const { el } = mod;

  // 桩的 addEventListener 是空实现，这里自己收集回调再手动触发。
  const handlers = new Map();
  const fake = (node, key) => ({
    value: node.value,
    dataset: node.dataset,
    addEventListener: (type, fn) => handlers.set(`${key}:${type}`, fn),
  });
  const minEl = fake(el.quickMinLen, "min");
  const maxEl = fake(el.quickMaxLen, "max");
  minEl.value = "6";
  maxEl.value = "8";

  const seen = [];
  mod.bindLengthRange(minEl, maxEl, {
    defMin: 6,
    defMax: 8,
    onInput: ({ minLen, maxLen }) => seen.push([minLen, maxLen]),
  });

  assert.equal(minEl.dataset.last, "6");
  assert.equal(maxEl.dataset.last, "8");

  minEl.value = "11";
  handlers.get("min:change")();
  assert.deepEqual(seen.at(-1), [11, 11], "改最小值超过最大值时最大值跟随");
  assert.equal(maxEl.value, "11");

  maxEl.value = "2";
  handlers.get("max:change")();
  assert.deepEqual(seen.at(-1), [2, 2], "改最大值低于最小值时最小值跟随");
  assert.equal(minEl.value, "2");
});
