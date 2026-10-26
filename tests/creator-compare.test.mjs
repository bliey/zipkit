// 「来源对比」（明文攻击面板）的渲染层单测。
//
// 跑的是真实的 frontend/app.js —— 用 dom-stub 提供够用的 DOM，用
// prepareAppModule 把三个裸导入换掉并把内部函数导出。这样改名、漏引入、
// 调错方法都会在这里炸，而不是等到界面上。
//
// 钉住的行为：
//   一、四种 verdict 分别落到 ok / warn / muted 三个样式类；
//   二、两个文件块都显示「识别结果 / 置信度 / 依据」，Version 为空时不出现
//       version made by；
//   三、hideCreatorCompare 会清空并隐藏；
//   四、非「明文 ZIP」模式、以及切换明文形式时会收起来源对比；
//   五、来源对比失败只留一行灰字，不抛错、不拦攻击。
//
//   node --test tests/creator-compare.test.mjs

import test from "node:test";
import assert from "node:assert/strict";
import path from "node:path";
import { pathToFileURL } from "node:url";

import {
  installDom,
  prepareAppModule,
  writeRuntimeStub,
} from "./dom-stub.mjs";

const ROOT = path.resolve(import.meta.dirname, "..");
const FRONTEND = path.join(ROOT, "frontend");

// ------------------------------------------------------------------ fixture

// creator 的字段形状取自 Go 侧 zipservice.Creator 的 json tag（全小写驼峰）。
function creator(overrides = {}) {
  return {
    name: "WinRAR",
    version: "6.3（FAT）",
    confidence: "high",
    evidence: "GPBF=0x000B（加密 + bit1 + 数据描述符），Bandizip 特征写法",
    ...overrides,
  };
}

function pair(overrides = {}) {
  return {
    encrypted: creator(),
    plain: creator(),
    verdict: "same",
    message: "两者来源一致（WinRAR），建议直接尝试攻击。",
    ...overrides,
  };
}

// ------------------------------------------------------------------ 桩工具

// 桩里的 className 只是普通字符串，不会同步到 classList，两个都要看。
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

// hasClass 同时看 className 字符串与 classList：app.js 里两种写法都有
// （verdict 用 className 赋值，show() 用 classList.toggle）。
function hasClass(node, name) {
  if (!node) return false;
  if (String(node.className || "").split(/\s+/).includes(name)) return true;
  return Boolean(node.classList && node.classList.contains(name));
}

function collectText(node, out = []) {
  if (!node) return out;
  if (typeof node.textContent === "string" && node.textContent) out.push(node.textContent);
  for (const child of node.children || []) collectText(child, out);
  return out;
}

function textOf(node) {
  return collectText(node).join("|");
}

let appPromise = null;

async function loadApp() {
  if (!appPromise) {
    installDom();
    const { dir, entry } = prepareAppModule(FRONTEND, [
      "state",
      "el",
      "renderCreatorCompare",
      "renderCreatorCompareNotice",
      "hideCreatorCompare",
      "runCreatorCompare",
      "runPrecheck",
      "onPlainModeChange",
    ]);
    writeRuntimeStub(dir);
    appPromise = import(pathToFileURL(entry).href).then(async (mod) => {
      await new Promise((r) => setTimeout(r, 50));
      return mod;
    });
  }
  return appPromise;
}

// setup 把「已选中一个加密包 + 一个明文 ZIP」的前置条件摆好。
async function setup({ cipher = "C:\\vault\\secret.zip", plain = "D:\\work\\plain.zip" } = {}) {
  const mod = await loadApp();
  mod.state.path = cipher;
  mod.el.attackPlainPath.value = plain;
  mod.el.attackEntry.value = "docs/report.csv";
  mod.el.attackCreator.textContent = "";
  mod.el.attackCreator.classList.remove("hidden");
  return mod;
}

// ================================================== 一、四种结论的样式

test("renderCreatorCompare：一致 → ok 绿，文案含「一致」", async () => {
  const mod = await setup();
  mod.renderCreatorCompare(pair());

  const verdicts = collectByClass(mod.el.attackCreator, "creator-verdict");
  assert.equal(verdicts.length, 1);
  assert.ok(hasClass(verdicts[0], "ok"), "一致应落到 ok");
  assert.ok(!hasClass(verdicts[0], "warn"));
  assert.match(verdicts[0].textContent, /两者来源一致/);
  assert.match(verdicts[0].textContent, /WinRAR/);

  // 显示出来（没有 hidden）
  assert.ok(!mod.el.attackCreator.classList.contains("hidden"));
});

test("renderCreatorCompare：不一致 → warn 黄，文案点出双方来源", async () => {
  const mod = await setup();
  mod.renderCreatorCompare(
    pair({
      plain: creator({ name: "7-Zip", evidence: "GPBF=0x0001 + Deflate" }),
      verdict: "differ",
      message: "两者来源不一致（加密=WinRAR，明文=7-Zip），明文攻击成功率可能较低。",
    }),
  );

  const verdict = collectByClass(mod.el.attackCreator, "creator-verdict")[0];
  assert.ok(hasClass(verdict, "warn"), "不一致应落到 warn");
  assert.match(verdict.textContent, /不一致/);
  assert.match(verdict.textContent, /WinRAR/);
  assert.match(verdict.textContent, /7-Zip/);
});

test("renderCreatorCompare：置信度不够 → muted 灰，不给一致性结论", async () => {
  const mod = await setup();
  mod.renderCreatorCompare(
    pair({
      encrypted: creator({ confidence: "medium", name: "360压缩 / 7-Zip" }),
      verdict: "unsure",
      message: "来源识别置信度较低，仅供参考；请以 Precheck 的压缩方式与 CRC 比对为准。",
    }),
  );

  const verdict = collectByClass(mod.el.attackCreator, "creator-verdict")[0];
  assert.ok(hasClass(verdict, "muted"), "unsure 应落到 muted");
  assert.ok(!hasClass(verdict, "ok"));
  assert.ok(!hasClass(verdict, "warn"));
  assert.match(verdict.textContent, /仅供参考/);
  // 不能出现「一致」这种结论
  assert.ok(!verdict.textContent.includes("两者来源一致"));
});

test("renderCreatorCompare：来源未知 → muted 灰，不做判断", async () => {
  const mod = await setup();
  mod.renderCreatorCompare(
    pair({
      encrypted: creator({ name: "Unknown", confidence: "unknown", version: "", evidence: "" }),
      verdict: "unknown",
      message: "来源未知，不做一致性判断；仍可直接尝试攻击。",
    }),
  );

  const verdict = collectByClass(mod.el.attackCreator, "creator-verdict")[0];
  assert.ok(hasClass(verdict, "muted"));
  assert.match(verdict.textContent, /来源未知/);
  assert.match(verdict.textContent, /不做一致性判断/);
});

// ================================================== 二、文件块的字段

test("renderCreatorCompare：两个文件块都有识别结果 / 置信度 / 依据", async () => {
  const mod = await setup();
  mod.renderCreatorCompare(
    pair({
      encrypted: creator({
        name: "WinRAR",
        confidence: "high",
        version: "6.3（FAT）",
        evidence: "GPBF=0x000B + Deflate",
      }),
      plain: creator({
        name: "7-Zip",
        confidence: "medium",
        version: "",
        evidence: "GPBF=0x0001 + Deflate",
      }),
      verdict: "unsure",
      message: "来源识别置信度较低，仅供参考。",
    }),
  );

  const blocks = collectByClass(mod.el.attackCreator, "creator-file");
  assert.equal(blocks.length, 2, "应当有两个文件块");

  const [encBlock, plainBlock] = blocks;

  // 标题行带文件名（标题文字与文件名是两个节点，分开断言）
  assert.match(textOf(collectByClass(encBlock, "creator-file-title")[0]), /加密文件：/);
  assert.equal(collectByClass(encBlock, "creator-file-name")[0].textContent, "secret.zip");
  assert.match(textOf(collectByClass(plainBlock, "creator-file-title")[0]), /明文文件：/);
  assert.equal(collectByClass(plainBlock, "creator-file-name")[0].textContent, "plain.zip");

  // 识别结果 + 中文置信度
  const encResult = collectByClass(encBlock, "creator-file-result")[0];
  assert.match(encResult.textContent, /识别结果：WinRAR/);
  assert.match(encResult.textContent, /置信度：高/);
  // Version 有值时要带上 version made by
  assert.match(encResult.textContent, /version made by 6\.3（FAT）/);

  const plainResult = collectByClass(plainBlock, "creator-file-result")[0];
  assert.match(plainResult.textContent, /识别结果：7-Zip/);
  assert.match(plainResult.textContent, /置信度：中/);
  // Version 为空时不能出现 version made by
  assert.ok(
    !plainResult.textContent.includes("version made by"),
    "Version 为空时不该输出 version made by",
  );

  // 依据
  assert.match(collectByClass(encBlock, "creator-file-evidence")[0].textContent, /依据：GPBF=0x000B/);
  assert.match(collectByClass(plainBlock, "creator-file-evidence")[0].textContent, /依据：GPBF=0x0001/);
});

test("creatorFileBlock：依据为空时给破折号而不是「undefined」", async () => {
  const mod = await setup();
  mod.renderCreatorCompare(
    pair({
      encrypted: creator({ evidence: "" }),
      plain: creator({ evidence: null }),
      verdict: "unsure",
      message: "仅供参考。",
    }),
  );

  const blocks = collectByClass(mod.el.attackCreator, "creator-file");
  for (const block of blocks) {
    const evidence = collectByClass(block, "creator-file-evidence")[0];
    assert.equal(evidence.textContent, "依据：—");
    assert.ok(!evidence.textContent.includes("undefined"));
  }
});

test("renderCreatorCompare：置信度用中文标签，未知值原样兜底", async () => {
  const mod = await setup();
  mod.renderCreatorCompare(
    pair({
      encrypted: creator({ confidence: "low" }),
      plain: creator({ confidence: "weird" }),
      verdict: "unsure",
      message: "仅供参考。",
    }),
  );

  const results = collectByClass(mod.el.attackCreator, "creator-file-result");
  assert.match(results[0].textContent, /置信度：低/);
  // 未登记的值不能变成 undefined
  assert.match(results[1].textContent, /置信度：weird/);
  assert.ok(!results[1].textContent.includes("undefined"));
});

// ================================================== 三、收起与降级

test("hideCreatorCompare：清空内容并隐藏", async () => {
  const mod = await setup();
  mod.renderCreatorCompare(pair());
  assert.ok(mod.el.attackCreator.children.length > 0);

  mod.hideCreatorCompare();
  assert.equal(mod.el.attackCreator.children.length, 0);
  assert.equal(mod.el.attackCreator.textContent, "");
  assert.ok(mod.el.attackCreator.classList.contains("hidden"));
});

test("renderCreatorCompare：pair 缺字段时直接收起，不画半截", async () => {
  const mod = await setup();

  for (const bad of [null, undefined, {}, { encrypted: creator() }, { plain: creator() }]) {
    mod.el.attackCreator.textContent = "";
    mod.el.attackCreator.classList.remove("hidden");
    mod.renderCreatorCompare(bad);
    assert.equal(mod.el.attackCreator.children.length, 0, `pair=${JSON.stringify(bad)} 应被收起`);
    assert.ok(mod.el.attackCreator.classList.contains("hidden"));
  }
});

test("renderCreatorCompareNotice：只留一行灰字，不画文件块", async () => {
  const mod = await setup();
  mod.renderCreatorCompareNotice("来源对比不可用：boom");

  assert.equal(collectByClass(mod.el.attackCreator, "creator-file").length, 0);
  assert.equal(collectByClass(mod.el.attackCreator, "creator-verdict").length, 0);

  const notice = collectByClass(mod.el.attackCreator, "creator-notice")[0];
  assert.ok(notice, "要有 creator-notice 这一行");
  assert.equal(notice.textContent, "来源对比不可用：boom");
  assert.ok(!mod.el.attackCreator.classList.contains("hidden"));
});

// ================================================== 四、与 Precheck 的关系

test("runCreatorCompare：成功后按 DetectCreators 的结果渲染", async () => {
  const mod = await setup();

  const calls = [];
  globalThis.__zipkitCall = async (name, ...args) => {
    calls.push([name, ...args]);
    if (name.endsWith(".DetectCreators")) {
      return pair({ verdict: "differ", message: "两者来源不一致（加密=WinRAR，明文=7-Zip）。" });
    }
    return {};
  };

  await mod.runCreatorCompare("D:\\work\\plain.zip");

  assert.equal(calls.length, 1);
  assert.equal(
    calls[0][0],
    "github.com/bliey/zipkit/internal/attack.AttackService.DetectCreators",
  );
  // 两个参数分别是加密包与明文包
  assert.equal(calls[0][1], "C:\\vault\\secret.zip");
  assert.equal(calls[0][2], "D:\\work\\plain.zip");

  const verdict = collectByClass(mod.el.attackCreator, "creator-verdict")[0];
  assert.ok(hasClass(verdict, "warn"));
});

test("runCreatorCompare：后端报错只留一行灰字，不抛异常", async () => {
  const mod = await setup();

  globalThis.__zipkitCall = async () => {
    throw new Error("识别加密包的来源失败：文件读不到");
  };

  // 不 reject 才算合格——它必须自己吞掉错误
  await mod.runCreatorCompare("D:\\work\\plain.zip");

  const notice = collectByClass(mod.el.attackCreator, "creator-notice")[0];
  assert.ok(notice, "失败时要有一行说明");
  assert.match(notice.textContent, /来源对比不可用/);
  assert.match(notice.textContent, /文件读不到/);
  assert.equal(collectByClass(mod.el.attackCreator, "creator-file").length, 0);
});

test("runCreatorCompare：没有加密包或没有明文包时直接收起，不调后端", async () => {
  const mod = await setup();

  let called = 0;
  globalThis.__zipkitCall = async () => {
    called += 1;
    return pair();
  };

  // 缺明文包
  await mod.runCreatorCompare("");
  assert.equal(called, 0);
  assert.ok(mod.el.attackCreator.classList.contains("hidden"));

  // 缺加密包
  mod.state.path = "";
  await mod.runCreatorCompare("D:\\work\\plain.zip");
  assert.equal(called, 0);
  assert.ok(mod.el.attackCreator.classList.contains("hidden"));
});

test("runPrecheck：非「明文 ZIP」模式要立刻收起来源对比", async () => {
  const mod = await setup();
  mod.renderCreatorCompare(pair());
  assert.ok(!mod.el.attackCreator.classList.contains("hidden"));

  // 桩里 document.querySelector 返回 null，currentPlainMode() 落到 "file"。
  // 只数 DetectCreators：这个模式会照常调 Precheck，那是另一条链路。
  let creatorCalls = 0;
  globalThis.__zipkitCall = async (name) => {
    if (String(name).endsWith(".DetectCreators")) creatorCalls += 1;
    return {};
  };
  await mod.runPrecheck();

  assert.equal(creatorCalls, 0, "独立文件模式不该调 DetectCreators");
  assert.ok(mod.el.attackCreator.classList.contains("hidden"), "独立文件模式要收起来源对比");
  assert.equal(mod.el.attackCreator.children.length, 0);
});

test("onPlainModeChange：切换明文形式会收起来源对比", async () => {
  const mod = await setup();
  mod.renderCreatorCompare(pair());
  assert.ok(!mod.el.attackCreator.classList.contains("hidden"));

  mod.onPlainModeChange();

  assert.ok(mod.el.attackCreator.classList.contains("hidden"));
  assert.equal(mod.el.attackCreator.children.length, 0);
});

test("来源对比不碰 Precheck 的容器，也不影响攻击按钮", async () => {
  const mod = await setup();

  // 摆一个「正在显示」的 Precheck，确认来源对比不把它清掉
  mod.el.attackPrecheck.textContent = "";
  const line = document.createElement("p");
  line.textContent = "预检通过";
  mod.el.attackPrecheck.appendChild(line);
  mod.el.attackPrecheck.classList.remove("hidden");

  mod.renderCreatorCompare(pair());

  assert.equal(mod.el.attackPrecheck.children.length, 1, "Precheck 的内容不该被清");
  assert.equal(textOf(mod.el.attackPrecheck), "预检通过");
  assert.ok(!mod.el.attackPrecheck.classList.contains("hidden"));

  // 反过来，收起来源对比也不该动 Precheck
  mod.hideCreatorCompare();
  assert.equal(mod.el.attackPrecheck.children.length, 1);
  assert.ok(!mod.el.attackPrecheck.classList.contains("hidden"));

  // 攻击按钮的 disabled 状态由 Precheck 决定，来源对比全程不参与
  const before = mod.el.attackStart ? mod.el.attackStart.disabled : undefined;
  mod.renderCreatorCompare(pair({ verdict: "differ", message: "不一致。" }));
  const after = mod.el.attackStart ? mod.el.attackStart.disabled : undefined;
  assert.equal(after, before, "来源对比不能改动攻击按钮");
});
