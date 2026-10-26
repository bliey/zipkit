// 拖放语义规则表的单测（Node 内置 test runner，无第三方依赖）。
//
//   node --test tests/
//
// 这里只测纯逻辑：把「界面状态快照 → 拖放语义」这张表钉死。DOM 接线和
// 业务函数的调用顺序不在覆盖范围内。

import test from "node:test";
import assert from "node:assert/strict";

import {
  DropAction,
  MAX_DROP_DEPTH,
  archiveLike,
  dropActionOf,
  dropHintText,
  expandDropPaths,
  fileNoticeOf,
  isSeparate,
  noticeLabel,
  zipLike,
} from "../frontend/drop-rules.js";

// base 是一份「初始状态」快照：没有任何任务、不在等明文。
const base = {
  awaitingPlaintext: false,
  hasPlain: false,
  taskRunning: false,
  count: 1,
};

const snap = (patch) => ({ ...base, ...patch });

// ------------------------------------------------------------ 拖放：二元规则
//
// 规则只有两条，没有第三种行为：
//   awaitingPlaintext === true  → 填明文
//   其余一切                    → 开始新流程
//
// 下面每个用例都对应界面上的一个具体状态，注释里写清是哪个状态，
// 这样改 app.js 的接线时能对上号。

test("初始状态（未选择文件）：开新流程", () => {
  const a = dropActionOf(snap({ count: 2 }));
  assert.equal(a.kind, DropAction.NewFlow);
  assert.equal(a.terminate, false);
});

test("单文件视图侦察完成：仍然是开新流程，不是替换", () => {
  // 侦察完成后没有任何任务在跑，所以不弹确认，直接换文件。
  const a = dropActionOf(snap({ count: 1 }));
  assert.equal(a.kind, DropAction.NewFlow);
  assert.equal(a.terminate, false);
});

test("批量视图：开新流程，不做追加", () => {
  const a = dropActionOf(snap({ count: 3 }));
  assert.equal(a.kind, DropAction.NewFlow);
  assert.equal(a.terminate, false);
});

test("伪加密结果展示中：开新流程", () => {
  const a = dropActionOf(snap({ count: 1 }));
  assert.equal(a.kind, DropAction.NewFlow);
});

test("hashcat 面板展开（未运行）：开新流程", () => {
  // 只有「明文攻击面板展开」才算等明文；hashcat 面板不算。
  const a = dropActionOf(snap({ count: 1 }));
  assert.equal(a.kind, DropAction.NewFlow);
});

test("批量破解进行中：开新流程，并且要求先确认终止", () => {
  const a = dropActionOf(snap({ taskRunning: true, count: 2 }));
  assert.equal(a.kind, DropAction.NewFlow);
  assert.equal(a.terminate, true);
});

test("解压进行中：开新流程 + 确认终止", () => {
  const a = dropActionOf(snap({ taskRunning: true, count: 1 }));
  assert.equal(a.kind, DropAction.NewFlow);
  assert.equal(a.terminate, true);
});

test("hashcat 运行中：开新流程 + 确认终止", () => {
  const a = dropActionOf(snap({ taskRunning: true, count: 1 }));
  assert.equal(a.kind, DropAction.NewFlow);
  assert.equal(a.terminate, true);
});

test("明文攻击运行中：开新流程 + 确认终止（不再是忽略）", () => {
  // 攻击一开跑，app.js 就把 awaitingPlaintext 强制置回 false，
  // 所以这里拿到的快照就是 awaitingPlaintext=false + taskRunning=true。
  const a = dropActionOf(snap({ awaitingPlaintext: false, taskRunning: true, count: 1 }));
  assert.equal(a.kind, DropAction.NewFlow);
  assert.equal(a.terminate, true);
});

test("明文攻击面板展开：填明文", () => {
  const a = dropActionOf(snap({ awaitingPlaintext: true }));
  assert.equal(a.kind, DropAction.Plaintext);
  assert.equal(a.replace, false);
  assert.equal(a.extraFiles, false);
});

test("明文面板展开 + 已有明文：标记 replace 以便二次确认", () => {
  const a = dropActionOf(snap({ awaitingPlaintext: true, hasPlain: true }));
  assert.equal(a.kind, DropAction.Plaintext);
  assert.equal(a.replace, true);
});

test("明文面板展开 + 一次拖多个：标记 extraFiles 以便提示只取第一个", () => {
  const a = dropActionOf(snap({ awaitingPlaintext: true, count: 3 }));
  assert.equal(a.kind, DropAction.Plaintext);
  assert.equal(a.extraFiles, true);
});

test("明文面板展开时不会触发「终止任务」确认", () => {
  // 这两个标志互斥：等明文的时候不可能有任务在跑。
  const a = dropActionOf(snap({ awaitingPlaintext: true, taskRunning: true }));
  assert.equal(a.kind, DropAction.Plaintext);
  assert.equal(a.terminate, undefined);
});

test("结果只有两种，不存在第三种行为", () => {
  const combos = [];
  for (const awaitingPlaintext of [false, true]) {
    for (const hasPlain of [false, true]) {
      for (const taskRunning of [false, true]) {
        for (const count of [0, 1, 2, 9]) {
          combos.push({ awaitingPlaintext, hasPlain, taskRunning, count });
        }
      }
    }
  }
  const kinds = new Set(combos.map((c) => dropActionOf(c).kind));
  assert.deepEqual([...kinds].sort(), [DropAction.NewFlow, DropAction.Plaintext].sort());
  assert.equal(kinds.size, 2);
});

test("遮罩文案只有两套：填明文 / 开新流程", () => {
  const plain = dropHintText(dropActionOf(snap({ awaitingPlaintext: true })));
  assert.equal(plain.title, "松开以填入明文文件");
  assert.match(plain.hint, /只接受一个文件/);

  const fresh = dropHintText(dropActionOf(snap({})));
  assert.equal(fresh.title, "松开以开始新流程");
  assert.match(fresh.hint, /单文件视图/);
  assert.match(fresh.hint, /批量视图/);

  // 有任务在跑时文案不变——确认框在松手之后才弹。
  assert.equal(dropHintText(dropActionOf(snap({ taskRunning: true }))).title, "松开以开始新流程");
});

test("快照缺字段时按初始状态处理", () => {
  assert.equal(dropActionOf({}).kind, DropAction.NewFlow);
  assert.equal(dropActionOf(null).kind, DropAction.NewFlow);
  assert.equal(dropActionOf(undefined).kind, DropAction.NewFlow);
  // count 缺失 / 非数字都当 0，不抛异常。
  assert.equal(dropActionOf({ count: "abc" }).kind, DropAction.NewFlow);
  assert.equal(dropActionOf({ awaitingPlaintext: true, count: undefined }).extraFiles, false);
});

test("zipLike 只认白名单扩展名", () => {
  assert.equal(zipLike("a.zip"), true);
  assert.equal(zipLike("A.ZIPX"), true);
  assert.equal(zipLike("a.docx"), true);
  assert.equal(zipLike("a.png"), false);
  assert.equal(zipLike("a.txt"), false);
  assert.equal(zipLike("noext"), false);
  assert.equal(zipLike(""), false);
});

test("archiveLike 认 zip / rar / 7z，不认图片和文本", () => {
  assert.equal(archiveLike("a.zip"), true);
  assert.equal(archiveLike("a.rar"), true);
  assert.equal(archiveLike("a.7z"), true);
  assert.equal(archiveLike("a.png"), false);
  assert.equal(archiveLike("a.txt"), false);
});

// ------------------------------------------------------- 批量行状态（阶段 9）

test("fileNoticeOf：能破解的返回 null", () => {
  assert.equal(fileNoticeOf({ path: "a.zip", applicable: true }), null);
  assert.equal(fileNoticeOf({ path: "a.zip", applicable: true, skipReason: "AES 加密" }), null);
});

test("fileNoticeOf：AES / 伪加密 / 未加密按 skipReason 认", () => {
  assert.equal(fileNoticeOf({ path: "a.zip", skipReason: "AES 加密" }), "aes");
  assert.equal(fileNoticeOf({ path: "a.zip", skipReason: "疑似伪加密（无需密码）" }), "fake");
  assert.equal(fileNoticeOf({ path: "a.zip", skipReason: "未加密" }), "plain");
});

test("fileNoticeOf：RAR / 7z 一律是需单独处理，与 skipReason 无关", () => {
  assert.equal(fileNoticeOf({ path: "a.rar", skipReason: "不支持的格式" }), "archive");
  assert.equal(fileNoticeOf({ path: "a.7z", skipReason: "" }), "archive");
  assert.equal(fileNoticeOf({ path: "A.RAR" }), "archive");
});

test("fileNoticeOf：非压缩包和「ZIP 但格式不支持」要分开", () => {
  assert.equal(fileNoticeOf({ path: "a.png", skipReason: "不支持的格式" }), "notzip");
  assert.equal(fileNoticeOf({ path: "a.txt" }), "notzip");
  assert.equal(fileNoticeOf({ path: "a.zip", skipReason: "不支持的格式" }), "other");
});

test("fileNoticeOf：有 err 时返回 null，交给错误分支处理", () => {
  assert.equal(fileNoticeOf({ path: "a.zip", err: "读取失败" }), null);
});

test("isSeparate：只有 AES / RAR-7z / 伪加密 可以点进去", () => {
  assert.equal(isSeparate("aes"), true);
  assert.equal(isSeparate("archive"), true);
  assert.equal(isSeparate("fake"), true);
  assert.equal(isSeparate("notzip"), false);
  assert.equal(isSeparate("plain"), false);
  assert.equal(isSeparate("other"), false);
});

test("noticeLabel 覆盖全部原因", () => {
  assert.equal(noticeLabel("aes"), "AES");
  assert.equal(noticeLabel("archive"), "RAR/7z");
  assert.equal(noticeLabel("fake"), "伪加密");
  assert.equal(noticeLabel("plain"), "未加密");
  assert.equal(noticeLabel("notzip"), "非压缩包");
  assert.equal(noticeLabel("other"), "不适用");
});

// ------------------------------------------------------- 目录展开（阶段 9）

// tree 把一张扁平表变成 probe：{ 路径: { dirs, files } }
function probeOf(tree) {
  return async (path) => {
    const hit = tree[path];
    if (!hit) return { isDir: false, dirs: [], files: [] };
    return { isDir: true, dirs: hit.dirs || [], files: hit.files || [] };
  };
}

test("expandDropPaths：普通文件原样返回", async () => {
  const res = await expandDropPaths(["a.zip", "b.rar"], probeOf({}));
  assert.deepEqual(res.files, ["a.zip", "b.rar"]);
  assert.deepEqual(res.dirs, []);
  assert.deepEqual(res.failed, []);
});

test("expandDropPaths：展开两层，第三层不碰", async () => {
  const tree = {
    "/root": { dirs: ["/root/sub"], files: ["/root/1.zip"] },
    "/root/sub": { dirs: ["/root/sub/deep"], files: ["/root/sub/2.zip"] },
    "/root/sub/deep": { files: ["/root/sub/deep/3.zip"] },
  };
  const res = await expandDropPaths(["/root"], probeOf(tree));
  assert.deepEqual(res.files, ["/root/1.zip", "/root/sub/2.zip"]);
  assert.deepEqual(res.dirs, ["/root"]);
});

test("expandDropPaths：深度上限写死为 2", () => {
  assert.equal(MAX_DROP_DEPTH, 2);
});

test("expandDropPaths：传再大的深度也不会超过上限", async () => {
  const tree = {
    "/a": { dirs: ["/a/b"], files: [] },
    "/a/b": { dirs: ["/a/b/c"], files: ["/a/b/x.zip"] },
    "/a/b/c": { files: ["/a/b/c/y.zip"] },
  };
  const res = await expandDropPaths(["/a"], probeOf(tree), 99);
  assert.deepEqual(res.files, ["/a/b/x.zip"]);
});

test("expandDropPaths：读不出来的目录进 failed，不阻塞其他路径", async () => {
  const probe = async (path) => {
    if (path === "/locked") return { isDir: true, dirs: [], files: [], err: "拒绝访问" };
    return { isDir: false, dirs: [], files: [] };
  };
  const res = await expandDropPaths(["/locked", "/ok.zip"], probe);
  assert.deepEqual(res.files, ["/ok.zip"]);
  assert.deepEqual(res.failed, ["/locked"]);
});

test("expandDropPaths：同一个文件出现两次只留一份", async () => {
  const tree = { "/d": { dirs: [], files: ["/d/a.zip"] } };
  const res = await expandDropPaths(["/d/a.zip", "/d"], probeOf(tree));
  assert.deepEqual(res.files, ["/d/a.zip"]);
});

test("expandDropPaths：probe 抛异常时按文件处理，不吞掉", async () => {
  const probe = async () => {
    throw new Error("boom");
  };
  const res = await expandDropPaths(["a.zip"], probe);
  assert.deepEqual(res.files, ["a.zip"]);
});
