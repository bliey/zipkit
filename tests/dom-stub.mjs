// 测试用的极简 DOM 桩。
//
// app.js 是普通 ES 模块，模块一加载就会 document.getElementById 一堆节点、
// 绑事件、调 init()。要在 Node 里跑真实代码（而不是复制一份逻辑），就得给它
// 一个「够用」的 DOM：元素能建、能挂子节点、classList 能增删、textContent
// 赋值会像真 DOM 一样清空子节点。
//
// 故意不实现布局与事件派发：测试关心的是「谁被创建、顺序对不对、状态改没改」，
// 不是像素。

import fs from "node:fs";
import os from "node:os";
import path from "node:path";

class ClassList {
  #set = new Set();
  add(...names) {
    for (const n of names) this.#set.add(n);
  }
  remove(...names) {
    for (const n of names) this.#set.delete(n);
  }
  contains(name) {
    return this.#set.has(name);
  }
  toggle(name, force) {
    if (force === undefined) {
      this.#set.has(name) ? this.#set.delete(name) : this.#set.add(name);
    } else if (force) {
      this.#set.add(name);
    } else {
      this.#set.delete(name);
    }
    return this.#set.has(name);
  }
}

export class El {
  constructor(tag = "div", id = "") {
    this.tagName = tag.toUpperCase();
    this.id = id;
    this.children = [];
    this.classList = new ClassList();
    this.style = {};
    this.dataset = {};
    this.attributes = {};
    this.#text = "";
    this.value = "";
    this.title = "";
    this.disabled = false;
    this.checked = false;
    this.type = "";
    this.selectionStart = 0;
    this.selectionEnd = 0;
  }
  // 真实 DOM 里给 textContent 赋值会清空子节点，桩里必须照做，
  // 否则「先 textContent = "" 再 appendChild」的列表会一直累加。
  #text = "";
  get textContent() {
    return this.#text;
  }
  set textContent(v) {
    this.#text = String(v);
    this.children = [];
  }
  addEventListener() {}
  removeEventListener() {}
  appendChild(child) {
    this.children.push(child);
    return child;
  }
  append(...nodes) {
    this.children.push(...nodes);
  }
  prepend(...nodes) {
    this.children.unshift(...nodes);
  }
  remove() {}
  setAttribute(k, v) {
    this.attributes[k] = v;
  }
  getAttribute(k) {
    return this.attributes[k] ?? null;
  }
  closest() {
    return null;
  }
  focus() {}
  select() {}
  setSelectionRange() {}
  querySelector() {
    return null;
  }
  querySelectorAll() {
    return [];
  }
  scrollTo() {}
  scrollIntoView() {}
  getBoundingClientRect() {
    return { width: 0, height: 0, top: 0, left: 0 };
  }
}

// installDom 把桩装到 globalThis 上，返回 body 与 byId。
// byId 是「按需创建」的：app.js 里 el.xxx 的 id 不用提前登记。
export function installDom() {
  const registry = new Map();
  const byId = (id) => {
    if (!registry.has(id)) registry.set(id, new El("div", id));
    return registry.get(id);
  };

  const body = byId("__body");
  body.tagName = "BODY";

  globalThis.document = {
    body,
    documentElement: byId("__html"),
    getElementById: byId,
    createElement: (tag) => new El(tag),
    createTextNode: (text) => ({ nodeType: 3, textContent: String(text) }),
    createDocumentFragment: () => new El("fragment"),
    querySelector: () => null,
    querySelectorAll: () => [],
    addEventListener: () => {},
    removeEventListener: () => {},
    readyState: "complete",
  };
  globalThis.window = globalThis;
  globalThis._wails = { flags: { enableFileDrop: true } };
  globalThis.requestAnimationFrame = (fn) => setTimeout(fn, 0);
  globalThis.setInterval = () => 0;
  globalThis.clearInterval = () => {};

  return { body, byId };
}

// prepareAppModule 把 app.js 复制到临时目录，并把三个裸导入
// （/wails/runtime.js、/drop-rules.js、/entry-detail.js）换成相对路径。
//
// extraExports 是要追加到副本末尾的 export 列表——app.js 本身不导出任何东西，
// 测试靠这一行拿到内部函数。
export function prepareAppModule(frontendDir, extraExports = []) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "zipkit-app-"));

  for (const name of ["drop-rules.js", "entry-detail.js"]) {
    fs.copyFileSync(path.join(frontendDir, name), path.join(dir, name));
  }

  let src = fs.readFileSync(path.join(frontendDir, "app.js"), "utf8");
  src = src.replace('from "/wails/runtime.js"', 'from "./runtime-stub.js"');
  src = src.replace('from "/drop-rules.js"', 'from "./drop-rules.js"');
  src = src.replace('from "/entry-detail.js"', 'from "./entry-detail.js"');

  if (extraExports.length) {
    src += `\nexport {\n  ${extraExports.join(",\n  ")},\n};\n`;
  }

  const entry = path.join(dir, "app.js");
  fs.writeFileSync(entry, src);
  return { dir, entry };
}

// writeRuntimeStub 写一个假的 Wails 运行时：Call.ByName 转给
// globalThis.__zipkitCall，测试想返回什么就装什么。
export function writeRuntimeStub(dir) {
  const body = [
    "export const Browser = { OpenURL: async () => {} };",
    "export const Call = {",
    "  ByName: async (name, ...args) =>",
    "    typeof globalThis.__zipkitCall === 'function'",
    "      ? globalThis.__zipkitCall(name, ...args)",
    "      : {},",
    "};",
    "export const Clipboard = { SetText: async () => {} };",
    "export const Dialogs = { OpenFile: async () => null, SaveFile: async () => null };",
    "export const Events = { On: () => {} };",
    "",
  ].join("\n");
  fs.writeFileSync(path.join(dir, "runtime-stub.js"), body);
  return path.join(dir, "runtime-stub.js");
}
