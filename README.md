# zipkit

zipkit 是一个 Windows 桌面工具，用来打开别人发来的 ZIP 压缩包，看清它到底是什么状况：里面
有哪些文件、用什么方式压缩、是不是真的加密，然后决定下一步怎么做——修一下就能打开、试几个
弱密码、用手上的原始文件还原密码，或者交给显卡去算。全程只读原文件，不会改动或删除你的压缩包。

---

## 功能

- **ZIP 结构分析**：列出每个条目的名称、压缩方式、加密类型、CRC 与大小，识别 ZipCrypto、
  AES 加密、伪加密，以及 RAR5 / 7z 容器；点开条目可以看字节级细节
- **一键修复伪加密**：把「看着加密其实没加密」的包另存一份能正常解压的副本，原文件不动
- **快速弱密码检测**：按 1–12 位纯数字逐个试，短密码几秒钟出结果
- **批量破解**：一次拖进几十个包，并行试密码，实时进度 + 结果表，跑完可导出 CSV
- **明文攻击**：手上有压缩前的原始文件时，用它反推出密码，再解密整个包或单个条目
- **显卡加速破解**：把 AES / RAR5 / 7z 的哈希交给 hashcat，支持字典、掩码、暴力三种策略
- **批量解压**：破解出密码后一次解开多个包，每个包解到自己的子目录

---

## 下载与安装

从 [Releases](https://github.com/bliey/zipkit/releases) 下载 `zipkit-windows-amd64.exe`，
放到任意目录双击运行。绿色版，不需要安装。

| 项目 | 要求 |
| --- | --- |
| 系统 | Windows 10 1809（build 17763）及以上，64 位；Windows 11 直接支持 |
| 运行时 | WebView2 Runtime（Windows 11 自带；Windows 10 若缺，装一次即可） |
| 其他 | 不需要安装 Go、Wails、7-Zip、bkcrack 或 john |

### 首次运行弹出「Windows 已保护你的电脑」

这是没有代码签名时的常规提示，不是病毒告警：

1. 点窗口里的「**更多信息**」
2. 点右下角出现的「**仍要运行**」

如果窗口里只有「不运行」、没有「更多信息」：右键 exe → 属性 → 勾选底部的「**解除锁定**」→
确定，再双击。

### 卸载

删掉 exe 即可。程序会在 `%LocalAppData%\zipkit\tools\` 留下释放出来的工具、在
`%AppData%\zipkit\` 留下你的设置，需要彻底清理时一并删除。

---

## 使用说明

把压缩包拖进窗口，或者点「选择文件」。程序会根据包的状况只给出一张推荐卡片，按卡片上的按钮
走即可。

- **ZIP 结构分析**：拖入一个包进入单文件视图。上方是文件概要，中间是条目表，点条目能展开
  字节级细节。未加密的包可以直接点「直接解压」。
- **批量破解**：拖入两个及以上文件，或用「加入批量」。设置密码长度范围与并发数，点「开始
  批量破解」。只处理 ZipCrypto 的 ZIP，AES 加密的包会被跳过（改用显卡加速破解），
  RAR / 7z 不能加入批量。
- **明文攻击**：打开一个 ZipCrypto 包，在推荐卡片里点「开始明文攻击」。明文可以是磁盘上的
  文件、另一个 ZIP 里的条目，或直接输入十六进制字节。点开始前会先做预检，告诉你三项条件
  对上了几项。
- **显卡加速破解**：打开 AES 加密的 ZIP 或 RAR5 / 7z 包，点「提取哈希并启动 hashcat」。
  选策略、填参数、点开始，日志与进度实时显示。破解成功后可以直接解密文件。
- **批量解压**：破解出密码后点「批量解压」，每个包解到自己的子目录，可平铺、可跳过已存在的
  文件。
- **设置**：顶部齿轮打开。可以指定各工具的路径、并发数、默认导出目录。每个工具会显示
  「已内置」/「用户配置：路径」/「系统路径：路径」/「未找到」四种状态之一。

---

## 内置工具与许可证

为了让程序下载下来就能用，除 hashcat 之外的依赖都随程序分发：构建时嵌入，启动时释放到
`%LocalAppData%\zipkit\tools\<版本号>\`，不修改、不重新编译。

| 工具 | 版本 | 来源 | 许可证 | 用途 |
| --- | --- | --- | --- | --- |
| bkcrack | 1.8.1 | https://github.com/kimci86/bkcrack | zlib | 明文攻击、密码恢复 |
| 7-Zip | 25.01 | https://www.7-zip.org/ | LGPL-2.1 | RAR / 7z 解压与条目列举 |
| rar2john | 1.9.0-jumbo-1 | https://www.openwall.com/john/ | GPL-2.0 | 从 RAR5 提取哈希 |
| 7z2john | 程序自带 | 本项目 | 同本项目 | 从 7z 提取哈希 |
| hashcat | 需自行安装 | https://hashcat.net/hashcat/ | MIT | 显卡加速破解 |

- 许可证全文在 [`licenses/`](licenses/) 目录。
- 7-Zip 与 John the Ripper 以未修改的官方二进制随包分发，源码分别见
  https://www.7-zip.org/a/7z2501-src.7z 与 https://www.openwall.com/john/ 。
- **hashcat 不随包分发**：官方包上百 MB、必须配 OpenCL 运行时、版本更新频繁。请自行下载，
  在设置里指定 `hashcat.exe` 路径。它是唯一会显示「未找到」的工具。
- 7z2john 没有对应的可执行文件：7z 的哈希由程序自己解析容器得到，所以不需要 Perl 或 Python。

---

## 从源码构建

需要 Go 1.25+、Wails 3 CLI 与 Task 3.x：

```bash
go install github.com/wailsapp/wails/v3/cmd/wails3@latest
```

前端是原生 HTML/CSS/JS，没有构建步骤，不需要 Node 或 npm。

```bash
git clone https://github.com/bliey/zipkit.git
cd zipkit
task VERSION=1.0.0 build      # 产物：bin/zipkit.exe
```

Windows 上还需要 WebView2 Runtime（Windows 11 自带；Windows 10 若缺，装
[Evergreen Bootstrapper](https://developer.microsoft.com/microsoft-edge/webview2/)）。

### 补齐内置工具（可选）

仓库里没有放工具二进制，所以直接构建出来的程序设置页会显示「未内置」，需要你手动指定工具
路径。想要「下载即用」的完整版本，把下面的文件下载好，用 `gzip -9 -n` 压成 `.gz` 放进
`internal/embedded/tools/windows/`（`-n` 不写时间戳，结果可复现）：

| 文件 | 从哪来 | 放成 |
| --- | --- | --- |
| `bkcrack.exe`、`LICENSE.txt` | https://github.com/kimci86/bkcrack/releases/tag/v1.8.1 的 `bkcrack-1.8.1-win64.zip` | `bkcrack.exe.gz`、`bkcrack-license.txt.gz` |
| `7z.exe`、`7z.dll` | https://www.7-zip.org/a/7z2501-x64.exe（取出这两个文件；不要用 `7za.exe`，它不支持 RAR） | `7z.exe.gz`、`7z.dll.gz` |
| `rar2john.exe`、`john.exe` 与 9 个 cygwin DLL | https://www.openwall.com/john/k/john-1.9.0-jumbo-1-win64.zip 里的 `run/` | `windows/<原名>.gz` |
| 7z2john | 不需要下载，程序自带 | — |

`rar2john.exe` 只有 9 KB，实际解析由同目录的 `john.exe` 完成，而 `john.exe` 依赖一组 cygwin
DLL，缺任何一个都会直接退出且不给提示。需要一起放的 11 个文件：

```
rar2john.exe  john.exe  cygwin1.dll  cyggomp-1.dll  cyggcc_s-seh-1.dll
cygz.dll  cygOpenCL-1.dll  cyggmp-10.dll  cygcrypto-1.1.dll  cygcrypt-2.dll
cygbz2-1.dll
```

补齐后重新构建，产物就是完整版。目录里应当有 15 个 `.gz` 文件。

### 测试

```bash
go test ./...                    # Go 单测
node --test "tests/*.test.mjs"   # 前端单测，无第三方依赖
```

---

## 常见问题

**双击没反应，或者窗口一闪就没了**
确认是 64 位 Windows 10 1809 或更高版本。完全没出现窗口，多半是缺 WebView2 Runtime，装一次
[Evergreen Bootstrapper](https://developer.microsoft.com/microsoft-edge/webview2/) 再试。

**杀毒软件报毒**
程序里带了 bkcrack 和 john（密码恢复工具），这类文件常被启发式规则误报。源码和构建脚本都在
仓库里，可以自己编译验证。

**提示「未找到 hashcat」，显卡加速破解是灰的**
hashcat 不随程序分发。去 https://hashcat.net/hashcat/ 下载，解压后在设置里指定 `hashcat.exe`
路径（或把目录加进 PATH），再点「重新检测」。

**明文攻击提示压缩方式不匹配，或一直 `Could not find the keys.`**
先看预检结果。最常见的情况是：你给的是压缩前的原始文件，但包里那个条目是 Deflate 压缩的。
这时改用「明文 ZIP」形式——用同版本的压缩软件把原始文件重新压成一份 ZIP 再选它。另外，明文
字节必须出现在**压缩后**的数据流里，所以 Store（不压缩）的条目最容易成功。

**批量破解找不到密码**
批量只试纯数字。确认长度范围覆盖了密码位数（默认 6–8 位，最多 12 位）；位数更长或含字母的
密码请用显卡加速破解。另外批量只处理 ZipCrypto 的 ZIP，AES 加密的包会被跳过。

**能不能破解 RAR / 7z 的密码**
可以，但只能走显卡加速破解：提取哈希交给 hashcat，需要你自己安装 hashcat。批量破解不支持
RAR / 7z。

---

## 许可证

本项目使用 [MIT](LICENSE)。随包分发的第三方工具许可证见上面的「内置工具与许可证」，全文在
[`licenses/`](licenses/)。

zipkit 用于恢复你自己拥有或已获授权访问的文件。请勿用于破解他人的文件。
