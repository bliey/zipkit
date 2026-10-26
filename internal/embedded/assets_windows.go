//go:build windows

package embedded

import "embed"

// tools/windows 里放 Windows 版的可执行文件，由构建前的脚本或手工放入。
//
// 每个平台一个目录、每个平台一个 embed 指令：构建 Windows 版时只把
// tools/windows 打进二进制，macOS / Linux 的二进制不会跟进来。用 all:
// 前缀是为了让目录里的隐藏文件也能嵌进去，同时目录为空时不会报错。
//
//go:embed all:tools/windows
var assets embed.FS

// assetsDir 是嵌入文件在 FS 里的目录名。
const assetsDir = "tools/windows"
