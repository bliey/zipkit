//go:build !windows && !darwin && !linux

package embedded

import "embed"

// 其它平台（FreeBSD 之类）没有放内置二进制，这里给一个空 FS，
// 让同一套代码在任何 GOOS 上都能编译：清单里的工具会全部落到
// 「未内置」，设置页提示用户自己配置路径。
var assets embed.FS

// assetsDir 是嵌入文件在 FS 里的目录名。
const assetsDir = "tools"
