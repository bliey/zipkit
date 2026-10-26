//go:build linux

package embedded

import "embed"

// tools/linux 里放 Linux 版的可执行文件。构建 Linux 版时只嵌入这个目录，
// Windows / macOS 的二进制不会跟进来。
//
//go:embed all:tools/linux
var assets embed.FS

// assetsDir 是嵌入文件在 FS 里的目录名。
const assetsDir = "tools/linux"
