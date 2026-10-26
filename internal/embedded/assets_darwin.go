//go:build darwin

package embedded

import "embed"

// tools/darwin 里放 macOS 版的可执行文件。构建 macOS 版时只嵌入这个目录，
// Windows / Linux 的二进制不会跟进来。
//
//go:embed all:tools/darwin
var assets embed.FS

// assetsDir 是嵌入文件在 FS 里的目录名。
const assetsDir = "tools/darwin"
