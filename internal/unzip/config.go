package unzip

import (
	"github.com/bliey/zipkit/internal/settings"
)

// 解压目录布局。值定义在 settings 包里，因为配置文件是几个包共享的。
const (
	// LayoutPerZip 每个压缩包解压到自己的子目录（默认）。
	LayoutPerZip = settings.LayoutPerZip
	// LayoutFlat 全部解压到同一个目录，重名文件自动加 _1、_2。
	LayoutFlat = settings.LayoutFlat
)

// Config 是解压相关的设置。7z 路径、bkcrack 路径与解压默认值存在同一个
// JSON 文件里，所以这里直接用 settings 的结构体：如果两个包各自定义一份，
// 谁后保存谁就会把对方的字段抹掉。
type Config = settings.Config

// DefaultConfig 返回默认设置：自动探测 7z、每个压缩包一个子目录、并发 3。
func DefaultConfig() Config { return settings.Default() }

// LoadConfig 读取配置。文件不存在或内容损坏时返回默认值。
func LoadConfig() Config { return settings.Load() }

// SaveConfig 原子地写入配置。
func SaveConfig(cfg Config) error { return settings.Save(cfg) }

// SetConfigPath 覆盖配置文件位置，仅供测试使用。
func SetConfigPath(path string) { settings.SetPath(path) }
