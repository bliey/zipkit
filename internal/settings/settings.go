// Package settings 管理 zipkit 的用户设置。
//
// 所有设置都落在同一个 JSON 文件里（<UserConfigDir>/zipkit/config.json）。
// 早期只有批量解压需要配置，那份结构由 unzip 包自己维护；现在 7z 与 bkcrack
// 的路径都要存，如果两个包各写各的，就会互相把对方的字段覆盖掉——所以
// 统一收到这里：一个文件、一个结构、一个写入者。
package settings

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
)

// 解压目录布局。
const (
	// LayoutPerZip 每个压缩包解压到自己的子目录（默认）。
	LayoutPerZip = "per-zip"
	// LayoutFlat 全部解压到同一个目录，重名文件自动加 _1、_2。
	LayoutFlat = "flat"
)

// DefaultConcurrency 是批量解压的默认并发数。
const DefaultConcurrency = 3

// Config 是持久化在用户配置目录里的设置。
type Config struct {
	// SevenZipPath 是用户手动指定的 7z 路径，空表示自动探测。
	SevenZipPath string `json:"sevenZipPath"`
	// BkcrackPath 是用户手动指定的 bkcrack 路径，空表示自动探测。
	BkcrackPath string `json:"bkcrackPath"`
	// HashcatPath 是用户手动指定的 hashcat 路径，空表示自动探测。
	HashcatPath string `json:"hashcatPath"`
	// Rar2JohnPath 是用户手动指定的 rar2john 路径，空表示自动探测。
	Rar2JohnPath string `json:"rar2johnPath"`
	// SevenZip2JohnPath 是用户手动指定的 7z2john 路径，空表示自动探测。
	SevenZip2JohnPath string `json:"sevenZip2JohnPath"`
	// SevenZip2HashcatPath 是用户手动指定的 7z2hashcat 路径（.pl 脚本或官方
	// 发布的 .exe），空表示自动探测。它和内建的 7z 提取器是互补关系：
	// 内建实现覆盖常见结构，遇到 BCJ2 / PPMd 这类编码链才需要它。
	SevenZip2HashcatPath string `json:"sevenZip2HashcatPath"`
	// InterpreterPath 是运行 .pl / .py 脚本用的解释器，空表示按脚本后缀
	// 自动探测（.pl → perl，.py → python3 / python）。
	//
	// 注意 7z2hashcat 是 Perl 脚本而不是 Python 脚本，所以这里不能写死 python。
	InterpreterPath string `json:"interpreterPath"`
	// Layout 是批量解压的目录布局。
	Layout string `json:"layout"`
	// Concurrency 是批量解压的并发数。
	Concurrency int `json:"concurrency"`
	// BatchConcurrency 是批量破解的并发数，0 表示按 CPU 核数推导。
	BatchConcurrency int `json:"batchConcurrency"`
	// DefaultExportDir 是解压时默认打开的导出目录，空表示不指定。
	DefaultExportDir string `json:"defaultExportDir"`
}

// Default 返回默认设置：自动探测外部工具、每个压缩包一个子目录、并发 3。
func Default() Config {
	return Config{Layout: LayoutPerZip, Concurrency: DefaultConcurrency}
}

// Normalize 把非法值拉回默认值，配置文件被手改坏也不会崩。
func (c Config) Normalize() Config {
	out := c
	switch out.Layout {
	case LayoutPerZip, LayoutFlat:
	default:
		out.Layout = LayoutPerZip
	}
	if out.Concurrency < 1 || out.Concurrency > 16 {
		out.Concurrency = DefaultConcurrency
	}
	if out.BatchConcurrency < 0 || out.BatchConcurrency > 64 {
		out.BatchConcurrency = 0
	}
	out.SevenZipPath = strings.TrimSpace(out.SevenZipPath)
	out.BkcrackPath = strings.TrimSpace(out.BkcrackPath)
	out.HashcatPath = strings.TrimSpace(out.HashcatPath)
	out.Rar2JohnPath = strings.TrimSpace(out.Rar2JohnPath)
	out.SevenZip2JohnPath = strings.TrimSpace(out.SevenZip2JohnPath)
	out.SevenZip2HashcatPath = strings.TrimSpace(out.SevenZip2HashcatPath)
	out.InterpreterPath = strings.TrimSpace(out.InterpreterPath)
	out.DefaultExportDir = strings.TrimSpace(out.DefaultExportDir)
	return out
}

var (
	pathMu       sync.RWMutex
	pathOverride string
)

// SetPath 覆盖配置文件位置，仅供测试使用。
func SetPath(path string) {
	pathMu.Lock()
	pathOverride = path
	pathMu.Unlock()
}

// Path 返回配置文件路径。
func Path() (string, error) {
	pathMu.RLock()
	override := pathOverride
	pathMu.RUnlock()
	if override != "" {
		return override, nil
	}

	dir, err := os.UserConfigDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, "zipkit", "config.json"), nil
}

// Load 读取配置。文件不存在或内容损坏时返回默认值——配置只是锦上添花，
// 不该因为读不到就让整个程序起不来。
func Load() Config {
	path, err := Path()
	if err != nil {
		return Default()
	}

	data, err := os.ReadFile(path)
	if err != nil {
		return Default()
	}

	var cfg Config
	if err := json.Unmarshal(data, &cfg); err != nil {
		return Default()
	}
	return cfg.Normalize()
}

// Save 原子地写入配置：先写临时文件再改名，避免写一半断电留下半个 JSON。
//
// 保存成功后递增一个全局版本号：各个 Service 缓存着自己的配置副本，靠这个
// 版本号判断「配置文件被别人改过了」，从而做到改完设置立刻生效、不用重启。
func Save(cfg Config) error {
	path, err := Path()
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}

	data, err := json.MarshalIndent(cfg.Normalize(), "", "  ")
	if err != nil {
		return err
	}
	data = append(data, '\n')

	tmp, err := os.CreateTemp(filepath.Dir(path), "config-*.json")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName)

	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmpName, path); err != nil {
		return err
	}
	revision.Add(1)
	return nil
}

var revision atomic.Int64

// Revision 返回配置文件的版本号。每次 Save 都会递增，各 Service 用它判断
// 缓存是否过期。
func Revision() int64 { return revision.Load() }

// Update 读-改-写一次配置，用来只改一个字段而不碰其他字段。
func Update(mutate func(*Config)) error {
	cfg := Load()
	mutate(&cfg)
	return Save(cfg)
}
