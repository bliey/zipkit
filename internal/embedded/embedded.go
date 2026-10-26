// Package embedded 把常用的外部工具打进 zipkit 二进制，运行时释放到缓存目录。
//
// 目的只有一个：用户下载 zipkit.exe 就能用，不需要先去装 7-Zip、再去找
// bkcrack、再配 john。hashcat 不在其中——它体积大且依赖 OpenCL 运行时，
// 强行塞进来只会让下载变慢，仍然由用户在设置里指定。
//
// 二进制按平台分目录放在 tools/<GOOS>/ 下，assets_<GOOS>.go 里各有一条
// go:embed 指令，构建时只嵌入当前平台的工具：Windows 版里不会混进
// Mach-O，macOS 版里也不会混进 PE。
//
// 释放位置是 <UserCacheDir>/zipkit/tools/<版本号>/，每个版本一个目录：
// 升级程序后旧目录会在下次启动时清掉，不会一直堆着。目标文件不存在、大小
// 或内容哈希与嵌入数据不一致时才写盘，正常启动几乎没有额外开销。
//
// 路径解析的优先级由各调用方实现：用户配置 > 这里的释放路径 > 系统 PATH。
// 这样高级用户仍然可以用自己编译的版本覆盖内置版本。
package embedded

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/bliey/zipkit/internal/executil"
)

// compressedSuffix 是嵌入文件在仓库里的存放后缀。
//
// 这些工具原始体积合计约 17 MB，直接以二进制形式提交会让仓库和 diff 都变得
// 难以阅读；用 gzip -9 压到 7 MB 左右再嵌入，运行时解压释放，用户拿到的
// 仍然是原始文件。压缩只是仓库侧的存放方式，不影响任何调用方。
const compressedSuffix = ".gz"

// 工具种类。与设置面板里的 kind 保持一致。
const (
	KindBkcrack       = "bkcrack"
	KindSevenZip      = "sevenzip"
	KindRar2John      = "rar2john"
	KindSevenZip2John = "7z2john"
)

// release 描述某个平台上要释放的内容。
type release struct {
	// Exe 是主程序在释放目录里的文件名。
	Exe string
	// Source 是它在嵌入数据里的文件名；为空表示与 Exe 相同。
	//
	// 支持 {arch} 占位符（替换成 runtime.GOARCH），用于同一个平台准备好几份
	// 不同架构的二进制——例如 Linux 的 amd64 / arm64。释放时只挑当前架构
	// 那一份，两份共用一个目标文件名，不会互相覆盖。
	Source string
	// Files 是需要一起释放的附属文件（7z.dll、cygwin*.dll、许可证…）。
	Files []string
}

// tool 描述一个要嵌入的工具。
type tool struct {
	Kind string
	// Version 是工具自己的版本号，显示在设置页里。
	Version string
	// License 用于「关于」区块的第三方组件声明。
	License string
	// ByOS 按 GOOS 列出各平台的释放内容。清单里没有某个 GOOS，就表示
	// 上游没有发布该平台的二进制（例如 rar2john 只有 Windows 构建），
	// 这个平台上设置页会显示「未内置，请手动配置」。
	ByOS map[string]release
	// Native 表示这个工具没有外部二进制，由程序内建实现提供。
	// 典型例子是 7z2john：john 上游只发布 Perl 脚本，Windows 包里没有
	// 可执行文件，硬塞一个 .pl 还要用户装 Perl 才跑得起来。
	Native bool
}

// releaseFor 返回某个平台上这个工具的释放内容。
func (t tool) releaseFor(goos string) (release, bool) {
	rel, ok := t.ByOS[goos]
	if !ok || rel.Exe == "" {
		return release{}, false
	}
	return rel, true
}

// manifest 是嵌入清单。
//
// 每个平台只列自己那几份文件，配合 assets_<GOOS>.go 里的按平台 embed 指令，
// Windows 二进制里不会混进 Mach-O / ELF。darwin 与 linux 的 7zz / bkcrack
// 都准备了 amd64 + arm64 两份，用 {arch} 占位符挑当前架构。
var manifest = []tool{
	{
		Kind:    KindBkcrack,
		Version: "1.8.1",
		License: "zlib",
		ByOS: map[string]release{
			"windows": {Exe: "bkcrack.exe", Files: []string{"bkcrack-license.txt"}},
			"darwin":  {Exe: "bkcrack", Source: "bkcrack-{arch}", Files: []string{"bkcrack-license.txt"}},
			"linux":   {Exe: "bkcrack", Source: "bkcrack-{arch}", Files: []string{"bkcrack-license.txt"}},
		},
	},
	{
		Kind:    KindSevenZip,
		Version: "25.01",
		License: "LGPL-2.1",
		ByOS: map[string]release{
			// 7z.exe + 7z.dll 来自官方安装包；命令行的 7za/7zz 不支持 RAR。
			"windows": {Exe: "7z.exe", Files: []string{"7z.dll"}},
			// 7zz 是官方静态链接的独立命令行版，macOS 包是 x86_64+arm64
			// 的通用二进制，一个文件两种架构都能跑。
			"darwin": {Exe: "7zz", Files: []string{"7z-License.txt"}},
			"linux":  {Exe: "7zz", Source: "7zz-{arch}", Files: []string{"7z-License.txt"}},
		},
	},
	{
		Kind:    KindRar2John,
		Version: "1.9.0-jumbo-1",
		License: "GPL-2.0",
		// john 上游只发布 Windows 预编译包（macOS / Linux 需要自己编译），
		// 所以只有 windows 这一项；其它平台走系统 PATH 或用户配置。
		// 7z 哈希已由内建实现覆盖，不影响主要流程。
		ByOS: map[string]release{
			// rar2john.exe 在 Windows 构建里只是个 9 KB 的存根，内部 execv
			// 转调 john.exe，所以 john.exe 必须同目录存在；而 john.exe 又是
			// cygwin 构建，缺任何一个 cygwin*.dll 都会以 0xc0000135 直接退出。
			// 这里把实测必需的那一组一并释放，少一个都会让「提取哈希」失败。
			"windows": {Exe: "rar2john.exe", Files: []string{
				"john.exe",
				"cygwin1.dll",
				"cyggomp-1.dll",
				"cyggcc_s-seh-1.dll",
				"cygz.dll",
				"cygOpenCL-1.dll",
				"cyggmp-10.dll",
				"cygcrypto-1.1.dll",
				"cygcrypt-2.dll",
				"cygbz2-1.dll",
			}},
		},
	},
	{
		Kind:    KindSevenZip2John,
		Version: "1.9.0-jumbo-1",
		License: "GPL-2.0",
		// 这个工具没有可执行文件：john 只发布 7z2john.pl，需要 Perl 和
		// Compress::Raw::Lzma 才能跑。程序内建了等价的 $7z$ 提取器
		// （internal/sevenzip），所以这里只留 Native 标记。
		Native: true,
	},
}

// 自检状态。设置页按这个值决定显示什么。
const (
	// StatusOK 三项全通过：嵌入数据在、释放文件在且哈希一致、能执行。
	StatusOK = "ok"
	// StatusNotEmbedded 这个平台没有放二进制，也没有内建实现。
	StatusNotEmbedded = "not-embedded"
	// StatusReleaseFailed 嵌入数据在，但写盘失败。
	StatusReleaseFailed = "release-failed"
	// StatusNotRunnable 文件释放出来了，但起不来（缺 DLL、权限不对…）。
	StatusNotRunnable = "not-runnable"
)

// Info 是一个内置工具对外暴露的状态。
type Info struct {
	Kind    string `json:"kind"`
	Version string `json:"version"`
	License string `json:"license"`
	// Builtin 表示这次运行确实有可用的内置实现（释放文件或原生实现）。
	Builtin bool `json:"builtin"`
	// Path 是释放后的可执行文件路径；原生实现为空。
	Path string `json:"path"`
	// Native 表示这个工具由程序内建实现提供，没有外部文件。
	Native bool `json:"native"`
	// Status 是自检结论，取值见上面的 Status* 常量。
	Status string `json:"status"`
	// Detail 是自检失败时的具体原因，成功时为空。
	Detail string `json:"detail"`
	// Runnable 表示「能启动」这一项是否通过。
	Runnable bool `json:"runnable"`
	// ProbeVersion 是从程序输出里读到的版本号（拿不到就是空）。
	ProbeVersion string `json:"probeVersion"`
}

var (
	mu       sync.RWMutex
	appVer   = "dev"
	cacheDir string // 测试用覆盖
	rootDir  string // 本次运行实际使用的版本目录
	released = map[string]string{}
	// releaseErrs 记录每个工具释放失败的原因，供自检显示。
	releaseErrs = map[string]string{}
	// verify 是「能不能执行」这一项的结果，按需探测一次后缓存。
	verify     = map[string]probeResult{}
	verifyDone bool
	lastErr    error
	done       bool
)

// SetVersion 设置用于隔离释放目录的程序版本号。
//
// 版本号来自构建时注入的 main.Version（-ldflags "-X main.Version=..."），
// 必须在 Release 之前调用；没调用时用 "dev"。
func SetVersion(v string) {
	v = strings.TrimSpace(v)
	if v == "" {
		v = "dev"
	}
	mu.Lock()
	appVer = v
	mu.Unlock()
}

// Version 返回当前的程序版本号。
func Version() string {
	mu.RLock()
	defer mu.RUnlock()
	return appVer
}

// SetCacheRoot 覆盖缓存根目录，仅供测试使用。传空字符串恢复默认。
func SetCacheRoot(dir string) {
	mu.Lock()
	cacheDir = dir
	mu.Unlock()
}

// Root 返回本次运行使用的释放目录（Release 之前为空）。
func Root() string {
	mu.RLock()
	defer mu.RUnlock()
	return rootDir
}

// LastError 返回上次 Release 的错误，供设置页显示。
func LastError() error {
	mu.RLock()
	defer mu.RUnlock()
	return lastErr
}

// Path 返回某个工具释放后的可执行文件路径；没有内置或释放失败时返回空。
func Path(kind string) string {
	mu.RLock()
	defer mu.RUnlock()
	return released[kind]
}

// Infos 返回所有内置工具的清单状态，顺序与 manifest 一致。
//
// 每一项都带三层自检结论：嵌入数据在不在、释放文件在不在（哈希已校验）、
// 能不能执行。设置页据此显示「已内置（版本）」或具体卡在哪一步。
func Infos() []Info {
	mu.RLock()
	defer mu.RUnlock()

	out := make([]Info, 0, len(manifest))
	for _, t := range manifest {
		info := Info{Kind: t.Kind, Version: t.Version, License: t.License, Native: t.Native}
		path, hasFile := released[t.Kind]
		_, onThisOS := t.releaseFor(runtime.GOOS)

		switch {
		case hasFile && path != "":
			info.Path = path
			if pr, ok := verify[t.Kind]; ok {
				info.Runnable = pr.ok
				info.ProbeVersion = pr.version
				if !pr.ok {
					info.Status = StatusNotRunnable
					info.Detail = pr.err
					break
				}
			}
			info.Builtin = true
			info.Status = StatusOK
		case t.Native:
			// 没有外部文件，但有内建实现：永远可用。
			info.Builtin = true
			info.Status = StatusOK
			info.Runnable = true
		case releaseErrs[t.Kind] != "":
			info.Status = StatusReleaseFailed
			info.Detail = releaseErrs[t.Kind]
		case !onThisOS:
			// 上游没有发布这个平台的二进制，不是用户的环境问题。
			info.Status = StatusNotEmbedded
			info.Detail = "上游没有发布 " + runtime.GOOS + " 的预编译二进制，请手动配置路径"
		default:
			info.Status = StatusNotEmbedded
		}
		out = append(out, info)
	}
	return out
}

// IsNative 表示某个工具由程序内建实现提供，没有外部可执行文件。
func IsNative(kind string) bool {
	for _, t := range manifest {
		if t.Kind == kind {
			return t.Native
		}
	}
	return false
}

// Info 返回单个工具的状态。
func InfoOf(kind string) (Info, bool) {
	for _, info := range Infos() {
		if info.Kind == kind {
			return info, true
		}
	}
	return Info{}, false
}

// Release 把嵌入的工具释放到缓存目录。可以重复调用，第二次直接返回。
//
// 单个工具释放失败不影响其它工具：能用的先用上，失败的原因记在 LastError
// 里给设置页显示，整个过程不弹窗、不阻塞启动。
func Release() error {
	mu.Lock()
	if done {
		err := lastErr
		mu.Unlock()
		return err
	}
	done = true
	version := appVer
	base := cacheDir
	mu.Unlock()

	target, err := releaseAll(version, base)

	// 部分工具失败时 target 仍然有效（成功的那些已经释放到里面了），
	// 所以目录照记，只把错误留给设置页显示。
	mu.Lock()
	if target != "" {
		rootDir = target
	}
	lastErr = err
	mu.Unlock()
	return err
}

// Reset 清空释放状态，仅供测试使用。
func Reset() {
	mu.Lock()
	done = false
	rootDir = ""
	released = map[string]string{}
	releaseErrs = map[string]string{}
	verify = map[string]probeResult{}
	verifyDone = false
	lastErr = nil
	mu.Unlock()
}

// probeResult 是「能不能执行」这一项的结果。
type probeResult struct {
	ok      bool
	version string
	err     string
}

// Verify 对每个已释放的工具做一次启动探测，结果缓存到本次运行。
//
// 这是自检的第三层：文件写出来了不代表能用——john 的 rar2john 缺一个
// cygwin DLL 就会以 0xC0000135 静默退出，光看文件存在根本发现不了。
// 探测一次要起几个进程，所以只在需要时跑一次，设置页「重新检测」会清缓存。
func Verify() {
	mu.Lock()
	if verifyDone {
		mu.Unlock()
		return
	}
	verifyDone = true
	paths := make(map[string]string, len(released))
	for kind, path := range released {
		paths[kind] = path
	}
	mu.Unlock()

	results := make(map[string]probeResult, len(paths))
	for kind, path := range paths {
		results[kind] = probeExecutable(path)
	}

	mu.Lock()
	for kind, res := range results {
		verify[kind] = res
	}
	mu.Unlock()
}

// ResetVerify 清掉探测缓存，下一次 Verify 会重新跑一遍。
func ResetVerify() {
	mu.Lock()
	verify = map[string]probeResult{}
	verifyDone = false
	mu.Unlock()
}

// probeExecutable 启动一个工具，确认它真的能跑起来。
//
// 不带参数启动就够了：这些工具都会打印用法后退出。要区分的是「跑起来了但
// 返回非 0」和「根本加载不了」——后者在 Windows 上是 0xC0000000 以上的
// 状态码（例如 0xC0000135 = 找不到 DLL），转成 int 是负数。
func probeExecutable(path string) probeResult {
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()

	cmd := executil.CommandContext(ctx, path)
	out, err := cmd.CombinedOutput()
	if err != nil {
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) {
			code := exitErr.ExitCode()
			if code < 0 || uint32(code) >= 0xC0000000 {
				return probeResult{err: fmt.Sprintf("无法执行（退出码 0x%X），通常是缺少依赖文件",
					uint32(code))}
			}
			// 打印用法后返回 1 是正常现象，继续往下读版本号。
		} else {
			return probeResult{err: fmt.Sprintf("无法执行：%v", err)}
		}
	}
	return probeResult{ok: true, version: parseVersion(string(out))}
}

// versionPattern 从工具输出里捞版本号，例如「7-Zip 25.01」「bkcrack 1.7.1」。
var versionPattern = regexp.MustCompile(`\b(\d+\.\d+(?:\.\d+)?)\b`)

func parseVersion(out string) string {
	if m := versionPattern.FindString(out); m != "" {
		return m
	}
	return ""
}

func releaseAll(version, base string) (string, error) {
	parent, err := toolsParent(base)
	if err != nil {
		return "", err
	}
	target := filepath.Join(parent, sanitizeVersion(version))
	if err := os.MkdirAll(target, 0o755); err != nil {
		return "", fmt.Errorf("embedded: 创建释放目录失败：%w", err)
	}

	var failures []string
	for _, t := range manifest {
		exe, err := releaseTool(target, t)
		if err != nil {
			failures = append(failures, fmt.Sprintf("%s: %v", t.Kind, err))
			mu.Lock()
			releaseErrs[t.Kind] = err.Error()
			mu.Unlock()
			continue
		}
		if exe == "" {
			// 这个平台没有放对应文件，跳过即可——设置页会显示「未内置」。
			continue
		}
		mu.Lock()
		released[t.Kind] = exe
		mu.Unlock()
	}

	cleanupOldVersions(parent, filepath.Base(target))

	if len(failures) > 0 {
		return target, fmt.Errorf("embedded: 部分工具释放失败：%s", strings.Join(failures, "；"))
	}
	return target, nil
}

// releaseTool 释放一个工具，返回主程序路径。这个平台没有内置文件时返回空字符串。
func releaseTool(dir string, t tool) (string, error) {
	rel, ok := t.releaseFor(runtime.GOOS)
	if !ok {
		// 这个平台没放对应文件，跳过即可——设置页会显示「未内置」。
		return "", nil
	}

	src := rel.Source
	if src == "" {
		src = rel.Exe
	}
	src = expandArch(src)

	embedded, path, err := ensureFile(dir, src, rel.Exe)
	if err != nil {
		return "", err
	}
	if !embedded {
		return "", nil
	}
	for _, name := range rel.Files {
		if _, _, err := ensureFile(dir, name, name); err != nil {
			return "", err
		}
	}
	return path, nil
}

// expandArch 把 {arch} 占位符换成当前架构，例如 bkcrack-{arch} → bkcrack-amd64。
func expandArch(name string) string {
	if !strings.Contains(name, archPlaceholder) {
		return name
	}
	return strings.ReplaceAll(name, archPlaceholder, runtime.GOARCH)
}

// archPlaceholder 是清单里表示「按架构取文件」的占位符。
const archPlaceholder = "{arch}"

// ensureFile 在需要时把一个嵌入文件写到 dir。
//
// 返回的第一个值是「嵌入数据里有没有这个文件」——它决定了这个工具在当前
// 平台上算不算内置；第二个值是目标路径（已存在且内容一致时也返回）。
// dest 为空表示目标文件名与嵌入文件名相同。
func ensureFile(dir, name, dest string) (bool, string, error) {
	if dest == "" {
		dest = name
	}
	data, ok, err := assetData(name)
	if err != nil {
		return false, "", err
	}
	if !ok {
		return false, "", nil
	}

	path := filepath.Join(dir, dest)
	if !sameContent(path, data) {
		if err := writeFile(path, data, dest); err != nil {
			return true, "", fmt.Errorf("写入 %s 失败：%w", path, err)
		}
	}
	ensureExecutable(path, dest)
	return true, path, nil
}

// assetData 取出一个嵌入文件的原始内容，透明处理 .gz 存放。
//
// 优先找 <name>.gz；找不到再退回未压缩的 <name>，这样往 tools/ 里放一个
// 没压缩的文件也能正常工作，不必为了加个新工具去改代码。
func assetData(name string) ([]byte, bool, error) {
	raw, err := assets.ReadFile(assetsDir + "/" + name + compressedSuffix)
	if err == nil {
		data, err := gunzip(raw)
		if err != nil {
			return nil, false, fmt.Errorf("解压嵌入文件 %s 失败：%w", name, err)
		}
		return data, true, nil
	}
	if !errors.Is(err, fs.ErrNotExist) {
		return nil, false, fmt.Errorf("读取嵌入文件 %s 失败：%w", name, err)
	}

	raw, err = assets.ReadFile(assetsDir + "/" + name)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil, false, nil
		}
		return nil, false, fmt.Errorf("读取嵌入文件 %s 失败：%w", name, err)
	}
	return raw, true, nil
}

func gunzip(raw []byte) ([]byte, error) {
	zr, err := gzip.NewReader(bytes.NewReader(raw))
	if err != nil {
		return nil, err
	}
	defer zr.Close()
	return io.ReadAll(zr)
}

// writeFile 先写临时文件再改名，避免中途被打断时留下半个 exe。
func writeFile(path string, data []byte, name string) error {
	mode := os.FileMode(0o644)
	if isExecutableName(name) {
		mode = 0o755
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, mode); err != nil {
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		// 目标正在运行（Windows 上会拒绝覆盖）时退回直接写，让下一次启动
		// 靠哈希校验自愈。
		_ = os.Remove(tmp)
		return os.WriteFile(path, data, mode)
	}
	return nil
}

// sameContent 判断磁盘上的文件是否与嵌入数据完全一致。
func sameContent(path string, data []byte) bool {
	info, err := os.Stat(path)
	if err != nil || info.IsDir() || info.Size() != int64(len(data)) {
		return false
	}
	sum, err := fileSHA256(path)
	if err != nil {
		return false
	}
	want := sha256.Sum256(data)
	return sum == hex.EncodeToString(want[:])
}

func fileSHA256(path string) (string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:]), nil
}

// ensureExecutable 在非 Windows 平台上补可执行位。
func ensureExecutable(path, name string) {
	if runtime.GOOS == "windows" {
		return
	}
	// 只有可执行文件需要 +x，附属文件（7z.dll 之类）保持 0644。
	if !isExecutableName(name) {
		return
	}
	_ = os.Chmod(path, 0o755)
}

func isExecutableName(name string) bool {
	switch strings.ToLower(filepath.Ext(name)) {
	case ".dll", ".pl", ".py", ".txt", ".md":
		return false
	}
	return true
}

// cleanupOldVersions 删掉 tools/ 下不是当前版本的目录。
func cleanupOldVersions(parent, current string) {
	entries, err := os.ReadDir(parent)
	if err != nil {
		return
	}
	names := make([]string, 0, len(entries))
	for _, e := range entries {
		if !e.IsDir() || e.Name() == current {
			continue
		}
		names = append(names, e.Name())
	}
	sort.Strings(names)
	for _, name := range names {
		_ = os.RemoveAll(filepath.Join(parent, name))
	}
}

func toolsParent(base string) (string, error) {
	if base == "" {
		dir, err := os.UserCacheDir()
		if err != nil {
			return "", fmt.Errorf("embedded: 找不到缓存目录：%w", err)
		}
		base = dir
	}
	return filepath.Join(base, "zipkit", "tools"), nil
}

// sanitizeVersion 让版本号能安全地当目录名用。
func sanitizeVersion(v string) string {
	v = strings.TrimSpace(v)
	if v == "" {
		return "dev"
	}
	replacer := strings.NewReplacer("/", "_", "\\", "_", ":", "_", " ", "_", "..", "_")
	return replacer.Replace(v)
}
