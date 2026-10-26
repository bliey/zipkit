// Package settingservice 把散落在各个包里的配置项汇总成一个设置面板。
//
// 配置本身仍然只存在一个地方（<UserConfigDir>/zipkit/config.json，由
// internal/settings 负责读写）。这个包只做三件事：
//
//  1. 把「当前配置 + 各外部工具是否可用」打成一个快照给前端；
//  2. 接受前端的修改，写回配置，并同步到各个包的进程内探测状态；
//  3. 保存后立刻重新检测，让界面上的状态与真实情况一致——不需要重启。
package settingservice

import (
	"errors"
	"fmt"
	"os"
	"runtime"
	"strings"

	"github.com/bliey/zipkit/internal/attack"
	"github.com/bliey/zipkit/internal/embedded"
	"github.com/bliey/zipkit/internal/hashcat"
	"github.com/bliey/zipkit/internal/settings"
	"github.com/bliey/zipkit/internal/unzip"
)

// 工具种类。与配置字段一一对应。
const (
	KindSevenZip      = "sevenzip"
	KindBkcrack       = "bkcrack"
	KindHashcat       = "hashcat"
	KindRar2John      = "rar2john"
	KindSevenZip2John = "7z2john"
	// KindSevenZip2Hashcat 是 7z 提哈希的备用路径（Perl 脚本或官方 .exe）。
	KindSevenZip2Hashcat = "7z2hashcat"
	// KindInterpreter 是运行 .pl / .py 脚本的解释器。
	KindInterpreter = "interpreter"
)

// 工具来源的四种状态。设置页按 State 决定显示哪一句文案、要不要给
// 「恢复为内置版本」按钮。
const (
	// StateBuiltin 用的是随程序分发的内置副本。
	StateBuiltin = "builtin"
	// StateConfig 用的是用户在设置里显式配置的路径。
	StateConfig = "config"
	// StateAuto 是既没内置也没配置，在系统 PATH 里找到的。
	StateAuto = "auto"
	// StateMissing 三者都没有。
	StateMissing = "missing"
)

// Tool 是一个外部工具在设置面板里的状态。
type Tool struct {
	Kind      string `json:"kind"`
	Label     string `json:"label"`
	Hint      string `json:"hint"`      // 一句话说明这个工具用在哪里
	Path      string `json:"path"`      // 配置里保存的路径（可能为空）
	Available bool   `json:"available"` // 当前是否真的能找到
	Resolved  string `json:"resolved"`  // 实际解析到的路径
	Message   string `json:"message"`   // 状态文案，见 State* 常量
	// Source 说明这条路径是怎么来的：config | builtin | auto | ""。
	Source string `json:"source"`
	// State 归一化后的来源，取值见 State* 常量。前端只认这个。
	State string `json:"state"`
	// CanRestore 表示「恢复为内置版本」按钮可用：用户配了路径，
	// 而程序里另有一份能用的内置副本可以直接顶上。
	CanRestore bool `json:"canRestore"`
	// Bundled 表示程序里带了这个工具的位置（在内置清单里）；
	// Builtin 表示这次运行确实释放成功，BuiltinVersion 是它自己的版本号。
	Bundled        bool   `json:"bundled"`
	Builtin        bool   `json:"builtin"`
	BuiltinVersion string `json:"builtinVersion"`
	// Native 表示这个工具由程序内建实现提供（当前只有 7z2john）。
	Native bool `json:"native"`
	// Check 是三层自检的结论：ok / not-embedded / release-failed / not-runnable。
	Check string `json:"check"`
	// CheckDetail 是自检失败时的具体原因。
	CheckDetail string `json:"checkDetail"`
	// Warning 是非致命的提示，例如「配置的路径无效，已回退到内置版本」。
	Warning string `json:"warning"`
}

// Snapshot 是设置面板需要的全部数据。
type Snapshot struct {
	Tools            []Tool `json:"tools"`
	BatchConcurrency int    `json:"batchConcurrency"`
	UnzipConcurrency int    `json:"unzipConcurrency"`
	NumCPU           int    `json:"numCPU"`
	DefaultExportDir string `json:"defaultExportDir"`
	ConfigPath       string `json:"configPath"`
	// Version 是程序版本，来自构建时注入的 main.Version。
	Version string `json:"version"`
	// Builtin 是内置工具清单，BuiltinDir 是本次运行的释放目录，
	// BuiltinError 是释放失败的原因（空表示全部正常）。
	Builtin      []embedded.Info `json:"builtin"`
	BuiltinDir   string          `json:"builtinDir"`
	BuiltinError string          `json:"builtinError"`
}

// SettingsService 是绑定到前端的设置服务。
type SettingsService struct{}

// Snapshot 读取配置并重新检测所有外部工具。
func (s *SettingsService) Snapshot() Snapshot {
	cfg := settings.Load()
	applyPaths(cfg)

	// 自检的第三层（能不能执行）要起进程，只在第一次进设置页时跑一遍。
	embedded.Verify()

	builtinErr := ""
	if err := embedded.LastError(); err != nil {
		builtinErr = err.Error()
	}

	return Snapshot{
		Tools:            detectAll(cfg),
		BatchConcurrency: batchConcurrency(cfg),
		UnzipConcurrency: cfg.Concurrency,
		NumCPU:           runtime.NumCPU(),
		DefaultExportDir: cfg.DefaultExportDir,
		ConfigPath:       configPath(),
		Version:          version(),
		Builtin:          embedded.Infos(),
		BuiltinDir:       embedded.Root(),
		BuiltinError:     builtinErr,
	}
}

// SetPath 修改某个外部工具的路径并保存。path 为空表示恢复自动探测。
//
// 路径会原样保存，即使检测不通过——面板上那一行会立刻变红显示「未找到」，
// 各个功能入口也跟着禁用。这样用户能看清「就是我填的这条路径不对」，
// 而不是莫名其妙被改回去；把输入框清空再保存即可回到自动探测。
func (s *SettingsService) SetPath(kind, path string) (Snapshot, error) {
	kind = strings.TrimSpace(kind)
	path = strings.TrimSpace(path)

	cfg := settings.Load()
	if _, ok := getPath(cfg, kind); !ok {
		return s.Snapshot(), fmt.Errorf("settings: 未知的工具 %q", kind)
	}

	setPath(&cfg, kind, path)
	if err := settings.Save(cfg); err != nil {
		return s.Snapshot(), fmt.Errorf("settings: 保存配置失败：%w", err)
	}
	applyPaths(cfg)

	return s.Snapshot(), nil
}

// SetBatchConcurrency 修改批量破解的并发数。
func (s *SettingsService) SetBatchConcurrency(n int) (Snapshot, error) {
	if n < 1 || n > runtime.NumCPU() {
		return s.Snapshot(), fmt.Errorf("settings: 并发数必须在 1 到 %d 之间", runtime.NumCPU())
	}
	if err := settings.Update(func(c *settings.Config) { c.BatchConcurrency = n }); err != nil {
		return s.Snapshot(), fmt.Errorf("settings: 保存配置失败：%w", err)
	}
	return s.Snapshot(), nil
}

// SetUnzipConcurrency 修改批量解压的并发数。
func (s *SettingsService) SetUnzipConcurrency(n int) (Snapshot, error) {
	if n < 1 || n > 8 {
		return s.Snapshot(), fmt.Errorf("settings: 解压并发数必须在 1 到 8 之间")
	}
	if err := settings.Update(func(c *settings.Config) { c.Concurrency = n }); err != nil {
		return s.Snapshot(), fmt.Errorf("settings: 保存配置失败：%w", err)
	}
	return s.Snapshot(), nil
}

// SetDefaultExportDir 修改默认导出目录。空字符串表示不指定。
func (s *SettingsService) SetDefaultExportDir(dir string) (Snapshot, error) {
	dir = strings.TrimSpace(dir)
	if dir != "" {
		st, err := os.Stat(dir)
		if err != nil {
			return s.Snapshot(), fmt.Errorf("settings: 打不开目录 %s：%w", dir, err)
		}
		if !st.IsDir() {
			return s.Snapshot(), fmt.Errorf("settings: %s 不是一个目录", dir)
		}
	}
	if err := settings.Update(func(c *settings.Config) { c.DefaultExportDir = dir }); err != nil {
		return s.Snapshot(), fmt.Errorf("settings: 保存配置失败：%w", err)
	}
	return s.Snapshot(), nil
}

// Recheck 只重新检测，不改配置。
func (s *SettingsService) Recheck() Snapshot {
	// 「重新检测」要重新跑一遍执行探测，否则用户修好依赖后状态还是旧的。
	embedded.ResetVerify()
	return s.Snapshot()
}

// ---------------------------------------------------------------- 内部实现

func configPath() string {
	path, err := settings.Path()
	if err != nil {
		return ""
	}
	return path
}

// batchConcurrency 返回实际生效的批量并发数：配置优先，否则按 CPU 推导。
func batchConcurrency(cfg settings.Config) int {
	if cfg.BatchConcurrency > 0 {
		return cfg.BatchConcurrency
	}
	n := runtime.NumCPU() - 1
	if n < 2 {
		n = 2
	}
	if n > runtime.NumCPU() {
		n = runtime.NumCPU()
	}
	return n
}

// applyPaths 把配置里的路径同步到各包的进程内探测状态。
func applyPaths(cfg settings.Config) {
	unzip.SetSevenZipPath(cfg.SevenZipPath)
	attack.SetBkcrackPath(cfg.BkcrackPath)
	hashcat.SetToolPaths(cfg.HashcatPath, cfg.Rar2JohnPath, cfg.SevenZip2JohnPath)
	hashcat.Set7z2HashcatPaths(cfg.SevenZip2HashcatPath, cfg.InterpreterPath)
}

// detectAll 列出设置页要显示的工具。
//
// 刻意**不列** 7z2hashcat 与脚本解释器：它们是 7z 提哈希的备用路径（内建实现
// 已经覆盖常见结构，只有 BCJ2 / PPMd 之类才需要），既不是必需依赖，也没有
// 内置副本。列出来只会在面板上多两行「未找到」，把「下载即用」这件事说反。
// 配置里仍然保留这两个字段，internal/hashcat 也仍会自动探测 PATH，所以
// 真有需要的用户手写 config.json 依旧能生效。
func detectAll(cfg settings.Config) []Tool {
	return []Tool{
		detectOne(cfg, KindSevenZip),
		detectOne(cfg, KindBkcrack),
		detectOne(cfg, KindHashcat),
		detectOne(cfg, KindRar2John),
		detectOne(cfg, KindSevenZip2John),
	}
}

func detectOne(cfg settings.Config, kind string) Tool {
	tool := Tool{
		Kind:  kind,
		Label: labelOf(kind),
		Hint:  hintOf(kind),
		Path:  mustGetPath(cfg, kind),
	}

	switch kind {
	case KindSevenZip:
		st := unzip.DetectSevenZip()
		tool.Available = st.Available
		tool.Resolved = st.Path
		tool.Message = st.Message
		tool.Source = st.Source
	case KindBkcrack:
		st := attack.DetectBkcrack()
		tool.Available = st.Available
		tool.Resolved = st.Path
		tool.Message = st.Message
		tool.Source = st.Source
	default:
		st := hashcat.DetectTool(kind)
		tool.Available = st.Available
		tool.Resolved = st.Path
		tool.Message = st.Message
		tool.Source = st.Source
		tool.Warning = st.Warning
	}

	// 内置信息按 kind 直接查清单：即使这次没用上（用户配了别的路径），
	// 面板上也应该显示「这个工具是内置的」。
	info, ok := embedded.InfoOf(embeddedKind(kind))
	if !ok {
		// hashcat（以及脚本类工具）本来就不内置，没有任何内置信息可查。
		tool.State = stateOf(tool, embedded.Info{})
		tool.Message = messageOf(tool, embedded.Info{})
		return tool
	}
	tool.Bundled = true
	tool.Builtin = info.Builtin
	tool.BuiltinVersion = info.Version
	tool.Native = info.Native
	tool.Check = info.Status
	tool.CheckDetail = info.Detail

	switch {
	case tool.Warning != "" && info.Builtin:
		// 用户配的路径不对，但内置的那份能用：功能照常，只是提醒他修一下。
		tool.Message = tool.Warning + "，已回退到内置版本"
	case info.Status == embedded.StatusNotRunnable:
		// 文件在、但跑不起来。这种情况最坑：光看文件存在会以为一切正常。
		tool.Available = false
		if tool.Source == "builtin" {
			tool.Source = ""
		}
		tool.Message = "内置版本无法执行：" + info.Detail
	case info.Status == embedded.StatusReleaseFailed:
		tool.Message = "内置版本释放失败：" + info.Detail
	case !tool.Available && info.Status == embedded.StatusNotEmbedded:
		if info.Detail != "" {
			tool.Message = "未内置：" + info.Detail
		} else {
			tool.Message = "未内置（这个平台没有放二进制），请手动配置"
		}
	}

	tool.State = stateOf(tool, info)

	// 文案优先级：先让「失败 / 回退」这类必须说清楚的原因留着，其余情况
	// 一律用统一措辞（已内置（版本）/ 用户配置：路径 / 系统路径：路径）。
	// 不能直接沿用各包自己的 Message（例如「7z 已就绪：<路径>」），
	// 那样面板上就看不出「这一份是内置的、版本是多少」。
	switch {
	case tool.Warning != "":
		// 上面已经拼好「配置无效，已回退到内置版本」。
	case info.Status != embedded.StatusOK:
		// 未内置 / 释放失败 / 跑不起来，都保留具体原因。
	case tool.State == StateBuiltin, tool.State == StateConfig, tool.State == StateAuto:
		tool.Message = messageOf(tool, info)
	}
	if tool.Message == "" {
		tool.Message = messageOf(tool, info)
	}
	// 只有「用户配了路径」且「另有一份能跑的内置副本」时才给恢复按钮。
	tool.CanRestore = tool.Path != "" && tool.Source == StateConfig && info.Builtin &&
		info.Status == embedded.StatusOK
	return tool
}

// stateOf 把「路径从哪来」归一化成四个状态之一。
func stateOf(tool Tool, info embedded.Info) string {
	switch {
	case tool.Source == StateConfig:
		return StateConfig
	case tool.Available && (tool.Source == "builtin" || info.Builtin && tool.Resolved == info.Path):
		return StateBuiltin
	case tool.Available:
		return StateAuto
	case info.Native:
		return StateBuiltin
	}
	return StateMissing
}

// messageOf 生成状态文案：已内置（版本）/ 用户配置：路径 / 系统路径：路径 / 未找到。
func messageOf(tool Tool, info embedded.Info) string {
	switch tool.State {
	case StateConfig:
		if tool.Resolved != "" {
			return "用户配置：" + tool.Resolved
		}
		return "用户配置：" + tool.Path + "（路径无效）"
	case StateBuiltin:
		if info.Native {
			return "已内置（程序内建实现，无需外部文件）"
		}
		if info.Version != "" {
			return "已内置（" + info.Version + "）"
		}
		return "已内置"
	case StateAuto:
		return "系统路径：" + tool.Resolved
	}
	return "未找到，需要手动指定"
}

// RestoreBuiltin 把某个工具的路径清空，回退到随程序分发的内置版本。
//
// 等价于 SetPath(kind, "")，单独留一个方法是为了让前端的「恢复为内置版本」
// 按钮有个明确语义的入口，语义不对（这个工具本来就不内置）时直接报错，
// 而不是悄悄清空用户填的路径。
func (s *SettingsService) RestoreBuiltin(kind string) (Snapshot, error) {
	kind = strings.TrimSpace(kind)
	if _, ok := getPath(settings.Load(), kind); !ok {
		return s.Snapshot(), fmt.Errorf("settings: 未知的工具 %q", kind)
	}
	info, ok := embedded.InfoOf(embeddedKind(kind))
	if !ok || !info.Builtin {
		return s.Snapshot(), fmt.Errorf("settings: %s 没有可用的内置版本，无法恢复", labelOf(kind))
	}
	return s.SetPath(kind, "")
}

// embeddedKind 把设置面板的工具种类映射到内置清单的种类。
func embeddedKind(kind string) string {
	switch kind {
	case KindSevenZip:
		return embedded.KindSevenZip
	case KindBkcrack:
		return embedded.KindBkcrack
	case KindRar2John:
		return embedded.KindRar2John
	case KindSevenZip2John:
		return embedded.KindSevenZip2John
	}
	return ""
}

// version 返回构建时注入的程序版本。
func version() string { return embedded.Version() }

func labelOf(kind string) string {
	switch kind {
	case KindSevenZip:
		return "7z"
	case KindBkcrack:
		return "bkcrack"
	case KindHashcat:
		return "hashcat"
	case KindRar2John:
		return "rar2john"
	case KindSevenZip2John:
		return "7z2john"
	case KindSevenZip2Hashcat:
		return "7z2hashcat"
	case KindInterpreter:
		return "脚本解释器"
	}
	return kind
}

func hintOf(kind string) string {
	switch kind {
	case KindSevenZip:
		return "批量解压、用密码解压"
	case KindBkcrack:
		return "明文攻击"
	case KindHashcat:
		// hashcat 刻意不内置：体积大、依赖 OpenCL 运行时、更新频繁。
		return "GPU 加速破解（需自行安装，不随程序分发）"
	case KindRar2John:
		return "RAR5 提取哈希"
	case KindSevenZip2John:
		return "7z 提取哈希（回退路径）"
	case KindSevenZip2Hashcat:
		return "7z 提取哈希的备用实现，内建实现不支持的编码链才用得上"
	case KindInterpreter:
		return "运行 7z2hashcat.pl 需要 Perl，运行 .py 脚本需要 Python 3"
	}
	return ""
}

func getPath(cfg settings.Config, kind string) (string, bool) {
	switch kind {
	case KindSevenZip:
		return cfg.SevenZipPath, true
	case KindBkcrack:
		return cfg.BkcrackPath, true
	case KindHashcat:
		return cfg.HashcatPath, true
	case KindRar2John:
		return cfg.Rar2JohnPath, true
	case KindSevenZip2John:
		return cfg.SevenZip2JohnPath, true
	case KindSevenZip2Hashcat:
		return cfg.SevenZip2HashcatPath, true
	case KindInterpreter:
		return cfg.InterpreterPath, true
	}
	return "", false
}

func mustGetPath(cfg settings.Config, kind string) string {
	path, _ := getPath(cfg, kind)
	return path
}

func setPath(cfg *settings.Config, kind, path string) {
	switch kind {
	case KindSevenZip:
		cfg.SevenZipPath = path
	case KindBkcrack:
		cfg.BkcrackPath = path
	case KindHashcat:
		cfg.HashcatPath = path
	case KindRar2John:
		cfg.Rar2JohnPath = path
	case KindSevenZip2John:
		cfg.SevenZip2JohnPath = path
	case KindSevenZip2Hashcat:
		cfg.SevenZip2HashcatPath = path
	case KindInterpreter:
		cfg.InterpreterPath = path
	}
}

// ErrUnknownKind 供调用方判断「传了个不认识的工具名」。
var ErrUnknownKind = errors.New("settings: 未知的工具")
