package main

import (
	"embed"
	"io/fs"
	"log"

	"github.com/wailsapp/wails/v3/pkg/application"
	"github.com/wailsapp/wails/v3/pkg/events"

	"github.com/bliey/zipkit/internal/attack"
	"github.com/bliey/zipkit/internal/batch"
	"github.com/bliey/zipkit/internal/embedded"
	"github.com/bliey/zipkit/internal/hashcat"
	"github.com/bliey/zipkit/internal/settingservice"
	"github.com/bliey/zipkit/internal/unzip"
	"github.com/bliey/zipkit/internal/zipservice"
)

// Version 是程序版本号，由构建时注入：
//
//	go build -ldflags "-X main.Version=1.0.0"
//
// 没注入时是 "dev"。它同时决定内置工具的释放目录（tools/<version>/），
// 所以每次发版都会用新目录，旧目录在下次启动时被清掉。
var Version = "dev"

// The frontend is plain HTML/CSS/JS with no build step, so it is embedded
// straight from the source directory.
//
//go:embed all:frontend
var frontendAssets embed.FS

func main() {
	assets, err := fs.Sub(frontendAssets, "frontend")
	if err != nil {
		log.Fatalf("zipkit: embedded frontend: %v", err)
	}

	// 窗口图标（Wails 3 的 application.Options.Icon）直接复用前端那份 128×128
	// 图标，省得再嵌一份二进制。Windows 的任务栏 / exe 图标不走这条路——它靠
	// 仓库根目录的 wails_windows_amd64.syso（由 wails3 generate syso 生成，
	// go build 会自动链接）。
	appIcon, err := fs.ReadFile(frontendAssets, "frontend/assets/appicon.png")
	if err != nil {
		log.Printf("zipkit: 读取窗口图标失败：%v", err)
	}

	// 先把内置工具放好：后面的路径探测会优先用释放出来的这一份。
	// 失败不阻塞启动——只是相应功能需要用户手动配路径，设置页会显示原因。
	embedded.SetVersion(Version)
	if err := embedded.Release(); err != nil {
		log.Printf("zipkit: 内置工具释放失败：%v", err)
	}

	app := application.New(application.Options{
		Name:        "zipkit",
		Description: "ZIP 结构侦察器、伪加密修复、批量破解、明文攻击与 GPU 恢复",
		Icon:        appIcon,
		Services: []application.Service{
			application.NewService(&zipservice.ZipService{}),
			application.NewService(&batch.BatchService{}),
			application.NewService(&unzip.UnzipService{}),
			application.NewService(&attack.AttackService{}),
			application.NewService(&hashcat.HashcatService{}),
			application.NewService(&settingservice.SettingsService{}),
		},
		Assets: application.AssetOptions{
			Handler: application.AssetFileServerFS(assets),
		},
		Mac: application.MacOptions{
			ApplicationShouldTerminateAfterLastWindowClosed: true,
		},
	})

	win := app.Window.NewWithOptions(application.WebviewWindowOptions{
		Title:            "zipkit — ZIP 侦察、伪加密修复、批量破解、明文攻击与 GPU 恢复",
		Width:            1180,
		Height:           820,
		MinWidth:         900,
		MinHeight:        560,
		URL:              "/",
		EnableFileDrop:   true,
		BackgroundColour: application.NewRGB(0xf6, 0xf1, 0xe7),
		Mac: application.MacWindow{
			InvisibleTitleBarHeight: 50,
			Backdrop:                application.MacBackdropTranslucent,
			TitleBar:                application.MacTitleBarHiddenInset,
		},
	})

	// 原生拖放拿到的是真实路径，前端只需要事件名和路径数组。
	win.OnWindowEvent(events.Common.WindowFilesDropped, func(e *application.WindowEvent) {
		files := e.Context().DroppedFiles()
		if len(files) == 0 {
			return
		}
		app.Event.Emit("files-dropped", files)
	})

	if err := app.Run(); err != nil {
		log.Fatalf("zipkit: %v", err)
	}
}
