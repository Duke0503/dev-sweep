// devsweep-gui: the desktop app. A native window (WebView2 on Windows, WebKitGTK on Linux)
// that shows the same UI as `devsweep gui`, served in-process with no network listener.
//
// Build with the wails tags:
//
//	go build -tags desktop,production -ldflags "-H windowsgui" -o bin/devsweep-gui.exe ./cmd/devsweep-gui   (Windows)
//	go build -tags desktop,production,webkit2_41 -o bin/devsweep-gui ./cmd/devsweep-gui                     (Ubuntu 24.04+)
package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/wailsapp/wails/v2"
	"github.com/wailsapp/wails/v2/pkg/options"
	"github.com/wailsapp/wails/v2/pkg/options/assetserver"

	"devsweep/internal/gui"
	"devsweep/internal/setup"
)

func main() {
	roots := flag.String("roots", "", "project directories to search for stale node_modules, target/, ... (comma separated)")
	flag.Parse()

	rs, opts, err := setup.Load(*roots, "safe,review", "")
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
	err = wails.Run(&options.App{
		Title:     "devsweep",
		Width:     1180,
		Height:    780,
		MinWidth:  760,
		MinHeight: 480,
		AssetServer: &assetserver.Options{
			Handler: gui.Handler(rs, opts),
		},
	})
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}
