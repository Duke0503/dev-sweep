#!/usr/bin/env bash
# Builds the CLI/TUI and the desktop app into ./bin (Ubuntu).
# Desktop app needs:  sudo apt install build-essential libgtk-3-dev libwebkit2gtk-4.1-dev
set -euo pipefail
mkdir -p bin
go build -o bin/devsweep ./cmd/devsweep
go build -tags desktop,production,webkit2_41 -o bin/devsweep-gui ./cmd/devsweep-gui
ls -l bin
