# Builds the CLI/TUI and the desktop app into ./bin (Windows).
$ErrorActionPreference = 'Stop'
New-Item -ItemType Directory -Force bin | Out-Null
go build -o bin\devsweep.exe .\cmd\devsweep
go build -tags desktop,production -ldflags "-H windowsgui" -o bin\devsweep-gui.exe .\cmd\devsweep-gui
Get-Item bin\*.exe | Select-Object Name, Length
