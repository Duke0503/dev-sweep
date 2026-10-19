# devsweep

CLI + TUI that finds junk on a developer machine (package caches, stale `node_modules`/`target/`,
old tool binaries, logs, temp files) and cleans it safely. Windows and Linux. Written in Go.

## Build

```
go build -o bin/devsweep ./cmd/devsweep                         # current OS
GOOS=linux GOARCH=amd64 go build -o bin/devsweep-linux ./cmd/devsweep   # cross-compile for Ubuntu
```

## Usage

```
devsweep                  interactive TUI
devsweep scan             list findings (read-only)
devsweep clean            dry-run
devsweep clean --yes      apply (moves to quarantine)
devsweep clean --yes --delete   delete permanently
devsweep restore [batch]  list / restore quarantine batches
devsweep purge --yes      delete the quarantine for good
devsweep rules            list rules
```

Common flags: `--roots a,b`, `--safety safe|review`, `--only rule-id,...`.

Project build output (`node_modules`, `target/`, `.next`, `.venv`) is only searched under *roots*:
`--roots`, else `roots:` in `~/.devsweep/config.yaml`, else common dirs in your home (`~/Projects`, `~/code`, ...),
else the current directory.

## Safety model

- Nothing changes without `--yes` (CLI) or an explicit `y` (TUI).
- Default mode moves items to `~/.devsweep/quarantine/<timestamp>/` with a manifest, so `restore` can undo it.
  Space is only freed after `purge` (or use `--delete`).
- When a rule has an official clean command (`npm cache clean`, `go clean -cache`, `pnpm store prune`, ...)
  and the tool is installed, that command is used instead.
- Hard-coded refusals (`internal/safety`): home dir and user document folders, system directories, drive/filesystem roots,
  anything inside `.git`, symlinks. Not configurable.
- Symlinks and junctions are never followed. Files in use are skipped.
- A rule path with an unset variable is dropped, never resolved against a drive root.
- Build output is only offered when the project's marker file (`package.json`, `Cargo.toml`, ...) has not changed for N days.

## Rules

Declarative YAML: `internal/rules/default.yaml`. Add your own in `~/.devsweep/rules.yaml`
(same schema; same `id` overrides a built-in rule).

## Roadmap

- v2: RAM report (top processes, orphaned `node`/language servers, startup items), Docker prune rules.
- Linux: apt cache, journal, old snaps/kernels (need sudo, separate elevated step).
- Windows: Windows Update cache, Recycle Bin (need admin).
- Not tested yet on Linux; Windows is verified.
