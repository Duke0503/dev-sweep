// Package scan turns rules into sized findings. It never modifies anything.
package scan

import (
	"context"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"sync"
	"time"

	"devsweep/internal/rules"
)

type Finding struct {
	RuleID      string       `json:"rule"`
	Name        string       `json:"name"`
	Description string       `json:"description"`
	Safety      rules.Safety `json:"safety"`
	Path        string       `json:"path"`
	Size        int64        `json:"size"`
	Files       int64        `json:"files"`
	Contents    bool         `json:"contents"`
	Clean       []string     `json:"clean,omitempty"`
	StaleDays   int          `json:"stale_days,omitempty"`
}

type Options struct {
	Roots    []string // where to look for project build output
	MaxDepth int      // directory depth below each root; default 6
	Workers  int      // parallel size calculations
}

const maxDepthDefault = 6

// Run evaluates every rule that applies to this OS and returns non-empty findings, largest first.
func Run(ctx context.Context, rs []rules.Rule, o Options) []Finding {
	if o.Workers <= 0 {
		o.Workers = 8
	}
	if o.MaxDepth <= 0 {
		o.MaxDepth = maxDepthDefault
	}
	var cands []Finding
	var artifactRules []rules.Rule
	for _, r := range rs {
		if !r.AppliesTo(runtime.GOOS) {
			continue
		}
		if r.Artifact != nil {
			artifactRules = append(artifactRules, r)
			continue
		}
		for _, raw := range r.Paths {
			exp := rules.Expand(raw)
			if exp == "" {
				continue
			}
			matches, err := filepath.Glob(exp)
			if err != nil {
				continue
			}
			for _, m := range matches {
				fi, err := os.Lstat(m)
				if err != nil || fi.Mode()&os.ModeSymlink != 0 {
					continue
				}
				cands = append(cands, base(r, m))
			}
		}
	}
	cands = append(cands, discover(ctx, artifactRules, o)...)
	cands = dedupe(cands)

	sizeAll(ctx, cands, o.Workers)

	out := cands[:0]
	for _, f := range cands {
		if f.Size > 0 {
			out = append(out, f)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Size > out[j].Size })
	return out
}

func base(r rules.Rule, path string) Finding {
	return Finding{
		RuleID: r.ID, Name: r.Name, Description: r.Description, Safety: r.Safety,
		Path: path, Contents: r.Contents, Clean: r.Clean,
	}
}

func dedupe(in []Finding) []Finding {
	seen := map[string]bool{}
	out := in[:0]
	for _, f := range in {
		key := strings.ToLower(f.Path)
		if seen[key] {
			continue
		}
		seen[key] = true
		out = append(out, f)
	}
	return out
}

// discover walks the roots once and collects stale build output for all artifact rules.
func discover(ctx context.Context, ars []rules.Rule, o Options) []Finding {
	if len(ars) == 0 || len(o.Roots) == 0 {
		return nil
	}
	byDir := map[string]rules.Rule{}
	for _, r := range ars {
		byDir[r.Artifact.Dir] = r
	}
	now := time.Now()
	var out []Finding
	for _, root := range o.Roots {
		root = filepath.Clean(root)
		_ = filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			if err != nil || !d.IsDir() {
				return nil
			}
			if path == root {
				return nil
			}
			name := d.Name()
			if r, ok := byDir[name]; ok {
				if age, ok := markerAge(filepath.Dir(path), r.Artifact.Markers, now); ok && age >= r.Artifact.StaleDays {
					f := base(r, path)
					f.StaleDays = age
					out = append(out, f)
				}
				return filepath.SkipDir
			}
			if name == ".git" || name == "node_modules" || strings.HasPrefix(name, ".") {
				return filepath.SkipDir
			}
			rel, _ := filepath.Rel(root, path)
			if strings.Count(rel, string(filepath.Separator))+1 > o.MaxDepth {
				return filepath.SkipDir
			}
			return nil
		})
	}
	return out
}

// markerAge returns the age in days of the newest marker file present in dir.
func markerAge(dir string, markers []string, now time.Time) (int, bool) {
	var newest time.Time
	found := false
	for _, m := range markers {
		fi, err := os.Stat(filepath.Join(dir, m))
		if err != nil {
			continue
		}
		found = true
		if fi.ModTime().After(newest) {
			newest = fi.ModTime()
		}
	}
	if !found {
		return 0, false
	}
	return int(now.Sub(newest).Hours() / 24), true
}

func sizeAll(ctx context.Context, fs []Finding, workers int) {
	var wg sync.WaitGroup
	sem := make(chan struct{}, workers)
	for i := range fs {
		wg.Add(1)
		sem <- struct{}{}
		go func(f *Finding) {
			defer wg.Done()
			defer func() { <-sem }()
			f.Size, f.Files = DirSize(ctx, f.Path)
		}(&fs[i])
	}
	wg.Wait()
}

// DirSize sums regular files below path. Symlinks, junctions and other irregular entries
// are neither followed nor counted.
func DirSize(ctx context.Context, path string) (size, files int64) {
	fi, err := os.Lstat(path)
	if err != nil {
		return 0, 0
	}
	if fi.Mode().IsRegular() {
		return fi.Size(), 1
	}
	_ = filepath.WalkDir(path, func(_ string, d fs.DirEntry, err error) error {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if err != nil || d.IsDir() || !d.Type().IsRegular() {
			return nil
		}
		if info, err := d.Info(); err == nil {
			size += info.Size()
			files++
		}
		return nil
	})
	return size, files
}

// FormatSize renders bytes as a short human readable string.
func FormatSize(n int64) string {
	const unit = 1024
	if n < unit {
		return fmt.Sprintf("%d B", n)
	}
	div, exp := int64(unit), 0
	for m := n / unit; m >= unit; m /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %ciB", float64(n)/float64(div), "KMGTPE"[exp])
}
