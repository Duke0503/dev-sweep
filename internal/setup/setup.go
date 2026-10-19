// Package setup resolves rules, scan roots and filters shared by every front end (CLI, TUI, GUI).
package setup

import (
	"strings"

	"devsweep/internal/config"
	"devsweep/internal/rules"
	"devsweep/internal/scan"
)

// Load builds the active rules and scan options. roots, safety and only are comma separated
// lists; empty roots fall back to config.yaml, then to common project directories.
func Load(roots, safety, only string) ([]rules.Rule, scan.Options, error) {
	rs, err := rules.Load(config.RulesFile())
	if err != nil {
		return nil, scan.Options{}, err
	}
	cfg, err := config.Load()
	if err != nil {
		return nil, scan.Options{}, err
	}
	rl := cfg.Roots
	if roots != "" {
		rl = SplitList(roots)
	}
	if len(rl) == 0 {
		rl = config.DefaultRoots()
	}
	for i, r := range rl {
		if e := rules.Expand(r); e != "" {
			rl[i] = e
		}
	}
	allow := map[string]bool{}
	for _, s := range SplitList(safety) {
		allow[s] = true
	}
	want := map[string]bool{}
	for _, s := range SplitList(only) {
		want[s] = true
	}
	var out []rules.Rule
	for _, r := range rs {
		if !allow[string(r.Safety)] || (len(want) > 0 && !want[r.ID]) {
			continue
		}
		out = append(out, r)
	}
	return out, scan.Options{Roots: rl}, nil
}

func SplitList(s string) []string {
	var out []string
	for _, p := range strings.Split(s, ",") {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}
