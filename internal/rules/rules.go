// Package rules loads the declarative cleanup rules (built-in plus user supplied).
package rules

import (
	_ "embed"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v3"
)

//go:embed default.yaml
var defaultYAML []byte

type Safety string

const (
	Safe   Safety = "safe"
	Review Safety = "review"
)

// Artifact describes build output discovered under the scan roots.
type Artifact struct {
	Dir       string   `yaml:"dir"`
	Markers   []string `yaml:"markers"`
	StaleDays int      `yaml:"stale_days"`
}

type Rule struct {
	ID          string    `yaml:"id"`
	Name        string    `yaml:"name"`
	Description string    `yaml:"description"`
	Safety      Safety    `yaml:"safety"`
	OS          []string  `yaml:"os"`
	Paths       []string  `yaml:"paths"`
	Contents    bool      `yaml:"contents"`
	Artifact    *Artifact `yaml:"artifact"`
	Clean       []string  `yaml:"clean"`
}

// Load returns the built-in rules followed by the rules in userFile (if it exists).
// A user rule with the same id replaces the built-in one.
func Load(userFile string) ([]Rule, error) {
	rs, err := parse(defaultYAML)
	if err != nil {
		return nil, fmt.Errorf("built-in rules: %w", err)
	}
	if userFile == "" {
		return rs, nil
	}
	data, err := os.ReadFile(userFile)
	if os.IsNotExist(err) {
		return rs, nil
	}
	if err != nil {
		return nil, err
	}
	extra, err := parse(data)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", userFile, err)
	}
	idx := map[string]int{}
	for i, r := range rs {
		idx[r.ID] = i
	}
	for _, r := range extra {
		if i, ok := idx[r.ID]; ok {
			rs[i] = r
		} else {
			rs = append(rs, r)
		}
	}
	return rs, nil
}

func parse(data []byte) ([]Rule, error) {
	var rs []Rule
	if err := yaml.Unmarshal(data, &rs); err != nil {
		return nil, err
	}
	seen := map[string]bool{}
	for _, r := range rs {
		switch {
		case r.ID == "":
			return nil, fmt.Errorf("rule %q has no id", r.Name)
		case seen[r.ID]:
			return nil, fmt.Errorf("duplicate rule id %q", r.ID)
		case r.Safety != Safe && r.Safety != Review:
			return nil, fmt.Errorf("rule %q: safety must be safe or review", r.ID)
		case len(r.Paths) == 0 && r.Artifact == nil:
			return nil, fmt.Errorf("rule %q needs paths or artifact", r.ID)
		case r.Artifact != nil && (r.Artifact.Dir == "" || len(r.Artifact.Markers) == 0):
			return nil, fmt.Errorf("rule %q: artifact needs dir and markers", r.ID)
		}
		seen[r.ID] = true
	}
	return rs, nil
}

// AppliesTo reports whether the rule is enabled on the given GOOS.
func (r Rule) AppliesTo(goos string) bool {
	if len(r.OS) == 0 {
		return true
	}
	for _, o := range r.OS {
		if o == goos {
			return true
		}
	}
	return false
}

// Expand resolves %VAR%, $VAR and a leading ~ and returns a cleaned absolute path.
// It returns "" when a variable is unset or the result is not absolute, so an
// unset variable can never turn into a path relative to a drive root.
func Expand(p string) string {
	for {
		i := strings.Index(p, "%")
		if i < 0 {
			break
		}
		j := strings.Index(p[i+1:], "%")
		if j < 0 {
			break
		}
		v := os.Getenv(p[i+1 : i+1+j])
		if v == "" {
			return ""
		}
		p = p[:i] + v + p[i+2+j:]
	}
	empty := false
	p = os.Expand(p, func(name string) string {
		v := os.Getenv(name)
		if v == "" {
			empty = true
		}
		return v
	})
	if empty {
		return ""
	}
	if p == "~" || strings.HasPrefix(p, "~/") || strings.HasPrefix(p, `~\`) {
		home, err := os.UserHomeDir()
		if err != nil || home == "" {
			return ""
		}
		p = filepath.Join(home, p[1:])
	}
	p = filepath.Clean(p)
	if !filepath.IsAbs(p) {
		return ""
	}
	return p
}
