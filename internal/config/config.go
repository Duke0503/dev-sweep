// Package config reads ~/.devsweep/config.yaml.
package config

import (
	"os"
	"path/filepath"

	"gopkg.in/yaml.v3"
)

type Config struct {
	// Roots are the directories searched for stale project build output.
	Roots []string `yaml:"roots"`
}

func Dir() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return ""
	}
	return filepath.Join(home, ".devsweep")
}

func RulesFile() string {
	if d := Dir(); d != "" {
		return filepath.Join(d, "rules.yaml")
	}
	return ""
}

// Load returns the config. A missing file is not an error.
func Load() (Config, error) {
	var c Config
	d := Dir()
	if d == "" {
		return c, nil
	}
	data, err := os.ReadFile(filepath.Join(d, "config.yaml"))
	if os.IsNotExist(err) {
		return c, nil
	}
	if err != nil {
		return c, err
	}
	err = yaml.Unmarshal(data, &c)
	return c, err
}

// DefaultRoots returns common project directories that exist, falling back to the working directory.
func DefaultRoots() []string {
	var roots []string
	if home, err := os.UserHomeDir(); err == nil {
		for _, n := range []string{"Projects", "projects", "Project", "code", "Code", "dev", "Dev", "src", "repos", "work", "workspace"} {
			p := filepath.Join(home, n)
			if fi, err := os.Stat(p); err == nil && fi.IsDir() {
				roots = append(roots, p)
			}
		}
	}
	if len(roots) == 0 {
		if wd, err := os.Getwd(); err == nil {
			roots = append(roots, wd)
		}
	}
	return roots
}
