package safety

import (
	"os"
	"path/filepath"
	"testing"
)

func TestCheck(t *testing.T) {
	home, err := os.UserHomeDir()
	if err != nil {
		t.Skip("no home dir")
	}
	root := filepath.VolumeName(home) + string(filepath.Separator)
	refuse := []string{
		home,
		root,
		filepath.Dir(home),
		filepath.Join(home, "Documents"),
		filepath.Join(home, "project", ".git", "objects"),
		"relative/path",
	}
	for _, p := range refuse {
		if Check(p) == nil {
			t.Errorf("Check(%q) = nil, want refusal", p)
		}
	}
	allow := []string{
		filepath.Join(home, ".cache", "pip"),
		filepath.Join(home, "AppData", "Local", "npm-cache"),
		filepath.Join(home, "project", "node_modules"),
	}
	for _, p := range allow {
		if err := Check(p); err != nil {
			t.Errorf("Check(%q) = %v, want nil", p, err)
		}
	}
}
