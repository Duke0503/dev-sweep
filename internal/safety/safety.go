// Package safety holds the hard-coded guard rails. They are not configurable on purpose.
package safety

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
)

func same(a, b string) bool {
	if runtime.GOOS == "windows" {
		return strings.EqualFold(a, b)
	}
	return a == b
}

// isAncestorOrEqual reports whether a is b or a directory containing b.
func isAncestorOrEqual(a, b string) bool {
	if same(a, b) {
		return true
	}
	rel, err := filepath.Rel(a, b)
	if err != nil {
		return false
	}
	return rel != "." && rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator))
}

func protectedDirs() []string {
	var dirs []string
	if home, err := os.UserHomeDir(); err == nil && home != "" {
		dirs = append(dirs, home)
		for _, d := range []string{"Documents", "Desktop", "Downloads", "Pictures", "Videos", "Music", "OneDrive", ".ssh", ".gnupg"} {
			dirs = append(dirs, filepath.Join(home, d))
		}
	}
	if runtime.GOOS == "windows" {
		for _, v := range []string{"SystemRoot", "ProgramFiles", "ProgramFiles(x86)", "ProgramData", "OneDrive"} {
			if p := os.Getenv(v); p != "" {
				dirs = append(dirs, p)
			}
		}
		if sd := os.Getenv("SystemDrive"); sd != "" {
			dirs = append(dirs, sd+`\Users`)
		}
		return dirs
	}
	return append(dirs, "/bin", "/boot", "/dev", "/etc", "/home", "/lib", "/lib64", "/opt", "/proc",
		"/root", "/run", "/sbin", "/srv", "/sys", "/usr", "/var", "/snap", "/mnt", "/media", "/tmp")
}

// Check returns an error when path must never be cleaned.
// A path is refused when it is, or contains, a protected directory (home, system
// roots, user document folders), is a filesystem root, is a symlink, or lives
// inside a .git directory. Directories *below* protected ones (for example
// ~/.cache/pip) are allowed.
func Check(path string) error {
	p := filepath.Clean(path)
	if !filepath.IsAbs(p) {
		return fmt.Errorf("refusing non-absolute path %q", path)
	}
	if filepath.Dir(p) == p {
		return fmt.Errorf("refusing filesystem root %q", p)
	}
	for _, part := range strings.Split(p, string(filepath.Separator)) {
		if part == ".git" {
			return fmt.Errorf("refusing path inside .git: %q", p)
		}
	}
	for _, prot := range protectedDirs() {
		if isAncestorOrEqual(p, filepath.Clean(prot)) {
			return fmt.Errorf("refusing protected path %q (matches %q)", p, prot)
		}
	}
	if fi, err := os.Lstat(p); err == nil && fi.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("refusing symlink %q", p)
	}
	return nil
}
