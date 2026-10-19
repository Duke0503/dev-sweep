// Package clean applies findings. Default mode moves things into a quarantine
// directory that can be restored or purged; Delete removes them for good.
package clean

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"time"

	"devsweep/internal/safety"
	"devsweep/internal/scan"
)

type Mode string

const (
	Quarantine Mode = "quarantine"
	Delete     Mode = "delete"
)

type Result struct {
	Finding scan.Finding
	Method  string // "command", "quarantine", "delete"
	Skipped int    // children that could not be removed (in use, permission)
	Err     error
}

type entry struct {
	Orig   string `json:"orig"`
	Stored string `json:"stored"`
}

// Root returns ~/.devsweep/quarantine.
func Root() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(home, ".devsweep", "quarantine"), nil
}

type Cleaner struct {
	Mode  Mode
	batch string
	seq   int
}

func New(mode Mode) (*Cleaner, error) {
	c := &Cleaner{Mode: mode}
	if mode == Quarantine {
		root, err := Root()
		if err != nil {
			return nil, err
		}
		c.batch = filepath.Join(root, time.Now().Format("20060102-150405"))
	}
	return c, nil
}

// Apply cleans one finding. It never panics on a single failure; errors are returned in the Result.
func (c *Cleaner) Apply(ctx context.Context, f scan.Finding) Result {
	r := Result{Finding: f}
	if err := safety.Check(f.Path); err != nil {
		r.Err = err
		return r
	}
	if len(f.Clean) > 0 {
		if bin, err := exec.LookPath(f.Clean[0]); err == nil {
			cctx, cancel := context.WithTimeout(ctx, 5*time.Minute)
			defer cancel()
			if out, err := exec.CommandContext(cctx, bin, f.Clean[1:]...).CombinedOutput(); err != nil {
				r.Err = fmt.Errorf("%v: %w (%s)", f.Clean, err, trim(string(out)))
			}
			r.Method = "command"
			return r
		}
	}
	r.Method = string(c.Mode)
	if !f.Contents {
		r.Err = c.remove(f.Path)
		return r
	}
	kids, err := os.ReadDir(f.Path)
	if err != nil {
		r.Err = err
		return r
	}
	for _, k := range kids {
		p := filepath.Join(f.Path, k.Name())
		if safety.Check(p) != nil {
			r.Skipped++
			continue
		}
		if err := c.remove(p); err != nil {
			r.Skipped++
		}
	}
	return r
}

func (c *Cleaner) remove(path string) error {
	if c.Mode == Delete {
		return os.RemoveAll(path)
	}
	if err := os.MkdirAll(c.batch, 0o700); err != nil {
		return err
	}
	c.seq++
	stored := filepath.Join(c.batch, fmt.Sprintf("%04d-%s", c.seq, filepath.Base(path)))
	if err := os.Rename(path, stored); err != nil {
		return fmt.Errorf("%w (different volume or file in use? try --delete)", err)
	}
	return c.record(entry{Orig: path, Stored: stored})
}

func (c *Cleaner) record(e entry) error {
	fh, err := os.OpenFile(filepath.Join(c.batch, "manifest.jsonl"), os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	defer fh.Close()
	b, _ := json.Marshal(e)
	_, err = fh.Write(append(b, '\n'))
	return err
}

// Batches lists quarantine batch names, newest first.
func Batches() ([]string, error) {
	root, err := Root()
	if err != nil {
		return nil, err
	}
	des, err := os.ReadDir(root)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var names []string
	for _, d := range des {
		if d.IsDir() {
			names = append(names, d.Name())
		}
	}
	sort.Sort(sort.Reverse(sort.StringSlice(names)))
	return names, nil
}

// Restore moves every item of a batch back to where it came from. Existing targets are left alone.
func Restore(batch string) (restored, skipped int, err error) {
	root, err := Root()
	if err != nil {
		return 0, 0, err
	}
	dir := filepath.Join(root, filepath.Base(batch))
	fh, err := os.Open(filepath.Join(dir, "manifest.jsonl"))
	if err != nil {
		return 0, 0, err
	}
	defer fh.Close()
	sc := bufio.NewScanner(fh)
	sc.Buffer(make([]byte, 1<<20), 1<<20)
	for sc.Scan() {
		var e entry
		if json.Unmarshal(sc.Bytes(), &e) != nil {
			continue
		}
		if _, err := os.Lstat(e.Orig); err == nil {
			skipped++
			continue
		}
		if err := os.MkdirAll(filepath.Dir(e.Orig), 0o755); err != nil {
			skipped++
			continue
		}
		if err := os.Rename(e.Stored, e.Orig); err != nil {
			skipped++
			continue
		}
		restored++
	}
	return restored, skipped, sc.Err()
}

// Purge permanently deletes the whole quarantine and returns the bytes freed.
func Purge(ctx context.Context) (int64, error) {
	root, err := Root()
	if err != nil {
		return 0, err
	}
	size, _ := scan.DirSize(ctx, root)
	if err := os.RemoveAll(root); err != nil {
		return 0, err
	}
	return size, nil
}

func trim(s string) string {
	if len(s) > 200 {
		return s[:200] + "..."
	}
	return s
}
