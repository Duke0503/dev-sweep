// Package tui is the interactive terminal UI (bubbletea).
package tui

import (
	"context"
	"fmt"
	"strings"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"

	"devsweep/internal/clean"
	"devsweep/internal/rules"
	"devsweep/internal/scan"
)

type state int

const (
	stScanning state = iota
	stList
	stConfirm
	stCleaning
	stDone
)

var (
	titleSt  = lipgloss.NewStyle().Bold(true)
	dimSt    = lipgloss.NewStyle().Foreground(lipgloss.Color("8"))
	safeSt   = lipgloss.NewStyle().Foreground(lipgloss.Color("2"))
	reviewSt = lipgloss.NewStyle().Foreground(lipgloss.Color("3"))
	curSt    = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("6"))
	errSt    = lipgloss.NewStyle().Foreground(lipgloss.Color("1"))
)

type scanDone []scan.Finding
type cleanDone []clean.Result

type model struct {
	rs       []rules.Rule
	opts     scan.Options
	st       state
	findings []scan.Finding
	sel      map[int]bool
	cursor   int
	offset   int
	width    int
	height   int
	mode     clean.Mode
	results  []clean.Result
	err      error
}

// Run starts the TUI and blocks until the user quits.
func Run(rs []rules.Rule, opts scan.Options) error {
	m := model{rs: rs, opts: opts, sel: map[int]bool{}, mode: clean.Quarantine, height: 24, width: 80}
	_, err := tea.NewProgram(m, tea.WithAltScreen()).Run()
	return err
}

func (m model) Init() tea.Cmd { return m.scanCmd() }

func (m model) scanCmd() tea.Cmd {
	return func() tea.Msg { return scanDone(scan.Run(context.Background(), m.rs, m.opts)) }
}

func (m model) cleanCmd() tea.Cmd {
	var picked []scan.Finding
	for i, f := range m.findings {
		if m.sel[i] {
			picked = append(picked, f)
		}
	}
	mode := m.mode
	return func() tea.Msg {
		c, err := clean.New(mode)
		if err != nil {
			return cleanDone{{Err: err}}
		}
		var out []clean.Result
		for _, f := range picked {
			out = append(out, c.Apply(context.Background(), f))
		}
		return cleanDone(out)
	}
}

func (m model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.width, m.height = msg.Width, msg.Height
	case scanDone:
		m.findings = []scan.Finding(msg)
		m.sel = map[int]bool{}
		m.cursor, m.offset = 0, 0
		m.st = stList
	case cleanDone:
		m.results = []clean.Result(msg)
		m.st = stDone
	case tea.KeyMsg:
		return m.key(msg)
	}
	return m, nil
}

func (m model) key(k tea.KeyMsg) (tea.Model, tea.Cmd) {
	s := k.String()
	if s == "ctrl+c" {
		return m, tea.Quit
	}
	switch m.st {
	case stList:
		switch s {
		case "q", "esc":
			return m, tea.Quit
		case "up", "k":
			m.move(-1)
		case "down", "j":
			m.move(1)
		case " ":
			if len(m.findings) > 0 {
				m.sel[m.cursor] = !m.sel[m.cursor]
			}
		case "a": // select / unselect all "safe" findings
			all := true
			for i, f := range m.findings {
				if f.Safety == rules.Safe && !m.sel[i] {
					all = false
				}
			}
			for i, f := range m.findings {
				if f.Safety == rules.Safe {
					m.sel[i] = !all
				}
			}
		case "A": // select / unselect every item, including "review"
			if m.selectedCount() == len(m.findings) {
				m.sel = map[int]bool{}
			} else {
				for i := range m.findings {
					m.sel[i] = true
				}
			}
		case "m":
			if m.mode == clean.Quarantine {
				m.mode = clean.Delete
			} else {
				m.mode = clean.Quarantine
			}
		case "r":
			m.st = stScanning
			return m, m.scanCmd()
		case "enter", "c":
			if m.selectedCount() > 0 {
				m.st = stConfirm
			}
		}
	case stConfirm:
		switch s {
		case "y":
			m.st = stCleaning
			return m, m.cleanCmd()
		case "n", "esc", "q":
			m.st = stList
		}
	case stDone:
		switch s {
		case "q", "esc":
			return m, tea.Quit
		default:
			m.st = stScanning
			return m, m.scanCmd()
		}
	}
	return m, nil
}

func (m *model) move(d int) {
	if len(m.findings) == 0 {
		return
	}
	m.cursor += d
	if m.cursor < 0 {
		m.cursor = 0
	}
	if m.cursor >= len(m.findings) {
		m.cursor = len(m.findings) - 1
	}
	rows := m.rows()
	if m.cursor < m.offset {
		m.offset = m.cursor
	}
	if m.cursor >= m.offset+rows {
		m.offset = m.cursor - rows + 1
	}
}

func (m model) rows() int {
	r := m.height - 9
	if r < 3 {
		r = 3
	}
	return r
}

func (m model) selectedCount() int {
	n := 0
	for _, v := range m.sel {
		if v {
			n++
		}
	}
	return n
}

func (m model) selectedSize() int64 {
	var t int64
	for i, f := range m.findings {
		if m.sel[i] {
			t += f.Size
		}
	}
	return t
}

func (m model) View() string {
	var b strings.Builder
	b.WriteString(titleSt.Render("devsweep") + dimSt.Render("  dev-focused disk cleaner") + "\n\n")
	switch m.st {
	case stScanning:
		b.WriteString("Scanning... (read-only)\n")
	case stCleaning:
		b.WriteString("Cleaning...\n")
	case stList, stConfirm:
		m.list(&b)
	case stDone:
		m.done(&b)
	}
	return b.String()
}

func (m model) list(b *strings.Builder) {
	if len(m.findings) == 0 {
		b.WriteString("Nothing to clean. Press q to quit.\n")
		return
	}
	var total int64
	for _, f := range m.findings {
		total += f.Size
	}
	fmt.Fprintf(b, "%d items, %s reclaimable\n\n", len(m.findings), scan.FormatSize(total))
	end := m.offset + m.rows()
	if end > len(m.findings) {
		end = len(m.findings)
	}
	pathW := m.width - 36
	if pathW < 20 {
		pathW = 20
	}
	for i := m.offset; i < end; i++ {
		f := m.findings[i]
		box := "[ ]"
		if m.sel[i] {
			box = "[x]"
		}
		badge := safeSt.Render("safe  ")
		if f.Safety == rules.Review {
			badge = reviewSt.Render("review")
		}
		line := fmt.Sprintf("%s %s %9s  %-18s %s", box, badge, scan.FormatSize(f.Size), clip(f.Name, 18), dimSt.Render(clip(f.Path, pathW)))
		if i == m.cursor {
			line = curSt.Render(">") + " " + line
		} else {
			line = "  " + line
		}
		b.WriteString(line + "\n")
	}
	if m.cursor < len(m.findings) {
		b.WriteString("\n" + dimSt.Render(clip(m.findings[m.cursor].Description, m.width-2)) + "\n")
	}
	b.WriteString("\n")
	if m.st == stConfirm {
		fmt.Fprintf(b, "%s\n", errSt.Render(fmt.Sprintf("Clean %d items (%s) using %s? y/n",
			m.selectedCount(), scan.FormatSize(m.selectedSize()), m.mode)))
		return
	}
	fmt.Fprintf(b, "selected: %d (%s)   mode: %s\n", m.selectedCount(), scan.FormatSize(m.selectedSize()), m.mode)
	b.WriteString(dimSt.Render("space select · a all safe · A all · m mode · enter clean · r rescan · q quit") + "\n")
}

func (m model) done(b *strings.Builder) {
	var freed int64
	var ok, failed int
	for _, r := range m.results {
		if r.Err != nil {
			failed++
			continue
		}
		ok++
		freed += r.Finding.Size
	}
	fmt.Fprintf(b, "Done: %d cleaned, %d failed, about %s processed.\n", ok, failed, scan.FormatSize(freed))
	if m.mode == clean.Quarantine {
		b.WriteString(dimSt.Render("Items are in quarantine: `devsweep restore` brings them back, `devsweep purge` frees the space.") + "\n")
	}
	b.WriteString("\n")
	for _, r := range m.results {
		if r.Err != nil {
			fmt.Fprintf(b, "%s %s: %s\n", errSt.Render("x"), r.Finding.Name, clip(r.Err.Error(), m.width-6-len(r.Finding.Name)))
		} else if r.Skipped > 0 {
			fmt.Fprintf(b, "%s %s: %d entries skipped (in use)\n", reviewSt.Render("!"), r.Finding.Name, r.Skipped)
		}
	}
	b.WriteString("\n" + dimSt.Render("any key: rescan · q quit") + "\n")
}

func clip(s string, n int) string {
	r := []rune(s)
	if n <= 1 || len(r) <= n {
		return s
	}
	return string(r[:n-1]) + "…"
}
