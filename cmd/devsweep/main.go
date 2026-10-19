// devsweep: find and clean developer-machine junk. Read-only unless you say otherwise.
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"strings"
	"text/tabwriter"

	"devsweep/internal/clean"
	"devsweep/internal/config"
	"devsweep/internal/gui"
	"devsweep/internal/rules"
	"devsweep/internal/scan"
	"devsweep/internal/setup"
	"devsweep/internal/tui"
)

const usage = `devsweep - find and clean developer-machine junk

Usage:
  devsweep                 interactive TUI (same as "devsweep tui")
  devsweep gui   [flags]   GUI in your browser (the desktop app is devsweep-gui)
  devsweep scan  [flags]   list what could be cleaned (read-only)
  devsweep clean [flags]   dry-run by default; add --yes to apply
  devsweep restore [batch] list quarantine batches / restore one
  devsweep purge --yes     permanently delete the quarantine
  devsweep rules           list the active rules

Flags (scan, clean, tui):
  --roots a,b       project directories to search for stale node_modules, target/, ...
  --safety safe     only these levels: safe, review (comma separated; default both)
  --only id,id      only these rule ids
Flags (clean):
  --yes             actually clean (without it nothing is changed)
  --delete          delete permanently instead of moving to quarantine
  --json            (scan) machine readable output
`

type common struct {
	roots, safety, only string
}

func (c *common) bind(fs *flag.FlagSet) {
	fs.StringVar(&c.roots, "roots", "", "")
	fs.StringVar(&c.safety, "safety", "safe,review", "")
	fs.StringVar(&c.only, "only", "", "")
}

func main() {
	args := os.Args[1:]
	cmd := "tui"
	if len(args) > 0 && !strings.HasPrefix(args[0], "-") {
		cmd, args = args[0], args[1:]
	}
	var err error
	switch cmd {
	case "tui":
		err = runTUI(args)
	case "scan":
		err = runScan(args)
	case "clean":
		err = runClean(args)
	case "restore":
		err = runRestore(args)
	case "purge":
		err = runPurge(args)
	case "gui":
		err = runGUI(args)
	case "rules":
		err = runRules()
	case "help":
		fmt.Print(usage)
	default:
		fmt.Fprintf(os.Stderr, "unknown command %q\n\n%s", cmd, usage)
		os.Exit(2)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

func setupFrom(c common) ([]rules.Rule, scan.Options, error) {
	return setup.Load(c.roots, c.safety, c.only)
}

func runGUI(args []string) error {
	var c common
	var port int
	var noOpen bool
	fs := flag.NewFlagSet("gui", flag.ExitOnError)
	c.bind(fs)
	fs.IntVar(&port, "port", 0, "")
	fs.BoolVar(&noOpen, "no-open", false, "")
	fs.Parse(args)
	rs, opts, err := setupFrom(c)
	if err != nil {
		return err
	}
	return gui.Run(rs, opts, port, !noOpen)
}

func runTUI(args []string) error {
	var c common
	fs := flag.NewFlagSet("tui", flag.ExitOnError)
	c.bind(fs)
	fs.Parse(args)
	rs, opts, err := setupFrom(c)
	if err != nil {
		return err
	}
	return tui.Run(rs, opts)
}

func runScan(args []string) error {
	var c common
	var asJSON bool
	fs := flag.NewFlagSet("scan", flag.ExitOnError)
	c.bind(fs)
	fs.BoolVar(&asJSON, "json", false, "")
	fs.Parse(args)
	rs, opts, err := setupFrom(c)
	if err != nil {
		return err
	}
	findings := scan.Run(context.Background(), rs, opts)
	if asJSON {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		return enc.Encode(findings)
	}
	printFindings(findings)
	fmt.Fprintf(os.Stderr, "\nproject roots searched: %s\n", strings.Join(opts.Roots, ", "))
	return nil
}

func printFindings(fs []scan.Finding) {
	tw := tabwriter.NewWriter(os.Stdout, 0, 4, 2, ' ', 0)
	fmt.Fprintln(tw, "SAFETY\tSIZE\tRULE\tPATH")
	var total int64
	for _, f := range fs {
		total += f.Size
		path := f.Path
		if f.StaleDays > 0 {
			path += fmt.Sprintf("  (stale %dd)", f.StaleDays)
		}
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\n", f.Safety, scan.FormatSize(f.Size), f.RuleID, path)
	}
	tw.Flush()
	fmt.Printf("\n%d items, %s reclaimable\n", len(fs), scan.FormatSize(total))
}

func runClean(args []string) error {
	var c common
	var yes, del bool
	fs := flag.NewFlagSet("clean", flag.ExitOnError)
	c.bind(fs)
	fs.BoolVar(&yes, "yes", false, "")
	fs.BoolVar(&del, "delete", false, "")
	fs.Parse(args)
	rs, opts, err := setupFrom(c)
	if err != nil {
		return err
	}
	findings := scan.Run(context.Background(), rs, opts)
	if len(findings) == 0 {
		fmt.Println("Nothing to clean.")
		return nil
	}
	printFindings(findings)
	if !yes {
		fmt.Println("\ndry-run: nothing was changed. Re-run with --yes to clean.")
		return nil
	}
	mode := clean.Quarantine
	if del {
		mode = clean.Delete
	}
	cl, err := clean.New(mode)
	if err != nil {
		return err
	}
	var freed int64
	failed := 0
	fmt.Println()
	for _, f := range findings {
		r := cl.Apply(context.Background(), f)
		switch {
		case r.Err != nil:
			failed++
			fmt.Printf("FAIL  %-22s %v\n", f.RuleID, r.Err)
		default:
			freed += f.Size
			note := ""
			if r.Skipped > 0 {
				note = fmt.Sprintf(" (%d entries skipped)", r.Skipped)
			}
			fmt.Printf("ok    %-22s %9s via %s%s\n", f.RuleID, scan.FormatSize(f.Size), r.Method, note)
		}
	}
	fmt.Printf("\n%s processed, %d failed.\n", scan.FormatSize(freed), failed)
	if mode == clean.Quarantine {
		fmt.Println("Items were moved to quarantine: `devsweep restore` undoes it, `devsweep purge --yes` frees the space.")
	}
	return nil
}

func runRestore(args []string) error {
	batches, err := clean.Batches()
	if err != nil {
		return err
	}
	if len(args) == 0 {
		if len(batches) == 0 {
			fmt.Println("Quarantine is empty.")
			return nil
		}
		fmt.Println("Quarantine batches (newest first); restore with: devsweep restore <batch>")
		for _, b := range batches {
			fmt.Println(" ", b)
		}
		return nil
	}
	n, skipped, err := clean.Restore(args[0])
	fmt.Printf("restored %d, skipped %d (target already exists or move failed)\n", n, skipped)
	return err
}

func runPurge(args []string) error {
	fs := flag.NewFlagSet("purge", flag.ExitOnError)
	yes := fs.Bool("yes", false, "")
	fs.Parse(args)
	if !*yes {
		fmt.Println("This permanently deletes everything in quarantine. Re-run with --yes.")
		return nil
	}
	freed, err := clean.Purge(context.Background())
	if err != nil {
		return err
	}
	fmt.Printf("freed %s\n", scan.FormatSize(freed))
	return nil
}

func runRules() error {
	rs, err := rules.Load(config.RulesFile())
	if err != nil {
		return err
	}
	tw := tabwriter.NewWriter(os.Stdout, 0, 4, 2, ' ', 0)
	fmt.Fprintln(tw, "ID\tSAFETY\tOS\tNAME")
	for _, r := range rs {
		osl := "all"
		if len(r.OS) > 0 {
			osl = strings.Join(r.OS, ",")
		}
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\n", r.ID, r.Safety, osl, r.Name)
	}
	return tw.Flush()
}
