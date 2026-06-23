// Command cisbench is a Go port of the core passive-scan surface of the
// Python cisbench tool. It evaluates the built-in CDB hardening baseline
// against an offline inventory snapshot (a settings JSON) and reports
// PASS/FAIL with a compliance score.
//
// This port is deliberately passive and offline: it only reads the inventory
// file you give it. It never connects to a database. (The optional
// authorization-gated active probe lives in the Python reference
// implementation.)
//
// Usage:
//
//	cisbench scan <inventory.json> [--json]
//	cisbench list [--json]
package main

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"

	cb "github.com/cognis-digital/cisbench/ports/go"
)

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

func run(args []string, stdout, stderr *os.File) int {
	if len(args) == 0 {
		fmt.Fprintln(stderr, "usage: cisbench <scan|list> [args]")
		return 2
	}
	jsonOut := false
	var positional []string
	for _, a := range args[1:] {
		if a == "--json" {
			jsonOut = true
		} else {
			positional = append(positional, a)
		}
	}

	switch args[0] {
	case "list":
		prof := cb.BuiltinProfile()
		if jsonOut {
			b, _ := json.MarshalIndent(prof, "", "  ")
			fmt.Fprintln(stdout, string(b))
			return 0
		}
		fmt.Fprintf(stdout, "Profile: %s (v%s) - %d checks\n",
			prof.Name, prof.Version, len(prof.Checks))
		for _, c := range prof.Checks {
			fmt.Fprintf(stdout, "%-10s [%-8s] %s\n", c.ID, c.Severity, c.Title)
		}
		return 0

	case "scan":
		if len(positional) < 1 {
			fmt.Fprintln(stderr, "error: scan requires an inventory path")
			return 2
		}
		inv, err := cb.LoadInventory(positional[0])
		if err != nil {
			fmt.Fprintf(stderr, "error: %v\n", err)
			return 2
		}
		report := cb.Scan(cb.BuiltinProfile(), inv)
		if jsonOut {
			b, _ := json.MarshalIndent(report.ToMap(), "", "  ")
			fmt.Fprintln(stdout, string(b))
		} else {
			printTable(stdout, report)
		}
		if report.Failed() > 0 {
			return 0 // default scan does not gate; mirrors the Python default
		}
		return 0

	default:
		fmt.Fprintf(stderr, "unknown command %q\n", args[0])
		return 2
	}
}

func printTable(out *os.File, r cb.Report) {
	fmt.Fprintf(out, "\ncisbench scan - profile: %s (v%s)\n",
		r.Profile.Name, r.Profile.Version)
	fmt.Fprintln(out, strings.Repeat("=", 72))
	for _, res := range r.Results {
		status := "PASS"
		if !res.Passed {
			status = "FAIL"
		}
		fmt.Fprintf(out, "[%s] %-8s %s\n", status, res.Check.ID, res.Check.Title)
		fmt.Fprintf(out, "        evidence: %s\n", res.Evidence)
	}
	fmt.Fprintln(out, strings.Repeat("-", 72))
	fmt.Fprintf(out, "%d/%d passed  |  score %.1f%%  |  weighted %.1f%%\n",
		r.Passed(), r.Total(), r.Score(), r.WeightedScore())
}
