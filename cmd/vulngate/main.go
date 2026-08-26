// Command vulngate is the security gate for AI-agent-generated code.
//
// Usage:
//
//	vulngate scan <path> [--format=text|json|sarif]
//	vulngate diff <patch-file> [--format=text|json|sarif]
//
// Exit codes: 0 = PASS/REVIEW, 1 = BLOCK (a HIGH finding exists — fail CI), 2 = usage error.
package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/raj921/vulngate/internal/report"
	"github.com/raj921/vulngate/internal/rules"
	"github.com/raj921/vulngate/internal/scan"
)

func usage() {
	fmt.Fprintln(os.Stderr, `usage:
  vulngate scan <path>        [--format=text|json|sarif] [--include-tests]
  vulngate diff <patch-file>  [--format=text|json|sarif]
  vulngate version

Per-project excludes: put a .vulngateignore file (gitignore-style lines,
matched as path substrings) at the scan root.

exit 1 when HIGH findings exist (BLOCK), else 0.`)
	os.Exit(2)
}

func main() {
	if len(os.Args) < 2 {
		usage()
	}

	if os.Args[1] == "version" {
		fmt.Println("vulngate " + report.Version)
		os.Exit(0)
	}
	fs := flag.NewFlagSet("vulngate", flag.ExitOnError)
	format := fs.String("format", "text", "output format: text|json|sarif")
	jsonAlias := fs.Bool("json", false, "shorthand for --format=json")
	includeTests := fs.Bool("include-tests", false, "also scan tests/examples/docs paths (excluded by default)")

	// Go's flag package stops at the first positional argument, so reorder
	// flags before positionals (accept flags anywhere on the command line).
	var flagArgs, positional []string
	rest := os.Args[2:]
	for i := 0; i < len(rest); i++ {
		a := rest[i]
		if len(a) > 0 && a[0] == '-' {
			flagArgs = append(flagArgs, a)
			if (a == "-format" || a == "--format") && i+1 < len(rest) {
				i++
				flagArgs = append(flagArgs, rest[i])
			}
		} else {
			positional = append(positional, a)
		}
	}
	_ = fs.Parse(append(flagArgs, positional...))
	if *jsonAlias {
		*format = "json"
	}

	if fs.NArg() < 1 {
		usage()
	}
	target := fs.Arg(0)
	scan.IncludeTests = *includeTests

	var findings []scan.Finding
	var err error

	switch os.Args[1] {
	case "scan":
		scan.LoadIgnore(target)
		findings, err = scan.Scan(target)
	case "diff":
		findings, err = scanPatch(target)
	default:
		usage()
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "vulngate: %v\n", err)
		os.Exit(2)
	}
	scan.SortFindings(findings)
	v, t := scan.SkippedVendor.Load(), scan.SkippedTests.Load()
	if n := v + t; n > 0 {
		fmt.Fprintf(os.Stderr, "vulngate: skipped %d file(s): %d vendor/minified, %d tests/examples\n", n, v, t)
	}

	switch *format {
	case "json":
		data, e := report.JSON(findings)
		if e != nil {
			fmt.Fprintf(os.Stderr, "vulngate: %v\n", e)
			os.Exit(2)
		}
		fmt.Println(string(data))
	case "sarif":
		data, e := report.SARIF(findings)
		if e != nil {
			fmt.Fprintf(os.Stderr, "vulngate: %v\n", e)
			os.Exit(2)
		}
		fmt.Println(string(data))
	default:
		fmt.Print(report.Text(findings))
	}

	if report.CountBySeverity(findings)[rules.High] > 0 {
		os.Exit(1)
	}
}

// scanPatch runs diff-only mode: regex tier over just the added lines.
func scanPatch(patchPath string) ([]scan.Finding, error) {
	fh, err := os.Open(patchPath)
	if err != nil {
		return nil, err
	}
	defer fh.Close()
	byFile, err := scan.ParseUnifiedDiff(fh)
	if err != nil {
		return nil, err
	}
	var out []scan.Finding
	for file, lines := range byFile {
		out = append(out, scan.ScanNumberedLines(file, lines)...)
	}
	return out, nil
}
