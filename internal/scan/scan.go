// Package scan walks files and applies rules concurrently.
package scan

import (
	"bytes"
	"cmp"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/raj921/vulngate/internal/rules"
	"github.com/raj921/vulngate/internal/taint"
)

var (
	// IncludeTests, when true, disables tests/examples path scoping.
	IncludeTests bool
	// SkippedVendor / SkippedTests count files excluded from scanning.
	SkippedVendor atomic.Int64
	SkippedTests  atomic.Int64
)

// ignorePatterns holds .vulngateignore lines for the current scan root.
var ignorePatterns atomic.Value // []string

// LoadIgnore reads <root>/.vulngateignore (gitignore-style: one pattern per
// line, # comments, substring match against slash-separated paths). Missing
// file means no extra ignores. Capped at 1024 patterns.
func LoadIgnore(root string) {
	base := root
	if info, err := os.Stat(root); err == nil && !info.IsDir() {
		base = filepath.Dir(root)
	}
	var pats []string
	if data, err := os.ReadFile(filepath.Join(base, ".vulngateignore")); err == nil {
		for _, line := range strings.Split(string(data), "\n") {
			line = strings.TrimSpace(line)
			if line != "" && !strings.HasPrefix(line, "#") {
				pats = append(pats, strings.Trim(line, "/"))
			}
		}
	}
	if len(pats) > 1024 {
		pats = pats[:1024]
	}
	ignorePatterns.Store(pats)
	// ponytail: substring-per-line matching; glob semantics would need a lib.
}

func isIgnored(path string) bool {
	pats, _ := ignorePatterns.Load().([]string)
	slashPath := filepath.ToSlash(path)
	for _, p := range pats {
		if p != "" && strings.Contains(slashPath, p) {
			return true
		}
	}
	return false
}

// Scannable decides whether a file path should be scanned.
func Scannable(path string) bool { return rules.Scannable(filepath.Ext(path)) && !isIgnored(path) }

var testPathSegs = map[string]bool{
	"test": true, "tests": true, "testing": true, "testdata": true,
	"fixtures": true, "examples": true, "example": true,
	"docs": true, "doc": true, "__tests__": true, "spec": true,
}

var vendorPathSegs = map[string]bool{
	"vendor": true, "third_party": true, "dist": true, "minified": true,
}

func pathSegs(path string) ([]string, string) {
	parts := strings.Split(filepath.ToSlash(path), "/")
	return parts[:len(parts)-1], strings.ToLower(parts[len(parts)-1])
}

// isTestLike reports whether path is test/example/docs code — excluded by
// default because findings there are almost never actionable.
func isTestLike(path string) bool {
	if IncludeTests {
		return false
	}
	segs, base := pathSegs(path)
	for _, s := range segs {
		if testPathSegs[strings.ToLower(s)] {
			return true
		}
	}
	return strings.HasPrefix(base, "test_") || strings.HasSuffix(base, "_test.py") ||
		strings.HasSuffix(base, "_test.go") || strings.Contains(base, ".test.") ||
		strings.Contains(base, ".spec.")
}

// isVendor reports whether path is vendored/generated code we should not gate.
func isVendorPath(path string) bool {
	segs, base := pathSegs(path)
	for _, s := range segs {
		if vendorPathSegs[strings.ToLower(s)] {
			return true
		}
	}
	return strings.HasSuffix(base, ".min.js")
}

// isMinifiedJS detects bundled/minified JS by average line length:
// Closure/webpack output is a few gigantic lines, not real source to review.
func isMinifiedJS(data []byte) bool {
	lines := bytes.Count(data, []byte("\n")) + 1
	return float64(len(data))/float64(lines) > 200
}

// Finding is one rule hit.
type Finding struct {
	RuleID   string `json:"rule_id"`
	Name     string `json:"name"`
	Severity string `json:"severity"`
	CWE      string `json:"cwe"`
	Path     string `json:"path"`
	Line     int    `json:"line"`
	Code     string `json:"code"`
	Fix      string `json:"fix"`
	Tier     string `json:"tier"` // "regex" (line pattern) | "ast" (tree-sitter taint)
}

var skipDirs = map[string]bool{
	".git": true, "node_modules": true, "__pycache__": true,
	".venv": true, "venv": true, "dist": true, "build": true,
}

// pyRegexSuppressed are line-rules replaced by the AST tier for .py files:
// tree-sitter taint owns SSRF / command-injection / deserialization there.
var pyRegexSuppressed = map[string]bool{"VG-003": true, "VG-004": true, "VG-007": true}

// Scan analyses root (a file or directory tree) and returns all findings,
// sorted by severity (HIGH first), then path and line.
func Scan(root string) ([]Finding, error) {
	paths, err := collect(root)
	if err != nil {
		return nil, err
	}

	jobs := make(chan string)
	found := make(chan []Finding, len(paths))
	var wg sync.WaitGroup
	for range runtime.NumCPU() {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for p := range jobs {
				found <- ScanFile(p)
			}
		}()
	}
	for _, p := range paths {
		jobs <- p
	}
	close(jobs)
	wg.Wait()
	close(found)

	var all []Finding
	for batch := range found {
		all = append(all, batch...)
	}
	SortFindings(all)
	return all, nil
}

// SortFindings orders HIGH→LOW, then path, then line.
func SortFindings(all []Finding) {
	sevRank := map[string]int{rules.High: 0, rules.Medium: 1, rules.Low: 2}
	slices.SortFunc(all, func(a, b Finding) int {
		return cmp.Or(
			cmp.Compare(sevRank[a.Severity], sevRank[b.Severity]),
			cmp.Compare(a.Path, b.Path),
			cmp.Compare(a.Line, b.Line),
		)
	})
}

func collect(root string) ([]string, error) {
	info, err := os.Stat(root)
	if err != nil {
		return nil, err
	}
	if !info.IsDir() {
		if rules.Scannable(filepath.Ext(root)) {
			return []string{root}, nil
		}
		return nil, nil
	}
	var paths []string
	err = filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			if skipDirs[d.Name()] {
				return filepath.SkipDir
			}
			return nil
		}
		if Scannable(path) {
			paths = append(paths, path)
		}
		return nil
	})
	return paths, err
}

// ScanFile applies regex rules and (for Python) AST taint analysis.
func ScanFile(path string) []Finding {
	if isVendorPath(path) {
		SkippedVendor.Add(1)
		return nil
	}
	if isTestLike(path) {
		SkippedTests.Add(1)
		return nil
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	ext := filepath.Ext(path)
	if (ext == ".js" || ext == ".ts" || ext == ".jsx" || ext == ".tsx") && isMinifiedJS(data) {
		SkippedVendor.Add(1)
		return nil
	}
	f := &fileRef{path: path}
	var lines []NumberedLine
	for i, l := range strings.Split(string(data), "\n") {
		lines = append(lines, NumberedLine{No: i + 1, Text: l})
	}
	findings := f.scanLines(lines, ext == ".py")

	if filepath.Ext(path) == ".py" {
		var ast []Finding
		astCWEs := map[int]map[string]bool{}
		for _, r := range taint.AnalyzePython(data) {
			ast = append(ast, Finding{
				RuleID: r.RuleID, Name: r.Name, Severity: rules.High, CWE: r.CWE,
				Path: path, Line: r.Line, Code: r.Code, Fix: r.Fix, Tier: "ast",
			})
			if astCWEs[r.Line] == nil {
				astCWEs[r.Line] = map[string]bool{}
			}
			astCWEs[r.Line][r.CWE] = true
		}
		// AST wins on same-line duplicates of the SAME vuln class (it carries
		// provenance). A regex finding of another CWE on that line survives.
		kept := findings[:0]
		for _, fdx := range findings {
			if !astCWEs[fdx.Line][fdx.CWE] {
				kept = append(kept, fdx)
			}
		}
		findings = append(kept, ast...)
	}
	return findings
}

// fileRef scans one file's lines against the rules for its extension.
type fileRef struct{ path string }

// suppressPyRegex turns off Python line-rules VG-003/004/007 — only valid when
// the AST tier will also run on the same content (full-file scans). Diff mode
// must pass false, or Python sink findings are dropped with no AST backstop.
func (fr *fileRef) scanLines(lines []NumberedLine, suppressPyRegex bool) []Finding {
	ext := filepath.Ext(fr.path)
	applicable := rules.ForExt(ext)
	if len(applicable) == 0 {
		return nil
	}

	var out []Finding
	for _, ln := range lines {
		for i := range applicable {
			r := &applicable[i]
			if suppressPyRegex && pyRegexSuppressed[r.ID] {
				continue
			}
			matches := r.Pattern.FindStringSubmatch(ln.Text)
			if matches == nil {
				continue
			}
			if r.SafeWord != nil && r.SafeWord.MatchString(ln.Text) {
				continue
			}
			if r.SelfNamed && len(matches) > 2 &&
				rules.NormName(matches[1]) == rules.NormName(matches[len(matches)-1]) {
				continue // a constant naming itself, e.g. RESET_PASSWORD = "reset_password"
			}
			if r.EntropyGate > 0 {
				val := matches[len(matches)-1]
				if rules.Shannon(val) < r.EntropyGate {
					continue
				}
			}
			out = append(out, Finding{
				RuleID: r.ID, Name: r.Name, Severity: r.Severity, CWE: r.CWE,
				Path: fr.path, Line: ln.No, Code: strings.TrimSpace(ln.Text),
				Fix: r.Fix, Tier: "regex",
			})
		}
	}
	return out
}
