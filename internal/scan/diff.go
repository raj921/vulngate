package scan

import (
	"bufio"
	"fmt"
	"io"
	"strconv"
	"strings"
)

// NumberedLine is one added line from a unified diff.
type NumberedLine struct {
	No   int
	Text string
}

// ParseUnifiedDiff extracts only the ADDED lines (the lines an agent wrote)
// from a unified diff, mapped by target file. This is what "diff-only mode"
// means: we gate what changed, not the whole repo history.
func ParseUnifiedDiff(r io.Reader) (map[string][]NumberedLine, error) {
	out := map[string][]NumberedLine{}
	var (
		file    string
		newLine int
	)
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for sc.Scan() {
		line := sc.Text()
		switch {
		case strings.HasPrefix(line, "+++ "):
			rest, _ := strings.CutPrefix(line, "+++ ")
			file, _ = strings.CutPrefix(rest, "b/")
		case strings.HasPrefix(line, "@@ "):
			l, err := hunkStart(line)
			if err != nil {
				return nil, err
			}
			newLine = l
		case strings.HasPrefix(line, "+"):
			if file != "" {
				out[file] = append(out[file], NumberedLine{No: newLine, Text: line[1:]})
			}
			newLine++
		case strings.HasPrefix(line, " "):
			newLine++
		}
	}
	return out, sc.Err()
}

// hunkStart parses "@@ -a,b +c,d @@" and returns c (first line of new hunk).
func hunkStart(header string) (int, error) {
	_, rest, ok := strings.Cut(header, "+")
	if !ok {
		return 0, fmt.Errorf("bad hunk header: %q", header)
	}
	num, _, _ := strings.Cut(rest, ",")
	num, _, _ = strings.Cut(num, " ")
	if num == "" {
		return 0, fmt.Errorf("bad hunk header: %q", header)
	}
	return strconv.Atoi(num)
}

// ScanNumberedLines applies the regex tier to explicit lines (diff mode).
// Taint analysis is intentionally NOT applied: a diff lacks whole-file
// context needed for provenance. CI should run the full scan for that.
// Test/example/vendor paths respect the same scoping as full scans.
func ScanNumberedLines(path string, lines []NumberedLine) []Finding {
	if isVendorPath(path) || isTestLike(path) || isIgnored(path) {
		return nil
	}
	file := &fileRef{path: path}
	return file.scanLines(lines, false) // AST never runs on diffs: keep all regex rules
}
