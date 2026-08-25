package scan_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/raj921/vulngate/internal/scan"
)

func hasRule(fs []scan.Finding, id string) bool {
	for _, f := range fs {
		if f.RuleID == id {
			return true
		}
	}
	return false
}

// Regression: AST dedupe must not drop unrelated regex findings that happen to
// sit on the same line (it was keyed on line number only).
func TestDedupeKeepsUnrelatedCWE(t *testing.T) {
	p := filepath.Join(t.TempDir(), "app.py")
	src := "password = \"hunter2prod\"; eval(request.data)\n"
	if err := os.WriteFile(p, []byte(src), 0o600); err != nil {
		t.Fatal(err)
	}
	got := scan.ScanFile(p)
	if !hasRule(got, "VG-001") {
		t.Errorf("lost VG-001 credential finding to line-scoped dedupe: %v", got)
	}
	if !hasRule(got, "VG-T05") {
		t.Errorf("lost VG-T05 eval finding: %v", got)
	}
}

// Regression: diff mode must keep Python sink rules. scanLines suppresses
// VG-003/004/007 only when the AST tier also runs — it never runs on diffs, so
// pickle.loads(request.data) in a Python PR passed the gate clean.
func TestDiffModeScansPythonSinks(t *testing.T) {
	patch := "--- a/app.py\n+++ b/app.py\n@@ -0,0 +1,2 @@\n" +
		"+import pickle\n+obj = pickle.loads(request.data)\n"
	byFile, err := scan.ParseUnifiedDiff(strings.NewReader(patch))
	if err != nil {
		t.Fatal(err)
	}
	var got []scan.Finding
	for file, lines := range byFile {
		got = append(got, scan.ScanNumberedLines(file, lines)...)
	}
	if !hasRule(got, "VG-007") {
		t.Errorf("diff mode missed VG-007 deserialization sink: %v", got)
	}
}
