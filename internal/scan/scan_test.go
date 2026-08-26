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

// Real-life field-test regressions: CORS wildcard fires (FastAPI style), TLS
// verify=False is CWE-295 (not the JWT rule), and ORM builders are not VG-T03 sinks.
func TestFieldTestRules(t *testing.T) {
	dir := t.TempDir()

	write := func(name, body string) string {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
		return p
	}

	// CORS wildcard must flag (the finding from our own datathon field test).
	if got := scan.ScanFile(write("cors.py", "app.add_middleware(CORSMiddleware, allow_origins=[\"*\"])\n")); !hasRule(got, "VG-010") {
		t.Errorf("CORS wildcard missed: %v", got)
	}

	// verify=False must be CWE-295 (VG-011), not the JWT rule (VG-009).
	got := scan.ScanFile(write("tls.py", "response = requests.get(url, verify=False)\n"))
	if !hasRule(got, "VG-011") {
		t.Errorf("verify=False not reported as CWE-295: %v", got)
	}
	if hasRule(got, "VG-009") {
		t.Errorf("verify=False mislabeled as JWT issue (VG-009): %v", got)
	}

	// ORM builder with tainted input must NOT fire VG-T03 (flaskbb false positive).
	src := "ids = request.args.getlist('id')\nrows = db.session.execute(db.select(Topic).where(Topic.id.in_(ids)))\n"
	if got := scan.ScanFile(write("orm.py", src)); hasRule(got, "VG-T03") {
		t.Errorf("ORM select() flagged as VG-T03: %v", got)
	}
}

// Regression: self-naming constants are not credentials (flaskbb field test),
// while real keys still fire.
func TestSelfNamingConstantNotCredential(t *testing.T) {
	dir := t.TempDir()
	write := func(name, body string) string {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
		return p
	}
	if got := scan.ScanFile(write("consts.py", "RESET_PASSWORD = \"reset_password\"\n")); hasRule(got, "VG-001") {
		t.Errorf("self-naming constant flagged as credential: %v", got)
	}
	if got := scan.ScanFile(write("realkey.py", "API_KEY = \"sk-live-9f8d7c6b5a4e3d2c1b0a\"\n")); !hasRule(got, "VG-001") {
		t.Errorf("real API key missed: %v", got)
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
