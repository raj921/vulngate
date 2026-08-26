# fix: close two detection holes between the regex and AST tiers

## What's broken

1. `diff` mode silently drops Python sink findings.
`scanLines` suppresses the Python line-rules (SSRF, command injection,
deserialization) on the assumption that the tree-sitter taint tier re-covers
them. That holds for full-file scans, but the AST tier never runs on diffs (it
needs whole-file context). So a PR adding `pickle.loads(request.data)` passed
the gate completely clean. That's the exact class of bug this tool exists to
catch.

2. AST dedupe keys on line number only.
When an AST finding lands on a line, every regex finding on that line is
discarded, even when it reports a different vulnerability class.
`password = "hunter2prod"; eval(request.data)` lost the credential finding
because the eval finding claimed the whole line.

## Changes

- `scanLines` takes a `suppressPyRegex` argument. Full `.py` scans pass true
  (the AST tier owns those vuln classes there); `ScanNumberedLines` passes
  false. One-line comment explains why the contract exists.
- Dedupe is keyed on `(line, CWE)` instead of `line`. AST still wins on
  same-class duplicates (it carries provenance); unrelated findings survive.
- Deleted the unused `assign` type and the unused `SeverityOf` helper in the
  taint package (and its now-orphaned rules import).
- `report.Version` const (0.3.1) shared by the JSON and SARIF writers.
  They had drifted to 0.1.0 / 0.2.0.

## Checks

- `internal/scan/scan_test.go`: two regression tests, one per hole.
  `go test ./...` green; `gofmt`, `go vet` clean.
- Seeded corpus unchanged: precision 1.00, recall 1.00, F1 1.00.
- Demo + flask + nodegoat reruns unchanged; versions in JSON/SARIF now match.
