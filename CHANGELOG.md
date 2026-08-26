# Changelog

All notable changes and fixes to VulnGate, newest first.

## [0.5] Universal CLI (2026-08-26)

- `make install` ships the single binary to `~/go/bin/vulngate`; `vulngate`
  now runs from any directory against any project path.
- `vulngate version` subcommand.
- Per-project config: `.vulngateignore` (gitignore-style, path-substring
  matching) at the scan root, honored by both `scan` and `diff`.
- Makefile: build / install / test / bench / clean targets.
- Regression test for ignore handling; seven tests total.

## [0.4] Field-test driven fixes (2026-08-25)

Scanned unfamiliar production repos (flaskbb, httpie, express, a live FastAPI app)
and hand-verified every finding; each false positive produced a fix.

- VG-T03: `.execute(db.select(...))` ORM builders are no longer treated as SQL
  sinks (first-argument shape check, 3 flaskbb false positives removed).
- VG-009 split: TLS `verify=False` is now VG-011 (CWE-295), not a JWT finding.
- New rule VG-010, permissive CORS wildcards (CWE-942); found in the wild on a
  real FastAPI app.
- VG-001 self-naming suppression: constants that name themselves
  (`RESET_PASSWORD = "reset_password"`) are labels, not credentials.
- Six regression tests total; corpus F1 unchanged at 1.00.
- Full matrix and hand-checked verdicts: `bench/BENCH.md` field test section.

## [Unreleased] Modern Go 1.24 pass

Modernized to current stdlib idioms. Verified behavior-preserving: corpus
F1 1.00, flask clean-repo run unchanged, diff mode unchanged.

| Change | Files |
|---|---|
| `slices.SortFunc` + `cmp.Or` chain for finding sort | `internal/scan/scan.go` |
| Typed `atomic.Int64` skip counters | `internal/scan/scan.go`, `cmd/vulngate/main.go` |
| Range-over-int loop forms (`for i := range n`) | `internal/taint/python.go`, `internal/scan/scan.go`, `internal/rules/rules.go` |
| `strings.CutPrefix` / `strings.Cut` diff-header parsing | `internal/scan/diff.go` |



## [0.3] Precision hardening (2026-08-25)

Every item found by the v0.2 benchmark, fixed:

- **Minified/vendor skipping**: `vendor/`, `third_party/`, `dist/`, `*.min.js` paths;
  average-line-length > 200 heuristic catches Closure/webpack bundles
  (`internal/scan/scan.go`).
- **Tests/examples scoping**: `tests/`, `examples/`, `docs/`, `test_*`, `*_test.go`,
  `*.test.*`, `*.spec.*` excluded by default; `--include-tests` overrides.
  Applied to both `scan` and `diff` modes.
- **VG-T03 parameterized-query suppression**: AST recognizes
  `execute("...", (params,))` as safe (`internal/taint/python.go`).
- **Secrets entropy gate**: VG-001 requires Shannon entropy ≥ 3.0 bits/char
  (gitleaks-style); dummies like `"password"` no longer flag (`internal/rules/rules.go`).
- **Vendor/test skip counters** printed to stderr per run for transparency.

Effect: flask clean-repo run 16 → 3 findings, verdict BLOCK → REVIEW;
NodeGoat 15 → 5 (the app's textbook teaching vulns); corpus F1 unchanged 1.00.

## [0.2] AST tier + gate modes (2026-08-25)

- **Tree-sitter AST taint tier (Python)**: 5 source→sink rules
  (VG-T01 SSRF, VG-T02 command injection, VG-T03 SQLi, VG-T04 unsafe
  deserialization, VG-T05 eval/exec) with provenance chains
  (`url = request.args.get("url") → requests.get(url)`); regex findings the
  AST disproves are suppressed; `tier` field on every finding.
- **Diff-only mode**: `vulngate diff patch.diff`: unified-diff parser, scans
  added lines only, correct new-file line numbers.
- **SARIF 2.1.0 export**: `--format=sarif`, GitHub code-scanning ready.
- **Benchmark harness** (`bench/`): seeded corpus (5 vulnerable + 2 FP-bait
  trap files) with CWE labels, scorer, naive-LLM baseline runner,
  reproducible numbers in `bench/BENCH.md`.
- Fix: Go `flag` package stops at first positional arg, flags now reordered
  so `scan dir --json` and `scan --json dir` both work.

## [0.1] MVP, rewritten Python → Go (2026-08-25)

- Research-first build (see README §2): decided against rebuilding
  semgrep/gosec/gitleaks; differentiate on the *gate*, not the engine.
- Key constraint found: Go `regexp` is RE2, no lookaheads. Rules redesigned
  as `Pattern` + optional `SafeWord` line suppressors.
- stdlib-only concurrent scanner (worker pool), 9 CWE-mapped rules,
  text/JSON reports, `BLOCK/REVIEW/PASS` verdicts, exit code 1 on HIGH.
- GitHub Actions gate workflow.
