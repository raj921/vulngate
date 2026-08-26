# VulnGate

The security gate for AI-agent-generated code.

Autonomous coding agents (Factory Droid, Devin, Claude Code, Copilot Workspace) now
write and merge code at machine speed. The security review step did not get faster.
VulnGate is the checkpoint: it runs on every agent-authored PR and decides
BLOCK / REVIEW / PASS before anything merges.

---

## 1. Why this exists

Factory's pitch is autonomy. Their platform docs list "Autonomy & Safety" as a pillar,
but safety there means permissions: what the agent is allowed to touch. It says nothing
about what the agent writes. Agent-generated code inherits every OWASP mistake at 100x
throughput, and Factory's enterprise customers (Blackstone, Adyen, Klarna, EY, Nvidia)
are exactly the organizations that cannot merge unaudited code.

VulnGate fills that hole as a single static binary: drop it in CI, or wire it into the
Droid harness as a pre-merge hook.

## 2. What already exists (verified Aug 2026)

| Tool | Lang | Stars | What it does | What we take | What we DON'T rebuild |
|---|---|---|---|---|---|
| semgrep/semgrep | OCaml core + Python CLI | 16.4k | 30+ language pattern SAST, YAML rules, registry | Rule *categories*; optional engine bridge later | The engine. It's LGPL-2.1, multi-binary, not embeddable in a Go static binary |
| securego/gosec | Go | 8.9k | Go-only AST+SSA+taint analysis, CWE mapping, SARIF, GitHub Action, exit codes | CWE-to-rule mapping, Go AST rules later, SARIF output format | Go-only coverage; agents write Python/JS/TS too |
| gitleaks/gitleaks | Go | 28.9k | Secrets detection, entropy scoring, baseline differencing, pre-commit | Entropy check to kill credential false positives; `gitleaks:allow`-style inline suppressions | Git-history scanning; we gate PRs, not archaeology |
| tree-sitter/go-tree-sitter | Go bindings (CGO) | 293 | Real parsers for every language, query API | AST layer so rules understand code, not text | Writing our own parsers; tree-sitter already won this |

One constraint shaped the design: Go's `regexp` is RE2, so no lookaheads and no
backreferences (gitleaks' docs call this out explicitly). The Python prototype's rules
used `(?!)` lookaheads and had to be redesigned as `pattern` + optional `safeWord`
(a line-level suppressor) instead.

## 3. Build vs. use decision

Compose, don't reinvent. The scanning engine is a commodity (semgrep, gosec, and
gitleaks prove that). The thing nobody ships is the gate: an opinionated single binary
that reads a PR diff, returns exploit-focused findings and a verdict, needs zero config
in CI, and plugs into the Droid harness's hooks. So VulnGate has its own small engine
(stdlib-only, with its limits documented) and leaves general-purpose SAST to the tools
that already do it well.

## 4. Architecture

```
┌────────────┐   walk    ┌──────────────┐  line scan   ┌──────────────┐
│ repo / diff │ ───────▶ │ scanner pool  │ ───────────▶ │ rules engine  │
└────────────┘ (goroutines)│ (Go RE2)    │              │ pattern+safe  │
                           └──────────────┘              └──────┬───────┘
                                                                 ▼
┌────────────┐   exit code ┌──────────────┐  findings   ┌──────────────┐
│ CI / hook   │ ◀───────── │  reporter     │ ◀────────── │ severity+CWE  │
└────────────┘             │ text / JSON  │              │ aggregation   │
                           └──────────────┘              └──────────────┘
```

- `vulngate scan <path>`: text report, exit 1 on any HIGH (CI-ready)
- `vulngate scan <path> --json`: machine output for agents and dashboards
- Severity floor flag, CWE on every finding, per-line suppressions (phase 2)

## 5. Phases

1. MVP (done): stdlib-only Go, concurrent line scanner, 9 CWE-mapped rules,
   text+JSON, BLOCK/REVIEW/PASS verdicts, exit codes.
2. AST + gate tier (done): tree-sitter Python taint analysis with 5 source-to-sink
   rules (SSRF, command injection, SQLi, unsafe deserialization, eval) plus
   provenance and false-positive suppression; diff-only mode
   (`vulngate diff patch.diff` gates just the added lines); SARIF 2.1.0 export;
   benchmark harness against a naive LLM-reviewer baseline. Numbers in
   `bench/BENCH.md`: F1 1.00 vs 0.92, whole-repo scans in roughly 50 to 100 ms.
3. Precision hardening (done): minified/vendor skipping (path rules plus a
   line-length heuristic), tests/examples scoping (`--include-tests` overrides),
   parameterized-query suppression for VG-T03, Shannon entropy gate on secrets.
   Result: the flask clean-repo run went from 16 findings and a BLOCK verdict to
   3 findings and REVIEW, and NodeGoat is down to its 5 textbook vulnerabilities.
   Next: JS/TS AST tier, per-finding confidence, Droid-harness hook.

## 6. Install and usage

Install once, use everywhere:

```bash
git clone https://github.com/raj921/vulngate && cd vulngate
make install        # builds and installs to ~/go/bin/vulngate
# make sure ~/go/bin is on your PATH, then from any directory:
vulngate scan /path/to/any/project
vulngate scan . --format=json          # machine report
vulngate scan . --format=sarif         # GitHub code scanning upload format
vulngate diff pull-request.patch       # gate only PR-added lines
vulngate scan . --include-tests        # also scan tests/examples
vulngate version
echo $?                                 # 1 when HIGH findings exist
```

Per-project config: drop a `.vulngateignore` at the repo root (gitignore-style, one
pattern per line, `#` comments, substring match) to exclude extra paths:

```
# .vulngateignore
gen/
legacy-vendor
# patterns are path-substring matches (not globs), so "gen/" matches any segment
```

## 7. Status

v0.3: AST taint tier, diff mode, SARIF, benchmark harness, precision hardening.
Details in [CHANGELOG.md](CHANGELOG.md). The `demo/` folder holds intentionally
vulnerable Python/JS; VulnGate blocks it (13 findings, 9 HIGH). Benchmark data and
the known-false-positive list live in `bench/BENCH.md`.
