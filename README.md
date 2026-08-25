# VulnGate

**The security gate for AI-agent-generated code.**

Autonomous coding agents (Factory Droid, Devin, Claude Code, Copilot Workspace) now
write and merge code at machine speed. The security review step did not get faster.
VulnGate is the checkpoint: it runs on every agent-authored PR and decides
**BLOCK / REVIEW / PASS** before anything merges.

---

## 1. Why this exists (thesis)

Factory's pitch is *autonomy*. Their platform docs list "Autonomy & Safety" as a pillar,
but safety there means *permissions* — what the agent is allowed to touch. Nobody checks
*what the agent writes*. Agent-generated code inherits every OWASP mistake at 100x
throughput, and Factory's enterprise customers (Blackstone, Adyen, Klarna, EY, Nvidia)
are exactly the organizations that cannot merge unaudited code.

VulnGate fills that hole as a single static binary: drop it in CI or wire it into the
Droid harness as a pre-merge hook.

## 2. Research: what already exists (verfied Aug 2026)

| Tool | Lang | Stars | What it does | What we take | What we DON'T rebuild |
|---|---|---|---|---|---|
| **semgrep/semgrep** | OCaml core + Python CLI | 16.4k | 30+ language pattern SAST, YAML rules, registry | Rule *categories* (its registry is a map of what to detect); optional engine bridge later | The engine. It's LGPL-2.1, multi-binary, not embeddable in a Go static binary |
| **securego/gosec** | Go | 8.9k | Go-only AST+SSA+**taint** analysis, CWE mapping, SARIF, GitHub Action, exit codes | CWE-to-rule mapping, Go AST rules **for Go targets** via `go/analysis` later, SARIF output format | Go-only coverage — agents write Python/JS/TS too |
| **gitleaks/gitleaks** | Go | 28.9k | Secrets detection, entropy scoring, baseline differencing, pre-commit | Entropy check to kill credential false positives; `gitleaks:allow`-style inline suppressions | Git-history scanning — we gate PRs, not archaeology |
| **tree-sitter/go-tree-sitter** | Go bindings (CGO) | 293 | Real parsers for every language, query API | Phase-2 AST layer so rules understand code, not text | Writing our own parsers — tree-sitter already won this |

**Key constraint found in research:** Go's `regexp` is RE2 — *no lookaheads, no
backreferences* (gitleaks' docs call this out explicitly). Python-prototype rules using
`(?!)` had to be redesigned: rules are `pattern` + optional `safeWord` (line-level
suppressor) instead of lookahead hacks.

Repo: https://github.com/raj921/vulngate

## 3. Build vs. use decision

> **Compose, don't reinvent. Differentiate on the gate, not the engine.**

- The scanning *engine* is a commodity (semgrep/gosec/gitleaks proved it).
- The **product** nobody has shipped: an opinionated, single-binary, agent-PR security
  **gate** — diff-aware, exploit-focused findings, machine-readable verdicts, zero-config
  CI, and a first-class hook into the Factory Droid harness (`hooks/` in their docs).
- So: own engine = yes (small, stdlib-only, honest about limits), general SAST = no.

## 4. Architecture

```
┌────────────┐   walk    ┌──────────────┐  line scan   ┌──────────────┐
│ repo / diff │ ───────▶ │ scanner pool  │ ───────────▶ │ rules engine  │
└────────────┘ (goroutines)│ (Go RE2)    │              │ pattern+safe  │
                           └──────────────┘              └──────┬───────┘
                                                                 ▼
┌────────────┐   exit code ┌──────────────┐  findings   ┌──────────────┐
│ CI / hook   │ ◀───────── │  reporter     │ ◀────────── │ severity+ CWE │
└────────────┘             │ text / JSON  │              │ aggregation   │
                           └──────────────┘              └──────────────┘
```

- `vulngate scan <path>` — text report, exit 1 on any HIGH (CI-ready)
- `vulngate scan <path> --json` — machine output for agents and dashboards
- Severity floor flag, CWE on every finding, per-line suppressions (phase 2)

## 5. Phases

1. **MVP (done):** stdlib-only Go, concurrent line scanner, 9 CWE-mapped rules,
   text+JSON, BLOCK/REVIEW/PASS verdicts, exit codes.
2. **AST + gate tier (done):** tree-sitter Python taint analysis (5 source→sink
   rules: SSRF/cmd/SQLi/deserialization/eval with provenance, regex FP suppression);
   diff-only mode (`vulngate diff patch.diff` gates just the added lines);
   SARIF 2.1.0 export; benchmark harness vs. naive LLM review (see `bench/BENCH.md`:
   F1 1.00 vs 0.92 naive LLM; ~50–100 ms whole-repo scans).
3. **Precision hardening (done):** minified/vendor skipping (path + line-length
   heuristics), tests/examples scoping (`--include-tests` overrides), VG-T03
   parameterized-query suppression, gitleaks-style Shannon entropy gate on secrets.
   Result: Flask clean-repo run 16→3 findings & BLOCK→REVIEW; NodeGoat cut to its
   5 textbook vulns. Next: JS/TS AST tier, per-finding confidence, Droid-harness hook.

## 6. Usage

```bash
go build -o vulngate ./cmd/vulngate
./vulngate scan ./demo                  # human report
./vulngate scan --format=json ./demo    # machine report
./vulngate scan --format=sarif ./demo   # GitHub code scanning upload format
./vulngate diff bench/demo.patch        # gate only PR-added lines
echo $?                                 # 1 when HIGH findings exist
```

## 7. Status

v0.3 — AST taint tier, diff mode, SARIF, benchmark harness, precision hardening shipped.
Demo: `demo/` contains intentionally vulnerable Python/JS; VulnGate blocks it
(13 findings, 9 HIGH). Benchmarks and known-FP analysis: `bench/BENCH.md`.
