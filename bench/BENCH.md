# VulnGate benchmark notes

Date: 2026-08-25 (v0.3, Phase 3 precision hardening applied).
All commands reproducible from this repo (`bench/`).

## 0. Phase 3 precision hardening (what changed since v0.2)

Applied the five FP-hardening items found by the v0.2 bench:

1. **Minified/vendor skipping**: `vendor/`, `third_party/`, `dist/`, `*.min.js` paths
   + average-line-length > 200 detection (catches Closure/webpack bundles).
2. **Tests/examples scoping**: `tests/`, `examples/`, `docs/`, `test_*`, `*.spec.*`,
   `*.test.*` excluded by default (`--include-tests` to override).
3. **Parameterized-query suppression (VG-T03)**: `execute("…", (params,))` shape
   recognized as safe at the AST level.
4. **Secrets entropy gate (VG-001)**: Shannon entropy ≥ 3.0 bits/char required,
   so dummies like `password = "password"` no longer flag.
5. `hashlib.sha1` context-class: kept MEDIUM, documented (see §2 Flask row).

### Effect on real repos (v0.2 → v0.3)

| Repo | v0.2 | v0.3 | Change |
|---|---|---|---|
| we45/Vulnerable-Flask-App | 23 | **5** | 18 noise findings removed: 109KB minified `loader.js` (12 FPs), `tests/` paths, low-entropy secret |
| OWASP/NodeGoat | 15 | **5** | 10 removed: test/artifact paths, templated secrets. Remaining 5 are the app's textbook teaching vulns, `eval(req.body.preTax)` etc. |
| pallets/flask (clean) | 16 / BLOCK | **3 / REVIEW** | 59 test files skipped; remaining: 2× `debug=True` (docstring config), 1× sha1 cookie digest. No more BLOCK on clean Flask |

Seeded corpus unchanged: **F1 1.00** (all 5 trap-file suppressions still hold;
entropy gate kept every corpus TP).

## Systems compared

- **VulnGate (full pipeline)**: regex tier + tree-sitter AST taint tier.
- **VulnGate (line-pattern tier only)**: what the tool is without AST.
- **Naive LLM baseline**: single prompt per file ("list vulnerabilities as JSON"),
  no rules, no tools, the common "just ask the LLM to review the diff" approach.
  Model: `raj315920--ep-kimi-k3-server` (temperature 0, one retry).

## 1. Seeded corpus (7 files: 5 vulnerable, 2 trap files designed to bait false positives)

| System | Precision | Recall | F1 |
|---|---|---|---|
| **VulnGate (full)** | **1.00** | **1.00** | **1.00** |
| VulnGate (line-pattern tier only) | 1.00 | 0.58 | 0.74 |
| Naive LLM baseline | 0.92 | 1.00 | 0.96 |

- AST tier adds **+42 recall points** over line patterns (it proves data flow:
  `url = request.args.get("url") → requests.get(url)`).
- Both trap files stayed clean for VulnGate. The LLM baseline's one FP: it
  flagged the 1-character JWT literal `'k'` as CWE-798 "hardcoded credential".
- Honest read: on tiny curated files, everything works. The gap shows at scale.

## 2. Real repos

| Repo | VulnGate | Naive LLM baseline |
|---|---|---|
| **we45/Vulnerable-Flask-App** (vulnerable training app) | **23 findings / BLOCK.** Verified true positives: `user.password='admin123'` (CWE-798, app.py:63), `jwt.decode(token, verify=False)` (CWE-347, app.py:97), AST-confirmed tainted SQL `db.engine.execute(str_query)` (CWE-89, app.py:265) | 13 findings; found the same headline bugs. **Could not ingest** the 109KB vendored `loader.js` (context limit, skipped). First run returned unparseable output; needed retry |
| **OWASP/NodeGoat** (50 JS files) | **15 findings / BLOCK**: 48 ms | not run: 50 paid API calls + long-tail files; this is exactly where the naive approach dies |
| **pallets/flask** (clean, 83 py files) | 16 flags, **0 in core runtime request-handling code**. Breakdown: 11× `debug=True` in *tests*/docs, 4× VG-T03 on tutorial examples (uses parameterized queries, parametrization awareness is Phase 3), 1× `hashlib.sha1` context-safe cookie digest | not run (clean repo; LLM baseline would only measure FP rate, and it was already nonzero on tiny files) |

## 3. Speed / cost / determinism

| Dimension | VulnGate | Naive LLM baseline |
|---|---|---|
| NodeGoat (50 JS files) | 48 ms, $0 | est. 50+ API calls, minutes |
| Flask (83 py, AST tier on) | 92 ms, $0 | minutes |
| Determinism | same input → same verdict | stochastic (observed unparseable reply) |
| Offline / air-gapped | yes | no |
| CI-native | exit code 1, SARIF for code scanning | needs schema-constraining + orchestration |
| Minified/vendor handling | scans today (FPs noted, Phase 3 filter) | can't ingest >context files |

## 4. Field test (v0.4): unfamiliar production repos, unlabeled verdicts

Scanning real code nobody prepared, then hand-checking every finding. This is the
loop that turned the tool into a real app: each false positive below produced a fix.

| Repo | Findings | Verdict | Hand-checked truth |
|---|---|---|---|
| datathon (my own FastAPI app) | 1 | REVIEW | VG-010 CORS wildcard at backend/main.py:30. Correct, actionable MEDIUM. App is otherwise clean: env secrets, secrets.compare_digest on OAuth state |
| express (JS framework) | 0 | PASS | Zero false positives on a clean production framework |
| pallets/flask | 3 | REVIEW | 59 test files skipped; remaining hits are docstring config and a context-safe sha1 |
| flaskbb (production forum) | 4 | BLOCK | 3x innerHTML with user-content previews (credible MEDIUM XSS-review flags) + WTF_CSRF default secret shipped in default config (legit catch: predictable signing key across every default install) |
| httpie (HTTP CLI) | 2 | REVIEW | requests.get(..., verify=False) in the update checker. True MITM-class finding, correctly relabeled CWE-295 after this round (it was mislabeled CWE-347 before) |

### Tool fixes driven by this field test

1. VG-T03 no longer treats `.execute(db.select(...))` ORM builders as sinks
   (flaskbb produced 3 of these; AST checks the first argument's shape now).
2. TLS `verify=False` split into its own rule, VG-011, CWE-295
   (it was masked under the JWT rule, CWE-347).
3. New rule VG-010, permissive CORS wildcards (CWE-942), from scanning my own app.
4. VG-001 self-naming suppression: `RESET_PASSWORD = "reset_password"` is a
   label constant, not a credential (name-normalized comparison).
5. Regression tests for all of the above; seeded corpus F1 unchanged at 1.00.

## 5. Known false-positive classes (found by this bench) → Phase 3 work items

1. Minified / vendored JS (Closure-compiled `loader.js`), skip by line-length + path heuristics.
2. Tests / examples / docs paths (`tests/`, `examples/`), default scope exclusions.
3. VG-T03: suppress flagging parameterized queries (`execute(sql, (params,))`), sink shape analysis.
4. `hashlib.sha1` used for non-security digests, context note, downgrade confidence.
5. Secrets: add Shannon-entropy gate (à la gitleaks) to kill short/dummy credential FPs.

## Reproduce

```bash
go build -o vulngate ./cmd/vulngate
./vulngate scan --format=json bench/corpus > bench/vg_pred.json
python3 bench/score.py bench/vg_pred.json                 # full pipeline
python3 bench/score.py bench/vg_pred.json --tier regex    # line-pattern tier only
OPENAI_BASE_URL=... OPENAI_API_KEY=... python3 bench/llm_baseline.py
python3 bench/score.py bench/llm_pred.json                # naive LLM baseline
```
