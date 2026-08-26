// Package rules defines VulnGate's detection rules.
//
// Design constraint: Go's regexp package is RE2 — no lookaheads, no
// backreferences. Where a Python-style rule would use a negative lookahead,
// we instead pair a Pattern with a SafeWord: a line that matches Pattern is a
// finding UNLESS SafeWord also matches the same line.
package rules

import (
	"math"
	"regexp"
	"strings"
	"unicode"
)

// NormName lowercases s and strips non-alphanumerics. Used to tell
// self-naming constants (RESET_PASSWORD = "reset_password") from real secrets.
func NormName(s string) string {
	var b strings.Builder
	for _, r := range s {
		if unicode.IsLetter(r) || unicode.IsDigit(r) {
			b.WriteRune(unicode.ToLower(r))
		}
	}
	return b.String()
}

// Shannon returns the Shannon entropy (bits/char) of s — gitleaks-style gate
// that separates real credentials (high entropy) from dummies like "password".
func Shannon(s string) float64 {
	if s == "" {
		return 0
	}
	var freq [256]int
	for i := range len(s) {
		freq[s[i]]++
	}
	n := float64(len(s))
	var h float64
	for _, c := range freq {
		if c == 0 {
			continue
		}
		p := float64(c) / n
		h -= p * math.Log2(p)
	}
	return h
}

// Severity levels, ordered LOW < MEDIUM < HIGH for report sorting.
const (
	High   = "HIGH"
	Medium = "MEDIUM"
	Low    = "LOW"
)

// Rule is one detection rule.
type Rule struct {
	ID       string
	Name     string
	Severity string
	CWE      string
	Pattern  *regexp.Regexp
	SafeWord *regexp.Regexp // suppresses the finding when it matches the same line
	// EntropyGate, when > 0, requires the LAST capture group's Shannon
	// entropy to exceed the threshold (kills dummy-credential FPs).
	EntropyGate float64
	// SelfNamed suppresses the finding when capture group 1 (the variable
	// name) normalize-equals the last group (the value).
	SelfNamed bool
	Fix       string
	Exts      []string // file extensions this rule applies to, e.g. []string{".py"}
	matchExts map[string]bool
}

// webExts covers the languages coding agents most often generate.
var webExts = []string{".py", ".js", ".ts", ".jsx", ".tsx", ".go", ".rb"}
var jsExts = []string{".js", ".ts", ".jsx", ".tsx"}

// All is VulnGate's MVP rule set. Every rule carries a CWE so findings can be
// mapped straight into enterprise reporting tools (same contract as gosec).
var All = []Rule{
	{
		ID: "VG-001", Name: "Hardcoded credential", Severity: High, CWE: "CWE-798",
		// Groups: 1 = variable name, 2 = value. A constant naming itself
		// (RESET_PASSWORD = "reset_password") is a label, not a credential.
		Pattern:     regexp.MustCompile(`(?i)(\w*(?:api[_-]?key|secret|password|passwd|token|auth)\w*)\s*=\s*["']([^"'\s]{8,})["']`),
		SafeWord:    regexp.MustCompile(`os\.environ|getenv|process\.env|example|placeholder|changeme|dummy|your[_-]`),
		EntropyGate: 3.0,
		SelfNamed:   true,
		Fix:         "Load from environment (os.environ['KEY']). Never commit secrets.",
		Exts:        webExts,
	},
	{
		ID: "VG-002", Name: "SQL injection (string-built query)", Severity: High, CWE: "CWE-89",
		Pattern: regexp.MustCompile(`execute\(\s*(f["']|["'][^"']*%|[^)]*\+\s*\w+)`),
		Fix:     "Use parameterized queries: execute(sql, (params,)).",
		Exts:    webExts,
	},
	{
		ID: "VG-003", Name: "Command injection", Severity: High, CWE: "CWE-78",
		Pattern: regexp.MustCompile(`os\.system\(|os\.popen\(|subprocess\.(call|run|Popen)\([^)]*shell\s*=\s*True|\beval\(|\bexec\(|child_process\.exec\(`),
		Fix:     "Avoid the shell; pass argv lists. Never eval/exec external input.",
		Exts:    webExts,
	},
	{
		ID: "VG-004", Name: "Server-side request forgery", Severity: High, CWE: "CWE-918",
		Pattern:  regexp.MustCompile(`requests\.(get|post|put|delete)\(\s*(request\.|\w*url\b)`),
		SafeWord: regexp.MustCompile(`allow-?list|whitelist|ALLOWED_HOSTS`),
		Fix:      "Validate against an allow-list of hosts; never fetch raw user-supplied URLs.",
		Exts:     []string{".py"},
	},
	{
		ID: "VG-005", Name: "Debug mode enabled", Severity: Medium, CWE: "CWE-489",
		Pattern: regexp.MustCompile(`debug\s*=\s*True|DEBUG\s*=\s*True`),
		Fix:     "Never run debug mode in production.",
		Exts:    []string{".py"},
	},
	{
		ID: "VG-006", Name: "Weak hash (MD5/SHA1)", Severity: Medium, CWE: "CWE-327",
		Pattern:  regexp.MustCompile(`\bmd5\(|\bsha1\(|createHash\(["'](md5|sha1)["']\)`),
		SafeWord: regexp.MustCompile(`usedforsecurity\s*=\s*False`),
		Fix:      "bcrypt/argon2 for passwords, SHA-256+ for integrity.",
		Exts:     webExts,
	},
	{
		ID: "VG-007", Name: "Unsafe deserialization", Severity: High, CWE: "CWE-502",
		Pattern:  regexp.MustCompile(`pickle\.loads?\(|yaml\.load\(`),
		SafeWord: regexp.MustCompile(`safe_load|SafeLoader`),
		Fix:      "Use json, or yaml.safe_load(). pickle on untrusted data = RCE.",
		Exts:     []string{".py"},
	},
	{
		ID: "VG-008", Name: "DOM XSS", Severity: Medium, CWE: "CWE-79",
		Pattern: regexp.MustCompile(`\.innerHTML\s*=|dangerouslySetInnerHTML`),
		Fix:     "Use textContent or a sanitizer (DOMPurify).",
		Exts:    jsExts,
	},
	{
		ID: "VG-009", Name: "JWT signature check disabled", Severity: High, CWE: "CWE-347",
		Pattern:  regexp.MustCompile(`(?i)algorithms?\s*[=:]\s*\[?\s*["']none["']|verify_signature"?\s*:\s*False`),
		SafeWord: nil,
		Fix:      "Always verify the JWT signature; reject alg=none.",
		Exts:     webExts,
	},
	{
		ID: "VG-010", Name: "Permissive CORS (wildcard origin)", Severity: Medium, CWE: "CWE-942",
		Pattern: regexp.MustCompile(`(?i)(Access-Control-Allow-Origin["']?\s*[:=,]\s*["']\*|allow_origins\s*=\s*\[\s*["']\*["'])`),
		Fix:     "Restrict allow_origins to an explicit list of your frontend hosts via config.",
		Exts:    webExts,
	},
	{
		ID: "VG-011", Name: "TLS certificate verification disabled", Severity: Medium, CWE: "CWE-295",
		Pattern: regexp.MustCompile(`verify\s*=\s*False|verify\s*:\s*false`),
		Fix:     "Never set verify=False on outbound HTTPS; pass the CA bundle instead.",
		Exts:    webExts,
	},
}

func init() {
	for i := range All {
		All[i].matchExts = make(map[string]bool, len(All[i].Exts))
		for _, e := range All[i].Exts {
			All[i].matchExts[e] = true
		}
	}
}

// ForExt returns the rules applicable to a file extension like ".py".
func ForExt(ext string) []Rule {
	var out []Rule
	for i := range All {
		if All[i].matchExts[ext] {
			out = append(out, All[i])
		}
	}
	return out
}

// Scannable reports whether any rule covers this extension.
func Scannable(ext string) bool {
	for i := range All {
		if All[i].matchExts[ext] {
			return true
		}
	}
	return false
}
