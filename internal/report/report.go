// Package report renders findings as text or JSON and computes the verdict.
package report

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/raj921/vulngate/internal/rules"
	"github.com/raj921/vulngate/internal/scan"
)

// Version is the single version string shared by JSON and SARIF reports.
const Version = "0.3.1"

// Document is the machine-readable (JSON) report.
type Document struct {
	Tool     string         `json:"tool"`
	Version  string         `json:"version"`
	Findings []scan.Finding `json:"findings"`
	Counts   map[string]int `json:"counts"`
	Verdict  string         `json:"verdict"` // BLOCK | REVIEW | PASS
}

// CountBySeverity tallies findings.
func CountBySeverity(findings []scan.Finding) map[string]int {
	c := map[string]int{rules.High: 0, rules.Medium: 0, rules.Low: 0}
	for _, f := range findings {
		c[f.Severity]++
	}
	return c
}

// Verdict is the gate decision: any HIGH blocks the merge.
func Verdict(findings []scan.Finding) string {
	c := CountBySeverity(findings)
	switch {
	case c[rules.High] > 0:
		return "BLOCK"
	case c[rules.Medium]+c[rules.Low] > 0:
		return "REVIEW"
	default:
		return "PASS"
	}
}

// JSON renders the full machine-readable document.
func JSON(findings []scan.Finding) ([]byte, error) {
	if findings == nil {
		findings = []scan.Finding{}
	}
	doc := Document{
		Tool:     "vulngate",
		Version:  Version,
		Findings: findings,
		Counts:   CountBySeverity(findings),
		Verdict:  Verdict(findings),
	}
	return json.MarshalIndent(doc, "", "  ")
}

// Text renders a human-readable report.
func Text(findings []scan.Finding) string {
	var b strings.Builder
	b.WriteString("\nVulnGate scan report\n")
	b.WriteString(strings.Repeat("=", 60) + "\n")
	for _, f := range findings {
		mark := map[string]string{rules.High: "[HIGH]  ", rules.Medium: "[MED]   ", rules.Low: "[LOW]   "}[f.Severity]
		fmt.Fprintf(&b, "%s %s  %s %s\n", mark, f.RuleID, f.Name, f.CWE)
		fmt.Fprintf(&b, "          %s:%d\n", f.Path, f.Line)
		code := f.Code
		if len(code) > 90 {
			code = code[:90]
		}
		fmt.Fprintf(&b, "          > %s\n", code)
		fmt.Fprintf(&b, "          fix: %s\n\n", f.Fix)
	}
	c := CountBySeverity(findings)
	b.WriteString(strings.Repeat("-", 60) + "\n")
	fmt.Fprintf(&b, "%d finding(s): %d high, %d medium, %d low\nVerdict: %s\n",
		len(findings), c[rules.High], c[rules.Medium], c[rules.Low], Verdict(findings))
	return b.String()
}
