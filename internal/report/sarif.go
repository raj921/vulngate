package report

import (
	"encoding/json"

	"github.com/raj921/vulngate/internal/rules"
	"github.com/raj921/vulngate/internal/scan"
)

// Minimal SARIF 2.1.0 types — enough for GitHub code scanning upload.
type sarifText struct {
	Text string `json:"text"`
}

type sarifRule struct {
	ID               string          `json:"id"`
	Name             string          `json:"name"`
	ShortDescription sarifText       `json:"shortDescription"`
	DefaultConfig    sarifRuleConfig `json:"defaultConfiguration"`
	Properties       sarifProps      `json:"properties"`
}

type sarifRuleConfig struct {
	Level string `json:"level"`
}

type sarifProps struct {
	Tags []string `json:"tags"`
}

type sarifLocation struct {
	Physical sarifPhysical `json:"physicalLocation"`
}

type sarifPhysical struct {
	Artifact sarifArtifact `json:"artifactLocation"`
	Region   sarifRegion   `json:"region"`
}

type sarifArtifact struct {
	URI string `json:"uri"`
}

type sarifRegion struct {
	StartLine int       `json:"startLine"`
	Snippet   sarifText `json:"snippet"`
}

type sarifResult struct {
	RuleID    string          `json:"ruleId"`
	Level     string          `json:"level"`
	Message   sarifText       `json:"message"`
	Locations []sarifLocation `json:"locations"`
}

type sarifLog struct {
	Version string `json:"version"`
	Schema  string `json:"$schema"`
	Runs    []struct {
		Tool struct {
			Driver struct {
				Name           string      `json:"name"`
				Version        string      `json:"version"`
				InformationURI string      `json:"informationUri"`
				Rules          []sarifRule `json:"rules"`
			} `json:"driver"`
		} `json:"tool"`
		Results []sarifResult `json:"results"`
	} `json:"runs"`
}

func sarifLevel(sev string) string {
	switch sev {
	case rules.High:
		return "error"
	case rules.Medium:
		return "warning"
	default:
		return "note"
	}
}

// SARIF renders findings in SARIF 2.1.0 for GitHub code scanning / IDEs.
func SARIF(findings []scan.Finding) ([]byte, error) {
	var log sarifLog
	log.Version = "2.1.0"
	log.Schema = "https://json.schemastore.org/sarif-2.1.0.json"
	log.Runs = make([]struct {
		Tool struct {
			Driver struct {
				Name           string      `json:"name"`
				Version        string      `json:"version"`
				InformationURI string      `json:"informationUri"`
				Rules          []sarifRule `json:"rules"`
			} `json:"driver"`
		} `json:"tool"`
		Results []sarifResult `json:"results"`
	}, 1)

	driver := &log.Runs[0].Tool.Driver
	driver.Name = "VulnGate"
	driver.Version = "0.2.0"
	driver.InformationURI = "https://github.com/raj921/vulngate"

	seen := map[string]bool{}
	for _, f := range findings {
		if !seen[f.RuleID] {
			seen[f.RuleID] = true
			driver.Rules = append(driver.Rules, sarifRule{
				ID:               f.RuleID,
				Name:             f.Name,
				ShortDescription: sarifText{f.Name},
				DefaultConfig:    sarifRuleConfig{Level: sarifLevel(f.Severity)},
				Properties:       sarifProps{Tags: []string{"security", f.CWE, f.Tier}},
			})
		}
		log.Runs[0].Results = append(log.Runs[0].Results, sarifResult{
			RuleID:  f.RuleID,
			Level:   sarifLevel(f.Severity),
			Message: sarifText{f.Name + " — " + f.CWE + ". Fix: " + f.Fix},
			Locations: []sarifLocation{{Physical: sarifPhysical{
				Artifact: sarifArtifact{URI: f.Path},
				Region:   sarifRegion{StartLine: f.Line, Snippet: sarifText{f.Code}},
			}}},
		})
	}
	if log.Runs[0].Results == nil {
		log.Runs[0].Results = []sarifResult{}
	}
	return json.MarshalIndent(log, "", "  ")
}
