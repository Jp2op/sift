package output

import (
	"context"
	"encoding/json"
	"fmt"
	"io"

	"github.com/jp2op/trivy-ai/internal"
	"github.com/jp2op/trivy-ai/pkg/types"
)

const (
	sarifVersion = "2.1.0"
	sarifSchema  = "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json"
	toolName     = "trivy-ai"
	toolVersion  = "0.2.0"
	toolInfoURI  = "https://github.com/jp2op/trivy-ai"
)

// SARIFReporter writes SARIF 2.1.0 output for GitHub Security tab.
type SARIFReporter struct{}

var _ internal.Reporter = (*SARIFReporter)(nil)

func (s *SARIFReporter) Name() string { return "sarif" }

type sarifLog struct {
	Version string    `json:"version"`
	Schema  string    `json:"$schema"`
	Runs    []sarifRun `json:"runs"`
}
type sarifRun struct {
	Tool    sarifTool     `json:"tool"`
	Results []sarifResult `json:"results"`
}
type sarifTool struct {
	Driver sarifDriver `json:"driver"`
}
type sarifDriver struct {
	Name           string      `json:"name"`
	Version        string      `json:"version"`
	InformationURI string      `json:"informationUri"`
	Rules          []sarifRule `json:"rules"`
}
type sarifRule struct {
	ID               string             `json:"id"`
	Name             string             `json:"name"`
	ShortDescription sarifMessage       `json:"shortDescription"`
	HelpURI          string             `json:"helpUri,omitempty"`
	Properties       map[string]string  `json:"properties"`
}
type sarifResult struct {
	RuleID    string          `json:"ruleId"`
	Level     string          `json:"level"`
	Message   sarifMessage    `json:"message"`
	Locations []sarifLocation `json:"locations"`
}
type sarifMessage  struct{ Text string `json:"text"` }
type sarifLocation struct {
	PhysicalLocation struct {
		ArtifactLocation struct {
			URI string `json:"uri"`
		} `json:"artifactLocation"`
	} `json:"physicalLocation"`
}

func (s *SARIFReporter) Report(_ context.Context, result types.ScanResult, w io.Writer) error {
	ruleMap := map[string]sarifRule{}
	for _, f := range result.Findings {
		if _, ok := ruleMap[f.ID]; ok { continue }
		ruleMap[f.ID] = sarifRule{
			ID: f.ID, Name: f.ID,
			ShortDescription: sarifMessage{Text: f.Description},
			HelpURI:          "https://nvd.nist.gov/vuln/detail/" + f.ID,
			Properties:       map[string]string{"security-severity": fmt.Sprintf("%.1f", f.CVSS)},
		}
	}
	rules := make([]sarifRule, 0, len(ruleMap))
	for _, r := range ruleMap { rules = append(rules, r) }

	explanations := map[string]string{}
	for _, r := range result.Results { explanations[r.FindingID] = r.Content }

	sarifResults := make([]sarifResult, 0, len(result.Findings))
	for _, f := range result.Findings {
		msg := f.Description
		if exp, ok := explanations[f.ID]; ok && exp != "" { msg = exp }

		var loc sarifLocation
		loc.PhysicalLocation.ArtifactLocation.URI = result.Target.Ref

		sarifResults = append(sarifResults, sarifResult{
			RuleID:    f.ID,
			Level:     severityToSARIFLevel(f.Severity),
			Message:   sarifMessage{Text: msg},
			Locations: []sarifLocation{loc},
		})
	}

	log := sarifLog{
		Version: sarifVersion,
		Schema:  sarifSchema,
		Runs: []sarifRun{{
			Tool: sarifTool{Driver: sarifDriver{
				Name: toolName, Version: toolVersion,
				InformationURI: toolInfoURI, Rules: rules,
			}},
			Results: sarifResults,
		}},
	}

	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(log)
}

func severityToSARIFLevel(s types.Severity) string {
	switch s {
	case types.SeverityCritical, types.SeverityHigh: return "error"
	case types.SeverityMedium: return "warning"
	default: return "note"
	}
}