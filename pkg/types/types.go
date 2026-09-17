// Package types defines the core data types shared across trivy-ai.
package types

import (
	"crypto/sha256"
	"fmt"
	"strings"
	"time"
)

// Severity represents the severity level of a CVE finding.
type Severity int

const (
	SeverityUnknown  Severity = iota
	SeverityLow
	SeverityMedium
	SeverityHigh
	SeverityCritical
)

// String returns the human-readable name of the severity level.
func (s Severity) String() string {
	switch s {
	case SeverityLow:
		return "LOW"
	case SeverityMedium:
		return "MEDIUM"
	case SeverityHigh:
		return "HIGH"
	case SeverityCritical:
		return "CRITICAL"
	default:
		return "UNKNOWN"
	}
}

// SeverityFromString parses a severity string and returns the corresponding Severity.
// Returns an error if the string is not a known severity level.
func SeverityFromString(s string) (Severity, error) {
	switch strings.ToUpper(strings.TrimSpace(s)) {
	case "LOW":
		return SeverityLow, nil
	case "MEDIUM":
		return SeverityMedium, nil
	case "HIGH":
		return SeverityHigh, nil
	case "CRITICAL":
		return SeverityCritical, nil
	default:
		return SeverityUnknown, fmt.Errorf("unknown severity %q: must be one of LOW, MEDIUM, HIGH, CRITICAL", s)
	}
}

// TargetType represents what kind of artifact is being scanned.
type TargetType string

const (
	TargetTypeImage      TargetType = "image"
	TargetTypeFilesystem TargetType = "fs"
	TargetTypeKubernetes TargetType = "k8s"
	TargetTypeIaC        TargetType = "iac"
)

// Target represents a scan target with its type and reference.
type Target struct {
	// Type is the kind of artifact to scan.
	Type TargetType
	// Ref is the reference to the target (e.g. image name, path, kubeconfig).
	Ref string
}

// Finding represents a single CVE finding from a vulnerability scan.
type Finding struct {
	// ID is the CVE identifier (e.g. CVE-2024-1234).
	ID string
	// Severity is the severity level of the finding.
	Severity Severity
	// CVSS is the CVSS score of the finding (0.0 - 10.0).
	CVSS float64
	// Package is the name of the vulnerable package.
	Package string
	// InstalledVersion is the currently installed version of the package.
	InstalledVersion string
	// FixedVersion is the version that fixes the vulnerability. Empty if no fix exists.
	FixedVersion string
	// Description is the raw CVE description from NVD. Must be sanitized before use in prompts.
	Description string
	// Target is what was scanned to produce this finding.
	Target string
	// TargetType is the type of the scan target.
	TargetType TargetType
	// References are URLs to advisories and NVD entries.
	References []string
}

// IsFixable returns true if a fixed version is available for this finding.
func (f Finding) IsFixable() bool {
	return strings.TrimSpace(f.FixedVersion) != ""
}

// Key returns a deterministic cache key for this finding combined with
// agent type and model name. Used to key the result cache.
func (f Finding) Key(agentName, model string) string {
	raw := fmt.Sprintf("%s|%s|%s|%s|%s|%s",
		f.ID, f.Package, f.InstalledVersion, f.FixedVersion, agentName, model)
	sum := sha256.Sum256([]byte(raw))
	return fmt.Sprintf("%x", sum)
}

// Usage tracks token usage for a single LLM call.
type Usage struct {
	// PromptTokens is the number of tokens in the prompt.
	PromptTokens int
	// CompletionTokens is the number of tokens in the completion.
	CompletionTokens int
}

// Total returns the total number of tokens used.
func (u Usage) Total() int {
	return u.PromptTokens + u.CompletionTokens
}

// AgentResult holds the output of an agent processing a single finding.
type AgentResult struct {
	// FindingID is the CVE ID this result corresponds to.
	FindingID string
	// AgentName is the name of the agent that produced this result.
	AgentName string
	// Content is the main output of the agent (explanation, fix suggestion, etc.).
	Content string
	// Usage is the token usage for this result.
	Usage Usage
	// Cached indicates whether this result was served from cache.
	Cached bool
	// Error holds any error that occurred during agent processing.
	Error error
}

// ScanResult holds the complete output of a scan run.
type ScanResult struct {
	// SchemaVersion identifies the output schema for forward compatibility.
	SchemaVersion string `json:"schema_version"`
	// Target is what was scanned.
	Target Target `json:"target"`
	// Findings are the raw CVE findings after guardrail filtering.
	Findings []Finding `json:"findings"`
	// Results are the agent results for each finding.
	Results []AgentResult `json:"results"`
	// TotalFound is the total number of findings before guardrail filtering.
	TotalFound int `json:"total_found"`
	// TotalFiltered is the number of findings dropped by guardrails.
	TotalFiltered int `json:"total_filtered"`
	// Usage is the total token usage across all agent calls.
	Usage Usage `json:"usage"`
	// Duration is the wall-clock time of the scan.
	Duration time.Duration `json:"duration_ms"`
	// CacheHits is the number of results served from cache.
	CacheHits int `json:"cache_hits"`
}

// Summary returns a one-line string summarising the scan result.
func (r ScanResult) Summary() string {
	bySeverity := map[Severity]int{}
	for _, f := range r.Findings {
		bySeverity[f.Severity]++
	}
	return fmt.Sprintf(
		"Found %d vulnerabilities (%d CRITICAL, %d HIGH, %d MEDIUM, %d LOW) | %d filtered | %d cached | %d tokens | %s",
		len(r.Findings),
		bySeverity[SeverityCritical],
		bySeverity[SeverityHigh],
		bySeverity[SeverityMedium],
		bySeverity[SeverityLow],
		r.TotalFiltered,
		r.CacheHits,
		r.Usage.Total(),
		r.Duration.Round(time.Millisecond),
	)
}
