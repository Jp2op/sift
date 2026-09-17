package types_test

import (
	"strings"
	"testing"

	"github.com/jp2op/trivy-ai/pkg/types"
)

// TestSeverityString verifies each severity level returns the correct string.
func TestSeverityString(t *testing.T) {
	tests := []struct {
		severity types.Severity
		want     string
	}{
		{types.SeverityCritical, "CRITICAL"},
		{types.SeverityHigh, "HIGH"},
		{types.SeverityMedium, "MEDIUM"},
		{types.SeverityLow, "LOW"},
		{types.SeverityUnknown, "UNKNOWN"},
	}
	for _, tc := range tests {
		t.Run(tc.want, func(t *testing.T) {
			if got := tc.severity.String(); got != tc.want {
				t.Errorf("Severity(%d).String() = %q, want %q", tc.severity, got, tc.want)
			}
		})
	}
}

// TestSeverityFromString verifies parsing of valid and invalid severity strings.
func TestSeverityFromString(t *testing.T) {
	tests := []struct {
		input   string
		want    types.Severity
		wantErr bool
	}{
		{"CRITICAL", types.SeverityCritical, false},
		{"HIGH", types.SeverityHigh, false},
		{"MEDIUM", types.SeverityMedium, false},
		{"LOW", types.SeverityLow, false},
		{"critical", types.SeverityCritical, false}, // case-insensitive
		{"  HIGH  ", types.SeverityHigh, false},     // whitespace trimmed
		{"BANANA", types.SeverityUnknown, true},
		{"", types.SeverityUnknown, true},
		{"info", types.SeverityUnknown, true},
	}
	for _, tc := range tests {
		t.Run(tc.input, func(t *testing.T) {
			got, err := types.SeverityFromString(tc.input)
			if tc.wantErr {
				if err == nil {
					t.Errorf("SeverityFromString(%q) expected error, got nil", tc.input)
				}
				return
			}
			if err != nil {
				t.Errorf("SeverityFromString(%q) unexpected error: %v", tc.input, err)
			}
			if got != tc.want {
				t.Errorf("SeverityFromString(%q) = %v, want %v", tc.input, got, tc.want)
			}
		})
	}
}

// TestFindingIsFixable verifies IsFixable returns true only when FixedVersion is non-empty.
func TestFindingIsFixable(t *testing.T) {
	tests := []struct {
		name         string
		fixedVersion string
		want         bool
	}{
		{"has fix", "1.2.3", true},
		{"no fix", "", false},
		{"whitespace only", "   ", false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			f := types.Finding{FixedVersion: tc.fixedVersion}
			if got := f.IsFixable(); got != tc.want {
				t.Errorf("IsFixable() = %v, want %v", got, tc.want)
			}
		})
	}
}

// TestFindingKey verifies the cache key is deterministic and unique per input.
func TestFindingKey(t *testing.T) {
	f := types.Finding{
		ID:               "CVE-2024-1234",
		Package:          "openssl",
		InstalledVersion: "3.0.13",
		FixedVersion:     "3.0.14",
	}

	// Deterministic: same inputs produce same key
	k1 := f.Key("explain", "llama3")
	k2 := f.Key("explain", "llama3")
	if k1 != k2 {
		t.Errorf("Key is not deterministic: %q != %q", k1, k2)
	}

	// Different agent produces different key
	k3 := f.Key("fix", "llama3")
	if k1 == k3 {
		t.Errorf("Different agent should produce different key")
	}

	// Different model produces different key
	k4 := f.Key("explain", "mistral")
	if k1 == k4 {
		t.Errorf("Different model should produce different key")
	}

	// Key is a hex string (sha256 = 64 hex chars)
	if len(k1) != 64 {
		t.Errorf("Key length = %d, want 64", len(k1))
	}
}

// TestUsageTotal verifies Total() sums prompt and completion tokens correctly.
func TestUsageTotal(t *testing.T) {
	tests := []struct {
		prompt     int
		completion int
		want       int
	}{
		{100, 200, 300},
		{0, 0, 0},
		{1500, 500, 2000},
	}
	for _, tc := range tests {
		u := types.Usage{PromptTokens: tc.prompt, CompletionTokens: tc.completion}
		if got := u.Total(); got != tc.want {
			t.Errorf("Usage{%d, %d}.Total() = %d, want %d", tc.prompt, tc.completion, got, tc.want)
		}
	}
}

// TestScanResultSummary verifies Summary() returns a string with correct counts.
func TestScanResultSummary(t *testing.T) {
	r := types.ScanResult{
		Findings: []types.Finding{
			{Severity: types.SeverityCritical},
			{Severity: types.SeverityCritical},
			{Severity: types.SeverityHigh},
			{Severity: types.SeverityMedium},
		},
		TotalFound:    6,
		TotalFiltered: 2,
		CacheHits:     1,
		Usage:         types.Usage{PromptTokens: 800, CompletionTokens: 200},
	}

	summary := r.Summary()

	checks := []string{"2 CRITICAL", "1 HIGH", "1 MEDIUM", "2 filtered", "1 cached", "1000 tokens"}
	for _, check := range checks {
		if !strings.Contains(summary, check) {
			t.Errorf("Summary() missing %q, got: %s", check, summary)
		}
	}
}
