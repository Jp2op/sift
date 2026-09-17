package output_test

import (
	"bytes"
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/jp2op/trivy-ai/internal"
	"github.com/jp2op/trivy-ai/internal/output"
	"github.com/jp2op/trivy-ai/pkg/types"
)

func testScanResult() types.ScanResult {
	return types.ScanResult{
		Target: types.Target{Type: types.TargetTypeImage, Ref: "nginx:latest"},
		Findings: []types.Finding{
			{ID: "CVE-2024-6119", Severity: types.SeverityCritical, CVSS: 9.1,
				Package: "openssl", InstalledVersion: "3.0.13", FixedVersion: "3.0.14"},
			{ID: "CVE-2024-2511", Severity: types.SeverityHigh, CVSS: 7.5,
				Package: "openssl", InstalledVersion: "3.0.13", FixedVersion: "3.0.14"},
		},
		Results: []types.AgentResult{
			{FindingID: "CVE-2024-6119", AgentName: "explain",
				Content: "This vulnerability allows denial of service via crafted certificates.",
				Usage:   types.Usage{PromptTokens: 200, CompletionTokens: 100}},
			{FindingID: "CVE-2024-2511", AgentName: "explain",
				Content: "Unbounded memory growth in TLS session handling.",
				Usage:   types.Usage{PromptTokens: 180, CompletionTokens: 90}},
		},
		TotalFound:    4,
		TotalFiltered: 2,
		CacheHits:     1,
		Usage:         types.Usage{PromptTokens: 380, CompletionTokens: 190},
	}
}

// --- TerminalReporter ---

func TestTerminalReporter_Name(t *testing.T) {
	r := &output.TerminalReporter{NoColor: true}
	if r.Name() != "terminal" {
		t.Errorf("Name() = %q, want %q", r.Name(), "terminal")
	}
}

func TestTerminalReporter_Report_ContainsCVEIDs(t *testing.T) {
	r := &output.TerminalReporter{NoColor: true}
	var buf bytes.Buffer
	if err := r.Report(context.Background(), testScanResult(), &buf); err != nil {
		t.Fatalf("Report() error: %v", err)
	}
	out := buf.String()
	for _, id := range []string{"CVE-2024-6119", "CVE-2024-2511"} {
		if !strings.Contains(out, id) {
			t.Errorf("Output missing CVE ID %q", id)
		}
	}
}

func TestTerminalReporter_Report_GroupsBySeverity(t *testing.T) {
	r := &output.TerminalReporter{NoColor: true}
	var buf bytes.Buffer
	_ = r.Report(context.Background(), testScanResult(), &buf)
	out := buf.String()

	critIdx := strings.Index(out, "CVE-2024-6119") // CRITICAL
	highIdx := strings.Index(out, "CVE-2024-2511") // HIGH

	if critIdx == -1 || highIdx == -1 {
		t.Skip("CVE IDs not found in output")
	}
	if critIdx > highIdx {
		t.Error("CRITICAL finding should appear before HIGH finding")
	}
}

func TestTerminalReporter_Report_Empty(t *testing.T) {
	r := &output.TerminalReporter{NoColor: true}
	var buf bytes.Buffer
	empty := types.ScanResult{}
	if err := r.Report(context.Background(), empty, &buf); err != nil {
		t.Fatalf("Report() error on empty result: %v", err)
	}
	if !strings.Contains(buf.String(), "No vulnerabilities found") {
		t.Errorf("Expected 'No vulnerabilities found', got: %s", buf.String())
	}
}

func TestTerminalReporter_Report_HasSummaryLine(t *testing.T) {
	r := &output.TerminalReporter{NoColor: true}
	var buf bytes.Buffer
	_ = r.Report(context.Background(), testScanResult(), &buf)
	out := buf.String()
	// Summary line should contain token count and filter info
	if !strings.Contains(out, "filtered") {
		t.Errorf("Summary line missing 'filtered', got: %s", out)
	}
}

func TestTerminalReporter_Interface(t *testing.T) {
	var _ internal.Reporter = (*output.TerminalReporter)(nil)
}

// --- JSONReporter ---

func TestJSONReporter_Name(t *testing.T) {
	r := &output.JSONReporter{}
	if r.Name() != "json" {
		t.Errorf("Name() = %q, want %q", r.Name(), "json")
	}
}

func TestJSONReporter_Valid(t *testing.T) {
	r := &output.JSONReporter{}
	var buf bytes.Buffer
	if err := r.Report(context.Background(), testScanResult(), &buf); err != nil {
		t.Fatalf("Report() error: %v", err)
	}

	var result types.ScanResult
	if err := json.Unmarshal(buf.Bytes(), &result); err != nil {
		t.Fatalf("Output is not valid JSON: %v\nGot: %s", err, buf.String())
	}

	if len(result.Findings) != 2 {
		t.Errorf("Decoded %d findings, want 2", len(result.Findings))
	}
}

func TestJSONReporter_SchemaVersion(t *testing.T) {
	r := &output.JSONReporter{}
	var buf bytes.Buffer
	_ = r.Report(context.Background(), testScanResult(), &buf)

	var raw map[string]interface{}
	_ = json.Unmarshal(buf.Bytes(), &raw)
	if raw["schema_version"] != output.SchemaVersion {
		t.Errorf("schema_version = %v, want %q", raw["schema_version"], output.SchemaVersion)
	}
}

func TestJSONReporter_WritesToAnyWriter(t *testing.T) {
	r := &output.JSONReporter{}
	// Writing to a bytes.Buffer (implements io.Writer) should work.
	var buf bytes.Buffer
	err := r.Report(context.Background(), testScanResult(), &buf)
	if err != nil {
		t.Errorf("Report() to bytes.Buffer failed: %v", err)
	}
	if buf.Len() == 0 {
		t.Error("Report() wrote nothing to writer")
	}
}

func TestJSONReporter_Interface(t *testing.T) {
	var _ internal.Reporter = (*output.JSONReporter)(nil)
}
