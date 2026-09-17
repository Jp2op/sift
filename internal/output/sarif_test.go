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

func sarifResult() types.ScanResult {
	return types.ScanResult{
		Target: types.Target{Type: types.TargetTypeImage, Ref: "nginx:latest"},
		Findings: []types.Finding{
			{ID: "CVE-2024-6119", Severity: types.SeverityCritical, CVSS: 9.1, Description: "DoS via X.509."},
			{ID: "CVE-2024-2511", Severity: types.SeverityHigh, CVSS: 7.5, Description: "Memory growth."},
		},
		Results: []types.AgentResult{
			{FindingID: "CVE-2024-6119", Content: "AI explanation for CVE-2024-6119"},
		},
	}
}

func TestSARIFReporter_Name(t *testing.T) {
	if (&output.SARIFReporter{}).Name() != "sarif" { t.Error("Name() should return 'sarif'") }
}

func TestSARIFReporter_ValidJSON(t *testing.T) {
	var buf bytes.Buffer
	if err := (&output.SARIFReporter{}).Report(context.Background(), sarifResult(), &buf); err != nil {
		t.Fatalf("Report() error: %v", err)
	}
	var raw map[string]interface{}
	if err := json.Unmarshal(buf.Bytes(), &raw); err != nil {
		t.Fatalf("Output is not valid JSON: %v", err)
	}
}

func TestSARIFReporter_SchemaVersion(t *testing.T) {
	var buf bytes.Buffer
	(&output.SARIFReporter{}).Report(context.Background(), sarifResult(), &buf)
	var raw map[string]interface{}
	json.Unmarshal(buf.Bytes(), &raw)
	if raw["version"] != "2.1.0" { t.Errorf("version = %v, want 2.1.0", raw["version"]) }
	if raw["$schema"] == nil { t.Error("missing $schema field") }
}

func TestSARIFReporter_ContainsCVEIDs(t *testing.T) {
	var buf bytes.Buffer
	(&output.SARIFReporter{}).Report(context.Background(), sarifResult(), &buf)
	for _, id := range []string{"CVE-2024-6119", "CVE-2024-2511"} {
		if !strings.Contains(buf.String(), id) { t.Errorf("Missing CVE ID %q", id) }
	}
}

func TestSARIFReporter_HasRuns(t *testing.T) {
	var buf bytes.Buffer
	(&output.SARIFReporter{}).Report(context.Background(), sarifResult(), &buf)
	var raw map[string]interface{}
	json.Unmarshal(buf.Bytes(), &raw)
	runs, ok := raw["runs"].([]interface{})
	if !ok || len(runs) == 0 { t.Error("SARIF output missing 'runs' array") }
}

func TestSARIFReporter_ErrorLevel(t *testing.T) {
	var buf bytes.Buffer
	(&output.SARIFReporter{}).Report(context.Background(), sarifResult(), &buf)
	if !strings.Contains(buf.String(), `"error"`) {
		t.Error("CRITICAL/HIGH findings should map to 'error' level")
	}
}

func TestSARIFReporter_UsesAIExplanation(t *testing.T) {
	var buf bytes.Buffer
	(&output.SARIFReporter{}).Report(context.Background(), sarifResult(), &buf)
	if !strings.Contains(buf.String(), "AI explanation for CVE-2024-6119") {
		t.Error("Should use AI explanation as message text when available")
	}
}

func TestSARIFReporter_Interface(t *testing.T) {
	var _ internal.Reporter = (*output.SARIFReporter)(nil)
}