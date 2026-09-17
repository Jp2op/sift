package guardrails_test

import (
	"context"
	"testing"

	"github.com/jp2op/trivy-ai/internal"
	"github.com/jp2op/trivy-ai/internal/guardrails"
	"github.com/jp2op/trivy-ai/pkg/types"
)

func findings(severities ...types.Severity) []types.Finding {
	out := make([]types.Finding, len(severities))
	for i, s := range severities {
		out[i] = types.Finding{ID: "CVE-TEST", Severity: s}
	}
	return out
}

func TestSeverityFilter_KeepsAboveThreshold(t *testing.T) {
	f := &guardrails.SeverityFilter{MinSeverity: types.SeverityHigh}
	input := findings(types.SeverityCritical, types.SeverityHigh, types.SeverityMedium, types.SeverityLow)

	got := f.Filter(context.Background(), input)
	if len(got) != 2 {
		t.Errorf("Filter() returned %d findings, want 2 (CRITICAL + HIGH)", len(got))
	}
	for _, finding := range got {
		if finding.Severity < types.SeverityHigh {
			t.Errorf("Filter() let through severity %s, want >= HIGH", finding.Severity)
		}
	}
}

func TestSeverityFilter_CriticalOnly(t *testing.T) {
	f := &guardrails.SeverityFilter{MinSeverity: types.SeverityCritical}
	input := findings(types.SeverityCritical, types.SeverityHigh, types.SeverityMedium)

	got := f.Filter(context.Background(), input)
	if len(got) != 1 {
		t.Errorf("Filter() returned %d findings, want 1 (CRITICAL only)", len(got))
	}
}

func TestSeverityFilter_AllPass(t *testing.T) {
	f := &guardrails.SeverityFilter{MinSeverity: types.SeverityLow}
	input := findings(types.SeverityCritical, types.SeverityHigh, types.SeverityMedium, types.SeverityLow)

	got := f.Filter(context.Background(), input)
	if len(got) != 4 {
		t.Errorf("Filter() returned %d findings, want 4 (all pass)", len(got))
	}
}

func TestSeverityFilter_EmptyInput(t *testing.T) {
	f := &guardrails.SeverityFilter{MinSeverity: types.SeverityHigh}
	got := f.Filter(context.Background(), []types.Finding{})
	if got == nil {
		t.Error("Filter() returned nil, want empty slice")
	}
	if len(got) != 0 {
		t.Errorf("Filter() returned %d findings, want 0", len(got))
	}
}

func TestPipeline_ChainsGuardrails(t *testing.T) {
	// Two filters: first keeps >= MEDIUM, second keeps >= HIGH.
	// Final result should be only HIGH and CRITICAL.
	f1 := &guardrails.SeverityFilter{MinSeverity: types.SeverityMedium}
	f2 := &guardrails.SeverityFilter{MinSeverity: types.SeverityHigh}
	p := guardrails.NewPipeline(f1, f2)

	input := findings(types.SeverityCritical, types.SeverityHigh, types.SeverityMedium, types.SeverityLow)
	got := p.Filter(context.Background(), input)
	if len(got) != 2 {
		t.Errorf("Pipeline.Filter() returned %d findings, want 2", len(got))
	}
}

func TestPipeline_EmptyPipeline(t *testing.T) {
	p := guardrails.NewPipeline() // zero guardrails = passthrough
	input := findings(types.SeverityCritical, types.SeverityHigh)
	got := p.Filter(context.Background(), input)
	if len(got) != 2 {
		t.Errorf("Empty pipeline should be passthrough, got %d findings", len(got))
	}
}

func TestSeverityFilter_Interface(t *testing.T) {
	var _ internal.Guardrail = (*guardrails.SeverityFilter)(nil)
}
