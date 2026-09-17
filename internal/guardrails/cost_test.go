package guardrails_test

import (
	"context"
	"strings"
	"testing"

	"github.com/jp2op/trivy-ai/internal/guardrails"
	"github.com/jp2op/trivy-ai/pkg/types"
)

func TestEstimateCost_Basic(t *testing.T) {
	est := guardrails.EstimateCost([]types.Finding{{}, {}, {}})
	if est.FindingCount != 3 { t.Errorf("FindingCount = %d, want 3", est.FindingCount) }
	if est.EstimatedTokens <= 0 { t.Error("EstimatedTokens should be > 0") }
	if est.EstimatedCostUSD <= 0 { t.Error("EstimatedCostUSD should be > 0") }
}

func TestEstimateCost_Empty(t *testing.T) {
	est := guardrails.EstimateCost([]types.Finding{})
	if est.FindingCount != 0 || est.EstimatedTokens != 0 || est.EstimatedCostUSD != 0 {
		t.Error("Empty input should return zero values")
	}
}

func TestCostEstimate_String(t *testing.T) {
	est := guardrails.EstimateCost([]types.Finding{{}, {}})
	s := est.String()
	if !strings.Contains(s, "2 findings") { t.Errorf("String() missing count: %s", s) }
	if !strings.Contains(s, "$") { t.Errorf("String() missing cost: %s", s) }
}

func TestNoFixFilter_DropUnfixable(t *testing.T) {
	f := &guardrails.NoFixFilter{FixModeOnly: true}
	input := []types.Finding{
		{ID: "CVE-1", FixedVersion: "1.0"},
		{ID: "CVE-2", FixedVersion: ""},
		{ID: "CVE-3", FixedVersion: "2.0"},
	}
	got := f.Filter(context.Background(), input)
	if len(got) != 2 { t.Errorf("Filter() = %d findings, want 2", len(got)) }
}

func TestNoFixFilter_PassAll_WhenNotFixMode(t *testing.T) {
	f := &guardrails.NoFixFilter{FixModeOnly: false}
	input := []types.Finding{{FixedVersion: "1.0"}, {FixedVersion: ""}}
	got := f.Filter(context.Background(), input)
	if len(got) != 2 { t.Errorf("Filter() = %d, want 2 when FixModeOnly=false", len(got)) }
}