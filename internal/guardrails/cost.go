package guardrails

import (
	"context"
	"fmt"

	"github.com/jp2op/trivy-ai/pkg/types"
)

const (
	avgTokensPerFinding = 2000
	costPer1KTokensUSD  = 0.003
)

// CostEstimate holds projected cost for a scan run.
type CostEstimate struct {
	FindingCount     int
	EstimatedTokens  int
	EstimatedCostUSD float64
}

func (c CostEstimate) String() string {
	return fmt.Sprintf("%d findings × ~%d tokens = ~%d tokens ≈ $%.4f",
		c.FindingCount, avgTokensPerFinding, c.EstimatedTokens, c.EstimatedCostUSD)
}

// EstimateCost calculates projected cost for a set of findings.
func EstimateCost(findings []types.Finding) CostEstimate {
	count := len(findings)
	tokens := count * avgTokensPerFinding
	return CostEstimate{
		FindingCount:     count,
		EstimatedTokens:  tokens,
		EstimatedCostUSD: float64(tokens) / 1000.0 * costPer1KTokensUSD,
	}
}

// NoFixFilter drops findings with no available fix when in fix mode.
type NoFixFilter struct {
	FixModeOnly bool
}

func (n *NoFixFilter) Name() string { return "no-fix-filter" }

func (n *NoFixFilter) Filter(_ context.Context, findings []types.Finding) []types.Finding {
	if !n.FixModeOnly {
		return findings
	}
	result := make([]types.Finding, 0, len(findings))
	for _, f := range findings {
		if f.IsFixable() {
			result = append(result, f)
		}
	}
	return result
}