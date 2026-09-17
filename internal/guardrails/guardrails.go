// Package guardrails provides filtering logic that runs before the AI pipeline.
// Guardrails reduce noise and cost by removing findings that don't need LLM processing.
package guardrails

import (
	"context"

	"github.com/jp2op/trivy-ai/internal"
	"github.com/jp2op/trivy-ai/pkg/types"
)

// SeverityFilter drops findings below a configured severity threshold.
// For example, with threshold HIGH, only CRITICAL and HIGH findings pass through.
type SeverityFilter struct {
	// MinSeverity is the minimum severity that will pass through the filter.
	MinSeverity types.Severity
}

// Compile-time check: SeverityFilter must satisfy the Guardrail interface.
var _ internal.Guardrail = (*SeverityFilter)(nil)

// Name returns "severity-filter".
func (s *SeverityFilter) Name() string { return "severity-filter" }

// Filter returns only findings at or above the configured minimum severity.
// It always returns a non-nil slice.
func (s *SeverityFilter) Filter(_ context.Context, findings []types.Finding) []types.Finding {
	result := make([]types.Finding, 0, len(findings))
	for _, f := range findings {
		if f.Severity >= s.MinSeverity {
			result = append(result, f)
		}
	}
	return result
}

// Pipeline chains multiple Guardrails in sequence.
// Each guardrail receives the output of the previous one.
// An empty pipeline is a no-op — all findings pass through.
type Pipeline struct {
	guardrails []internal.Guardrail
}

// NewPipeline creates a new Pipeline with the given guardrails in order.
func NewPipeline(guards ...internal.Guardrail) *Pipeline {
	return &Pipeline{guardrails: guards}
}

// Filter applies each guardrail in sequence and returns the final filtered findings.
// Always returns a non-nil slice.
func (p *Pipeline) Filter(ctx context.Context, findings []types.Finding) []types.Finding {
	current := findings
	for _, g := range p.guardrails {
		current = g.Filter(ctx, current)
	}
	if current == nil {
		return []types.Finding{}
	}
	return current
}
