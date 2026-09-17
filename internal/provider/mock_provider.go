// Package provider contains LLM provider implementations for trivy-ai.
package provider

import (
	"context"
	"fmt"

	"github.com/jp2op/trivy-ai/internal"
	"github.com/jp2op/trivy-ai/pkg/types"
)

// MockProvider returns canned LLM responses without making any network calls.
// It is used in unit tests and when --provider mock is set, so contributors
// can run the full pipeline without an API key.
type MockProvider struct {
	// ModelName is the reported model name (default: "mock-model").
	ModelName string
}

// Compile-time check: MockProvider must satisfy the Provider interface.
var _ internal.Provider = (*MockProvider)(nil)

// Name returns "mock".
func (m *MockProvider) Name() string { return "mock" }

// Model returns the mock model name.
func (m *MockProvider) Model() string {
	if m.ModelName == "" {
		return "mock-model"
	}
	return m.ModelName
}

// MaxTokens returns a sensible default context window for the mock provider.
func (m *MockProvider) MaxTokens() int { return 8192 }

// Complete returns a canned explanation based on the CVE ID found in the messages.
// For unknown CVEs it returns a generic but realistic response.
func (m *MockProvider) Complete(_ context.Context, msgs []internal.Message) (string, types.Usage, error) {
	// Extract the CVE ID from the last user message if present
	cveID := extractCVEID(msgs)

	usage := types.Usage{
		PromptTokens:     estimateTokens(msgs),
		CompletionTokens: 150,
	}

	return fmt.Sprintf(
		"[MOCK RESPONSE for %s]\n\n"+
			"This vulnerability affects the package in the scanned image. "+
			"An attacker who can supply crafted input may trigger the vulnerable code path. "+
			"The impact depends on how the package is used in your specific environment.\n\n"+
			"Risk assessment: Evaluate whether this package is reachable from untrusted input. "+
			"If it is, prioritise patching. The fixed version resolves the root cause.\n\n"+
			"Note: This is a mock response for testing. Use --provider ollama for real analysis.",
		cveID,
	), usage, nil
}

// extractCVEID searches messages for a CVE ID pattern (CVE-YYYY-NNNNN).
func extractCVEID(msgs []internal.Message) string {
	for i := len(msgs) - 1; i >= 0; i-- {
		content := msgs[i].Content
		// Simple scan for CVE- prefix
		if idx := findCVEIndex(content); idx >= 0 {
			end := idx + 4 // "CVE-"
			for end < len(content) && (content[end] == '-' || isDigit(content[end])) {
				end++
			}
			return content[idx:end]
		}
	}
	return "UNKNOWN-CVE"
}

func findCVEIndex(s string) int {
	for i := 0; i < len(s)-4; i++ {
		if s[i:i+4] == "CVE-" {
			return i
		}
	}
	return -1
}

func isDigit(b byte) bool { return b >= '0' && b <= '9' }

// estimateTokens provides a rough token estimate (1 token ≈ 4 chars).
func estimateTokens(msgs []internal.Message) int {
	total := 0
	for _, m := range msgs {
		total += len(m.Content) / 4
	}
	return total
}
