// Package internal defines the core interfaces for trivy-ai.
// All components depend on these abstractions, never on concrete implementations.
package internal

import (
	"context"
	"io"

	"github.com/jp2op/trivy-ai/pkg/types"
)

// Scanner scans a target for vulnerabilities and returns structured findings.
type Scanner interface {
	// Scan runs a vulnerability scan against the given target.
	// It returns a slice of findings or an error if the scan could not complete.
	Scan(ctx context.Context, target types.Target) ([]types.Finding, error)
}

// Message represents a single message in an LLM conversation.
type Message struct {
	// Role is either "user" or "assistant".
	Role string
	// Content is the text content of the message.
	Content string
}

// Provider abstracts any LLM backend (Anthropic, OpenAI, Ollama, etc.).
type Provider interface {
	// Name returns a human-readable identifier for this provider (e.g. "ollama", "anthropic").
	Name() string
	// Model returns the active model name (e.g. "llama3", "claude-sonnet-4-6").
	Model() string
	// Complete sends a list of messages to the LLM and returns the full response.
	Complete(ctx context.Context, msgs []Message) (string, types.Usage, error)
	// MaxTokens returns the context window size of the active model.
	MaxTokens() int
}

// Agent processes a single CVE finding and returns a result.
// Different agents perform different tasks: explaining, fixing, auto-fixing.
type Agent interface {
	// Name returns a human-readable identifier for this agent.
	Name() string
	// Run processes a single finding using the given provider.
	// ctx should carry a timeout appropriate for one LLM call.
	Run(ctx context.Context, f types.Finding, provider Provider) (types.AgentResult, error)
}

// Guardrail filters a slice of findings before they reach the AI pipeline.
// Guardrails are chained in a pipeline; each one receives the output of the previous.
type Guardrail interface {
	// Name returns a human-readable identifier for this guardrail.
	Name() string
	// Filter applies the guardrail logic and returns the filtered findings.
	// Implementations must never return nil — return an empty slice instead.
	Filter(ctx context.Context, findings []types.Finding) []types.Finding
}

// Reporter formats and writes scan results to an output destination.
type Reporter interface {
	// Name returns a human-readable identifier for this reporter (e.g. "terminal", "json").
	Name() string
	// Report writes the scan result to the given writer.
	Report(ctx context.Context, result types.ScanResult, w io.Writer) error
}
