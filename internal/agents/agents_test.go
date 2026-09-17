 package agents_test

import (
	"context"
	"fmt"
	"strings"
	"testing"

	"github.com/jp2op/trivy-ai/internal"
	"github.com/jp2op/trivy-ai/internal/agents"
	"github.com/jp2op/trivy-ai/internal/provider"
	"github.com/jp2op/trivy-ai/pkg/types"
)

func testFinding() types.Finding {
	return types.Finding{
		ID:               "CVE-2024-6119",
		Severity:         types.SeverityCritical,
		CVSS:             9.1,
		Package:          "openssl",
		InstalledVersion: "3.0.13",
		FixedVersion:     "3.0.14",
		Description:      "Possible denial of service in X.509 name checks.",
	}
}

func TestExplainAgent_Name(t *testing.T) {
	a := &agents.ExplainAgent{}
	if a.Name() != "explain" {
		t.Errorf("Name() = %q, want %q", a.Name(), "explain")
	}
}

func TestExplainAgent_Run(t *testing.T) {
	a := &agents.ExplainAgent{}
	p := &provider.MockProvider{}
	f := testFinding()

	result, err := a.Run(context.Background(), f, p)
	if err != nil {
		t.Fatalf("Run() unexpected error: %v", err)
	}
	if result.Content == "" {
		t.Error("Run() returned empty Content")
	}
	if result.FindingID != f.ID {
		t.Errorf("FindingID = %q, want %q", result.FindingID, f.ID)
	}
	if result.AgentName != "explain" {
		t.Errorf("AgentName = %q, want %q", result.AgentName, "explain")
	}
	if result.Usage.Total() == 0 {
		t.Error("Run() returned zero token usage")
	}
}

func TestExplainAgent_PromptContainsCVEID(t *testing.T) {
	// Use a capturing provider to inspect the prompt.
	capture := &capturingProvider{}
	a := &agents.ExplainAgent{}
	f := testFinding()

	_, _ = a.Run(context.Background(), f, capture)

	if !strings.Contains(capture.lastPrompt, "CVE-2024-6119") {
		t.Errorf("Prompt does not contain CVE ID. Prompt: %s", capture.lastPrompt)
	}
}

func TestExplainAgent_PromptContainsSeverity(t *testing.T) {
	capture := &capturingProvider{}
	a := &agents.ExplainAgent{}
	_, _ = a.Run(context.Background(), testFinding(), capture)

	if !strings.Contains(capture.lastPrompt, "CRITICAL") {
		t.Errorf("Prompt does not contain severity. Prompt: %s", capture.lastPrompt)
	}
}

func TestExplainAgent_PromptContainsPackage(t *testing.T) {
	capture := &capturingProvider{}
	a := &agents.ExplainAgent{}
	_, _ = a.Run(context.Background(), testFinding(), capture)

	if !strings.Contains(capture.lastPrompt, "openssl") {
		t.Errorf("Prompt does not contain package name. Prompt: %s", capture.lastPrompt)
	}
}

func TestExplainAgent_PromptHasXMLDelimiters(t *testing.T) {
	capture := &capturingProvider{}
	a := &agents.ExplainAgent{}
	_, _ = a.Run(context.Background(), testFinding(), capture)

	if !strings.Contains(capture.lastPrompt, "<untrusted_data>") {
		t.Errorf("Prompt missing <untrusted_data> wrapper. Prompt: %s", capture.lastPrompt)
	}
	if !strings.Contains(capture.lastPrompt, "</untrusted_data>") {
		t.Errorf("Prompt missing </untrusted_data> closing tag. Prompt: %s", capture.lastPrompt)
	}
}

func TestExplainAgent_ProviderError(t *testing.T) {
	a := &agents.ExplainAgent{}
	p := &errorProvider{}
	f := testFinding()

	_, err := a.Run(context.Background(), f, p)
	if err == nil {
		t.Fatal("Run() expected error when provider fails, got nil")
	}
	if !strings.Contains(err.Error(), "CVE-2024-6119") {
		t.Errorf("Error should include CVE ID for debugging: %v", err)
	}
}

func TestExplainAgent_Interface(t *testing.T) {
	var _ internal.Agent = (*agents.ExplainAgent)(nil)
}

// --- Test helpers ---

// capturingProvider records the prompt sent to Complete for inspection.
type capturingProvider struct {
	lastPrompt string
}

func (c *capturingProvider) Name() string   { return "capture" }
func (c *capturingProvider) Model() string  { return "capture-model" }
func (c *capturingProvider) MaxTokens() int { return 8192 }
func (c *capturingProvider) Complete(_ context.Context, msgs []internal.Message) (string, types.Usage, error) {
	for _, m := range msgs {
		c.lastPrompt += m.Content
	}
	return "mock explanation", types.Usage{PromptTokens: 100, CompletionTokens: 50}, nil
}

// errorProvider always returns an error from Complete.
type errorProvider struct{}

func (e *errorProvider) Name() string   { return "error" }
func (e *errorProvider) Model() string  { return "error-model" }
func (e *errorProvider) MaxTokens() int { return 8192 }
func (e *errorProvider) Complete(_ context.Context, _ []internal.Message) (string, types.Usage, error) {
	return "", types.Usage{}, fmt.Errorf("provider unavailable")
}
