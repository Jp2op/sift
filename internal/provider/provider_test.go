package provider_test

import (
	"context"
	"strings"
	"testing"

	"github.com/jp2op/trivy-ai/internal"
	"github.com/jp2op/trivy-ai/internal/provider"
)

// --- MockProvider tests ---

func TestMockProvider_Name(t *testing.T) {
	p := &provider.MockProvider{}
	if p.Name() != "mock" {
		t.Errorf("Name() = %q, want %q", p.Name(), "mock")
	}
}

func TestMockProvider_Model_Default(t *testing.T) {
	p := &provider.MockProvider{}
	if p.Model() == "" {
		t.Error("Model() must not be empty")
	}
}

func TestMockProvider_Complete_ReturnsContent(t *testing.T) {
	p := &provider.MockProvider{}
	msgs := []internal.Message{
		{Role: "system", Content: "You are a security expert."},
		{Role: "user", Content: "Explain CVE-2024-6119 in openssl."},
	}

	content, usage, err := p.Complete(context.Background(), msgs)
	if err != nil {
		t.Fatalf("Complete() unexpected error: %v", err)
	}
	if content == "" {
		t.Error("Complete() returned empty content")
	}
	if usage.Total() == 0 {
		t.Error("Complete() returned zero token usage")
	}
}

func TestMockProvider_Complete_ContainsCVEID(t *testing.T) {
	p := &provider.MockProvider{}
	msgs := []internal.Message{
		{Role: "user", Content: "Explain CVE-2024-5535 vulnerability."},
	}

	content, _, err := p.Complete(context.Background(), msgs)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.Contains(content, "CVE-2024-5535") {
		t.Errorf("Expected response to contain CVE ID, got: %s", content)
	}
}

func TestMockProvider_Complete_UnknownCVE(t *testing.T) {
	p := &provider.MockProvider{}
	msgs := []internal.Message{
		{Role: "user", Content: "Generic security question with no CVE ID."},
	}

	content, _, err := p.Complete(context.Background(), msgs)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if content == "" {
		t.Error("Complete() should return a generic response for unknown CVEs")
	}
}

func TestMockProvider_Interface(t *testing.T) {
	// Compile-time interface check — if this compiles, the test passes.
	var _ internal.Provider = (*provider.MockProvider)(nil)
}

func TestMockProvider_MaxTokens(t *testing.T) {
	p := &provider.MockProvider{}
	if p.MaxTokens() <= 0 {
		t.Error("MaxTokens() must return a positive value")
	}
}

// --- OllamaProvider unit tests (no network calls) ---

func TestOllamaProvider_Name(t *testing.T) {
	p := provider.NewOllamaProvider("", "")
	if p.Name() != "ollama" {
		t.Errorf("Name() = %q, want %q", p.Name(), "ollama")
	}
}

func TestOllamaProvider_Model_Default(t *testing.T) {
	p := provider.NewOllamaProvider("", "")
	if p.Model() == "" {
		t.Error("Model() must not be empty with default settings")
	}
}

func TestOllamaProvider_Interface(t *testing.T) {
	var _ internal.Provider = (*provider.OllamaProvider)(nil)
}

func TestOllamaProvider_ConnectionRefused(t *testing.T) {
	// Point at a port that should be closed to test error messaging.
	p := provider.NewOllamaProvider("http://localhost:19999", "llama3")
	msgs := []internal.Message{{Role: "user", Content: "test"}}

	_, _, err := p.Complete(context.Background(), msgs)
	if err == nil {
		t.Fatal("Expected error when Ollama is not running, got nil")
	}
	// The error message should be actionable — tell the user how to fix it.
	errStr := err.Error()
	if !strings.Contains(errStr, "ollama") {
		t.Errorf("Error should mention 'ollama', got: %s", errStr)
	}
}

func TestOllamaProvider_Timeout(t *testing.T) {
	p := provider.NewOllamaProvider("http://localhost:19999", "llama3")
	msgs := []internal.Message{{Role: "user", Content: "test"}}

	// A cancelled context should return immediately with an error.
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // cancel immediately

	_, _, err := p.Complete(ctx, msgs)
	if err == nil {
		t.Fatal("Expected error with cancelled context, got nil")
	}
}
