package provider_test

import (
	"testing"

	"github.com/jp2op/trivy-ai/internal"
	"github.com/jp2op/trivy-ai/internal/provider"
)

func TestAnthropicProvider_Interface(t *testing.T) {
	var _ internal.Provider = (*provider.AnthropicProvider)(nil)
}

func TestAnthropicProvider_NoKeyError(t *testing.T) {
	t.Setenv("TRIVY_AI_ANTHROPIC_KEY", "")
	_, err := provider.NewAnthropicProvider("")
	if err == nil { t.Fatal("Expected error when key missing") }
	if !contains(err.Error(), "TRIVY_AI_ANTHROPIC_KEY") {
		t.Errorf("Error should mention env var: %s", err)
	}
}

func TestAnthropicProvider_DefaultModel(t *testing.T) {
	t.Setenv("TRIVY_AI_ANTHROPIC_KEY", "sk-ant-test")
	p, err := provider.NewAnthropicProvider("")
	if err != nil { t.Fatalf("unexpected error: %v", err) }
	if p.Model() == "" { t.Error("Model() should not be empty") }
	if p.Name() != "anthropic" { t.Errorf("Name() = %q, want anthropic", p.Name()) }
}

func TestAnthropicProvider_MaxTokens(t *testing.T) {
	t.Setenv("TRIVY_AI_ANTHROPIC_KEY", "sk-ant-test")
	p, _ := provider.NewAnthropicProvider("")
	if p.MaxTokens() <= 0 { t.Error("MaxTokens() must be positive") }
}

func TestOpenAIProvider_Interface(t *testing.T) {
	var _ internal.Provider = (*provider.OpenAIProvider)(nil)
}

func TestOpenAIProvider_NoKeyError(t *testing.T) {
	t.Setenv("TRIVY_AI_OPENAI_KEY", "")
	_, err := provider.NewOpenAIProvider("")
	if err == nil { t.Fatal("Expected error when key missing") }
	if !contains(err.Error(), "TRIVY_AI_OPENAI_KEY") {
		t.Errorf("Error should mention env var: %s", err)
	}
}

func TestOpenAIProvider_DefaultModel(t *testing.T) {
	t.Setenv("TRIVY_AI_OPENAI_KEY", "sk-test")
	p, err := provider.NewOpenAIProvider("")
	if err != nil { t.Fatalf("unexpected error: %v", err) }
	if p.Model() == "" { t.Error("Model() should not be empty") }
	if p.Name() != "openai" { t.Errorf("Name() = %q, want openai", p.Name()) }
}

func contains(s, sub string) bool {
	for i := 0; i <= len(s)-len(sub); i++ {
		if s[i:i+len(sub)] == sub { return true }
	}
	return false
}

func TestGeminiProvider_Interface(t *testing.T) {
	var _ internal.Provider = (*provider.GeminiProvider)(nil)
}

func TestGeminiProvider_NoProjectError(t *testing.T) {
	t.Setenv("TRIVY_AI_GCP_PROJECT", "")
	_, err := provider.NewGeminiProvider("", "", "")
	if err == nil { t.Fatal("Expected error when project ID missing") }
}

func TestGeminiProvider_DefaultModel(t *testing.T) {
	p, err := provider.NewGeminiProvider("my-project", "", "")
	if err != nil { t.Fatalf("unexpected error: %v", err) }
	if p.Model() == "" { t.Error("Model() should not be empty") }
	if p.Name() != "gemini" { t.Errorf("Name() = %q, want gemini", p.Name()) }
}