// Package config handles all configuration loading for trivy-ai.
// Precedence order: CLI flag > environment variable > config.yaml > default value.
package config

import (
	"fmt"

	"github.com/jp2op/trivy-ai/pkg/types"
)

// Config holds all runtime configuration for a trivy-ai scan.
type Config struct {
	// Image is the container image to scan (e.g. nginx:latest).
	Image string
	// TargetType is the kind of artifact to scan (image, fs, k8s, iac).
	TargetType string
	// Provider is the LLM backend to use (mock, ollama, anthropic, openai).
	Provider string
	// Model is the LLM model name (e.g. llama3, claude-sonnet-4-6).
	Model string
	// OllamaBaseURL is the Ollama API URL (default: http://localhost:11434).
	OllamaBaseURL string
	// Severity is the minimum severity threshold (LOW, MEDIUM, HIGH, CRITICAL).
	Severity string
	// Output is the output format (terminal, json, sarif, html).
	Output string
	// MaxParallel is the maximum number of concurrent LLM calls.
	MaxParallel int
	// MinSeverity is the parsed Severity value from the Severity string.
	MinSeverity types.Severity
}

// DefaultConfig returns a Config populated with sensible defaults.
func DefaultConfig() Config {
	return Config{
		Provider:      "mock",
		Model:         "llama3",
		OllamaBaseURL: "http://localhost:11434",
		Severity:      "HIGH",
		Output:        "terminal",
		MaxParallel:   5,
		MinSeverity:   types.SeverityHigh,
		TargetType:    "image",
	}
}

// Validate checks that the config values are valid and returns an error if not.
// It also parses string fields into their typed equivalents (e.g. Severity string → MinSeverity).
func (c *Config) Validate() error {
	// Parse and validate severity
	sev, err := types.SeverityFromString(c.Severity)
	if err != nil {
		return fmt.Errorf("invalid --severity: %w", err)
	}
	c.MinSeverity = sev

	// Validate provider
	validProviders := map[string]bool{
		"mock": true, "ollama": true, "anthropic": true, "openai": true, "gemini": true,
	}
	if !validProviders[c.Provider] {
		return fmt.Errorf("unknown --provider %q: available providers are: mock, ollama, anthropic, openai, gemini", c.Provider)
	}

	// Validate output format
	validOutputs := map[string]bool{
		"terminal": true, "json": true, "sarif": true, "html": true,
	}
	if !validOutputs[c.Output] {
		return fmt.Errorf("unknown --output %q: available formats are: terminal, json, sarif, html", c.Output)
	}

	// Image is required for image target type
	if c.TargetType == "image" && c.Image == "" {
		return fmt.Errorf("--image is required when scanning a container image\n  example: trivy-ai scan --image nginx:latest")
	}

	return nil
}
