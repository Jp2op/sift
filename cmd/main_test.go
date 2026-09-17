package main

import (
	"strings"
	"testing"

	"github.com/jp2op/trivy-ai/internal/config"
	"github.com/jp2op/trivy-ai/pkg/types"
)

// TestEndToEnd_MockPipeline runs the full pipeline:
// mock scan → severity filter → ExplainAgent (mock) → JSON output
// ZERO external dependencies — no Docker, no API key, no Ollama.
func TestEndToEnd_MockPipeline(t *testing.T) {
	result, err := RunScanJSON("nginx:latest", "HIGH")
	if err != nil {
		t.Fatalf("End-to-end scan failed: %v", err)
	}

	if len(result.Findings) == 0 {
		t.Error("Expected findings, got zero")
	}
	for _, f := range result.Findings {
		if f.Severity < types.SeverityHigh {
			t.Errorf("Finding %s has severity %s, below HIGH threshold", f.ID, f.Severity)
		}
	}

	if len(result.Results) == 0 {
		t.Error("Expected agent results, got zero")
	}
	for _, r := range result.Results {
		if r.Content == "" {
			t.Errorf("AgentResult for %s has empty Content", r.FindingID)
		}
	}

	if result.SchemaVersion == "" {
		t.Error("ScanResult.SchemaVersion must not be empty")
	}

	if result.TotalFound == 0 {
		t.Error("TotalFound should be > 0")
	}
	if result.TotalFiltered < 0 {
		t.Error("TotalFiltered should not be negative")
	}
}

func TestEndToEnd_CriticalOnly(t *testing.T) {
	result, err := RunScanJSON("nginx:latest", "CRITICAL")
	if err != nil {
		t.Fatalf("Scan with CRITICAL threshold failed: %v", err)
	}
	for _, f := range result.Findings {
		if f.Severity != types.SeverityCritical {
			t.Errorf("Expected only CRITICAL findings, got %s (%s)", f.Severity, f.ID)
		}
	}
}

func TestConfig_RequiresImage(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.Image = ""
	err := cfg.Validate()
	if err == nil {
		t.Fatal("Expected error when image is empty, got nil")
	}
	if !strings.Contains(err.Error(), "--image") {
		t.Errorf("Error should mention --image flag: %v", err)
	}
}

func TestConfig_InvalidProvider(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.Image = "nginx:latest"
	cfg.Provider = "nonexistent"
	if err := cfg.Validate(); err == nil {
		t.Fatal("Expected error for unknown provider, got nil")
	}
}

func TestConfig_InvalidSeverity(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.Image = "nginx:latest"
	cfg.Severity = "BANANA"
	if err := cfg.Validate(); err == nil {
		t.Fatal("Expected error for invalid severity, got nil")
	}
}
