package config_test

import (
	"testing"

	"github.com/jp2op/trivy-ai/internal/config"
	"github.com/jp2op/trivy-ai/pkg/types"
)

func TestConfig_Defaults(t *testing.T) {
	c := config.DefaultConfig()
	if c.Provider != "mock" {
		t.Errorf("default Provider = %q, want %q", c.Provider, "mock")
	}
	if c.Severity != "HIGH" {
		t.Errorf("default Severity = %q, want %q", c.Severity, "HIGH")
	}
	if c.Output != "terminal" {
		t.Errorf("default Output = %q, want %q", c.Output, "terminal")
	}
	if c.MaxParallel <= 0 {
		t.Errorf("default MaxParallel = %d, want > 0", c.MaxParallel)
	}
}

func TestConfig_Validate_ValidSeverity(t *testing.T) {
	for _, sev := range []string{"LOW", "MEDIUM", "HIGH", "CRITICAL"} {
		c := config.DefaultConfig()
		c.Image = "nginx:latest"
		c.Severity = sev
		if err := c.Validate(); err != nil {
			t.Errorf("Validate() with severity %q returned error: %v", sev, err)
		}
	}
}

func TestConfig_Validate_InvalidSeverity(t *testing.T) {
	c := config.DefaultConfig()
	c.Image = "nginx:latest"
	c.Severity = "BANANA"
	if err := c.Validate(); err == nil {
		t.Error("Validate() expected error for invalid severity, got nil")
	}
}

func TestConfig_Validate_ParsesSeverity(t *testing.T) {
	c := config.DefaultConfig()
	c.Image = "nginx:latest"
	c.Severity = "CRITICAL"
	if err := c.Validate(); err != nil {
		t.Fatalf("Validate() error: %v", err)
	}
	if c.MinSeverity != types.SeverityCritical {
		t.Errorf("MinSeverity = %v, want CRITICAL", c.MinSeverity)
	}
}

func TestConfig_Validate_InvalidProvider(t *testing.T) {
	c := config.DefaultConfig()
	c.Image = "nginx:latest"
	c.Provider = "nonexistent"
	if err := c.Validate(); err == nil {
		t.Error("Validate() expected error for invalid provider, got nil")
	}
}

func TestConfig_Validate_InvalidOutput(t *testing.T) {
	c := config.DefaultConfig()
	c.Image = "nginx:latest"
	c.Output = "pdf"
	if err := c.Validate(); err == nil {
		t.Error("Validate() expected error for invalid output format, got nil")
	}
}

func TestConfig_Validate_RequiresImage(t *testing.T) {
	c := config.DefaultConfig()
	c.Image = "" // no image
	if err := c.Validate(); err == nil {
		t.Error("Validate() expected error when --image is missing, got nil")
	}
}
