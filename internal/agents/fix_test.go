package agents_test

import (
	"context"
	"strings"
	"testing"

	"github.com/jp2op/trivy-ai/internal"
	"github.com/jp2op/trivy-ai/internal/agents"
	"github.com/jp2op/trivy-ai/pkg/types"
)

// Note: capturingProvider and errorProvider are defined in agents_test.go

func fixAgentFinding() types.Finding {
	return types.Finding{
		ID: "CVE-2024-6119", Severity: types.SeverityCritical, CVSS: 9.1,
		Package: "openssl", InstalledVersion: "3.0.13", FixedVersion: "3.0.14",
		Description: "Possible denial of service.", Target: "nginx:latest",
		TargetType: types.TargetTypeImage,
	}
}

func TestFixAgent_Name(t *testing.T) {
	if (&agents.FixAgent{}).Name() != "fix" {
		t.Error("Name() should return 'fix'")
	}
}

func TestFixAgent_Run_Fixable(t *testing.T) {
	result, err := (&agents.FixAgent{}).Run(context.Background(), fixAgentFinding(), &capturingProvider{})
	if err != nil { t.Fatalf("Run() error: %v", err) }
	if result.Content == "" { t.Error("Run() returned empty Content") }
	if result.AgentName != "fix" { t.Errorf("AgentName = %q, want fix", result.AgentName) }
}

func TestFixAgent_Run_NoFixAvailable(t *testing.T) {
	f := fixAgentFinding()
	f.FixedVersion = ""
	cap := &capturingProvider{}
	result, err := (&agents.FixAgent{}).Run(context.Background(), f, cap)
	if err != nil { t.Fatalf("unexpected error: %v", err) }
	if cap.callCount > 0 { t.Error("FixAgent should not call provider when no fix available") }
	if !strings.Contains(result.Content, "No fix available") {
		t.Errorf("Expected 'No fix available', got: %s", result.Content)
	}
}

func TestFixAgent_PromptContainsFixedVersion(t *testing.T) {
	cap := &capturingProvider{}
	(&agents.FixAgent{}).Run(context.Background(), fixAgentFinding(), cap)
	if !strings.Contains(cap.lastPrompt, "3.0.14") {
		t.Error("Prompt should contain fixed version")
	}
}

func TestFixAgent_PromptHasXMLDelimiters(t *testing.T) {
	cap := &capturingProvider{}
	(&agents.FixAgent{}).Run(context.Background(), fixAgentFinding(), cap)
	if !strings.Contains(cap.lastPrompt, "<untrusted_data>") {
		t.Error("Prompt missing XML delimiter")
	}
}

func TestFixAgent_ProviderError(t *testing.T) {
	_, err := (&agents.FixAgent{}).Run(context.Background(), fixAgentFinding(), &errorProvider{})
	if err == nil { t.Fatal("Expected error when provider fails") }
	if !strings.Contains(err.Error(), "CVE-2024-6119") {
		t.Errorf("Error should include CVE ID: %v", err)
	}
}

func TestFixAgent_Interface(t *testing.T) {
	var _ internal.Agent = (*agents.FixAgent)(nil)
}