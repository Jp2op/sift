package scanner_test

import (
	"context"
	"testing"

	"github.com/jp2op/trivy-ai/internal/scanner"
	"github.com/jp2op/trivy-ai/pkg/types"
)

func TestMockScanner_Scan(t *testing.T) {
	s := &scanner.MockScanner{}
	target := types.Target{Type: types.TargetTypeImage, Ref: "nginx:latest"}

	findings, err := s.Scan(context.Background(), target)
	if err != nil {
		t.Fatalf("Scan() unexpected error: %v", err)
	}
	if len(findings) == 0 {
		t.Fatal("Scan() returned zero findings, expected > 0")
	}

	// Verify expected severities are present
	sevCount := map[types.Severity]int{}
	for _, f := range findings {
		sevCount[f.Severity]++
		if f.Target != target.Ref {
			t.Errorf("Finding.Target = %q, want %q", f.Target, target.Ref)
		}
		if f.ID == "" {
			t.Error("Finding.ID must not be empty")
		}
		if f.Package == "" {
			t.Error("Finding.Package must not be empty")
		}
	}

	if sevCount[types.SeverityCritical] < 1 {
		t.Error("Expected at least one CRITICAL finding")
	}
	if sevCount[types.SeverityHigh] < 1 {
		t.Error("Expected at least one HIGH finding")
	}
}

func TestMockScanner_ReturnsTargetRef(t *testing.T) {
	s := &scanner.MockScanner{}
	ref := "myapp:v1.2.3"
	findings, err := s.Scan(context.Background(), types.Target{Type: types.TargetTypeImage, Ref: ref})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	for _, f := range findings {
		if f.Target != ref {
			t.Errorf("Finding.Target = %q, want %q", f.Target, ref)
		}
	}
}

func TestParseTarget_Image(t *testing.T) {
	tests := []struct {
		input    string
		wantType types.TargetType
		wantErr  bool
	}{
		{"nginx:latest", types.TargetTypeImage, false},
		{"gcr.io/myproject/myapp:v1", types.TargetTypeImage, false},
		{"ubuntu:22.04", types.TargetTypeImage, false},
	}
	for _, tc := range tests {
		t.Run(tc.input, func(t *testing.T) {
			got, err := scanner.ParseTarget(tc.input, "")
			if tc.wantErr {
				if err == nil {
					t.Error("expected error, got nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got.Type != tc.wantType {
				t.Errorf("Type = %q, want %q", got.Type, tc.wantType)
			}
			if got.Ref != tc.input {
				t.Errorf("Ref = %q, want %q", got.Ref, tc.input)
			}
		})
	}
}

func TestParseTarget_ExplicitType(t *testing.T) {
	target, err := scanner.ParseTarget("./myrepo", "fs")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if target.Type != types.TargetTypeFilesystem {
		t.Errorf("Type = %q, want %q", target.Type, types.TargetTypeFilesystem)
	}
}

func TestParseTarget_UnsupportedInV01(t *testing.T) {
	unsupported := []string{"k8s", "iac"}
	for _, u := range unsupported {
		t.Run(u, func(t *testing.T) {
			_, err := scanner.ParseTarget("./path", u)
			if err == nil {
				t.Errorf("ParseTarget with target %q expected error, got nil", u)
			}
		})
	}
}
