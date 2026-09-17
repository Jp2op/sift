// export_test.go exposes internal pipeline functions for black-box testing.
// This file is compiled ONLY during test runs (the _test.go suffix ensures this).
// Production binaries never include this code.
// This is the standard Go pattern for testing unexported internals without
// polluting the production API.
package main

import (
	"bytes"
	"context"
	"fmt"

	"encoding/json"

	"github.com/jp2op/trivy-ai/internal/agents"
	"github.com/jp2op/trivy-ai/internal/config"
	"github.com/jp2op/trivy-ai/internal/guardrails"
	"github.com/jp2op/trivy-ai/internal/output"
	"github.com/jp2op/trivy-ai/internal/scanner"
	"github.com/jp2op/trivy-ai/pkg/types"
)

// RunScanJSON runs the full scan pipeline and returns a parsed ScanResult.
// It writes to a bytes.Buffer — never to os.Stdout — so it works identically
// on Windows, Linux, and Mac with no pipe deadlock risk.
func RunScanJSON(image, severity string) (types.ScanResult, error) {
	cfg := config.DefaultConfig()
	cfg.Image = image
	cfg.Provider = "mock"
	cfg.Severity = severity
	if err := cfg.Validate(); err != nil {
		return types.ScanResult{}, err
	}

	ctx := context.Background()

	target, err := scanner.ParseTarget(cfg.Image, cfg.TargetType)
	if err != nil {
		return types.ScanResult{}, err
	}

	s := &scanner.MockScanner{}
	allFindings, err := s.Scan(ctx, target)
	if err != nil {
		return types.ScanResult{}, fmt.Errorf("scan failed: %w", err)
	}
	totalFound := len(allFindings)

	pipeline := guardrails.NewPipeline(
		&guardrails.SeverityFilter{MinSeverity: cfg.MinSeverity},
	)
	filtered := pipeline.Filter(ctx, allFindings)
	totalFiltered := totalFound - len(filtered)

	prov := selectProvider(cfg)
	agnt := &agents.ExplainAgent{}
	results := runAgents(ctx, agnt, prov, filtered, cfg.MaxParallel)

	var totalUsage types.Usage
	for _, r := range results {
		totalUsage.PromptTokens += r.Usage.PromptTokens
		totalUsage.CompletionTokens += r.Usage.CompletionTokens
	}

	scanResult := types.ScanResult{
		Target:        target,
		Findings:      filtered,
		Results:       results,
		TotalFound:    totalFound,
		TotalFiltered: totalFiltered,
		Usage:         totalUsage,
	}

	var buf bytes.Buffer
	reporter := &output.JSONReporter{}
	if err := reporter.Report(ctx, scanResult, &buf); err != nil {
		return types.ScanResult{}, fmt.Errorf("reporting: %w", err)
	}

	var result types.ScanResult
	if err := json.Unmarshal(buf.Bytes(), &result); err != nil {
		return types.ScanResult{}, fmt.Errorf("parsing output: %w", err)
	}
	return result, nil
}
