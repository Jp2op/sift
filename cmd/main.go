// trivy-ai is an AI-powered CVE scanner that wraps Trivy with intelligent
// triage, fix suggestions, and optional auto-remediation.
//
// Usage:
//
//	trivy-ai scan   --image nginx:latest [--provider mock|ollama] [--severity HIGH] [--output terminal|json]
//	trivy-ai version
package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"runtime"
	"sync"
	"syscall"
	"time"

	"github.com/jp2op/trivy-ai/internal"
	"github.com/jp2op/trivy-ai/internal/agents"
	"github.com/jp2op/trivy-ai/internal/config"
	"github.com/jp2op/trivy-ai/internal/guardrails"
	"github.com/jp2op/trivy-ai/internal/output"
	"github.com/jp2op/trivy-ai/internal/provider"
	"github.com/jp2op/trivy-ai/internal/scanner"
	"github.com/jp2op/trivy-ai/pkg/types"
)

// Version is set at build time: -ldflags "-X main.Version=v0.1.0"
var Version = "v0.1.0-dev"

func main() {
	if len(os.Args) < 2 {
		printUsage()
		os.Exit(1)
	}

	switch os.Args[1] {
	case "scan":
		if err := runScanCmd(os.Args[2:]); err != nil {
			fmt.Fprintln(os.Stderr, "Error:", err)
			os.Exit(1)
		}
	case "version":
		runVersionCmd()
	case "help", "--help", "-h":
		printUsage()
	default:
		fmt.Fprintf(os.Stderr, "unknown command %q\n\n", os.Args[1])
		printUsage()
		os.Exit(1)
	}
}

func printUsage() {
	fmt.Fprintln(os.Stderr, `trivy-ai — AI-powered CVE scanning and remediation

Usage:
  trivy-ai scan     Scan a target for CVEs and explain findings with AI
  trivy-ai version  Print version information
  trivy-ai help     Show this help

Run 'trivy-ai scan --help' for scan options.`)
}

// ── scan command ──────────────────────────────────────────────────────────────

func runScanCmd(args []string) error {
	fs := flag.NewFlagSet("scan", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	fs.Usage = func() {
		fmt.Fprintln(os.Stderr, `Usage: trivy-ai scan [flags]

Flags:`)
		fs.PrintDefaults()
		fmt.Fprintln(os.Stderr, `
Examples:
  trivy-ai scan --image nginx:latest
  trivy-ai scan --image nginx:latest --provider ollama --model llama3
  trivy-ai scan --image myapp:latest --severity CRITICAL --output json`)
	}

	def := config.DefaultConfig()
	image    := fs.String("image",       "",              "Container image to scan (required)")
	prov     := fs.String("provider",    def.Provider,    "LLM provider: mock, ollama, anthropic, openai")
	model    := fs.String("model",       def.Model,       "LLM model name (provider-specific)")
	severity := fs.String("severity",    def.Severity,    "Minimum severity: LOW, MEDIUM, HIGH, CRITICAL")
	outFmt   := fs.String("output",      def.Output,      "Output format: terminal, json")
	parallel := fs.Int("max-parallel",   def.MaxParallel, "Maximum concurrent LLM calls")

	if err := fs.Parse(args); err != nil {
		return err
	}

	cfg := config.Config{
		Image:       *image,
		Provider:    *prov,
		Model:       *model,
		Severity:    *severity,
		Output:      *outFmt,
		MaxParallel: *parallel,
		TargetType:  "image",
	}

	if err := cfg.Validate(); err != nil {
		return err
	}

	return executeScan(cfg)
}

// executeScan runs the full scan pipeline.
func executeScan(cfg config.Config) error {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	start := time.Now()

	// Parse target
	target, err := scanner.ParseTarget(cfg.Image, cfg.TargetType)
	if err != nil {
		return err
	}

	// Scan (mock scanner in v0.1 — Trivy adapter in v0.2)
	s := &scanner.MockScanner{}
	fmt.Fprintf(os.Stderr, "Scanning %s...\n", target.Ref)
	allFindings, err := s.Scan(ctx, target)
	if err != nil {
		return fmt.Errorf("scan failed: %w", err)
	}
	totalFound := len(allFindings)

	// Guardrails
	pipeline := guardrails.NewPipeline(
		&guardrails.SeverityFilter{MinSeverity: cfg.MinSeverity},
	)
	filtered := pipeline.Filter(ctx, allFindings)
	totalFiltered := totalFound - len(filtered)

	fmt.Fprintf(os.Stderr, "Found %d vulnerabilities, %d above %s threshold\n",
		totalFound, len(filtered), cfg.Severity)

	if len(filtered) == 0 {
		fmt.Fprintln(os.Stderr, "Nothing to explain.")
		return nil
	}

	// Provider + Agent
	prov := selectProvider(cfg)
	agent := &agents.ExplainAgent{}
	results := runAgents(ctx, agent, prov, filtered, cfg.MaxParallel)

	// Aggregate usage
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
		Duration:      time.Since(start),
	}

	// Report
	reporter := selectReporter(cfg)
	return reporter.Report(ctx, scanResult, os.Stdout)
}

// runAgents processes each finding with the agent in parallel,
// bounded by a semaphore of size maxParallel.
func runAgents(ctx context.Context, agent internal.Agent, prov internal.Provider,
	findings []types.Finding, maxParallel int) []types.AgentResult {

	sem := make(chan struct{}, maxParallel)
	results := make([]types.AgentResult, len(findings))
	var wg sync.WaitGroup

	for i, f := range findings {
		wg.Add(1)
		go func(idx int, finding types.Finding) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()

			result, err := agent.Run(ctx, finding, prov)
			if err != nil {
				result = types.AgentResult{
					FindingID: finding.ID,
					AgentName: agent.Name(),
					Content:   fmt.Sprintf("(error: %v)", err),
					Error:     err,
				}
			}
			results[idx] = result
		}(i, f)
	}
	wg.Wait()
	return results
}

func selectProvider(cfg config.Config) internal.Provider {
	switch cfg.Provider {
	case "ollama":
		return provider.NewOllamaProvider(cfg.OllamaBaseURL, cfg.Model)
	case "anthropic":
		p, err := provider.NewAnthropicProvider(cfg.Model)
		if err != nil {
			fmt.Fprintln(os.Stderr, "Error:", err)
			os.Exit(1)
		}
		return p
	case "openai":
		p, err := provider.NewOpenAIProvider(cfg.Model)
		if err != nil {
			fmt.Fprintln(os.Stderr, "Error:", err)
			os.Exit(1)
		}
		return p

	case "gemini":
    p, err := provider.NewGeminiProvider(
        "project-6a05dcc2-fe5f-4095-82d",
        "us-central1",
        cfg.Model,
    )
    if err != nil {
        fmt.Fprintln(os.Stderr, "Error:", err)
        os.Exit(1)
    }
    return p

	
	default:
		return &provider.MockProvider{ModelName: cfg.Model}
	}
}

func selectReporter(cfg config.Config) internal.Reporter {
	switch cfg.Output {
	case "json":
		return &output.JSONReporter{}
	case "sarif":
		return &output.SARIFReporter{}
	default:
		return &output.TerminalReporter{}
	}
}

// ── version command ───────────────────────────────────────────────────────────

func runVersionCmd() {
	fmt.Printf("trivy-ai %s\n", Version)
	fmt.Printf("Go:       %s\n", runtime.Version())
	fmt.Printf("OS/Arch:  %s/%s\n", runtime.GOOS, runtime.GOARCH)
}