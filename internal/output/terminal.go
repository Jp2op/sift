// Package output contains Reporter implementations for trivy-ai.
package output

import (
	"context"
	"fmt"
	"io"
	"sort"
	"strings"

	"github.com/jp2op/trivy-ai/internal"
	"github.com/jp2op/trivy-ai/pkg/types"
)

// ANSI color codes
const (
	colorReset  = "\033[0m"
	colorRed    = "\033[31m"
	colorYellow = "\033[33m"
	colorCyan   = "\033[36m"
	colorGray   = "\033[90m"
	colorBold   = "\033[1m"
	colorGreen  = "\033[32m"
)

// TerminalReporter writes colored, human-readable output to a terminal.
type TerminalReporter struct {
	// NoColor disables ANSI color codes (e.g. when output is piped).
	NoColor bool
}

// Compile-time check: TerminalReporter must satisfy the Reporter interface.
var _ internal.Reporter = (*TerminalReporter)(nil)

// Name returns "terminal".
func (t *TerminalReporter) Name() string { return "terminal" }

// Report writes a colored, grouped-by-severity report to w.
func (t *TerminalReporter) Report(_ context.Context, result types.ScanResult, w io.Writer) error {
	if len(result.Findings) == 0 {
		fmt.Fprintf(w, "%s  No vulnerabilities found above threshold.%s\n",
			t.color(colorGreen), t.color(colorReset))
		return nil
	}

	// Group results by finding ID for easy lookup
	resultMap := map[string]types.AgentResult{}
	for _, r := range result.Results {
		resultMap[r.FindingID] = r
	}

	// Sort findings: CRITICAL first, then HIGH, then others
	sorted := make([]types.Finding, len(result.Findings))
	copy(sorted, result.Findings)
	sort.Slice(sorted, func(i, j int) bool {
		return sorted[i].Severity > sorted[j].Severity
	})

	// Print each finding
	for _, f := range sorted {
		t.printFinding(w, f, resultMap[f.ID])
	}

	// Summary line
	fmt.Fprintf(w, "\n%s%s%s\n",
		t.color(colorBold),
		result.Summary(),
		t.color(colorReset))

	return nil
}

func (t *TerminalReporter) printFinding(w io.Writer, f types.Finding, result types.AgentResult) {
	sevColor := t.severityColor(f.Severity)

	// Header line
	fmt.Fprintf(w, "\n%s%s[%s]%s  %s%s%s\n",
		t.color(colorBold),
		t.color(sevColor),
		f.Severity,
		t.color(colorReset),
		t.color(colorBold),
		f.ID,
		t.color(colorReset),
	)

	// Package info
	fmt.Fprintf(w, "  %sPackage:%s  %s  %s→%s  %s\n",
		t.color(colorGray), t.color(colorReset),
		f.Package,
		t.color(colorGray), t.color(colorReset),
		formatVersion(f),
	)

	// CVSS score
	fmt.Fprintf(w, "  %sCVSS:%s    %.1f\n",
		t.color(colorGray), t.color(colorReset),
		f.CVSS,
	)

	// AI explanation (if available)
	if result.Content != "" {
		fmt.Fprintf(w, "\n  %sExplanation:%s\n", t.color(colorCyan), t.color(colorReset))
		for _, line := range strings.Split(result.Content, "\n") {
			fmt.Fprintf(w, "  %s\n", line)
		}
	}

	fmt.Fprintln(w, strings.Repeat("─", 72))
}

func formatVersion(f types.Finding) string {
	if f.IsFixable() {
		return fmt.Sprintf("%s → fix: %s", f.InstalledVersion, f.FixedVersion)
	}
	return fmt.Sprintf("%s (no fix available)", f.InstalledVersion)
}

func (t *TerminalReporter) color(code string) string {
	if t.NoColor {
		return ""
	}
	return code
}

func (t *TerminalReporter) severityColor(s types.Severity) string {
	switch s {
	case types.SeverityCritical:
		return colorRed
	case types.SeverityHigh:
		return colorYellow
	default:
		return colorCyan
	}
}
