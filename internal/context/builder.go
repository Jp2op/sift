// Package context provides code context extraction for the FixAgent.
package context

import (
	"fmt"
	"strings"

	"github.com/jp2op/trivy-ai/pkg/types"
)

const (
	DefaultTokenBudget  = 2000
	approxCharsPerToken = 4
)

// CodeContext holds extracted code context for a single finding.
type CodeContext struct {
	LockfileLines     []string
	DockerfileLines   []string
	DependentPackages []string
	TokensUsed        int
}

// Format returns the context as a string for inclusion in a prompt.
func (c CodeContext) Format() string {
	if len(c.LockfileLines) == 0 && len(c.DockerfileLines) == 0 && len(c.DependentPackages) == 0 {
		return ""
	}
	var sb strings.Builder
	sb.WriteString("## Relevant code context\n\n")
	if len(c.DockerfileLines) > 0 {
		sb.WriteString("### Dockerfile layers:\n```dockerfile\n")
		for _, l := range c.DockerfileLines {
			sb.WriteString(l + "\n")
		}
		sb.WriteString("```\n\n")
	}
	if len(c.DependentPackages) > 0 {
		sb.WriteString("### Dependency notes:\n")
		for _, p := range c.DependentPackages {
			sb.WriteString("- " + p + "\n")
		}
	}
	return sb.String()
}

// Builder extracts code context for CVE findings with token budgeting.
type Builder struct {
	TokenBudget       int
	MaxProviderTokens int
}

func NewBuilder(maxProviderTokens int) *Builder {
	budget := DefaultTokenBudget
	if maxProviderTokens > 0 && maxProviderTokens < budget*4 {
		budget = maxProviderTokens / 4
	}
	return &Builder{TokenBudget: budget, MaxProviderTokens: maxProviderTokens}
}

func (b *Builder) Build(f types.Finding) CodeContext {
	ctx := CodeContext{}
	remaining := b.TokenBudget

	if f.TargetType == types.TargetTypeImage {
		lines := b.buildDockerfileContext(f)
		if tokens := estimateTokens(strings.Join(lines, "\n")); tokens <= remaining {
			ctx.DockerfileLines = lines
			ctx.TokensUsed += tokens
			remaining -= tokens
		}
	}

	if remaining > 50 {
		deps := b.buildDependencyContext(f)
		if len(deps) > 0 {
			ctx.DependentPackages = deps
			ctx.TokensUsed += estimateTokens(strings.Join(deps, "\n"))
		}
	}

	return ctx
}

func (b *Builder) buildDockerfileContext(f types.Finding) []string {
	lines := []string{
		fmt.Sprintf("FROM %s", f.Target),
		fmt.Sprintf("# Package %s@%s is installed as a system dependency", f.Package, f.InstalledVersion),
	}
	if f.IsFixable() {
		lines = append(lines, fmt.Sprintf("# Fix: upgrade to %s@%s", f.Package, f.FixedVersion))
	}
	return lines
}

func (b *Builder) buildDependencyContext(f types.Finding) []string {
	if !f.IsFixable() {
		return nil
	}
	return []string{
		fmt.Sprintf("WARNING: Upgrading %s may affect dependent packages.", f.Package),
		"Verify your application still builds and tests pass after the upgrade.",
	}
}

func estimateTokens(s string) int {
	return len(s) / approxCharsPerToken
}