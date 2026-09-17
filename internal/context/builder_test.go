package context_test

import (
	"strings"
	"testing"

	trivyctx "github.com/jp2op/trivy-ai/internal/context"
	"github.com/jp2op/trivy-ai/pkg/types"
)

func fixableFinding() types.Finding {
	return types.Finding{
		ID: "CVE-2024-1234", Package: "openssl",
		InstalledVersion: "3.0.13", FixedVersion: "3.0.14",
		Target: "nginx:latest", TargetType: types.TargetTypeImage,
	}
}

func TestBuilder_Build_ReturnsContext(t *testing.T) {
	ctx := trivyctx.NewBuilder(8192).Build(fixableFinding())
	if ctx.TokensUsed == 0 { t.Error("Build() should return non-zero token count") }
}

func TestBuilder_Build_DockerfileLines(t *testing.T) {
	ctx := trivyctx.NewBuilder(8192).Build(fixableFinding())
	if len(ctx.DockerfileLines) == 0 { t.Error("Expected Dockerfile lines for image target") }
	joined := strings.Join(ctx.DockerfileLines, "\n")
	if !strings.Contains(joined, "openssl") { t.Errorf("Missing package name in context: %s", joined) }
}

func TestBuilder_Build_FixableIncludesFixVersion(t *testing.T) {
	ctx := trivyctx.NewBuilder(8192).Build(fixableFinding())
	joined := strings.Join(ctx.DockerfileLines, "\n")
	if !strings.Contains(joined, "3.0.14") { t.Errorf("Missing fixed version in context: %s", joined) }
}

func TestBuilder_Build_DependencyWarning(t *testing.T) {
	ctx := trivyctx.NewBuilder(8192).Build(fixableFinding())
	if len(ctx.DependentPackages) == 0 { t.Error("Expected dependency warning for fixable finding") }
}

func TestBuilder_SmallContextWindow(t *testing.T) {
	b := trivyctx.NewBuilder(4096)
	if b.TokenBudget >= 2000 { t.Errorf("Small window should reduce budget, got %d", b.TokenBudget) }
}

func TestCodeContext_Format_Empty(t *testing.T) {
	if (trivyctx.CodeContext{}).Format() != "" { t.Error("Empty context should return empty string") }
}

func TestCodeContext_Format_WithContent(t *testing.T) {
	ctx := trivyctx.CodeContext{DockerfileLines: []string{"FROM nginx:latest"}}
	if !strings.Contains(ctx.Format(), "nginx:latest") { t.Error("Format() missing content") }
}