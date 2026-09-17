package scanner

import (
	"fmt"
	"strings"

	"github.com/jp2op/trivy-ai/pkg/types"
)

// ParseTarget parses a target reference and optional target type flag into a Target.
// When targetType is empty, it auto-detects based on the ref format.
// Returns an error for target types not supported in v0.1.
func ParseTarget(ref, targetType string) (types.Target, error) {
	if targetType == "" {
		targetType = autoDetectTargetType(ref)
	}

	switch strings.ToLower(targetType) {
	case "image", "":
		return types.Target{Type: types.TargetTypeImage, Ref: ref}, nil
	case "fs", "filesystem":
		return types.Target{Type: types.TargetTypeFilesystem, Ref: ref}, nil
	case "k8s", "kubernetes":
		return types.Target{}, fmt.Errorf(
			"kubernetes target not yet supported in v0.1 — coming in v0.4.0")
	case "iac", "terraform":
		return types.Target{}, fmt.Errorf(
			"IaC target not yet supported in v0.1 — coming in v0.4.0")
	default:
		return types.Target{}, fmt.Errorf(
			"unknown target type %q: must be one of image, fs", targetType)
	}
}

// autoDetectTargetType guesses the target type from the ref string.
// Paths starting with . or / are treated as filesystem targets.
// Everything else is treated as a container image reference.
func autoDetectTargetType(ref string) string {
	if strings.HasPrefix(ref, "./") || strings.HasPrefix(ref, "/") || ref == "." {
		return "fs"
	}
	return "image"
}
