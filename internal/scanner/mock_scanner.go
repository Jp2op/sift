// Package scanner provides Scanner implementations for trivy-ai.
package scanner

import (
	"context"

	"github.com/jp2op/trivy-ai/pkg/types"
)

// MockScanner returns a hardcoded set of findings.
// It is used in tests and when --provider mock is set, so contributors
// can run the full pipeline without Docker or an API key.
type MockScanner struct{}

// Compile-time check: MockScanner must satisfy the Scanner interface.
// This line causes a compile error if the interface is not satisfied.
var _ scannerInterface = (*MockScanner)(nil)

// scannerInterface is a local copy of internal.Scanner to avoid import cycles.
type scannerInterface interface {
	Scan(ctx context.Context, target types.Target) ([]types.Finding, error)
}

// Scan returns a fixed set of realistic CVE findings regardless of target.
func (m *MockScanner) Scan(_ context.Context, target types.Target) ([]types.Finding, error) {
	return []types.Finding{
		{
			ID:               "CVE-2024-6119",
			Severity:         types.SeverityCritical,
			CVSS:             9.1,
			Package:          "openssl",
			InstalledVersion: "3.0.13",
			FixedVersion:     "3.0.14",
			Description:      "Issue summary: Possible denial of service in X.509 name checks.",
			Target:           target.Ref,
			TargetType:       target.Type,
			References:       []string{"https://nvd.nist.gov/vuln/detail/CVE-2024-6119"},
		},
		{
			ID:               "CVE-2024-5535",
			Severity:         types.SeverityCritical,
			CVSS:             9.1,
			Package:          "openssl",
			InstalledVersion: "3.0.13",
			FixedVersion:     "3.0.14",
			Description:      "Issue summary: SSL_select_next_proto buffer overread.",
			Target:           target.Ref,
			TargetType:       target.Type,
			References:       []string{"https://nvd.nist.gov/vuln/detail/CVE-2024-5535"},
		},
		{
			ID:               "CVE-2024-2511",
			Severity:         types.SeverityHigh,
			CVSS:             7.5,
			Package:          "openssl",
			InstalledVersion: "3.0.13",
			FixedVersion:     "3.0.14",
			Description:      "Issue summary: Unbounded memory growth with session handling in TLSv1.3.",
			Target:           target.Ref,
			TargetType:       target.Type,
			References:       []string{"https://nvd.nist.gov/vuln/detail/CVE-2024-2511"},
		},
		{
			ID:               "CVE-2024-0727",
			Severity:         types.SeverityHigh,
			CVSS:             7.1,
			Package:          "openssl",
			InstalledVersion: "3.0.13",
			FixedVersion:     "3.0.14",
			Description:      "Processing a maliciously formatted PKCS12 file may lead OpenSSL to crash.",
			Target:           target.Ref,
			TargetType:       target.Type,
			References:       []string{"https://nvd.nist.gov/vuln/detail/CVE-2024-0727"},
		},
		{
			ID:               "CVE-2023-6129",
			Severity:         types.SeverityMedium,
			CVSS:             6.5,
			Package:          "openssl",
			InstalledVersion: "3.0.13",
			FixedVersion:     "",
			Description:      "Issue summary: POLY1305 MAC implementation corrupts vector registers on PowerPC.",
			Target:           target.Ref,
			TargetType:       target.Type,
			References:       []string{"https://nvd.nist.gov/vuln/detail/CVE-2023-6129"},
		},
	}, nil
}
