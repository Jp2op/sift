package output

import (
	"context"
	"encoding/json"
	"fmt"
	"io"

	"github.com/jp2op/trivy-ai/internal"
	"github.com/jp2op/trivy-ai/pkg/types"
)

// SchemaVersion is the current JSON output schema version.
// Bump this when making breaking changes to the output format.
const SchemaVersion = "v1"

// JSONReporter writes machine-readable JSON to any io.Writer.
type JSONReporter struct{}

// Compile-time check: JSONReporter must satisfy the Reporter interface.
var _ internal.Reporter = (*JSONReporter)(nil)

// Name returns "json".
func (j *JSONReporter) Name() string { return "json" }

// Report marshals the ScanResult to indented JSON and writes it to w.
func (j *JSONReporter) Report(_ context.Context, result types.ScanResult, w io.Writer) error {
	result.SchemaVersion = SchemaVersion
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	if err := enc.Encode(result); err != nil {
		return fmt.Errorf("json reporter: encoding result: %w", err)
	}
	return nil
}
