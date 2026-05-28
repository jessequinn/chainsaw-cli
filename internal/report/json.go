package report

import (
	"context"
	"encoding/json"
	"fmt"
	"io"

	"github.com/chainsaw-dev/chainsaw/pkg/models"
)

// WriteJSON writes scan results as indented JSON to w.
func WriteJSON(_ context.Context, w io.Writer, result models.ScanResult) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	if err := enc.Encode(result); err != nil {
		return fmt.Errorf("encoding JSON: %w", err)
	}
	return nil
}
