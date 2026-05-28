package report

import (
	"bytes"
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/chainsaw-dev/chainsaw/pkg/models"
)

func TestWriteJSON(t *testing.T) {
	var buf bytes.Buffer
	result := models.ScanResult{
		Components: []models.Component{
			{Name: "lodash", Version: "4.17.21", Ecosystem: models.EcosystemNpm},
		},
		Findings: []models.Finding{{
			ID:       "GHSA-TEST",
			Summary:  "Test vuln",
			Severity: models.SeverityHigh,
			Component: models.Component{
				Name:    "lodash",
				Version: "4.17.21",
			},
		}},
		Timestamp: time.Date(2025, 1, 15, 10, 0, 0, 0, time.UTC),
	}
	if err := WriteJSON(context.Background(), &buf, result); err != nil {
		t.Fatalf("WriteJSON error: %v", err)
	}

	var decoded models.ScanResult
	if err := json.Unmarshal(buf.Bytes(), &decoded); err != nil {
		t.Fatalf("output is not valid JSON: %v", err)
	}
	if len(decoded.Components) != 1 {
		t.Errorf("components count = %d, want 1", len(decoded.Components))
	}
	if len(decoded.Findings) != 1 {
		t.Errorf("findings count = %d, want 1", len(decoded.Findings))
	}
	if decoded.Findings[0].ID != "GHSA-TEST" {
		t.Errorf("finding ID = %q, want %q", decoded.Findings[0].ID, "GHSA-TEST")
	}
}

func TestWriteJSON_EmptyResult(t *testing.T) {
	var buf bytes.Buffer
	result := models.ScanResult{
		Timestamp: time.Date(2025, 1, 15, 10, 0, 0, 0, time.UTC),
	}
	if err := WriteJSON(context.Background(), &buf, result); err != nil {
		t.Fatalf("WriteJSON error: %v", err)
	}
	var decoded map[string]interface{}
	if err := json.Unmarshal(buf.Bytes(), &decoded); err != nil {
		t.Fatalf("output is not valid JSON: %v", err)
	}
}
