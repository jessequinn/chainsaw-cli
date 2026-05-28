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

func TestWriteJSON_WithFindings(t *testing.T) {
	var buf bytes.Buffer
	result := models.ScanResult{
		Components: []models.Component{
			{Name: "lodash", Version: "4.17.21", Ecosystem: models.EcosystemNpm},
			{Name: "express", Version: "4.18.0", Ecosystem: models.EcosystemNpm},
		},
		Findings: []models.Finding{
			{
				ID: "GHSA-001", Summary: "Prototype pollution", Severity: models.SeverityCritical,
				Component: models.Component{Name: "lodash", Version: "4.17.21"}, FixedIn: "4.17.22",
			},
			{
				ID: "GHSA-002", Summary: "Open redirect", Severity: models.SeverityHigh,
				Component: models.Component{Name: "express", Version: "4.18.0"},
			},
		},
		Hygiene: []models.Finding{{
			ID: "INTEGRITY-001", Summary: "Missing hash", Severity: models.SeverityMedium,
			Component: models.Component{Name: "lodash", Version: "4.17.21"},
		}},
		Timestamp: time.Date(2025, 1, 15, 10, 0, 0, 0, time.UTC),
	}
	if err := WriteJSON(context.Background(), &buf, result); err != nil {
		t.Fatalf("WriteJSON error: %v", err)
	}

	var decoded models.ScanResult
	if err := json.Unmarshal(buf.Bytes(), &decoded); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}
	if len(decoded.Findings) != 2 {
		t.Errorf("findings count = %d, want 2", len(decoded.Findings))
	}
	if len(decoded.Hygiene) != 1 {
		t.Errorf("hygiene count = %d, want 1", len(decoded.Hygiene))
	}
	if decoded.Findings[0].FixedIn != "4.17.22" {
		t.Errorf("findings[0].FixedIn = %q, want %q", decoded.Findings[0].FixedIn, "4.17.22")
	}
}

func TestWriteJSON_RoundTrip(t *testing.T) {
	original := models.ScanResult{
		Components: []models.Component{
			{Name: "pkg-a", Version: "1.0.0", Ecosystem: models.EcosystemGo, PkgURL: "pkg:golang/pkg-a@1.0.0"},
		},
		Findings: []models.Finding{{
			ID: "VULN-1", Summary: "A bug", Severity: models.SeverityLow, Details: "Detailed info",
			Component: models.Component{Name: "pkg-a", Version: "1.0.0"}, FixedIn: "1.0.1", Source: "osv",
		}},
		Timestamp:   time.Date(2025, 6, 1, 12, 0, 0, 0, time.UTC),
		ToolVersion: "0.3.0",
	}

	var buf bytes.Buffer
	if err := WriteJSON(context.Background(), &buf, original); err != nil {
		t.Fatalf("WriteJSON error: %v", err)
	}

	var decoded models.ScanResult
	if err := json.Unmarshal(buf.Bytes(), &decoded); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}

	if decoded.ToolVersion != original.ToolVersion {
		t.Errorf("ToolVersion = %q, want %q", decoded.ToolVersion, original.ToolVersion)
	}
	if len(decoded.Components) != len(original.Components) {
		t.Errorf("components count = %d, want %d", len(decoded.Components), len(original.Components))
	}
	if decoded.Components[0].Name != "pkg-a" {
		t.Errorf("component name = %q, want %q", decoded.Components[0].Name, "pkg-a")
	}
	if decoded.Findings[0].ID != "VULN-1" {
		t.Errorf("finding ID = %q, want %q", decoded.Findings[0].ID, "VULN-1")
	}
	if decoded.Findings[0].Source != "osv" {
		t.Errorf("finding Source = %q, want %q", decoded.Findings[0].Source, "osv")
	}
	if !decoded.Timestamp.Equal(original.Timestamp) {
		t.Errorf("Timestamp = %v, want %v", decoded.Timestamp, original.Timestamp)
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
