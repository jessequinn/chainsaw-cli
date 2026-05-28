package report

import (
	"bytes"
	"context"
	"strings"
	"testing"
	"time"

	"github.com/chainsaw-dev/chainsaw/pkg/models"
)

func TestWriteTable(t *testing.T) {
	var buf bytes.Buffer
	result := models.ScanResult{
		Components: []models.Component{
			{Name: "lodash", Version: "4.17.21", Ecosystem: models.EcosystemNpm},
		},
		Timestamp: time.Date(2025, 1, 15, 10, 0, 0, 0, time.UTC),
	}
	if err := WriteTable(context.Background(), &buf, result); err != nil {
		t.Fatalf("WriteTable error: %v", err)
	}
	out := buf.String()
	if !strings.Contains(out, "1 components scanned") {
		t.Errorf("output missing component count: %s", out)
	}
	if !strings.Contains(out, "SEVERITY") {
		t.Errorf("output missing header: %s", out)
	}
}

func TestWriteTable_WithFindings(t *testing.T) {
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
			FixedIn: "4.17.22",
		}},
		Timestamp: time.Date(2025, 1, 15, 10, 0, 0, 0, time.UTC),
	}
	if err := WriteTable(context.Background(), &buf, result); err != nil {
		t.Fatalf("WriteTable error: %v", err)
	}
	out := buf.String()
	if !strings.Contains(out, "GHSA-TEST") {
		t.Errorf("output missing finding ID: %s", out)
	}
	if !strings.Contains(out, "lodash") {
		t.Errorf("output missing package name: %s", out)
	}
}
