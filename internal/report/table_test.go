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

func TestWriteTable_EmptyResult(t *testing.T) {
	var buf bytes.Buffer
	result := models.ScanResult{
		Timestamp: time.Date(2025, 1, 15, 10, 0, 0, 0, time.UTC),
	}
	if err := WriteTable(context.Background(), &buf, result); err != nil {
		t.Fatalf("WriteTable error: %v", err)
	}
	out := buf.String()
	if !strings.Contains(out, "0 components scanned") {
		t.Errorf("expected 0 components scanned, got: %s", out)
	}
	if !strings.Contains(out, "0 vulnerabilities found") {
		t.Errorf("expected 0 vulnerabilities, got: %s", out)
	}
}

func TestWriteTable_WithHygieneFindings(t *testing.T) {
	var buf bytes.Buffer
	result := models.ScanResult{
		Components: []models.Component{
			{Name: "express", Version: "4.18.0", Ecosystem: models.EcosystemNpm},
		},
		Hygiene: []models.Finding{{
			ID:       "INTEGRITY-npm-express",
			Summary:  "Missing integrity hash",
			Severity: models.SeverityMedium,
			Component: models.Component{
				Name:    "express",
				Version: "4.18.0",
			},
		}},
		Timestamp: time.Date(2025, 1, 15, 10, 0, 0, 0, time.UTC),
	}
	if err := WriteTable(context.Background(), &buf, result); err != nil {
		t.Fatalf("WriteTable error: %v", err)
	}
	out := buf.String()
	if !strings.Contains(out, "1 hygiene warnings") {
		t.Errorf("expected 1 hygiene warning in summary: %s", out)
	}
	if !strings.Contains(out, "Hygiene Warnings") {
		t.Errorf("expected Hygiene Warnings section: %s", out)
	}
	if !strings.Contains(out, "INTEGRITY-npm-exp") {
		t.Errorf("expected hygiene finding ID: %s", out)
	}
	if !strings.Contains(out, "Missing integrity hash") {
		t.Errorf("expected hygiene summary: %s", out)
	}
}

func TestWriteTable_MultipleFindings(t *testing.T) {
	var buf bytes.Buffer
	result := models.ScanResult{
		Components: []models.Component{
			{Name: "lodash", Version: "4.17.21"},
			{Name: "express", Version: "4.18.0"},
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
			{
				ID: "GHSA-003", Summary: "ReDoS", Severity: models.SeverityLow,
				Component: models.Component{Name: "lodash", Version: "4.17.21"}, FixedIn: "4.17.25",
			},
		},
		Timestamp: time.Date(2025, 1, 15, 10, 0, 0, 0, time.UTC),
	}
	if err := WriteTable(context.Background(), &buf, result); err != nil {
		t.Fatalf("WriteTable error: %v", err)
	}
	out := buf.String()
	for _, id := range []string{"GHSA-001", "GHSA-002", "GHSA-003"} {
		if !strings.Contains(out, id) {
			t.Errorf("output missing finding %s", id)
		}
	}
	if !strings.Contains(out, "CRITICAL") {
		t.Error("output missing CRITICAL severity")
	}
	if !strings.Contains(out, "3 vulnerabilities found") {
		t.Errorf("expected 3 vulnerabilities in summary: %s", out)
	}
	// FixedIn "-" for missing
	if !strings.Contains(out, "-") {
		t.Error("expected dash for missing FixedIn")
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
