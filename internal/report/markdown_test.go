package report

import (
	"bytes"
	"context"
	"strings"
	"testing"
	"time"

	"github.com/chainsaw-dev/chainsaw/pkg/models"
)

func TestWriteMarkdown_has_sections(t *testing.T) {
	var buf bytes.Buffer
	result := models.ScanResult{
		Components: []models.Component{
			{Name: "lodash", Version: "4.17.21", Ecosystem: models.EcosystemNpm},
		},
		Findings: []models.Finding{
			{
				ID: "GHSA-001", Summary: "Prototype pollution", Severity: models.SeverityCritical,
				Component: models.Component{Name: "lodash", Version: "4.17.21"}, FixedIn: "4.17.22",
			},
		},
		Timestamp: time.Date(2025, 1, 15, 10, 0, 0, 0, time.UTC),
	}
	if err := WriteMarkdown(context.Background(), &buf, result); err != nil {
		t.Fatalf("WriteMarkdown error: %v", err)
	}
	out := buf.String()

	// Check for expected sections
	if !strings.Contains(out, "# Chainsaw Scan Report") {
		t.Errorf("output missing title: %s", out)
	}
	if !strings.Contains(out, "## Summary") {
		t.Errorf("output missing Summary section: %s", out)
	}
	if !strings.Contains(out, "## Vulnerabilities") {
		t.Errorf("output missing Vulnerabilities section: %s", out)
	}
	if !strings.Contains(out, "## Components") {
		t.Errorf("output missing Components section: %s", out)
	}
}

func TestWriteMarkdown_severity_breakdown(t *testing.T) {
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
			{
				ID: "GHSA-003", Summary: "XSS vuln", Severity: models.SeverityMedium,
				Component: models.Component{Name: "express", Version: "4.18.0"},
			},
		},
		Timestamp: time.Date(2025, 1, 15, 10, 0, 0, 0, time.UTC),
	}
	if err := WriteMarkdown(context.Background(), &buf, result); err != nil {
		t.Fatalf("WriteMarkdown error: %v", err)
	}
	out := buf.String()

	// Check for severity breakdown
	if !strings.Contains(out, "**Severity Breakdown:**") {
		t.Errorf("output missing severity breakdown label: %s", out)
	}
	if !strings.Contains(out, "CRITICAL: 1") {
		t.Errorf("output missing CRITICAL count: %s", out)
	}
	if !strings.Contains(out, "HIGH: 1") {
		t.Errorf("output missing HIGH count: %s", out)
	}
	if !strings.Contains(out, "MEDIUM: 1") {
		t.Errorf("output missing MEDIUM count: %s", out)
	}
}

func TestWriteMarkdown_escapes_pipes(t *testing.T) {
	var buf bytes.Buffer
	result := models.ScanResult{
		Components: []models.Component{
			{Name: "pkg|name", Version: "1.0.0", Ecosystem: models.EcosystemNpm},
		},
		Findings: []models.Finding{
			{
				ID: "GHSA-001", Summary: "Summary | with pipe", Severity: models.SeverityHigh,
				Component: models.Component{Name: "pkg|name", Version: "1.0.0"},
			},
		},
		Timestamp: time.Date(2025, 1, 15, 10, 0, 0, 0, time.UTC),
	}
	if err := WriteMarkdown(context.Background(), &buf, result); err != nil {
		t.Fatalf("WriteMarkdown error: %v", err)
	}
	out := buf.String()

	// Check that pipes are escaped in the vulnerability table
	if !strings.Contains(out, "pkg\\|name") {
		t.Errorf("output did not escape pipe in package name: %s", out)
	}
	if !strings.Contains(out, "Summary \\| with pipe") {
		t.Errorf("output did not escape pipe in summary: %s", out)
	}
}

func TestWriteMarkdown_no_findings(t *testing.T) {
	var buf bytes.Buffer
	result := models.ScanResult{
		Components: []models.Component{
			{Name: "safe-pkg", Version: "1.0.0", Ecosystem: models.EcosystemGo},
		},
		Timestamp: time.Date(2025, 1, 15, 10, 0, 0, 0, time.UTC),
	}
	if err := WriteMarkdown(context.Background(), &buf, result); err != nil {
		t.Fatalf("WriteMarkdown error: %v", err)
	}
	out := buf.String()

	// Check that Vulnerabilities section is not present
	if strings.Contains(out, "## Vulnerabilities") {
		t.Errorf("output should not have Vulnerabilities section when empty: %s", out)
	}
	// But Components section should exist
	if !strings.Contains(out, "## Components") {
		t.Errorf("output missing Components section: %s", out)
	}
	// And Summary should exist
	if !strings.Contains(out, "## Summary") {
		t.Errorf("output missing Summary section: %s", out)
	}
}

func TestWriteMarkdown_no_hygiene(t *testing.T) {
	var buf bytes.Buffer
	result := models.ScanResult{
		Components: []models.Component{
			{Name: "safe-pkg", Version: "1.0.0", Ecosystem: models.EcosystemGo},
		},
		Timestamp: time.Date(2025, 1, 15, 10, 0, 0, 0, time.UTC),
	}
	if err := WriteMarkdown(context.Background(), &buf, result); err != nil {
		t.Fatalf("WriteMarkdown error: %v", err)
	}
	out := buf.String()

	// Check that Hygiene Issues section is not present
	if strings.Contains(out, "## Hygiene Issues") {
		t.Errorf("output should not have Hygiene Issues section when empty: %s", out)
	}
}

func TestWriteMarkdown_with_hygiene(t *testing.T) {
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
	if err := WriteMarkdown(context.Background(), &buf, result); err != nil {
		t.Fatalf("WriteMarkdown error: %v", err)
	}
	out := buf.String()

	// Check for Hygiene Issues section
	if !strings.Contains(out, "## Hygiene Issues") {
		t.Errorf("output missing Hygiene Issues section: %s", out)
	}
	if !strings.Contains(out, "INTEGRITY-npm-express") {
		t.Errorf("output missing hygiene finding ID: %s", out)
	}
	if !strings.Contains(out, "Missing integrity hash") {
		t.Errorf("output missing hygiene summary: %s", out)
	}
}

func TestWriteCRAMarkdown_score(t *testing.T) {
	var buf bytes.Buffer
	result := models.CRAResult{
		ProductName:  "TestProduct",
		Version:      "1.0.0",
		OverallScore: 75,
		Date:         time.Date(2025, 1, 15, 10, 0, 0, 0, time.UTC),
		Regulation:   "EU CRA",
	}
	if err := WriteCRAMarkdown(context.Background(), &buf, result); err != nil {
		t.Fatalf("WriteCRAMarkdown error: %v", err)
	}
	out := buf.String()

	// Check for title
	if !strings.Contains(out, "# CRA Compliance Report") {
		t.Errorf("output missing title: %s", out)
	}
	// Check for score
	if !strings.Contains(out, "**Overall Score:** 75/100") {
		t.Errorf("output missing overall score: %s", out)
	}
}

func TestWriteCRAMarkdown_check_table(t *testing.T) {
	var buf bytes.Buffer
	result := models.CRAResult{
		ProductName:  "TestProduct",
		Version:      "1.0.0",
		OverallScore: 80,
		Date:         time.Date(2025, 1, 15, 10, 0, 0, 0, time.UTC),
		Regulation:   "EU CRA",
		Checks: []models.CRACheck{
			{
				ID:      "CRA-001",
				Title:   "Vulnerability Monitoring",
				Article: "Art. 8",
				Status:  models.CRAPass,
				Severity: models.SeverityHigh,
			},
			{
				ID:      "CRA-002",
				Title:   "Supply Chain Security",
				Article: "Art. 10",
				Status:  models.CRAFail,
				Severity: models.SeverityCritical,
			},
			{
				ID:      "CRA-003",
				Title:   "Incident Reporting",
				Article: "Art. 12",
				Status:  models.CRAWarn,
				Severity: models.SeverityMedium,
			},
		},
	}
	if err := WriteCRAMarkdown(context.Background(), &buf, result); err != nil {
		t.Fatalf("WriteCRAMarkdown error: %v", err)
	}
	out := buf.String()

	// Check for Checks section
	if !strings.Contains(out, "## Checks") {
		t.Errorf("output missing Checks section: %s", out)
	}
	// Check for check rows
	if !strings.Contains(out, "CRA-001") {
		t.Errorf("output missing CRA-001: %s", out)
	}
	if !strings.Contains(out, "Vulnerability Monitoring") {
		t.Errorf("output missing check title: %s", out)
	}
	if !strings.Contains(out, "Art. 8") {
		t.Errorf("output missing article: %s", out)
	}
	if !strings.Contains(out, "PASS") {
		t.Errorf("output missing PASS status: %s", out)
	}
	if !strings.Contains(out, "FAIL") {
		t.Errorf("output missing FAIL status: %s", out)
	}
	if !strings.Contains(out, "WARN") {
		t.Errorf("output missing WARN status: %s", out)
	}
}

func TestWriteCRAMarkdown_status_counts(t *testing.T) {
	var buf bytes.Buffer
	result := models.CRAResult{
		ProductName:  "TestProduct",
		Version:      "1.0.0",
		OverallScore: 60,
		Date:         time.Date(2025, 1, 15, 10, 0, 0, 0, time.UTC),
		Regulation:   "EU CRA",
		Checks: []models.CRACheck{
			{ID: "C1", Title: "Check 1", Article: "Art. 1", Status: models.CRAPass, Severity: models.SeverityLow},
			{ID: "C2", Title: "Check 2", Article: "Art. 2", Status: models.CRAPass, Severity: models.SeverityLow},
			{ID: "C3", Title: "Check 3", Article: "Art. 3", Status: models.CRAFail, Severity: models.SeverityHigh},
			{ID: "C4", Title: "Check 4", Article: "Art. 4", Status: models.CRAWarn, Severity: models.SeverityMedium},
		},
	}
	if err := WriteCRAMarkdown(context.Background(), &buf, result); err != nil {
		t.Fatalf("WriteCRAMarkdown error: %v", err)
	}
	out := buf.String()

	// Check status table
	if !strings.Contains(out, "| Pass | 2 |") {
		t.Errorf("output missing correct Pass count: %s", out)
	}
	if !strings.Contains(out, "| Fail | 1 |") {
		t.Errorf("output missing correct Fail count: %s", out)
	}
	if !strings.Contains(out, "| Warn | 1 |") {
		t.Errorf("output missing correct Warn count: %s", out)
	}
}
