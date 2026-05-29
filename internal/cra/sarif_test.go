package cra

import (
	"bytes"
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/chainsaw-dev/chainsaw/pkg/models"
)

func TestWriteCRASARIF_valid_json(t *testing.T) {
	result := models.CRAResult{
		ProductName:  "test-product",
		Version:      "1.0.0",
		Date:         time.Date(2026, 5, 29, 0, 0, 0, 0, time.UTC),
		Regulation:   "EU Cyber Resilience Act (Regulation (EU) 2024/2847)",
		OverallScore: 75,
		Checks: []models.CRACheck{
			{
				ID:          "CRA-001",
				Title:       "Vulnerability Disclosure Policy",
				Article:     "Article 14",
				Status:      models.CRAPass,
				Details:     "Disclosure policy is present and accessible",
				Severity:    models.SeverityHigh,
				Remediation: "",
			},
			{
				ID:          "CRA-002",
				Title:       "Security Update Availability",
				Article:     "Article 13",
				Status:      models.CRAFail,
				Details:     "No security updates available",
				Severity:    models.SeverityCritical,
				Remediation: "Implement security update mechanism",
			},
			{
				ID:          "CRA-003",
				Title:       "Product Support Lifecycle",
				Article:     "Article 12",
				Status:      models.CRAWarn,
				Details:     "Support lifecycle is short",
				Severity:    models.SeverityMedium,
				Remediation: "Extend support lifecycle",
			},
		},
	}

	buf := new(bytes.Buffer)
	err := WriteCRASARIF(context.Background(), buf, result)
	if err != nil {
		t.Fatalf("WriteCRASARIF failed: %v", err)
	}

	// Verify valid JSON.
	var log sarifLog
	if err := json.Unmarshal(buf.Bytes(), &log); err != nil {
		t.Fatalf("Output is not valid JSON: %v", err)
	}

	// Verify basic structure.
	if log.Version != "2.1.0" {
		t.Errorf("Expected version 2.1.0, got %s", log.Version)
	}
	if log.Schema == "" {
		t.Error("Expected schema URI to be set")
	}
	if len(log.Runs) != 1 {
		t.Errorf("Expected 1 run, got %d", len(log.Runs))
	}
}

func TestWriteCRASARIF_only_failures_in_results(t *testing.T) {
	result := models.CRAResult{
		ProductName:  "test-product",
		Version:      "1.0.0",
		Date:         time.Date(2026, 5, 29, 0, 0, 0, 0, time.UTC),
		Regulation:   "EU Cyber Resilience Act (Regulation (EU) 2024/2847)",
		OverallScore: 50,
		Checks: []models.CRACheck{
			{
				ID:       "CRA-001",
				Title:    "Check 1",
				Article:  "Article 14",
				Status:   models.CRAPass,
				Details:  "Pass",
				Severity: models.SeverityHigh,
			},
			{
				ID:       "CRA-002",
				Title:    "Check 2",
				Article:  "Article 13",
				Status:   models.CRAFail,
				Details:  "Fail",
				Severity: models.SeverityCritical,
			},
			{
				ID:       "CRA-003",
				Title:    "Check 3",
				Article:  "Article 12",
				Status:   models.CRANA,
				Details:  "N/A",
				Severity: models.SeverityLow,
			},
			{
				ID:       "CRA-004",
				Title:    "Check 4",
				Article:  "Article 11",
				Status:   models.CRAWarn,
				Details:  "Warn",
				Severity: models.SeverityMedium,
			},
		},
	}

	buf := new(bytes.Buffer)
	err := WriteCRASARIF(context.Background(), buf, result)
	if err != nil {
		t.Fatalf("WriteCRASARIF failed: %v", err)
	}

	var log sarifLog
	if err := json.Unmarshal(buf.Bytes(), &log); err != nil {
		t.Fatalf("Output is not valid JSON: %v", err)
	}

	// Only CRA-002 (fail) and CRA-004 (warn) should be in results.
	if len(log.Runs[0].Results) != 2 {
		t.Errorf("Expected 2 results (fail + warn), got %d", len(log.Runs[0].Results))
	}

	ruleIDs := make(map[string]bool)
	for _, res := range log.Runs[0].Results {
		ruleIDs[res.RuleID] = true
	}

	if !ruleIDs["CRA-002"] {
		t.Error("Expected CRA-002 (fail) in results")
	}
	if !ruleIDs["CRA-004"] {
		t.Error("Expected CRA-004 (warn) in results")
	}
	if ruleIDs["CRA-001"] {
		t.Error("CRA-001 (pass) should not be in results")
	}
	if ruleIDs["CRA-003"] {
		t.Error("CRA-003 (N/A) should not be in results")
	}
}

func TestWriteCRASARIF_rules_include_all_checks(t *testing.T) {
	result := models.CRAResult{
		ProductName:  "test-product",
		Version:      "1.0.0",
		Date:         time.Date(2026, 5, 29, 0, 0, 0, 0, time.UTC),
		Regulation:   "EU Cyber Resilience Act (Regulation (EU) 2024/2847)",
		OverallScore: 50,
		Checks: []models.CRACheck{
			{
				ID:       "CRA-001",
				Title:    "Check 1",
				Article:  "Article 14",
				Status:   models.CRAPass,
				Details:  "Pass",
				Severity: models.SeverityHigh,
			},
			{
				ID:       "CRA-002",
				Title:    "Check 2",
				Article:  "Article 13",
				Status:   models.CRAFail,
				Details:  "Fail",
				Severity: models.SeverityCritical,
			},
		},
	}

	buf := new(bytes.Buffer)
	err := WriteCRASARIF(context.Background(), buf, result)
	if err != nil {
		t.Fatalf("WriteCRASARIF failed: %v", err)
	}

	var log sarifLog
	if err := json.Unmarshal(buf.Bytes(), &log); err != nil {
		t.Fatalf("Output is not valid JSON: %v", err)
	}

	// Both checks should be in rules.
	if len(log.Runs[0].Tool.Driver.Rules) != 2 {
		t.Errorf("Expected 2 rules, got %d", len(log.Runs[0].Tool.Driver.Rules))
	}

	ruleIDs := make(map[string]bool)
	for _, rule := range log.Runs[0].Tool.Driver.Rules {
		ruleIDs[rule.ID] = true
	}

	if !ruleIDs["CRA-001"] {
		t.Error("Expected CRA-001 in rules")
	}
	if !ruleIDs["CRA-002"] {
		t.Error("Expected CRA-002 in rules")
	}
}

func TestWriteCRASARIF_severity_mapping(t *testing.T) {
	tests := []struct {
		severity models.Severity
		status   models.CRACheckStatus
		expected string
	}{
		{models.SeverityCritical, models.CRAFail, "error"},
		{models.SeverityHigh, models.CRAFail, "error"},
		{models.SeverityMedium, models.CRAFail, "warning"},
		{models.SeverityLow, models.CRAFail, "note"},
		{models.SeverityNone, models.CRAFail, "note"},
		// Warn status should always be "warning" regardless of severity.
		{models.SeverityCritical, models.CRAWarn, "warning"},
		{models.SeverityMedium, models.CRAWarn, "warning"},
		{models.SeverityLow, models.CRAWarn, "warning"},
	}

	for _, tt := range tests {
		result := models.CRAResult{
			ProductName:  "test",
			Version:      "1.0.0",
			Date:         time.Now().UTC(),
			Regulation:   "EU Cyber Resilience Act (Regulation (EU) 2024/2847)",
			OverallScore: 0,
			Checks: []models.CRACheck{
				{
					ID:       "TEST",
					Title:    "Test",
					Article:  "Article 14",
					Status:   tt.status,
					Details:  "Test",
					Severity: tt.severity,
				},
			},
		}

		buf := new(bytes.Buffer)
		err := WriteCRASARIF(context.Background(), buf, result)
		if err != nil {
			t.Fatalf("WriteCRASARIF failed for %s/%s: %v", tt.severity, tt.status, err)
		}

		var log sarifLog
		if err := json.Unmarshal(buf.Bytes(), &log); err != nil {
			t.Fatalf("Invalid JSON for %s/%s: %v", tt.severity, tt.status, err)
		}

		if len(log.Runs[0].Results) > 0 {
			got := log.Runs[0].Results[0].Level
			if got != tt.expected {
				t.Errorf("Severity %s / Status %s: expected level %s, got %s",
					tt.severity, tt.status, tt.expected, got)
			}
		}
	}
}

func TestArticleToURI(t *testing.T) {
	tests := []struct {
		article  string
		expected string
	}{
		{"Article 14", "https://eur-lex.europa.eu/eli/reg/2024/2847/oj#article-14"},
		{"Article 13", "https://eur-lex.europa.eu/eli/reg/2024/2847/oj#article-13"},
		{"Article 12", "https://eur-lex.europa.eu/eli/reg/2024/2847/oj#article-12"},
		{"", "https://eur-lex.europa.eu/eli/reg/2024/2847/oj"},
	}

	for _, tt := range tests {
		got := articleToURI(tt.article)
		if got != tt.expected {
			t.Errorf("articleToURI(%q) = %q, expected %q", tt.article, got, tt.expected)
		}
	}
}

func TestSanitizeRuleName(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"Vulnerability Disclosure Policy", "Vulnerability-Disclosure-Policy"},
		{"Check (with) parentheses", "Check-with-parentheses"},
		{"Path/to/something", "Path-to-something"},
		{"Simple", "Simple"},
	}

	for _, tt := range tests {
		got := sanitizeRuleName(tt.input)
		if got != tt.expected {
			t.Errorf("sanitizeRuleName(%q) = %q, expected %q", tt.input, got, tt.expected)
		}
	}
}
