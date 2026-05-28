package report

import (
	"bytes"
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/chainsaw-dev/chainsaw/pkg/models"
)

func TestWriteSARIF(t *testing.T) {
	var buf bytes.Buffer
	result := models.ScanResult{
		Timestamp:   time.Date(2025, 1, 15, 10, 0, 0, 0, time.UTC),
		ToolVersion: "0.1.0",
	}
	if err := WriteSARIF(context.Background(), &buf, result); err != nil {
		t.Fatalf("WriteSARIF error: %v", err)
	}

	var decoded map[string]interface{}
	if err := json.Unmarshal(buf.Bytes(), &decoded); err != nil {
		t.Fatalf("output is not valid JSON: %v", err)
	}
	if v, ok := decoded["version"].(string); !ok || v != "2.1.0" {
		t.Errorf("SARIF version = %v, want %q", decoded["version"], "2.1.0")
	}
	if _, ok := decoded["$schema"].(string); !ok {
		t.Error("SARIF output missing $schema")
	}
}

func TestWriteSARIF_WithFindings(t *testing.T) {
	var buf bytes.Buffer
	result := models.ScanResult{
		Findings: []models.Finding{{
			ID:       "GHSA-TEST",
			Summary:  "Test vuln",
			Severity: models.SeverityHigh,
			Component: models.Component{
				Name:    "lodash",
				Version: "4.17.21",
				PkgURL:  "pkg:npm/lodash@4.17.21",
			},
		}},
		Hygiene: []models.Finding{{
			ID:       "INTEGRITY-npm-express-4.18.0",
			Summary:  "Missing integrity hash",
			Severity: models.SeverityMedium,
			Component: models.Component{
				Name:    "express",
				Version: "4.18.0",
			},
		}},
		Timestamp:   time.Date(2025, 1, 15, 10, 0, 0, 0, time.UTC),
		ToolVersion: "0.1.0",
	}
	if err := WriteSARIF(context.Background(), &buf, result); err != nil {
		t.Fatalf("WriteSARIF error: %v", err)
	}

	var decoded sarifLog
	if err := json.Unmarshal(buf.Bytes(), &decoded); err != nil {
		t.Fatalf("output is not valid SARIF JSON: %v", err)
	}
	if len(decoded.Runs) != 1 {
		t.Fatalf("expected 1 run, got %d", len(decoded.Runs))
	}
	run := decoded.Runs[0]
	if len(run.Results) != 2 {
		t.Errorf("expected 2 results, got %d", len(run.Results))
	}
	if len(run.Tool.Driver.Rules) != 2 {
		t.Errorf("expected 2 rules, got %d", len(run.Tool.Driver.Rules))
	}
	if run.Results[0].RuleID != "GHSA-TEST" {
		t.Errorf("first result ruleId = %q, want %q", run.Results[0].RuleID, "GHSA-TEST")
	}
	if run.Results[0].Level != "error" {
		t.Errorf("HIGH severity should map to SARIF level 'error', got %q", run.Results[0].Level)
	}
	if run.Results[1].Level != "warning" {
		t.Errorf("MEDIUM severity should map to SARIF level 'warning', got %q", run.Results[1].Level)
	}
}

func TestWriteSARIF_EnrichedFields(t *testing.T) {
	var buf bytes.Buffer
	result := models.ScanResult{
		Findings: []models.Finding{{
			ID:       "GHSA-ENRICH",
			Summary:  "Enriched vuln",
			Details:  "A detailed description of the vulnerability.",
			Severity: models.SeverityCritical,
			FixedIn:  "2.0.0",
			Component: models.Component{
				Name:    "example-pkg",
				Version: "1.0.0",
				PkgURL:  "pkg:npm/example-pkg@1.0.0",
			},
		}},
		Timestamp:   time.Date(2025, 6, 1, 12, 0, 0, 0, time.UTC),
		ToolVersion: "0.2.0",
	}
	if err := WriteSARIF(context.Background(), &buf, result); err != nil {
		t.Fatalf("WriteSARIF error: %v", err)
	}

	var decoded sarifLog
	if err := json.Unmarshal(buf.Bytes(), &decoded); err != nil {
		t.Fatalf("output is not valid SARIF JSON: %v", err)
	}

	run := decoded.Runs[0]
	driver := run.Tool.Driver

	// Tool metadata
	if driver.InformationURI != "https://github.com/chainsaw-dev/chainsaw" {
		t.Errorf("informationUri = %q, want GitHub URL", driver.InformationURI)
	}
	if driver.SemanticVersion != "0.2.0" {
		t.Errorf("semanticVersion = %q, want %q", driver.SemanticVersion, "0.2.0")
	}

	// Rule enrichments
	if len(driver.Rules) != 1 {
		t.Fatalf("expected 1 rule, got %d", len(driver.Rules))
	}
	rule := driver.Rules[0]
	if rule.HelpURI != "https://osv.dev/vulnerability/GHSA-ENRICH" {
		t.Errorf("helpUri = %q, want OSV URL", rule.HelpURI)
	}
	if rule.Help == nil {
		t.Fatal("help is nil, expected remediation guidance")
	}
	if rule.Help.Markdown == "" {
		t.Error("help.markdown is empty")
	}

	// Result enrichments
	r := run.Results[0]
	if r.Message.Markdown == "" {
		t.Error("result message.markdown is empty")
	}
	fp, ok := r.Fingerprints["primaryLocationLineHash"]
	if !ok || fp == "" {
		t.Error("fingerprints.primaryLocationLineHash missing or empty")
	}
}
