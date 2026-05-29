package cra

import (
	"bytes"
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/chainsaw-dev/chainsaw/pkg/models"
)

func sampleResult(score int, checks []models.CRACheck) models.CRAResult {
	return models.CRAResult{
		ProductName:  "TestProduct",
		Version:      "1.0.0",
		Date:         time.Date(2026, 1, 15, 0, 0, 0, 0, time.UTC),
		Regulation:   "EU Cyber Resilience Act (Regulation (EU) 2024/2847)",
		OverallScore: score,
		Checks:       checks,
		NextDeadline: "2026-09-11",
		NextDeadDesc: "Article 14 reporting obligations",
	}
}

func TestWriteComplianceReport(t *testing.T) {
	checks := []models.CRACheck{
		{ID: "sbom-exists", Title: "SBOM exists", Article: "Annex I", Status: models.CRAPass, Details: "2 components.", Severity: models.SeverityCritical},
		{ID: "vuln-none-critical", Title: "No critical vulns", Article: "Annex I", Status: models.CRAFail, Details: "1 critical.", Severity: models.SeverityCritical, Remediation: "Fix it."},
	}
	result := sampleResult(50, checks)

	var buf bytes.Buffer
	err := WriteComplianceReport(context.Background(), &buf, result)
	if err != nil {
		t.Fatalf("WriteComplianceReport error: %v", err)
	}

	out := buf.String()
	for _, want := range []string{"CRA Compliance Assessment", "[PASS]", "[FAIL]", "50%"} {
		if !strings.Contains(out, want) {
			t.Errorf("output missing %q", want)
		}
	}
}

func TestWriteComplianceJSON(t *testing.T) {
	checks := []models.CRACheck{
		{ID: "sbom-exists", Title: "SBOM exists", Article: "Annex I", Status: models.CRAPass, Details: "ok", Severity: models.SeverityCritical},
	}
	result := sampleResult(80, checks)

	var buf bytes.Buffer
	err := WriteComplianceJSON(context.Background(), &buf, result)
	if err != nil {
		t.Fatalf("WriteComplianceJSON error: %v", err)
	}

	var parsed models.CRAResult
	if err := json.Unmarshal(buf.Bytes(), &parsed); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}
	if parsed.OverallScore != 80 {
		t.Errorf("score = %d, want 80", parsed.OverallScore)
	}
	if parsed.ProductName != "TestProduct" {
		t.Errorf("product = %q, want TestProduct", parsed.ProductName)
	}
}

func TestWriteComplianceReport_AllPass(t *testing.T) {
	checks := []models.CRACheck{
		{ID: "a", Title: "Check A", Article: "Art 1", Status: models.CRAPass, Details: "ok", Severity: models.SeverityMedium},
		{ID: "b", Title: "Check B", Article: "Art 1", Status: models.CRAPass, Details: "ok", Severity: models.SeverityMedium},
	}
	result := sampleResult(100, checks)

	var buf bytes.Buffer
	if err := WriteComplianceReport(context.Background(), &buf, result); err != nil {
		t.Fatal(err)
	}
	out := buf.String()
	if !strings.Contains(out, "100%") {
		t.Error("output missing 100% score")
	}
	// No recommendations when all pass.
	if strings.Contains(out, "Recommendations") {
		t.Error("should not have Recommendations section when all pass")
	}
}

func TestWriteComplianceReport_AllFail(t *testing.T) {
	checks := []models.CRACheck{
		{ID: "a", Title: "Check A", Article: "Art 1", Status: models.CRAFail, Details: "bad", Severity: models.SeverityCritical, Remediation: "Fix A"},
		{ID: "b", Title: "Check B", Article: "Art 1", Status: models.CRAFail, Details: "bad", Severity: models.SeverityHigh, Remediation: "Fix B"},
	}
	result := sampleResult(0, checks)

	var buf bytes.Buffer
	if err := WriteComplianceReport(context.Background(), &buf, result); err != nil {
		t.Fatal(err)
	}
	out := buf.String()
	if !strings.Contains(out, "Recommendations") {
		t.Error("output missing Recommendations section")
	}
	if !strings.Contains(out, "Fix A") {
		t.Error("output missing remediation for Check A")
	}
	if !strings.Contains(out, "Fix B") {
		t.Error("output missing remediation for Check B")
	}
}

func TestWriteComplianceReport_DeadlineCountdown(t *testing.T) {
	checks := []models.CRACheck{
		{ID: "a", Title: "Check A", Article: "Art 1", Status: models.CRAPass, Details: "ok", Severity: models.SeverityMedium},
	}
	result := sampleResult(100, checks)

	var buf bytes.Buffer
	if err := WriteComplianceReport(context.Background(), &buf, result); err != nil {
		t.Fatal(err)
	}
	out := buf.String()
	if !strings.Contains(out, "CRA Compliance Timeline") {
		t.Error("output missing CRA Compliance Timeline header")
	}
	if !strings.Contains(out, "2026-09-11") {
		t.Error("output missing deadline date 2026-09-11")
	}
	if !strings.Contains(out, "days remaining") {
		t.Error("output missing days remaining text")
	}
}

func TestWriteComplianceReport_DeadlineCountdown_NoDeadline(t *testing.T) {
	checks := []models.CRACheck{
		{ID: "a", Title: "Check A", Article: "Art 1", Status: models.CRAPass, Details: "ok", Severity: models.SeverityMedium},
	}
	result := sampleResult(100, checks)
	result.NextDeadline = ""
	result.NextDeadDesc = ""

	var buf bytes.Buffer
	if err := WriteComplianceReport(context.Background(), &buf, result); err != nil {
		t.Fatal(err)
	}
	out := buf.String()
	// CRA timeline is always shown now, regardless of NextDeadline field
	if !strings.Contains(out, "CRA Compliance Timeline") {
		t.Error("output should have CRA Compliance Timeline")
	}
}

func TestWriteComplianceJSON_DeadlineCountdown(t *testing.T) {
	checks := []models.CRACheck{
		{ID: "a", Title: "Check A", Article: "Art 1", Status: models.CRAPass, Details: "ok", Severity: models.SeverityMedium},
	}
	result := sampleResult(100, checks)

	var buf bytes.Buffer
	if err := WriteComplianceJSON(context.Background(), &buf, result); err != nil {
		t.Fatal(err)
	}

	var parsed map[string]interface{}
	if err := json.Unmarshal(buf.Bytes(), &parsed); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}

	if _, ok := parsed["days_remaining"]; !ok {
		t.Error("JSON missing days_remaining field")
	}

	daysRemaining, ok := parsed["days_remaining"].(float64)
	if !ok {
		t.Error("days_remaining is not a number")
	}

	// The deadline is 2026-09-11, which should be positive days from now (2026-05-29).
	if daysRemaining <= 0 {
		t.Errorf("days_remaining should be positive, got %v", daysRemaining)
	}
}

func TestWriteComplianceJSON_DeadlineCountdown_NoDeadline(t *testing.T) {
	checks := []models.CRACheck{
		{ID: "a", Title: "Check A", Article: "Art 1", Status: models.CRAPass, Details: "ok", Severity: models.SeverityMedium},
	}
	result := sampleResult(100, checks)
	result.NextDeadline = ""
	result.NextDeadDesc = ""

	var buf bytes.Buffer
	if err := WriteComplianceJSON(context.Background(), &buf, result); err != nil {
		t.Fatal(err)
	}

	var parsed map[string]interface{}
	if err := json.Unmarshal(buf.Bytes(), &parsed); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}

	// days_remaining should be 0 or omitted when no deadline.
	daysRemaining, ok := parsed["days_remaining"]
	if ok && daysRemaining != float64(0) {
		t.Errorf("days_remaining should be 0 or omitted when no deadline, got %v", daysRemaining)
	}
}
