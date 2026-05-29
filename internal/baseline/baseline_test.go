package baseline

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/chainsaw-dev/chainsaw/pkg/models"
)

func TestSave_creates_file(t *testing.T) {
	t.Helper()
	tmpDir := t.TempDir()

	findings := []models.Finding{
		{
			ID:       "CVE-2024-0001",
			Summary:  "Test vuln 1",
			Severity: models.SeverityCritical,
		},
		{
			ID:       "CVE-2024-0002",
			Summary:  "Test vuln 2",
			Severity: models.SeverityHigh,
		},
	}

	hygiene := []models.Finding{
		{
			ID:       "HYG-001",
			Summary:  "Typosquatting",
			Severity: models.SeverityMedium,
		},
	}

	scanResult := models.ScanResult{
		Findings: findings,
		Hygiene:  hygiene,
	}

	err := Save(tmpDir, scanResult)
	if err != nil {
		t.Fatalf("Save failed: %v", err)
	}

	// Verify file exists
	path := filepath.Join(tmpDir, DefaultFile)
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("Baseline file not created: %v", err)
	}

	// Verify contents are valid JSON
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("Failed to read baseline file: %v", err)
	}

	var baseline Baseline
	if err := json.Unmarshal(data, &baseline); err != nil {
		t.Fatalf("Baseline file contains invalid JSON: %v", err)
	}

	if baseline.Version != "1.0" {
		t.Errorf("Expected version 1.0, got %s", baseline.Version)
	}
	if len(baseline.FindingIDs) != 2 {
		t.Errorf("Expected 2 finding IDs, got %d", len(baseline.FindingIDs))
	}
	if len(baseline.HygieneIDs) != 1 {
		t.Errorf("Expected 1 hygiene ID, got %d", len(baseline.HygieneIDs))
	}
	if baseline.Total != 3 {
		t.Errorf("Expected total 3, got %d", baseline.Total)
	}
}

func TestLoad_no_file(t *testing.T) {
	t.Helper()
	tmpDir := t.TempDir()

	baseline, err := Load(tmpDir)
	if err != nil {
		t.Fatalf("Load should not error on missing file: %v", err)
	}
	if baseline != nil {
		t.Errorf("Expected nil baseline, got %v", baseline)
	}
}

func TestLoad_valid_file(t *testing.T) {
	t.Helper()
	tmpDir := t.TempDir()

	findings := []models.Finding{
		{ID: "CVE-2024-0001", Summary: "Test", Severity: models.SeverityCritical},
	}

	scanResult := models.ScanResult{Findings: findings}

	// Save baseline
	if err := Save(tmpDir, scanResult); err != nil {
		t.Fatalf("Save failed: %v", err)
	}

	// Load baseline
	baseline, err := Load(tmpDir)
	if err != nil {
		t.Fatalf("Load failed: %v", err)
	}

	if baseline == nil {
		t.Fatalf("Expected baseline, got nil")
	}
	if baseline.Version != "1.0" {
		t.Errorf("Expected version 1.0, got %s", baseline.Version)
	}
	if len(baseline.FindingIDs) != 1 {
		t.Errorf("Expected 1 finding ID, got %d", len(baseline.FindingIDs))
	}
	if baseline.FindingIDs[0] != "CVE-2024-0001" {
		t.Errorf("Expected CVE-2024-0001, got %s", baseline.FindingIDs[0])
	}
}

func TestFilterNew_no_baseline(t *testing.T) {
	t.Helper()

	findings := []models.Finding{
		{ID: "CVE-2024-0001", Summary: "Test 1", Severity: models.SeverityCritical},
		{ID: "CVE-2024-0002", Summary: "Test 2", Severity: models.SeverityHigh},
	}

	newFindings, baselinedCount := FilterNew(findings, nil)

	if len(newFindings) != 2 {
		t.Errorf("Expected 2 new findings, got %d", len(newFindings))
	}
	if baselinedCount != 0 {
		t.Errorf("Expected 0 baselined, got %d", baselinedCount)
	}
}

func TestFilterNew_filters_known(t *testing.T) {
	t.Helper()

	baseline := &Baseline{
		FindingIDs: []string{"CVE-2024-0001", "CVE-2024-0002"},
		HygieneIDs: []string{"HYG-001"},
	}

	findings := []models.Finding{
		{ID: "CVE-2024-0001", Summary: "Test 1", Severity: models.SeverityCritical},
		{ID: "CVE-2024-0002", Summary: "Test 2", Severity: models.SeverityHigh},
		{ID: "CVE-2024-0003", Summary: "Test 3", Severity: models.SeverityMedium},
		{ID: "HYG-001", Summary: "Typo", Severity: models.SeverityLow},
		{ID: "HYG-002", Summary: "New Typo", Severity: models.SeverityLow},
	}

	newFindings, baselinedCount := FilterNew(findings, baseline)

	if len(newFindings) != 2 {
		t.Errorf("Expected 2 new findings, got %d", len(newFindings))
	}
	if baselinedCount != 3 {
		t.Errorf("Expected 3 baselined, got %d", baselinedCount)
	}

	// Verify new findings are the right ones
	if newFindings[0].ID != "CVE-2024-0003" {
		t.Errorf("Expected first new finding to be CVE-2024-0003, got %s", newFindings[0].ID)
	}
	if newFindings[1].ID != "HYG-002" {
		t.Errorf("Expected second new finding to be HYG-002, got %s", newFindings[1].ID)
	}
}

func TestUpdate_preserves_created_at(t *testing.T) {
	t.Helper()
	tmpDir := t.TempDir()

	// Save initial baseline
	findings1 := []models.Finding{
		{ID: "CVE-2024-0001", Summary: "Test 1", Severity: models.SeverityCritical},
	}
	scanResult1 := models.ScanResult{Findings: findings1}

	if err := Save(tmpDir, scanResult1); err != nil {
		t.Fatalf("Save failed: %v", err)
	}

	// Load and verify initial created_at
	initial, err := Load(tmpDir)
	if err != nil {
		t.Fatalf("Load failed: %v", err)
	}
	initialCreatedAt := initial.CreatedAt

	// Sleep briefly to ensure time difference
	time.Sleep(10 * time.Millisecond)

	// Update baseline with new findings
	findings2 := []models.Finding{
		{ID: "CVE-2024-0001", Summary: "Test 1", Severity: models.SeverityCritical},
		{ID: "CVE-2024-0002", Summary: "Test 2", Severity: models.SeverityHigh},
	}
	scanResult2 := models.ScanResult{Findings: findings2}

	if err := Update(tmpDir, scanResult2); err != nil {
		t.Fatalf("Update failed: %v", err)
	}

	// Load updated baseline and verify created_at was preserved
	updated, err := Load(tmpDir)
	if err != nil {
		t.Fatalf("Load after update failed: %v", err)
	}

	if updated.CreatedAt != initialCreatedAt {
		t.Errorf("CreatedAt changed after update: %v -> %v", initialCreatedAt, updated.CreatedAt)
	}

	// Verify updated_at was changed
	if updated.UpdatedAt == initial.UpdatedAt {
		t.Errorf("UpdatedAt should have changed")
	}

	// Verify new findings were added
	if len(updated.FindingIDs) != 2 {
		t.Errorf("Expected 2 findings after update, got %d", len(updated.FindingIDs))
	}
}

func TestUpdate_creates_new_baseline_if_not_exists(t *testing.T) {
	t.Helper()
	tmpDir := t.TempDir()

	findings := []models.Finding{
		{ID: "CVE-2024-0001", Summary: "Test 1", Severity: models.SeverityCritical},
	}
	scanResult := models.ScanResult{Findings: findings}

	// Update on non-existent baseline should create it
	if err := Update(tmpDir, scanResult); err != nil {
		t.Fatalf("Update on non-existent baseline failed: %v", err)
	}

	// Verify file was created
	baseline, err := Load(tmpDir)
	if err != nil {
		t.Fatalf("Load after update failed: %v", err)
	}

	if baseline == nil {
		t.Fatalf("Expected baseline to be created, got nil")
	}
	if len(baseline.FindingIDs) != 1 {
		t.Errorf("Expected 1 finding, got %d", len(baseline.FindingIDs))
	}
}
