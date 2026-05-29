package trend

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/chainsaw-dev/chainsaw/pkg/models"
)

func TestSaveAndLoadHistory(t *testing.T) {
	tmpDir := t.TempDir()

	// Create three CRA results with different scores.
	results := []models.CRAResult{
		{
			ProductName:  "test-app",
			Version:      "1.0.0",
			Date:         time.Date(2026, 5, 27, 10, 0, 0, 0, time.UTC),
			OverallScore: 60,
			Checks: []models.CRACheck{
				{ID: "1", Status: models.CRAPass},
				{ID: "2", Status: models.CRAPass},
				{ID: "3", Status: models.CRAFail},
			},
		},
		{
			ProductName:  "test-app",
			Version:      "1.0.1",
			Date:         time.Date(2026, 5, 28, 10, 0, 0, 0, time.UTC),
			OverallScore: 70,
			Checks: []models.CRACheck{
				{ID: "1", Status: models.CRAPass},
				{ID: "2", Status: models.CRAPass},
				{ID: "3", Status: models.CRAPass},
			},
		},
		{
			ProductName:  "test-app",
			Version:      "1.0.2",
			Date:         time.Date(2026, 5, 29, 10, 0, 0, 0, time.UTC),
			OverallScore: 75,
			Checks: []models.CRACheck{
				{ID: "1", Status: models.CRAPass},
				{ID: "2", Status: models.CRAPass},
				{ID: "3", Status: models.CRAPass},
				{ID: "4", Status: models.CRAWarn},
			},
		},
	}

	// Save all results.
	for _, result := range results {
		if err := SaveResult(tmpDir, result); err != nil {
			t.Fatalf("SaveResult failed: %v", err)
		}
	}

	// Load history.
	history, err := LoadHistory(tmpDir)
	if err != nil {
		t.Fatalf("LoadHistory failed: %v", err)
	}

	// Verify count and order.
	if len(history) != 3 {
		t.Errorf("expected 3 entries, got %d", len(history))
	}

	// Verify chronological order.
	for i := 0; i < len(history)-1; i++ {
		if history[i].Date.After(history[i+1].Date) {
			t.Errorf("entries not in chronological order: %v > %v", history[i].Date, history[i+1].Date)
		}
	}

	// Verify scores.
	expectedScores := []int{60, 70, 75}
	for i, expected := range expectedScores {
		if history[i].OverallScore != expected {
			t.Errorf("entry %d: expected score %d, got %d", i, expected, history[i].OverallScore)
		}
	}

	// Verify pass/fail/warn counts for last entry.
	if history[2].PassCount != 3 {
		t.Errorf("expected 3 passes, got %d", history[2].PassCount)
	}
	if history[2].WarnCount != 1 {
		t.Errorf("expected 1 warning, got %d", history[2].WarnCount)
	}
	if history[2].TotalChecks != 4 {
		t.Errorf("expected 4 total checks, got %d", history[2].TotalChecks)
	}
}

func TestLoadHistory_emptyDir(t *testing.T) {
	tmpDir := t.TempDir()

	// Load from non-existent directory.
	history, err := LoadHistory(tmpDir)
	if err != nil {
		t.Fatalf("LoadHistory should not error on missing dir: %v", err)
	}

	if history != nil {
		t.Errorf("expected nil slice for empty history, got %v", history)
	}
}

func TestLoadHistory_ignoresNonJSON(t *testing.T) {
	tmpDir := t.TempDir()

	// Create history directory with mixed files.
	histDir := filepath.Join(tmpDir, historyDir)
	if err := os.MkdirAll(histDir, 0755); err != nil {
		t.Fatalf("failed to create history dir: %v", err)
	}

	// Write a valid JSON entry.
	validEntry := TrendEntry{
		Date:         time.Date(2026, 5, 27, 10, 0, 0, 0, time.UTC),
		OverallScore: 60,
		PassCount:    2,
		FailCount:    1,
		WarnCount:    0,
		TotalChecks:  3,
	}
	data, _ := json.Marshal(validEntry)
	if err := os.WriteFile(filepath.Join(histDir, "cra-2026-05-27T100000.json"), data, 0644); err != nil {
		t.Fatalf("failed to write valid entry: %v", err)
	}

	// Write a non-JSON file.
	if err := os.WriteFile(filepath.Join(histDir, "readme.txt"), []byte("ignore me"), 0644); err != nil {
		t.Fatalf("failed to write non-JSON file: %v", err)
	}

	// Write a subdirectory.
	if err := os.Mkdir(filepath.Join(histDir, "subdir"), 0755); err != nil {
		t.Fatalf("failed to create subdir: %v", err)
	}

	// Load history.
	history, err := LoadHistory(tmpDir)
	if err != nil {
		t.Fatalf("LoadHistory failed: %v", err)
	}

	// Should only load the JSON file.
	if len(history) != 1 {
		t.Errorf("expected 1 entry, got %d", len(history))
	}
	if history[0].OverallScore != 60 {
		t.Errorf("expected score 60, got %d", history[0].OverallScore)
	}
}

func TestFormatTrend_noHistory(t *testing.T) {
	current := TrendEntry{
		Date:         time.Date(2026, 5, 29, 10, 0, 0, 0, time.UTC),
		OverallScore: 75,
		PassCount:    3,
		FailCount:    0,
		WarnCount:    1,
		TotalChecks:  4,
	}

	result := FormatTrend(nil, current)
	if result != "CRA Score: 75% (first assessment, no trend data)" {
		t.Errorf("unexpected format: %s", result)
	}
}

func TestFormatTrend_improvement(t *testing.T) {
	history := []TrendEntry{
		{
			Date:         time.Date(2026, 5, 27, 10, 0, 0, 0, time.UTC),
			OverallScore: 60,
			PassCount:    2,
			FailCount:    1,
			WarnCount:    0,
			TotalChecks:  3,
		},
	}

	current := TrendEntry{
		Date:         time.Date(2026, 5, 29, 10, 0, 0, 0, time.UTC),
		OverallScore: 75,
		PassCount:    3,
		FailCount:    0,
		WarnCount:    1,
		TotalChecks:  4,
	}

	result := FormatTrend(history, current)
	expected := "CRA Score: 75% (+15% improvement since 2026-05-27)"
	if result != expected {
		t.Errorf("expected %q, got %q", expected, result)
	}
}

func TestFormatTrend_regression(t *testing.T) {
	history := []TrendEntry{
		{
			Date:         time.Date(2026, 5, 27, 10, 0, 0, 0, time.UTC),
			OverallScore: 80,
			PassCount:    4,
			FailCount:    0,
			WarnCount:    0,
			TotalChecks:  4,
		},
	}

	current := TrendEntry{
		Date:         time.Date(2026, 5, 29, 10, 0, 0, 0, time.UTC),
		OverallScore: 65,
		PassCount:    2,
		FailCount:    1,
		WarnCount:    1,
		TotalChecks:  4,
	}

	result := FormatTrend(history, current)
	expected := "CRA Score: 65% (-15% regression since 2026-05-27)"
	if result != expected {
		t.Errorf("expected %q, got %q", expected, result)
	}
}

func TestFormatTrend_unchanged(t *testing.T) {
	history := []TrendEntry{
		{
			Date:         time.Date(2026, 5, 27, 10, 0, 0, 0, time.UTC),
			OverallScore: 70,
			PassCount:    3,
			FailCount:    0,
			WarnCount:    1,
			TotalChecks:  4,
		},
	}

	current := TrendEntry{
		Date:         time.Date(2026, 5, 29, 10, 0, 0, 0, time.UTC),
		OverallScore: 70,
		PassCount:    3,
		FailCount:    0,
		WarnCount:    1,
		TotalChecks:  4,
	}

	result := FormatTrend(history, current)
	expected := "CRA Score: 70% (unchanged since 2026-05-27)"
	if result != expected {
		t.Errorf("expected %q, got %q", expected, result)
	}
}

func TestToEntry(t *testing.T) {
	result := models.CRAResult{
		ProductName:  "test-app",
		Version:      "1.0.0",
		Date:         time.Date(2026, 5, 29, 10, 0, 0, 0, time.UTC),
		OverallScore: 75,
		Checks: []models.CRACheck{
			{ID: "1", Status: models.CRAPass},
			{ID: "2", Status: models.CRAPass},
			{ID: "3", Status: models.CRAFail},
			{ID: "4", Status: models.CRAWarn},
			{ID: "5", Status: models.CRANA},
		},
	}

	entry := toEntry(result)

	if entry.Date != result.Date {
		t.Errorf("date mismatch: %v != %v", entry.Date, result.Date)
	}
	if entry.OverallScore != 75 {
		t.Errorf("score mismatch: %d != 75", entry.OverallScore)
	}
	if entry.PassCount != 2 {
		t.Errorf("pass count: expected 2, got %d", entry.PassCount)
	}
	if entry.FailCount != 1 {
		t.Errorf("fail count: expected 1, got %d", entry.FailCount)
	}
	if entry.WarnCount != 1 {
		t.Errorf("warn count: expected 1, got %d", entry.WarnCount)
	}
	if entry.TotalChecks != 5 {
		t.Errorf("total checks: expected 5, got %d", entry.TotalChecks)
	}
}
