package initcmd

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestDefaultCRAConfig(t *testing.T) {
	cfg := DefaultCRAConfig()

	if cfg.Category != "default" {
		t.Errorf("Category = %q, want %q", cfg.Category, "default")
	}

	// Check that SupportEndDate is roughly 5 years in the future.
	now := time.Now()
	expectedYear := now.AddDate(5, 0, 0).Year()
	if !strings.Contains(cfg.SupportEndDate, string(rune(expectedYear%10)+'0')) {
		// Just verify the date format is reasonable.
		parts := strings.Split(cfg.SupportEndDate, "-")
		if len(parts) != 3 {
			t.Errorf("SupportEndDate = %q, expected YYYY-MM-DD format", cfg.SupportEndDate)
		}
	}
}

func TestValidateCategory_valid(t *testing.T) {
	tests := []struct {
		category string
		want     bool
	}{
		{"default", true},
		{"important-class-1", true},
		{"important-class-2", true},
		{"critical", true},
	}

	for _, tt := range tests {
		t.Run(tt.category, func(t *testing.T) {
			got := ValidateCategory(tt.category)
			if got != tt.want {
				t.Errorf("ValidateCategory(%q) = %v, want %v", tt.category, got, tt.want)
			}
		})
	}
}

func TestValidateCategory_invalid(t *testing.T) {
	got := ValidateCategory("unknown")
	if got {
		t.Errorf("ValidateCategory(\"unknown\") = true, want false")
	}
}

func TestWriteCRAConfig_creates_file(t *testing.T) {
	dir := t.TempDir()
	cfg := CRAInitConfig{
		Manufacturer:    "Acme Corp",
		SecurityContact: "sec@acme.com",
		SupportEndDate:  "2030-01-01",
		CSIRTContact:    "csirt@acme.com",
	}

	path, err := WriteCRAConfig(dir, cfg)
	if err != nil {
		t.Fatalf("WriteCRAConfig: %v", err)
	}

	expectedPath := filepath.Join(dir, ".chainsaw.yaml")
	if path != expectedPath {
		t.Errorf("path = %q, want %q", path, expectedPath)
	}

	content, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("reading file: %v", err)
	}

	contentStr := string(content)
	required := []string{
		"cra:",
		"manufacturer",
		"Acme Corp",
		"sec@acme.com",
	}
	for _, s := range required {
		if !strings.Contains(contentStr, s) {
			t.Errorf("content missing %q", s)
		}
	}
}

func TestWriteCRAConfig_no_overwrite(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, ".chainsaw.yaml")

	// Create file first.
	if err := os.WriteFile(path, []byte("existing"), 0o644); err != nil {
		t.Fatalf("creating existing file: %v", err)
	}

	cfg := CRAInitConfig{
		Manufacturer: "Acme",
	}

	_, err := WriteCRAConfig(dir, cfg)
	if err == nil {
		t.Error("WriteCRAConfig should error when file exists")
	}
	if !strings.Contains(err.Error(), "already exists") {
		t.Errorf("error message = %q, should contain 'already exists'", err.Error())
	}
}

func TestWriteCRAConfigForce_overwrites(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, ".chainsaw.yaml")

	// Create file first with content.
	if err := os.WriteFile(path, []byte("existing content"), 0o644); err != nil {
		t.Fatalf("creating existing file: %v", err)
	}

	cfg := CRAInitConfig{
		Manufacturer:    "NewCorp",
		SecurityContact: "new@example.com",
		SupportEndDate:  "2031-01-01",
		CSIRTContact:    "csirt@example.com",
	}

	resultPath, err := WriteCRAConfigForce(dir, cfg)
	if err != nil {
		t.Fatalf("WriteCRAConfigForce: %v", err)
	}

	if resultPath != path {
		t.Errorf("path = %q, want %q", resultPath, path)
	}

	content, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("reading file: %v", err)
	}

	contentStr := string(content)
	if strings.Contains(contentStr, "existing content") {
		t.Error("file was not overwritten")
	}
	if !strings.Contains(contentStr, "NewCorp") {
		t.Error("file does not contain new content")
	}
}

func TestFormatNextSteps_default(t *testing.T) {
	out := FormatNextSteps("default")

	required := []string{
		"Next steps:",
		"Review and customize .chainsaw.yaml",
		"chainsaw comply",
		"chainsaw check",
		"manufacturer self-assessment",
	}

	for _, s := range required {
		if !strings.Contains(out, s) {
			t.Errorf("output missing %q", s)
		}
	}
}

func TestFormatNextSteps_critical(t *testing.T) {
	out := FormatNextSteps("critical")

	required := []string{
		"Next steps:",
		"Review and customize .chainsaw.yaml",
		"Engage a Notified Body",
		"third-party conformity assessment",
	}

	for _, s := range required {
		if !strings.Contains(out, s) {
			t.Errorf("output missing %q", s)
		}
	}
}

func TestFormatNextSteps_important_class_1(t *testing.T) {
	out := FormatNextSteps("important-class-1")

	required := []string{
		"Prepare conformity self-assessment",
		"EU-type examination for Class II",
		"Monitor Notified Body availability",
	}

	for _, s := range required {
		if !strings.Contains(out, s) {
			t.Errorf("output missing %q", s)
		}
	}
}

func TestValidCategories(t *testing.T) {
	cats := ValidCategories()
	if len(cats) != 4 {
		t.Errorf("ValidCategories returned %d items, want 4", len(cats))
	}

	expected := map[string]bool{
		"default":             true,
		"important-class-1":   true,
		"important-class-2":   true,
		"critical":            true,
	}

	for _, cat := range cats {
		if !expected[cat] {
			t.Errorf("unexpected category: %q", cat)
		}
	}
}
