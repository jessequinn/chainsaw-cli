package engine

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/chainsaw-dev/chainsaw/pkg/models"
)

func TestResolveScanners_Empty(t *testing.T) {
	scanners := ResolveScanners("")
	if len(scanners) == 0 {
		t.Error("expected scanners for empty ecosystem filter, got none")
	}
}

func TestResolveScanners_Filtered(t *testing.T) {
	scanners := ResolveScanners("go")
	if len(scanners) == 0 {
		t.Error("expected at least one scanner for 'go' ecosystem, got none")
	}
	// Verify it's the Go scanner
	if scanners[0].Ecosystem() != models.EcosystemGo {
		t.Errorf("expected Go ecosystem, got %s", scanners[0].Ecosystem())
	}
}

func TestResolveScanners_MultipleEcosystems(t *testing.T) {
	scanners := ResolveScanners("go,npm")
	if len(scanners) < 2 {
		t.Errorf("expected at least 2 scanners for 'go,npm', got %d", len(scanners))
	}
}

func TestLoadPolicy_DefaultFile(t *testing.T) {
	dir := t.TempDir()
	oldCwd, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}
	defer os.Chdir(oldCwd)

	if err := os.Chdir(dir); err != nil {
		t.Fatalf("chdir: %v", err)
	}

	// Create a default policy file
	content := `
fail_on: HIGH
`
	if err := os.WriteFile(".chainsaw.yaml", []byte(content), 0644); err != nil {
		t.Fatalf("write policy file: %v", err)
	}

	p, err := LoadPolicy(context.Background(), "")
	if err != nil {
		t.Fatalf("LoadPolicy returned error: %v", err)
	}
	if p.FailOn != models.SeverityHigh {
		t.Errorf("FailOn = %q, want %q", p.FailOn, models.SeverityHigh)
	}
}

func TestLoadPolicy_ExplicitPath(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, ".chainsaw.yaml")
	content := `
fail_on: CRITICAL
`
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatalf("write policy file: %v", err)
	}

	p, err := LoadPolicy(context.Background(), path)
	if err != nil {
		t.Fatalf("LoadPolicy returned error: %v", err)
	}
	if p.FailOn != models.SeverityCritical {
		t.Errorf("FailOn = %q, want %q", p.FailOn, models.SeverityCritical)
	}
}

func TestLoadPolicy_NoFile(t *testing.T) {
	dir := t.TempDir()
	oldCwd, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}
	defer os.Chdir(oldCwd)

	if err := os.Chdir(dir); err != nil {
		t.Fatalf("chdir: %v", err)
	}

	// No policy file exists
	p, err := LoadPolicy(context.Background(), "")
	if err != nil {
		t.Fatalf("LoadPolicy returned error: %v", err)
	}
	if p == nil {
		t.Error("expected default policy, got nil")
	}
	if p.FailOn != models.SeverityNone {
		t.Errorf("FailOn = %q, want %q", p.FailOn, models.SeverityNone)
	}
}

func TestDefaultPolicy(t *testing.T) {
	p := DefaultPolicy()
	if p == nil {
		t.Error("expected policy, got nil")
	}
	if p.FailOn != models.SeverityNone {
		t.Errorf("FailOn = %q, want %q", p.FailOn, models.SeverityNone)
	}
}
