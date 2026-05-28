package policy

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/chainsaw-dev/chainsaw/pkg/models"
)

func TestLoadPolicy(t *testing.T) {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, ".chainsaw.yaml")
	content := `
fail_on: HIGH
ignore:
  - CVE-2024-0001
licenses:
  deny:
    - GPL-3.0
`
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatalf("write temp file: %v", err)
	}

	p, err := LoadPolicy(context.Background(), path)
	if err != nil {
		t.Fatalf("LoadPolicy returned error: %v", err)
	}
	if p.FailOn != models.SeverityHigh {
		t.Errorf("FailOn = %q, want %q", p.FailOn, models.SeverityHigh)
	}
	if len(p.Ignore) != 1 || p.Ignore[0] != "CVE-2024-0001" {
		t.Errorf("Ignore = %v, want [CVE-2024-0001]", p.Ignore)
	}
	if len(p.Licenses.Deny) != 1 || p.Licenses.Deny[0] != "GPL-3.0" {
		t.Errorf("Licenses.Deny = %v, want [GPL-3.0]", p.Licenses.Deny)
	}
}

func TestLoadPolicy_FileNotFound(t *testing.T) {
	_, err := LoadPolicy(context.Background(), "/nonexistent/.chainsaw.yaml")
	if err == nil {
		t.Fatal("expected error for missing file, got nil")
	}
}

func TestDefaultPolicy(t *testing.T) {
	p := DefaultPolicy()
	if p.FailOn != models.SeverityNone {
		t.Errorf("FailOn = %q, want %q", p.FailOn, models.SeverityNone)
	}
	if len(p.Ignore) != 0 {
		t.Errorf("Ignore = %v, want empty", p.Ignore)
	}
	if len(p.Licenses.Deny) != 0 {
		t.Errorf("Licenses.Deny = %v, want empty", p.Licenses.Deny)
	}
}

func TestPolicy_Evaluate_NoFindings(t *testing.T) {
	p := &Policy{FailOn: models.SeverityHigh}
	result := models.ScanResult{}

	violations, code := p.Evaluate(result)
	if code != 0 {
		t.Errorf("exit code = %d, want 0", code)
	}
	if len(violations) != 0 {
		t.Errorf("expected 0 violations, got %d", len(violations))
	}
}

func TestPolicy_Evaluate_FailOnSeverity(t *testing.T) {
	tests := []struct {
		name      string
		failOn    models.Severity
		severity  models.Severity
		wantCode  int
		wantCount int
	}{
		{"critical above high threshold", models.SeverityHigh, models.SeverityCritical, 1, 1},
		{"high meets high threshold", models.SeverityHigh, models.SeverityHigh, 1, 1},
		{"medium below high threshold", models.SeverityHigh, models.SeverityMedium, 0, 0},
		{"low below medium threshold", models.SeverityMedium, models.SeverityLow, 0, 0},
		{"critical above low threshold", models.SeverityLow, models.SeverityCritical, 1, 1},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := &Policy{FailOn: tt.failOn}
			result := models.ScanResult{
				Findings: []models.Finding{{
					ID:       "GHSA-TEST",
					Severity: tt.severity,
					Component: models.Component{
						Name:    "pkg",
						Version: "1.0.0",
					},
				}},
			}
			violations, code := p.Evaluate(result)
			if code != tt.wantCode {
				t.Errorf("exit code = %d, want %d", code, tt.wantCode)
			}
			if len(violations) != tt.wantCount {
				t.Errorf("violations count = %d, want %d", len(violations), tt.wantCount)
			}
		})
	}
}

func TestPolicy_Evaluate_IgnoredCVE(t *testing.T) {
	p := &Policy{
		FailOn: models.SeverityLow,
		Ignore: []string{"GHSA-IGNORE"},
	}
	result := models.ScanResult{
		Findings: []models.Finding{{
			ID:       "GHSA-IGNORE",
			Severity: models.SeverityCritical,
			Component: models.Component{
				Name:    "pkg",
				Version: "1.0.0",
			},
		}},
	}

	violations, code := p.Evaluate(result)
	if code != 0 {
		t.Errorf("exit code = %d, want 0 (ignored CVE)", code)
	}
	if len(violations) != 0 {
		t.Errorf("expected 0 violations, got %d", len(violations))
	}
}

func TestPolicy_Evaluate_DeniedLicence(t *testing.T) {
	p := &Policy{
		FailOn:   models.SeverityHigh,
		Licenses: LicensePolicy{Deny: []string{"GPL-3.0"}},
	}
	result := models.ScanResult{
		Components: []models.Component{{
			Name:      "badlib",
			Version:   "2.0.0",
			Ecosystem: models.EcosystemNpm,
			Licenses:  []string{"GPL-3.0"},
		}},
	}

	violations, code := p.Evaluate(result)
	if code != 1 {
		t.Errorf("exit code = %d, want 1", code)
	}
	if len(violations) != 1 {
		t.Fatalf("expected 1 violation, got %d", len(violations))
	}
	if violations[0].Source != "policy" {
		t.Errorf("violation source = %q, want %q", violations[0].Source, "policy")
	}
}

func TestLoadPolicy_WithCRASection(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, ".chainsaw.yaml")
	content := `
fail_on: HIGH
cra:
  required-score: 75
  manufacturer: "Acme Corp"
  security-contact: "security@acme.com"
  support-end-date: "2027-12-31"
  csirt-contact: "csirt@acme.com"
`
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatalf("write temp file: %v", err)
	}

	p, err := LoadPolicy(context.Background(), path)
	if err != nil {
		t.Fatalf("LoadPolicy returned error: %v", err)
	}
	if p.CRA.RequiredScore != 75 {
		t.Errorf("CRA.RequiredScore = %d, want 75", p.CRA.RequiredScore)
	}
	if p.CRA.Manufacturer != "Acme Corp" {
		t.Errorf("CRA.Manufacturer = %q, want %q", p.CRA.Manufacturer, "Acme Corp")
	}
	if p.CRA.SecurityContact != "security@acme.com" {
		t.Errorf("CRA.SecurityContact = %q, want %q", p.CRA.SecurityContact, "security@acme.com")
	}
	if p.CRA.SupportEndDate != "2027-12-31" {
		t.Errorf("CRA.SupportEndDate = %q, want %q", p.CRA.SupportEndDate, "2027-12-31")
	}
	if p.CRA.CSIRTContact != "csirt@acme.com" {
		t.Errorf("CRA.CSIRTContact = %q, want %q", p.CRA.CSIRTContact, "csirt@acme.com")
	}
}

func TestLoadPolicy_WithSupplyChainSection(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, ".chainsaw.yaml")
	content := `
fail_on: MEDIUM
supply-chain:
  min-pinning-score: 80
  require-sha-pins: true
`
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatalf("write temp file: %v", err)
	}

	p, err := LoadPolicy(context.Background(), path)
	if err != nil {
		t.Fatalf("LoadPolicy returned error: %v", err)
	}
	if p.SupplyChain.MinPinningScore != 80 {
		t.Errorf("SupplyChain.MinPinningScore = %d, want 80", p.SupplyChain.MinPinningScore)
	}
	if !p.SupplyChain.RequireSHAPins {
		t.Error("SupplyChain.RequireSHAPins = false, want true")
	}
}

func TestPolicy_EvaluateCRA_Pass(t *testing.T) {
	p := &Policy{CRA: CRAPolicy{RequiredScore: 70}}
	result := models.CRAResult{OverallScore: 85}
	pass, reason := p.EvaluateCRA(result)
	if !pass {
		t.Errorf("expected pass, got fail: %s", reason)
	}
}

func TestPolicy_EvaluateCRA_Fail(t *testing.T) {
	p := &Policy{CRA: CRAPolicy{RequiredScore: 70}}
	result := models.CRAResult{OverallScore: 50}
	pass, reason := p.EvaluateCRA(result)
	if pass {
		t.Error("expected fail, got pass")
	}
	if reason == "" {
		t.Error("expected non-empty reason")
	}
}

func TestPolicy_EvaluateSupplyChain_Pass(t *testing.T) {
	p := &Policy{SupplyChain: SupplyChainPolicy{MinPinningScore: 60}}
	result := models.SupplyChainResult{PinningScore: 80}
	pass, reason := p.EvaluateSupplyChain(result)
	if !pass {
		t.Errorf("expected pass, got fail: %s", reason)
	}
}

func TestPolicy_EvaluateSupplyChain_Fail(t *testing.T) {
	p := &Policy{SupplyChain: SupplyChainPolicy{MinPinningScore: 60}}
	result := models.SupplyChainResult{PinningScore: 40}
	pass, reason := p.EvaluateSupplyChain(result)
	if pass {
		t.Error("expected fail, got pass")
	}
	if reason == "" {
		t.Error("expected non-empty reason")
	}
}

func TestDefaultPolicy_V2Fields(t *testing.T) {
	p := DefaultPolicy()
	if p.CRA.RequiredScore != 0 {
		t.Errorf("CRA.RequiredScore = %d, want 0", p.CRA.RequiredScore)
	}
	if p.SupplyChain.MinPinningScore != 0 {
		t.Errorf("SupplyChain.MinPinningScore = %d, want 0", p.SupplyChain.MinPinningScore)
	}
	if p.SupplyChain.RequireSHAPins {
		t.Error("SupplyChain.RequireSHAPins = true, want false")
	}
	if p.Licences.Mode != "deny" {
		t.Errorf("Licences.Mode = %q, want %q", p.Licences.Mode, "deny")
	}
}
