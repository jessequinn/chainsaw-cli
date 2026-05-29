package policy

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/chainsaw-dev/chainsaw/pkg/models"
)

func TestLoadPolicy(t *testing.T) {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, ".chainsaw.yaml")
	content := `
policy:
  fail-on: HIGH
  ignore:
    - CVE-2024-0001
  licences:
    deny-list:
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
	if len(p.Ignore) != 1 || p.Ignore[0].ID != "CVE-2024-0001" {
		t.Errorf("Ignore = %v, want [IgnoreRule{ID: CVE-2024-0001}]", p.Ignore)
	}
	if len(p.Licences.DenyList) != 1 || p.Licences.DenyList[0] != "GPL-3.0" {
		t.Errorf("Licences.DenyList = %v, want [GPL-3.0]", p.Licences.DenyList)
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
	if len(p.Licences.DenyList) != 0 {
		t.Errorf("Licences.DenyList = %v, want empty", p.Licences.DenyList)
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
		Ignore: []IgnoreRule{{ID: "GHSA-IGNORE"}},
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
		Licences: LicencePolicy{DenyList: []string{"GPL-3.0"}},
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
policy:
  fail-on: HIGH
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
policy:
  fail-on: MEDIUM
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

func TestLoadPolicy_invalidSeverity(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, ".chainsaw.yaml")
	content := `
policy:
  fail-on: HIHG
`
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatalf("write temp file: %v", err)
	}

	_, err := LoadPolicy(context.Background(), path)
	if err == nil {
		t.Fatal("expected error for invalid severity, got nil")
	}
	if !contains(err.Error(), "invalid fail_on severity") {
		t.Errorf("error message = %q, want to contain 'invalid fail_on severity'", err.Error())
	}
}

func TestLoadPolicy_invalidCRAScore(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, ".chainsaw.yaml")
	content := `
cra:
  required-score: 150
`
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatalf("write temp file: %v", err)
	}

	_, err := LoadPolicy(context.Background(), path)
	if err == nil {
		t.Fatal("expected error for invalid CRA score, got nil")
	}
	if !contains(err.Error(), "cra.required-score must be between 0 and 100") {
		t.Errorf("error message = %q, want to contain 'cra.required-score must be between 0 and 100'", err.Error())
	}
}

func TestLoadPolicy_invalidSupplyChainScore(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, ".chainsaw.yaml")
	content := `
supply-chain:
  min-pinning-score: -10
`
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatalf("write temp file: %v", err)
	}

	_, err := LoadPolicy(context.Background(), path)
	if err == nil {
		t.Fatal("expected error for invalid supply chain score, got nil")
	}
	if !contains(err.Error(), "supply-chain.min-pinning-score must be between 0 and 100") {
		t.Errorf("error message = %q, want to contain 'supply-chain.min-pinning-score must be between 0 and 100'", err.Error())
	}
}

func TestLoadPolicy_invalidLicenceMode(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, ".chainsaw.yaml")
	content := `
licences:
  mode: "block"
`
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatalf("write temp file: %v", err)
	}

	_, err := LoadPolicy(context.Background(), path)
	if err == nil {
		t.Fatal("expected error for invalid licence mode, got nil")
	}
	if !contains(err.Error(), "licences.mode must be \"allow\" or \"deny\"") {
		t.Errorf("error message = %q, want to contain 'licences.mode must be \"allow\" or \"deny\"'", err.Error())
	}
}

func TestLoadPolicy_unknownField(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, ".chainsaw.yaml")
	content := `
policy:
  fail-on: HIGH
unknown_field: true
`
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatalf("write temp file: %v", err)
	}

	_, err := LoadPolicy(context.Background(), path)
	if err == nil {
		t.Fatal("expected error for unknown field, got nil")
	}
	if !contains(err.Error(), "unknown") {
		t.Errorf("error message = %q, want to contain 'unknown'", err.Error())
	}
}

func TestLoadPolicy_validPolicy(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, ".chainsaw.yaml")
	content := `
policy:
  fail-on: HIGH
  ignore:
    - CVE-2024-0001
cra:
  required-score: 75
supply-chain:
  min-pinning-score: 80
licences:
  mode: "deny"
  deny-list:
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
	if p.CRA.RequiredScore != 75 {
		t.Errorf("CRA.RequiredScore = %d, want 75", p.CRA.RequiredScore)
	}
	if p.SupplyChain.MinPinningScore != 80 {
		t.Errorf("SupplyChain.MinPinningScore = %d, want 80", p.SupplyChain.MinPinningScore)
	}
	if p.Licences.Mode != "deny" {
		t.Errorf("Licences.Mode = %q, want %q", p.Licences.Mode, "deny")
	}
}

// IgnoreRule tests

func TestIgnoreRule_IsExpired_no_date(t *testing.T) {
	rule := IgnoreRule{ID: "CVE-2024-0001"}
	now := time.Now()
	if rule.IsExpired(now) {
		t.Error("rule with no expires date should not be expired")
	}
}

func TestIgnoreRule_IsExpired_future(t *testing.T) {
	rule := IgnoreRule{
		ID:      "CVE-2024-0001",
		Expires: "2099-01-01",
	}
	now := time.Now()
	if rule.IsExpired(now) {
		t.Error("rule with future expires date should not be expired")
	}
}

func TestIgnoreRule_IsExpired_past(t *testing.T) {
	rule := IgnoreRule{
		ID:      "CVE-2024-0001",
		Expires: "2020-01-01",
	}
	now := time.Now()
	if !rule.IsExpired(now) {
		t.Error("rule with past expires date should be expired")
	}
}

func TestIgnoreRule_IsExpired_invalid_format(t *testing.T) {
	rule := IgnoreRule{
		ID:      "CVE-2024-0001",
		Expires: "not-a-date",
	}
	now := time.Now()
	if !rule.IsExpired(now) {
		t.Error("rule with invalid expires format should be treated as expired")
	}
}

func TestPolicy_Evaluate_ExpiredIgnore_surfaces_finding(t *testing.T) {
	p := &Policy{
		FailOn: models.SeverityLow,
		Ignore: []IgnoreRule{{
			ID:      "GHSA-EXPIRED",
			Expires: "2020-01-01",
		}},
	}
	result := models.ScanResult{
		Findings: []models.Finding{{
			ID:       "GHSA-EXPIRED",
			Severity: models.SeverityHigh,
			Component: models.Component{
				Name:    "pkg",
				Version: "1.0.0",
			},
		}},
	}

	violations, code := p.Evaluate(result)
	if code != 1 {
		t.Errorf("exit code = %d, want 1 (expired ignore should not suppress)", code)
	}
	if len(violations) != 1 {
		t.Errorf("expected 1 violation (ignore expired), got %d", len(violations))
	}
}

func TestIgnoreRule_UnmarshalYAML_string(t *testing.T) {
	yamlContent := `
policy:
  ignore:
    - CVE-2024-0001
`
	var pf policyFile
	if err := yaml.Unmarshal([]byte(yamlContent), &pf); err != nil {
		t.Fatalf("unmarshal failed: %v", err)
	}
	if len(pf.Policy.Ignore) != 1 {
		t.Errorf("expected 1 ignore rule, got %d", len(pf.Policy.Ignore))
	}
	if pf.Policy.Ignore[0].ID != "CVE-2024-0001" {
		t.Errorf("ignore rule ID = %q, want %q", pf.Policy.Ignore[0].ID, "CVE-2024-0001")
	}
	if pf.Policy.Ignore[0].Expires != "" {
		t.Errorf("ignore rule Expires = %q, want empty", pf.Policy.Ignore[0].Expires)
	}
}

func TestIgnoreRule_UnmarshalYAML_object(t *testing.T) {
	yamlContent := `
policy:
  ignore:
    - id: CVE-2024-0001
      expires: "2026-12-31"
      reason: "Accepted risk - no exploitable path"
`
	var pf policyFile
	if err := yaml.Unmarshal([]byte(yamlContent), &pf); err != nil {
		t.Fatalf("unmarshal failed: %v", err)
	}
	if len(pf.Policy.Ignore) != 1 {
		t.Errorf("expected 1 ignore rule, got %d", len(pf.Policy.Ignore))
	}
	rule := pf.Policy.Ignore[0]
	if rule.ID != "CVE-2024-0001" {
		t.Errorf("ignore rule ID = %q, want %q", rule.ID, "CVE-2024-0001")
	}
	if rule.Expires != "2026-12-31" {
		t.Errorf("ignore rule Expires = %q, want %q", rule.Expires, "2026-12-31")
	}
	if rule.Reason != "Accepted risk - no exploitable path" {
		t.Errorf("ignore rule Reason = %q, want %q", rule.Reason, "Accepted risk - no exploitable path")
	}
}

func TestIgnoreRule_UnmarshalYAML_mixed(t *testing.T) {
	yamlContent := `
policy:
  ignore:
    - CVE-2024-0001
    - id: CVE-2024-0002
      expires: "2026-12-31"
      reason: "Accepted risk"
`
	var pf policyFile
	if err := yaml.Unmarshal([]byte(yamlContent), &pf); err != nil {
		t.Fatalf("unmarshal failed: %v", err)
	}
	if len(pf.Policy.Ignore) != 2 {
		t.Errorf("expected 2 ignore rules, got %d", len(pf.Policy.Ignore))
	}
	// First should be bare string form
	if pf.Policy.Ignore[0].ID != "CVE-2024-0001" {
		t.Errorf("first rule ID = %q, want %q", pf.Policy.Ignore[0].ID, "CVE-2024-0001")
	}
	if pf.Policy.Ignore[0].Expires != "" || pf.Policy.Ignore[0].Reason != "" {
		t.Error("first rule should have empty Expires and Reason")
	}
	// Second should be object form
	if pf.Policy.Ignore[1].ID != "CVE-2024-0002" {
		t.Errorf("second rule ID = %q, want %q", pf.Policy.Ignore[1].ID, "CVE-2024-0002")
	}
	if pf.Policy.Ignore[1].Expires != "2026-12-31" {
		t.Errorf("second rule Expires = %q, want %q", pf.Policy.Ignore[1].Expires, "2026-12-31")
	}
	if pf.Policy.Ignore[1].Reason != "Accepted risk" {
		t.Errorf("second rule Reason = %q, want %q", pf.Policy.Ignore[1].Reason, "Accepted risk")
	}
}

// contains is a helper to check if a string contains a substring.
func contains(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
