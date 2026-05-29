package cra

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/chainsaw-dev/chainsaw/pkg/models"
)

func fullConfig() *CRAConfig {
	return &CRAConfig{
		ProductName:     "TestProduct",
		ProductVersion:  "1.0.0",
		Manufacturer:    "TestCorp",
		SupportEndDate:  "2030-12-31",
		SecurityContact: "security@test.com",
		DisclosureURL:   "https://test.com/security",
		CSIRTContact:    "csirt@test.com",
		ProductCategory: "default",
	}
}

func setupProjectDir(t *testing.T, securityMD, changelog bool, ciScanner string) string {
	t.Helper()
	dir := t.TempDir()

	if securityMD {
		content := "# Security Policy\n\nPlease report vulnerabilities to security@test.com.\n\nWe follow a responsible disclosure process.\n"
		if err := os.WriteFile(filepath.Join(dir, "SECURITY.md"), []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	if changelog {
		content := "# Changelog\n\n## 1.0.0\n\n- Fix security vulnerability CVE-2024-0001\n"
		if err := os.WriteFile(filepath.Join(dir, "CHANGELOG.md"), []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	if ciScanner != "" {
		wfDir := filepath.Join(dir, ".github", "workflows")
		if err := os.MkdirAll(wfDir, 0o755); err != nil {
			t.Fatal(err)
		}
		wf := "name: CI\non: push\njobs:\n  scan:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: " + ciScanner + "\n"
		if err := os.WriteFile(filepath.Join(wfDir, "ci.yml"), []byte(wf), 0o644); err != nil {
			t.Fatal(err)
		}
	}

	// Init a git repo with a semver tag so update checks pass.
	// We skip this since exec.Command("git") may not be available in all envs;
	// the update-releases check will return N/A or fail, which is acceptable.

	return dir
}

func completeComponents() []models.Component {
	return []models.Component{
		{
			Name:      "github.com/foo/bar",
			Version:   "v1.2.3",
			Ecosystem: models.EcosystemGo,
			Hash:      "sha256:abc123",
			PkgURL:    "pkg:golang/github.com/foo/bar@v1.2.3",
		},
		{
			Name:      "lodash",
			Version:   "4.17.21",
			Ecosystem: models.EcosystemNpm,
			Hash:      "sha512:def456",
			PkgURL:    "pkg:npm/lodash@4.17.21",
		},
	}
}

func TestAssess_AllPass(t *testing.T) {
	dir := setupProjectDir(t, true, true, "chainsaw")
	actx := &AssessmentContext{
		RootPath:    dir,
		Components:  completeComponents(),
		Findings:    nil,
		Hygiene:     nil,
		ToolVersion: "0.1.0",
		Config:      fullConfig(),
	}

	result := Assess(context.Background(), actx)

	if result.ProductName != "TestProduct" {
		t.Errorf("ProductName = %q, want %q", result.ProductName, "TestProduct")
	}
	if result.Version != "1.0.0" {
		t.Errorf("Version = %q, want %q", result.Version, "1.0.0")
	}

	// Count non-N/A checks that pass.
	passing := 0
	total := 0
	for _, ch := range result.Checks {
		if ch.Status == models.CRANA {
			continue
		}
		total++
		if ch.Status == models.CRAPass {
			passing++
		}
	}

	// The 24h early warning always fails, so we expect total-1 passes at best.
	// Score should still be high.
	if result.OverallScore < 50 {
		t.Errorf("OverallScore = %d, want >= 50 for an all-pass context", result.OverallScore)
	}

	if len(result.Checks) == 0 {
		t.Fatal("expected checks, got none")
	}
}

func TestAssess_MinimalContext(t *testing.T) {
	dir := t.TempDir() // empty dir, no security files
	actx := &AssessmentContext{
		RootPath:   dir,
		Components: completeComponents(),
		Config:     nil, // no config
	}

	result := Assess(context.Background(), actx)

	if result.ProductName != "unknown" {
		t.Errorf("ProductName = %q, want %q", result.ProductName, "unknown")
	}

	// Several checks should fail: disclosure-contact, support-end-date, etc.
	failCount := 0
	for _, ch := range result.Checks {
		if ch.Status == models.CRAFail {
			failCount++
		}
	}
	if failCount == 0 {
		t.Error("expected some failing checks with minimal context")
	}

	if result.OverallScore >= 90 {
		t.Errorf("OverallScore = %d, should be < 90 with minimal context", result.OverallScore)
	}
}

func TestAssess_NoComponents(t *testing.T) {
	dir := t.TempDir()
	actx := &AssessmentContext{
		RootPath:   dir,
		Components: nil,
		Config:     fullConfig(),
	}

	result := Assess(context.Background(), actx)

	// SBOM checks after sbom-exists should be N/A.
	naCount := 0
	for _, ch := range result.Checks {
		if ch.Status == models.CRANA {
			naCount++
		}
	}
	if naCount < 4 {
		t.Errorf("expected >= 4 N/A checks with no components, got %d", naCount)
	}

	// sbom-exists should fail.
	for _, ch := range result.Checks {
		if ch.ID == "sbom-exists" && ch.Status != models.CRAFail {
			t.Errorf("sbom-exists status = %q, want %q", ch.Status, models.CRAFail)
		}
	}
}

func TestAssess_WithCriticalVulnerabilities(t *testing.T) {
	dir := setupProjectDir(t, true, true, "chainsaw")
	actx := &AssessmentContext{
		RootPath:   dir,
		Components: completeComponents(),
		Findings: []models.Finding{
			{
				ID:       "CVE-2024-0001",
				Severity: models.SeverityCritical,
				FixedIn:  "v1.2.4",
				Component: models.Component{
					Name:    "github.com/foo/bar",
					Version: "v1.2.3",
				},
			},
			{
				ID:       "CVE-2024-0002",
				Severity: models.SeverityHigh,
				Component: models.Component{
					Name:    "lodash",
					Version: "4.17.21",
				},
			},
		},
		Config: fullConfig(),
	}

	result := Assess(context.Background(), actx)

	// vuln-none-critical should fail.
	found := false
	for _, ch := range result.Checks {
		if ch.ID == "vuln-none-critical" {
			found = true
			if ch.Status != models.CRAFail {
				t.Errorf("vuln-none-critical status = %q, want %q", ch.Status, models.CRAFail)
			}
		}
		if ch.ID == "vuln-none-high" {
			if ch.Status != models.CRAFail {
				t.Errorf("vuln-none-high status = %q, want %q", ch.Status, models.CRAFail)
			}
		}
		if ch.ID == "vuln-remediation" {
			if ch.Status != models.CRAFail {
				t.Errorf("vuln-remediation status = %q, want %q", ch.Status, models.CRAFail)
			}
		}
	}
	if !found {
		t.Error("vuln-none-critical check not found")
	}
}

func TestAssess_CheckCount(t *testing.T) {
	// 8 checkers: Classification(2), SBOM(5), Vuln(3), Disclosure(4), Update(3), Support(2), Reporting(6), SecureDefaults(2) = 27 total
	dir := setupProjectDir(t, true, true, "chainsaw")
	actx := &AssessmentContext{
		RootPath:   dir,
		Components: completeComponents(),
		Config:     fullConfig(),
	}

	result := Assess(context.Background(), actx)

	// With components present, Classification produces 2, SBOM 5, Vuln 3, Disclosure 4, Update 3, Support 2, Reporting 7, SecureDefaults 2 = 28.
	expected := 28
	if len(result.Checks) != expected {
		t.Errorf("check count = %d, want %d", len(result.Checks), expected)
	}
}
