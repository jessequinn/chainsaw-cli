package cra

import (
	"os"
	"path/filepath"
	"strings"

	"github.com/chainsaw-dev/chainsaw/pkg/models"
)

// ReportingChecker verifies Article 14 reporting readiness.
type ReportingChecker struct{}

// Check returns CRA checks for Article 14 reporting obligations.
func (r *ReportingChecker) Check(ctx *AssessmentContext) []models.CRACheck {
	var checks []models.CRACheck

	// 1. CI security scanning configured.
	checks = append(checks, checkCIScanning(ctx.RootPath))

	// 2. CSIRT contact configured.
	if ctx.Config != nil && ctx.Config.CSIRTContact != "" {
		checks = append(checks, models.CRACheck{
			ID:       "reporting-csirt",
			Title:    "CSIRT contact configured",
			Article:  "Article 14",
			Status:   models.CRAPass,
			Details:  "CSIRT contact: " + ctx.Config.CSIRTContact + ".",
			Severity: models.SeverityHigh,
		})
	} else {
		checks = append(checks, models.CRACheck{
			ID:          "reporting-csirt",
			Title:       "CSIRT contact configured",
			Article:     "Article 14",
			Status:      models.CRAFail,
			Details:     "No CSIRT contact configured.",
			Severity:    models.SeverityHigh,
			Remediation: "Add csirt-contact to the cra section of .chainsaw.yaml.",
		})
	}

	// 3. 24-hour early warning process (always fails -- manual process).
	checks = append(checks, models.CRACheck{
		ID:          "reporting-24h-process",
		Title:       "24-hour early warning process documented",
		Article:     "Article 14",
		Status:      models.CRAFail,
		Details:     "A 24-hour early warning notification process to ENISA is required but cannot be verified automatically.",
		Severity:    models.SeverityHigh,
		Remediation: "Document a 24-hour early warning process for ENISA before September 2026.",
	})

	return checks
}

var scannerKeywords = []string{"osv-scanner", "trivy", "grype", "chainsaw", "snyk"}

func checkCIScanning(rootPath string) models.CRACheck {
	workflowDir := filepath.Join(rootPath, ".github", "workflows")
	entries, err := os.ReadDir(workflowDir)
	if err != nil {
		return models.CRACheck{
			ID:          "reporting-ci-scanning",
			Title:       "CI security scanning configured",
			Article:     "Article 14",
			Status:      models.CRAFail,
			Details:     "No .github/workflows/ directory found.",
			Severity:    models.SeverityCritical,
			Remediation: "Set up GitHub Actions workflows with automated security scanning.",
		}
	}

	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		name := entry.Name()
		if !strings.HasSuffix(name, ".yml") && !strings.HasSuffix(name, ".yaml") {
			continue
		}
		data, err := os.ReadFile(filepath.Join(workflowDir, name))
		if err != nil {
			continue
		}
		lower := strings.ToLower(string(data))
		for _, kw := range scannerKeywords {
			if strings.Contains(lower, kw) {
				return models.CRACheck{
					ID:       "reporting-ci-scanning",
					Title:    "CI security scanning configured",
					Article:  "Article 14",
					Status:   models.CRAPass,
					Details:  "Security scanner reference (" + kw + ") found in " + name + ".",
					Severity: models.SeverityCritical,
				}
			}
		}
	}

	return models.CRACheck{
		ID:          "reporting-ci-scanning",
		Title:       "CI security scanning configured",
		Article:     "Article 14",
		Status:      models.CRAFail,
		Details:     "GitHub Actions workflows exist but no security scanner references found.",
		Severity:    models.SeverityCritical,
		Remediation: "Add a security scanning step (osv-scanner, trivy, grype, or chainsaw) to CI workflows.",
	}
}
