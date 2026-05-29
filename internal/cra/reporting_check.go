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
	checks = append(checks, checkCSIRTContact(ctx.Config))

	// 3. Security contact configured.
	checks = append(checks, checkSecurityContact(ctx.Config))

	// 4. Incident response documentation (SECURITY.md).
	checks = append(checks, checkIncidentResponseDoc(ctx.RootPath))

	// 5. Security.txt check.
	checks = append(checks, checkSecurityTxt(ctx.RootPath))

	// 6. Incident response playbook (INCIDENT-RESPONSE.md).
	checks = append(checks, checkIncidentResponsePlaybook(ctx.RootPath))

	// 7. 24-hour early warning process.
	checks = append(checks, check24HourProcess(ctx.Config))

	return checks
}

func checkCSIRTContact(config *CRAConfig) models.CRACheck {
	if config != nil && config.CSIRTContact != "" {
		return models.CRACheck{
			ID:       "reporting-csirt",
			Title:    "CSIRT contact configured",
			Article:  "Article 14",
			Status:   models.CRAPass,
			Details:  "CSIRT contact: " + config.CSIRTContact + ".",
			Severity: models.SeverityHigh,
		}
	}
	return models.CRACheck{
		ID:          "reporting-csirt",
		Title:       "CSIRT contact configured",
		Article:     "Article 14",
		Status:      models.CRAFail,
		Details:     "No CSIRT contact configured.",
		Severity:    models.SeverityHigh,
		Remediation: "Add csirt-contact to the cra section of .chainsaw.yaml.",
	}
}

func checkSecurityContact(config *CRAConfig) models.CRACheck {
	if config != nil && config.SecurityContact != "" {
		return models.CRACheck{
			ID:       "reporting-security-contact",
			Title:    "Security contact configured",
			Article:  "Article 14",
			Status:   models.CRAPass,
			Details:  "Security contact: " + config.SecurityContact + ".",
			Severity: models.SeverityHigh,
		}
	}
	return models.CRACheck{
		ID:          "reporting-security-contact",
		Title:       "Security contact configured",
		Article:     "Article 14",
		Status:      models.CRAFail,
		Details:     "No security contact configured.",
		Severity:    models.SeverityHigh,
		Remediation: "Add security-contact to the cra section of .chainsaw.yaml.",
	}
}

func checkIncidentResponseDoc(rootPath string) models.CRACheck {
	securityMDPath := filepath.Join(rootPath, "SECURITY.md")
	data, err := os.ReadFile(securityMDPath)
	if err != nil {
		return models.CRACheck{
			ID:          "reporting-incident-response",
			Title:       "Incident response documentation",
			Article:     "Article 14",
			Status:      models.CRAFail,
			Details:     "SECURITY.md not found.",
			Severity:    models.SeverityHigh,
			Remediation: "Create a SECURITY.md file documenting incident response procedures.",
		}
	}

	lower := strings.ToLower(string(data))
	hasIncident := strings.Contains(lower, "incident")
	hasReport := strings.Contains(lower, "report")

	if hasIncident || hasReport {
		return models.CRACheck{
			ID:       "reporting-incident-response",
			Title:    "Incident response documentation",
			Article:  "Article 14",
			Status:   models.CRAPass,
			Details:  "SECURITY.md found with incident response keywords.",
			Severity: models.SeverityHigh,
		}
	}

	return models.CRACheck{
		ID:          "reporting-incident-response",
		Title:       "Incident response documentation",
		Article:     "Article 14",
		Status:      models.CRAWarn,
		Details:     "SECURITY.md exists but does not contain incident response keywords.",
		Severity:    models.SeverityHigh,
		Remediation: "Add incident response procedures to SECURITY.md.",
	}
}

func checkSecurityTxt(rootPath string) models.CRACheck {
	securityTxtPath := filepath.Join(rootPath, ".well-known", "security.txt")
	_, err := os.Stat(securityTxtPath)
	if err == nil {
		return models.CRACheck{
			ID:       "reporting-security-txt",
			Title:    "security.txt configured",
			Article:  "Article 14",
			Status:   models.CRAPass,
			Details:  ".well-known/security.txt found.",
			Severity: models.SeverityHigh,
		}
	}

	return models.CRACheck{
		ID:          "reporting-security-txt",
		Title:       "security.txt configured",
		Article:     "Article 14",
		Status:      models.CRAFail,
		Details:     ".well-known/security.txt not found.",
		Severity:    models.SeverityHigh,
		Remediation: "Create .well-known/security.txt following RFC 9110 to publish security contact information.",
	}
}

func checkIncidentResponsePlaybook(rootPath string) models.CRACheck {
	playbookPath := filepath.Join(rootPath, "INCIDENT-RESPONSE.md")
	data, err := os.ReadFile(playbookPath)
	if err != nil {
		return models.CRACheck{
			ID:          "reporting-incident-playbook",
			Title:       "Incident response playbook (CRA Article 14)",
			Article:     "Article 14",
			Status:      models.CRAFail,
			Details:     "INCIDENT-RESPONSE.md not found.",
			Severity:    models.SeverityHigh,
			Remediation: "Create INCIDENT-RESPONSE.md documenting the 24-hour, 72-hour, and 14-day reporting timelines required by CRA Article 14.",
		}
	}

	lower := strings.ToLower(string(data))
	hasCRA := strings.Contains(lower, "cra")
	hasTimeline := strings.Contains(lower, "24") && strings.Contains(lower, "72") && strings.Contains(lower, "14")

	if hasCRA && hasTimeline {
		return models.CRACheck{
			ID:       "reporting-incident-playbook",
			Title:    "Incident response playbook (CRA Article 14)",
			Article:  "Article 14",
			Status:   models.CRAPass,
			Details:  "INCIDENT-RESPONSE.md found with CRA Article 14 reporting timelines.",
			Severity: models.SeverityHigh,
		}
	}

	return models.CRACheck{
		ID:          "reporting-incident-playbook",
		Title:       "Incident response playbook (CRA Article 14)",
		Article:     "Article 14",
		Status:      models.CRAWarn,
		Details:     "INCIDENT-RESPONSE.md exists but may not fully document CRA Article 14 timelines.",
		Severity:    models.SeverityHigh,
		Remediation: "Update INCIDENT-RESPONSE.md to document the 24-hour early warning, 72-hour notification, and 14-day final report timelines.",
	}
}

func check24HourProcess(config *CRAConfig) models.CRACheck {
	if config != nil && config.CSIRTContact != "" {
		return models.CRACheck{
			ID:       "reporting-24h-process",
			Title:    "24-hour early warning process configured",
			Article:  "Article 14",
			Status:   models.CRAPass,
			Details:  "CSIRT contact is configured, enabling 24-hour early warning notifications.",
			Severity: models.SeverityHigh,
		}
	}

	return models.CRACheck{
		ID:          "reporting-24h-process",
		Title:       "24-hour early warning process configured",
		Article:     "Article 14",
		Status:      models.CRAWarn,
		Details:     "CSIRT contact not configured; 24-hour early warning process cannot be verified.",
		Severity:    models.SeverityHigh,
		Remediation: "Configure csirt-contact in .chainsaw.yaml to enable 24-hour early warning notifications to ENISA.",
	}
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
