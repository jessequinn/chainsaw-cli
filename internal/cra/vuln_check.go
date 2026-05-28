package cra

import (
	"fmt"

	"github.com/chainsaw-dev/chainsaw/pkg/models"
)

// VulnChecker verifies no known exploitable vulnerabilities exist per CRA Annex I, Part 1(2)(a).
type VulnChecker struct{}

// Check returns CRA checks for known vulnerability status.
func (v *VulnChecker) Check(ctx *AssessmentContext) []models.CRACheck {
	var checks []models.CRACheck

	criticalCount := 0
	highCount := 0
	fixAvailable := 0

	for _, f := range ctx.Findings {
		switch f.Severity {
		case models.SeverityCritical:
			criticalCount++
		case models.SeverityHigh:
			highCount++
		}
		if f.FixedIn != "" {
			fixAvailable++
		}
	}

	// 1. No critical vulnerabilities.
	if criticalCount > 0 {
		checks = append(checks, models.CRACheck{
			ID:          "vuln-none-critical",
			Title:       "No critical known vulnerabilities",
			Article:     "Annex I, Part 1(2)(a)",
			Status:      models.CRAFail,
			Details:     fmt.Sprintf("%d critical vulnerability(ies) found.", criticalCount),
			Severity:    models.SeverityCritical,
			Remediation: "Update affected components to patched versions immediately.",
		})
	} else {
		checks = append(checks, models.CRACheck{
			ID:       "vuln-none-critical",
			Title:    "No critical known vulnerabilities",
			Article:  "Annex I, Part 1(2)(a)",
			Status:   models.CRAPass,
			Details:  "No critical vulnerabilities detected.",
			Severity: models.SeverityCritical,
		})
	}

	// 2. No high vulnerabilities.
	if highCount > 0 {
		checks = append(checks, models.CRACheck{
			ID:          "vuln-none-high",
			Title:       "No high-severity known vulnerabilities",
			Article:     "Annex I, Part 1(2)(a)",
			Status:      models.CRAFail,
			Details:     fmt.Sprintf("%d high-severity vulnerability(ies) found.", highCount),
			Severity:    models.SeverityHigh,
			Remediation: "Update affected components to patched versions.",
		})
	} else {
		checks = append(checks, models.CRACheck{
			ID:       "vuln-none-high",
			Title:    "No high-severity known vulnerabilities",
			Article:  "Annex I, Part 1(2)(a)",
			Status:   models.CRAPass,
			Details:  "No high-severity vulnerabilities detected.",
			Severity: models.SeverityHigh,
		})
	}

	// 3. Remediation applied (no fix available but unapplied).
	if fixAvailable > 0 {
		checks = append(checks, models.CRACheck{
			ID:          "vuln-remediation",
			Title:       "Available fixes applied",
			Article:     "Annex I, Part 1(2)(a)",
			Status:      models.CRAFail,
			Details:     fmt.Sprintf("%d vulnerability(ies) have fixes available but not applied.", fixAvailable),
			Severity:    models.SeverityHigh,
			Remediation: "Update dependencies to the fixed versions listed in the scan report.",
		})
	} else {
		status := models.CRAPass
		details := "No unapplied fixes detected."
		if len(ctx.Findings) == 0 {
			details = "No vulnerabilities found; no fixes to apply."
		}
		checks = append(checks, models.CRACheck{
			ID:       "vuln-remediation",
			Title:    "Available fixes applied",
			Article:  "Annex I, Part 1(2)(a)",
			Status:   status,
			Details:  details,
			Severity: models.SeverityHigh,
		})
	}

	return checks
}
