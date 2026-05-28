package cra

import (
	"github.com/chainsaw-dev/chainsaw/pkg/models"
)

// SupportChecker verifies support period documentation per CRA Annex II(7).
type SupportChecker struct{}

// Check returns CRA checks for support period configuration.
func (s *SupportChecker) Check(ctx *AssessmentContext) []models.CRACheck {
	var checks []models.CRACheck

	// 1. Support end date configured.
	if ctx.Config != nil && ctx.Config.SupportEndDate != "" {
		checks = append(checks, models.CRACheck{
			ID:       "support-end-date",
			Title:    "Support end date declared",
			Article:  "Annex II(7)",
			Status:   models.CRAPass,
			Details:  "Support end date: " + ctx.Config.SupportEndDate + ".",
			Severity: models.SeverityHigh,
		})
	} else {
		checks = append(checks, models.CRACheck{
			ID:          "support-end-date",
			Title:       "Support end date declared",
			Article:     "Annex II(7)",
			Status:      models.CRAFail,
			Details:     "No support end date configured.",
			Severity:    models.SeverityHigh,
			Remediation: "Add support-end-date to the cra section of .chainsaw.yaml.",
		})
	}

	// 2. Manufacturer contact configured.
	if ctx.Config != nil && ctx.Config.Manufacturer != "" {
		checks = append(checks, models.CRACheck{
			ID:       "support-contact",
			Title:    "Manufacturer contact declared",
			Article:  "Annex II(7)",
			Status:   models.CRAPass,
			Details:  "Manufacturer: " + ctx.Config.Manufacturer + ".",
			Severity: models.SeverityMedium,
		})
	} else {
		checks = append(checks, models.CRACheck{
			ID:          "support-contact",
			Title:       "Manufacturer contact declared",
			Article:     "Annex II(7)",
			Status:      models.CRAFail,
			Details:     "No manufacturer configured.",
			Severity:    models.SeverityMedium,
			Remediation: "Add manufacturer to the cra section of .chainsaw.yaml.",
		})
	}

	return checks
}
