package cra

import (
	"fmt"

	"github.com/chainsaw-dev/chainsaw/pkg/models"
)

// SBOMChecker verifies that the SBOM meets CRA Annex I, Part 2(1) requirements.
type SBOMChecker struct{}

// Check returns CRA checks for SBOM completeness.
func (s *SBOMChecker) Check(ctx *AssessmentContext) []models.CRACheck {
	var checks []models.CRACheck

	// 1. SBOM exists (components were discovered).
	if len(ctx.Components) == 0 {
		checks = append(checks, models.CRACheck{
			ID:          "sbom-exists",
			Title:       "Software Bill of Materials exists",
			Article:     "Annex I, Part 2(1)",
			Status:      models.CRAFail,
			Details:     "No components found. A machine-readable SBOM is required.",
			Severity:    models.SeverityCritical,
			Remediation: "Run a dependency scan and ensure lockfiles are present in the project.",
		})
	} else {
		checks = append(checks, models.CRACheck{
			ID:       "sbom-exists",
			Title:    "Software Bill of Materials exists",
			Article:  "Annex I, Part 2(1)",
			Status:   models.CRAPass,
			Details:  fmt.Sprintf("%d components identified.", len(ctx.Components)),
			Severity: models.SeverityCritical,
		})
	}

	// If no components, remaining checks are N/A.
	if len(ctx.Components) == 0 {
		for _, stub := range []struct {
			id, title string
			sev       models.Severity
		}{
			{"sbom-versions", "All components have versions", models.SeverityHigh},
			{"sbom-purls", "All components have package URLs", models.SeverityMedium},
			{"sbom-hashes", "All components have integrity hashes", models.SeverityMedium},
			{"sbom-top-level", "Top-level dependency enumeration", models.SeverityHigh},
		} {
			checks = append(checks, models.CRACheck{
				ID:       stub.id,
				Title:    stub.title,
				Article:  "Annex I, Part 2(1)",
				Status:   models.CRANA,
				Details:  "No components to evaluate.",
				Severity: stub.sev,
			})
		}
		return checks
	}

	// 2. All components have versions.
	missingVersion := 0
	for _, c := range ctx.Components {
		if c.Version == "" {
			missingVersion++
		}
	}
	if missingVersion > 0 {
		checks = append(checks, models.CRACheck{
			ID:          "sbom-versions",
			Title:       "All components have versions",
			Article:     "Annex I, Part 2(1)",
			Status:      models.CRAFail,
			Details:     fmt.Sprintf("%d of %d components missing version information.", missingVersion, len(ctx.Components)),
			Severity:    models.SeverityHigh,
			Remediation: "Ensure all dependencies specify exact versions in lockfiles.",
		})
	} else {
		checks = append(checks, models.CRACheck{
			ID:       "sbom-versions",
			Title:    "All components have versions",
			Article:  "Annex I, Part 2(1)",
			Status:   models.CRAPass,
			Details:  fmt.Sprintf("All %d components have version information.", len(ctx.Components)),
			Severity: models.SeverityHigh,
		})
	}

	// 3. All components have package URLs.
	missingPurl := 0
	for _, c := range ctx.Components {
		if c.PkgURL == "" {
			missingPurl++
		}
	}
	if missingPurl > 0 {
		checks = append(checks, models.CRACheck{
			ID:          "sbom-purls",
			Title:       "All components have package URLs",
			Article:     "Annex I, Part 2(1)",
			Status:      models.CRAFail,
			Details:     fmt.Sprintf("%d of %d components missing package URL (purl).", missingPurl, len(ctx.Components)),
			Severity:    models.SeverityMedium,
			Remediation: "Generate package URLs for all dependencies in the SBOM.",
		})
	} else {
		checks = append(checks, models.CRACheck{
			ID:       "sbom-purls",
			Title:    "All components have package URLs",
			Article:  "Annex I, Part 2(1)",
			Status:   models.CRAPass,
			Details:  fmt.Sprintf("All %d components have package URLs.", len(ctx.Components)),
			Severity: models.SeverityMedium,
		})
	}

	// 4. All components have integrity hashes.
	missingHash := 0
	for _, c := range ctx.Components {
		if c.Hash == "" {
			missingHash++
		}
	}
	if missingHash > 0 {
		checks = append(checks, models.CRACheck{
			ID:          "sbom-hashes",
			Title:       "All components have integrity hashes",
			Article:     "Annex I, Part 2(1)",
			Status:      models.CRAFail,
			Details:     fmt.Sprintf("%d of %d components missing integrity hash.", missingHash, len(ctx.Components)),
			Severity:    models.SeverityMedium,
			Remediation: "Ensure lockfiles contain integrity hashes for all dependencies.",
		})
	} else {
		checks = append(checks, models.CRACheck{
			ID:       "sbom-hashes",
			Title:    "All components have integrity hashes",
			Article:  "Annex I, Part 2(1)",
			Status:   models.CRAPass,
			Details:  fmt.Sprintf("All %d components have integrity hashes.", len(ctx.Components)),
			Severity: models.SeverityMedium,
		})
	}

	// 5. Top-level dependency enumeration.
	checks = append(checks, models.CRACheck{
		ID:       "sbom-top-level",
		Title:    "Top-level dependency enumeration",
		Article:  "Annex I, Part 2(1)",
		Status:   models.CRAPass,
		Details:  fmt.Sprintf("Top-level dependencies enumerated (%d components).", len(ctx.Components)),
		Severity: models.SeverityHigh,
	})

	return checks
}
