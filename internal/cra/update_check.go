package cra

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/chainsaw-dev/chainsaw/pkg/models"
)

// UpdateChecker verifies update and release mechanism per CRA Annex I, Part 2(7).
type UpdateChecker struct{}

var semverTagPattern = regexp.MustCompile(`^v\d+\.\d+\.\d+`)

// Check returns CRA checks for update mechanism readiness.
func (u *UpdateChecker) Check(ctx *AssessmentContext) []models.CRACheck {
	var checks []models.CRACheck

	changelogPath := filepath.Join(ctx.RootPath, "CHANGELOG.md")
	changelogContent := ""

	// 1. CHANGELOG.md exists.
	data, err := os.ReadFile(changelogPath)
	if err == nil {
		changelogContent = string(data)
		checks = append(checks, models.CRACheck{
			ID:       "update-changelog",
			Title:    "Changelog maintained",
			Article:  "Annex I, Part 2(7)",
			Status:   models.CRAPass,
			Details:  "CHANGELOG.md found.",
			Severity: models.SeverityMedium,
		})
	} else {
		checks = append(checks, models.CRACheck{
			ID:          "update-changelog",
			Title:       "Changelog maintained",
			Article:     "Annex I, Part 2(7)",
			Status:      models.CRAFail,
			Details:     "No CHANGELOG.md found at project root.",
			Severity:    models.SeverityMedium,
			Remediation: "Create a CHANGELOG.md to document changes, especially security fixes.",
		})
	}

	// 2. Semver release tags exist.
	checks = append(checks, checkReleaseTags(ctx.RootPath))

	// 3. Security fixes documented in changelog.
	if changelogContent != "" {
		lower := strings.ToLower(changelogContent)
		keywords := []string{"security", "cve", "vulnerability", "fix"}
		found := 0
		for _, kw := range keywords {
			if strings.Contains(lower, kw) {
				found++
			}
		}
		if found >= 2 {
			checks = append(checks, models.CRACheck{
				ID:       "update-security-fixes",
				Title:    "Security fixes documented in changelog",
				Article:  "Annex I, Part 2(7)",
				Status:   models.CRAPass,
				Details:  "CHANGELOG.md references security-related content.",
				Severity: models.SeverityMedium,
			})
		} else {
			checks = append(checks, models.CRACheck{
				ID:          "update-security-fixes",
				Title:       "Security fixes documented in changelog",
				Article:     "Annex I, Part 2(7)",
				Status:      models.CRAWarn,
				Details:     "CHANGELOG.md exists but may not document security fixes explicitly.",
				Severity:    models.SeverityMedium,
				Remediation: "Document security fixes in CHANGELOG.md with CVE identifiers when applicable.",
			})
		}
	} else {
		checks = append(checks, models.CRACheck{
			ID:          "update-security-fixes",
			Title:       "Security fixes documented in changelog",
			Article:     "Annex I, Part 2(7)",
			Status:      models.CRANA,
			Details:     "No CHANGELOG.md to evaluate.",
			Severity:    models.SeverityMedium,
			Remediation: "Create a CHANGELOG.md and document security fixes.",
		})
	}

	return checks
}

func checkReleaseTags(rootPath string) models.CRACheck {
	cmd := exec.Command("git", "tag", "-l", "v*")
	cmd.Dir = rootPath
	out, err := cmd.Output()
	if err != nil {
		return models.CRACheck{
			ID:          "update-releases",
			Title:       "Versioned releases exist",
			Article:     "Annex I, Part 2(7)",
			Status:      models.CRANA,
			Details:     "Unable to check git tags (not a git repository or git not available).",
			Severity:    models.SeverityMedium,
			Remediation: "Use git tags with semantic versioning for releases.",
		}
	}

	tags := strings.Split(strings.TrimSpace(string(out)), "\n")
	semverCount := 0
	for _, tag := range tags {
		tag = strings.TrimSpace(tag)
		if semverTagPattern.MatchString(tag) {
			semverCount++
		}
	}

	if semverCount > 0 {
		return models.CRACheck{
			ID:       "update-releases",
			Title:    "Versioned releases exist",
			Article:  "Annex I, Part 2(7)",
			Status:   models.CRAPass,
			Details:  fmt.Sprintf("%d semver release tag(s) found.", semverCount),
			Severity: models.SeverityMedium,
		}
	}

	return models.CRACheck{
		ID:          "update-releases",
		Title:       "Versioned releases exist",
		Article:     "Annex I, Part 2(7)",
		Status:      models.CRAFail,
		Details:     "No semantic version tags found.",
		Severity:    models.SeverityMedium,
		Remediation: "Tag releases with semantic versions (e.g., v1.0.0).",
	}
}
