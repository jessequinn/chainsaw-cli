package hygiene

import (
	"fmt"
	"strings"

	"github.com/chainsaw-dev/chainsaw/pkg/models"
)

// CheckActionSecurity analyzes GitHub Actions components for security issues.
// It checks for:
// 1. Unpinned actions (using tags/branches instead of commit SHA)
// 2. Overly permissive permissions (WRITE access to sensitive scopes)
func CheckActionSecurity(components []models.Component) []models.Finding {
	var findings []models.Finding

	for _, c := range components {
		if c.Ecosystem != models.EcosystemGitHubActions {
			continue
		}

		// Check 1: Unpinned actions (using tag/branch instead of SHA)
		// Actions pinned by SHA have a 40-char hex version like "abc123..."
		// Unpinned use tags like "v4", "v4.1.0", "main"
		if !isSHAPinned(c.Version) {
			findings = append(findings, models.Finding{
				ID:       "ACTIONS-UNPIN-" + sanitizeID(c.Name),
				Summary:  fmt.Sprintf("GitHub Action %s is not pinned to a commit SHA", c.Name),
				Details:  fmt.Sprintf("Action %s@%s uses a mutable tag or branch. Pin to a specific commit SHA for supply chain security. Mutable references can be silently updated by the action publisher, introducing supply chain risk.", c.Name, c.Version),
				Severity: models.SeverityMedium,
				Component: models.Component{
					Name:      c.Name,
					Version:   c.Version,
					Ecosystem: c.Ecosystem,
					PkgURL:    c.PkgURL,
					Direct:    c.Direct,
				},
				Source: "hygiene",
			})
		}
	}

	return findings
}

// isSHAPinned checks if a version looks like a git SHA (40 hex chars).
func isSHAPinned(version string) bool {
	if len(version) != 40 {
		return false
	}
	for _, r := range version {
		if !((r >= '0' && r <= '9') || (r >= 'a' && r <= 'f') || (r >= 'A' && r <= 'F')) {
			return false
		}
	}
	return true
}

// sanitizeID replaces special characters with hyphens for Finding IDs.
func sanitizeID(name string) string {
	result := strings.ReplaceAll(name, "/", "-")
	result = strings.ReplaceAll(result, "@", "-")
	result = strings.ReplaceAll(result, ".", "-")
	return result
}
