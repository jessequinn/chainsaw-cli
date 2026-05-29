package cra

import (
	"os"
	"path/filepath"
	"strings"

	"github.com/chainsaw-dev/chainsaw/pkg/models"
)

// SecureDefaultsChecker validates secure-by-default configurations.
type SecureDefaultsChecker struct{}

func (s *SecureDefaultsChecker) Check(actx *AssessmentContext) []models.CRACheck {
	var checks []models.CRACheck

	checks = append(checks, s.checkDockerfiles(actx.RootPath))
	checks = append(checks, s.checkGitHubActions(actx.RootPath))

	return checks
}

// checkDockerfiles scans for Dockerfile and *.dockerfile files and validates secure defaults.
func (s *SecureDefaultsChecker) checkDockerfiles(rootPath string) models.CRACheck {
	dockerfiles := []string{}

	// Find Dockerfile
	if _, err := os.Stat(filepath.Join(rootPath, "Dockerfile")); err == nil {
		dockerfiles = append(dockerfiles, filepath.Join(rootPath, "Dockerfile"))
	}

	// Find *.dockerfile files
	entries, err := os.ReadDir(rootPath)
	if err == nil {
		for _, entry := range entries {
			if !entry.IsDir() && strings.HasSuffix(entry.Name(), ".dockerfile") {
				dockerfiles = append(dockerfiles, filepath.Join(rootPath, entry.Name()))
			}
		}
	}

	// If no Dockerfiles found, return N/A
	if len(dockerfiles) == 0 {
		return models.CRACheck{
			ID:       "CRA-SECURE-001",
			Title:    "Dockerfile secure defaults",
			Article:  "Annex I",
			Status:   models.CRANA,
			Details:  "No Dockerfile found in project root",
			Severity: models.SeverityNone,
		}
	}

	// Check each Dockerfile
	var issues []string
	for _, dockerfile := range dockerfiles {
		content, err := os.ReadFile(dockerfile)
		if err != nil {
			issues = append(issues, "Error reading "+filepath.Base(dockerfile))
			continue
		}

		lines := strings.Split(string(content), "\n")
		hasUserDirective := false
		hasPrivileged := false

		for _, line := range lines {
			trimmed := strings.TrimSpace(line)
			if strings.HasPrefix(strings.ToUpper(trimmed), "USER") {
				hasUserDirective = true
			}
			if strings.Contains(trimmed, "--privileged") {
				hasPrivileged = true
			}
		}

		if hasPrivileged {
			issues = append(issues, filepath.Base(dockerfile)+": --privileged flag found")
		}
		if !hasUserDirective {
			issues = append(issues, filepath.Base(dockerfile)+": No USER directive found; container runs as root by default")
		}
	}

	// Determine status based on issues
	status := models.CRAPass
	details := "All Dockerfiles have secure defaults (USER directive, no --privileged)"
	if len(issues) > 0 {
		status = models.CRAWarn
		details = strings.Join(issues, "; ")
	}

	return models.CRACheck{
		ID:       "CRA-SECURE-001",
		Title:    "Dockerfile secure defaults",
		Article:  "Annex I",
		Status:   status,
		Details:  details,
		Severity: models.SeverityHigh,
	}
}

// checkGitHubActions scans .github/workflows for least-privilege permissions.
func (s *SecureDefaultsChecker) checkGitHubActions(rootPath string) models.CRACheck {
	workflowDir := filepath.Join(rootPath, ".github", "workflows")

	// Check if workflows directory exists
	entries, err := os.ReadDir(workflowDir)
	if err != nil {
		// Directory doesn't exist or can't be read
		return models.CRACheck{
			ID:       "CRA-SECURE-002",
			Title:    "GitHub Actions least-privilege permissions",
			Article:  "Annex I",
			Status:   models.CRANA,
			Details:  "No .github/workflows directory found",
			Severity: models.SeverityNone,
		}
	}

	// Find workflow files
	var workflows []string
	for _, entry := range entries {
		if !entry.IsDir() && (strings.HasSuffix(entry.Name(), ".yml") || strings.HasSuffix(entry.Name(), ".yaml")) {
			workflows = append(workflows, filepath.Join(workflowDir, entry.Name()))
		}
	}

	// If no workflows found, return N/A
	if len(workflows) == 0 {
		return models.CRACheck{
			ID:       "CRA-SECURE-002",
			Title:    "GitHub Actions least-privilege permissions",
			Article:  "Annex I",
			Status:   models.CRANA,
			Details:  "No workflow files found in .github/workflows",
			Severity: models.SeverityNone,
		}
	}

	// Check each workflow
	var issues []string
	for _, workflow := range workflows {
		content, err := os.ReadFile(workflow)
		if err != nil {
			issues = append(issues, "Error reading "+filepath.Base(workflow))
			continue
		}

		contentStr := string(content)
		hasPermissionsBlock := strings.Contains(contentStr, "permissions:")
		hasWriteAll := strings.Contains(contentStr, "permissions: write-all") || strings.Contains(contentStr, "permissions:\n  write-all")

		if hasWriteAll {
			issues = append(issues, filepath.Base(workflow)+": permissions: write-all found")
		}
		if !hasPermissionsBlock {
			issues = append(issues, filepath.Base(workflow)+": No permissions block; workflow uses default (potentially broad) permissions")
		}
	}

	// Determine status based on issues
	status := models.CRAPass
	details := "All workflows have explicit least-privilege permissions"
	if len(issues) > 0 {
		status = models.CRAWarn
		details = strings.Join(issues, "; ")
	}

	return models.CRACheck{
		ID:       "CRA-SECURE-002",
		Title:    "GitHub Actions least-privilege permissions",
		Article:  "Annex I",
		Status:   status,
		Details:  details,
		Severity: models.SeverityHigh,
	}
}
