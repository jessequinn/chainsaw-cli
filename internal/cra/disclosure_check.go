package cra

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/chainsaw-dev/chainsaw/pkg/models"
)

// DisclosureChecker verifies vulnerability disclosure processes per CRA Annex I, Part 2(5) and Annex II(8).
type DisclosureChecker struct{}

var emailPattern = regexp.MustCompile(`[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}`)
var urlPattern = regexp.MustCompile(`https?://[^\s"'<>]+`)

// Check returns CRA checks for vulnerability disclosure readiness.
func (d *DisclosureChecker) Check(ctx *AssessmentContext) []models.CRACheck {
	var checks []models.CRACheck

	securityMDPath, securityMDContent := findSecurityMD(ctx.RootPath)

	// 1. SECURITY.md exists.
	if securityMDPath != "" {
		checks = append(checks, models.CRACheck{
			ID:       "disclosure-security-md",
			Title:    "Security policy document exists",
			Article:  "Annex I, Part 2(5)",
			Status:   models.CRAPass,
			Details:  "SECURITY.md found at " + securityMDPath + ".",
			Severity: models.SeverityCritical,
		})
	} else {
		checks = append(checks, models.CRACheck{
			ID:          "disclosure-security-md",
			Title:       "Security policy document exists",
			Article:     "Annex I, Part 2(5)",
			Status:      models.CRAFail,
			Details:     "No SECURITY.md found at project root or .github/ directory.",
			Severity:    models.SeverityCritical,
			Remediation: "Create a SECURITY.md file documenting your vulnerability disclosure process.",
		})
	}

	// 2. Security contact is available.
	hasContact := false
	contactDetails := ""
	if ctx.Config != nil && ctx.Config.SecurityContact != "" {
		hasContact = true
		contactDetails = "Security contact configured in policy file."
	} else if securityMDContent != "" {
		if emailPattern.MatchString(securityMDContent) || urlPattern.MatchString(securityMDContent) {
			hasContact = true
			contactDetails = "Contact information found in SECURITY.md."
		}
	}
	if hasContact {
		checks = append(checks, models.CRACheck{
			ID:       "disclosure-contact",
			Title:    "Security contact information available",
			Article:  "Annex II(8)",
			Status:   models.CRAPass,
			Details:  contactDetails,
			Severity: models.SeverityHigh,
		})
	} else {
		checks = append(checks, models.CRACheck{
			ID:          "disclosure-contact",
			Title:       "Security contact information available",
			Article:     "Annex II(8)",
			Status:      models.CRAFail,
			Details:     "No security contact found in SECURITY.md or policy configuration.",
			Severity:    models.SeverityHigh,
			Remediation: "Add a security-contact to .chainsaw.yaml or include contact info in SECURITY.md.",
		})
	}

	// 3. security.txt exists.
	securityTxtFound := false
	for _, rel := range []string{".well-known/security.txt", "security.txt"} {
		p := filepath.Join(ctx.RootPath, rel)
		if _, err := os.Stat(p); err == nil {
			securityTxtFound = true
			checks = append(checks, models.CRACheck{
				ID:       "disclosure-security-txt",
				Title:    "security.txt file exists (RFC 9116)",
				Article:  "Annex I, Part 2(5)",
				Status:   models.CRAPass,
				Details:  "Found " + rel + ".",
				Severity: models.SeverityMedium,
			})
			break
		}
	}
	if !securityTxtFound {
		checks = append(checks, models.CRACheck{
			ID:          "disclosure-security-txt",
			Title:       "security.txt file exists (RFC 9116)",
			Article:     "Annex I, Part 2(5)",
			Status:      models.CRAFail,
			Details:     "No security.txt found at .well-known/security.txt or project root.",
			Severity:    models.SeverityMedium,
			Remediation: "Create a .well-known/security.txt per RFC 9116 with contact and disclosure policy.",
		})
	}

	// 4. Disclosure policy content in SECURITY.md.
	if securityMDContent != "" {
		lower := strings.ToLower(securityMDContent)
		keywords := []string{"disclosure", "report", "vulnerability"}
		found := 0
		for _, kw := range keywords {
			if strings.Contains(lower, kw) {
				found++
			}
		}
		if found >= 2 {
			checks = append(checks, models.CRACheck{
				ID:       "disclosure-policy",
				Title:    "Disclosure policy documented",
				Article:  "Annex I, Part 2(5)",
				Status:   models.CRAPass,
				Details:  "SECURITY.md contains disclosure-related content.",
				Severity: models.SeverityHigh,
			})
		} else {
			checks = append(checks, models.CRACheck{
				ID:          "disclosure-policy",
				Title:       "Disclosure policy documented",
				Article:     "Annex I, Part 2(5)",
				Status:      models.CRAWarn,
				Details:     "SECURITY.md exists but may lack disclosure process details.",
				Severity:    models.SeverityHigh,
				Remediation: "Expand SECURITY.md to describe how vulnerabilities are reported, triaged, and disclosed.",
			})
		}
	} else {
		checks = append(checks, models.CRACheck{
			ID:          "disclosure-policy",
			Title:       "Disclosure policy documented",
			Article:     "Annex I, Part 2(5)",
			Status:      models.CRAFail,
			Details:     "No SECURITY.md to evaluate for disclosure policy content.",
			Severity:    models.SeverityHigh,
			Remediation: "Create a SECURITY.md with a complete vulnerability disclosure policy.",
		})
	}

	return checks
}

// findSecurityMD looks for SECURITY.md at the project root and .github/.
func findSecurityMD(root string) (string, string) {
	candidates := []string{
		filepath.Join(root, "SECURITY.md"),
		filepath.Join(root, ".github", "SECURITY.md"),
	}
	for _, p := range candidates {
		data, err := os.ReadFile(p)
		if err == nil {
			rel, _ := filepath.Rel(root, p)
			if rel == "" {
				rel = p
			}
			return rel, string(data)
		}
	}
	return "", ""
}
