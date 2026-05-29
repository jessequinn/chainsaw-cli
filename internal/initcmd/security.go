package initcmd

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// SecurityConfig holds user inputs for security file generation.
type SecurityConfig struct {
	ProjectName    string
	OrgName        string
	SecurityEmail  string
	SupportEndDate string // YYYY-MM-DD
	CSIRTContact   string
	Manufacturer   string
}

// DefaultSecurityConfig returns config with placeholder values.
func DefaultSecurityConfig() SecurityConfig {
	endDate := time.Now().AddDate(2, 0, 0).Format("2006-01-02")
	return SecurityConfig{
		ProjectName:    "my-project",
		OrgName:        "Organization",
		SecurityEmail:  "security@example.com",
		SupportEndDate: endDate,
		CSIRTContact:   "security@example.com",
		Manufacturer:   "Organization",
	}
}

// GenerateSecurityMD generates SECURITY.md content.
func GenerateSecurityMD(cfg SecurityConfig) string {
	var b strings.Builder
	b.WriteString("# Security Policy\n\n")

	b.WriteString("## Supported Versions\n\n")
	b.WriteString("| Version | Supported |\n")
	b.WriteString("|---------|:---------:|\n")
	b.WriteString("| x.y.z   | Yes       |\n")
	b.WriteString("| < x.y.z | No        |\n\n")
	b.WriteString("<!-- TODO: Update the table above with actual supported versions. -->\n\n")

	b.WriteString("## Reporting a Vulnerability\n\n")
	b.WriteString("We take security seriously. If you discover a vulnerability, please report it\n")
	b.WriteString("through coordinated disclosure rather than the public issue tracker.\n\n")
	b.WriteString(fmt.Sprintf("**Email:** [%s](mailto:%s)\n\n", cfg.SecurityEmail, cfg.SecurityEmail))
	b.WriteString("Please include:\n\n")
	b.WriteString("- Description of the vulnerability\n")
	b.WriteString("- Steps to reproduce\n")
	b.WriteString("- Potential impact\n")
	b.WriteString("- Your name and affiliation (optional)\n\n")

	b.WriteString("## Response Timeline\n\n")
	b.WriteString("We aim to respond within 48 hours and provide a fix within 90 days.\n\n")

	b.WriteString("## Disclosure Policy\n\n")
	b.WriteString("We follow a coordinated disclosure policy with a 90-day window:\n\n")
	b.WriteString("- Day 0: Vulnerability reported\n")
	b.WriteString("- Day 1-7: Initial assessment and reproduction\n")
	b.WriteString("- Day 8-80: Fix development and testing\n")
	b.WriteString("- Day 81-90: Coordinated public disclosure\n\n")

	b.WriteString("## Scope\n\n")
	b.WriteString("This policy applies to the latest supported release of this project.\n")
	b.WriteString("Third-party dependencies are out of scope but will be triaged if reported.\n\n")
	b.WriteString("<!-- TODO: Review and update the scope for your project. -->\n")

	return b.String()
}

// GenerateSecurityTxt generates .well-known/security.txt per RFC 9116.
func GenerateSecurityTxt(cfg SecurityConfig) string {
	expires := time.Now().AddDate(1, 0, 0).Format("2006-01-02T15:04:05Z")

	var b strings.Builder
	b.WriteString(fmt.Sprintf("Contact: mailto:%s\n", cfg.SecurityEmail))
	b.WriteString(fmt.Sprintf("Expires: %s\n", expires))
	b.WriteString("Preferred-Languages: en\n")
	b.WriteString("Canonical: https://example.com/.well-known/security.txt\n")
	b.WriteString("Policy: https://example.com/SECURITY.md\n")
	b.WriteString("# TODO: Update Canonical and Policy URLs for your project.\n")

	return b.String()
}

// GenerateChainsawYAML generates .chainsaw.yaml with CRA section.
func GenerateChainsawYAML(cfg SecurityConfig) string {
	var b strings.Builder
	b.WriteString("# Chainsaw policy configuration\n")
	b.WriteString("# See https://github.com/chainsaw-dev/chainsaw for details.\n\n")
	b.WriteString("fail-on: HIGH\n\n")
	b.WriteString("cra:\n")
	b.WriteString(fmt.Sprintf("  manufacturer: %q\n", cfg.OrgName))
	b.WriteString(fmt.Sprintf("  security-contact: %q\n", cfg.SecurityEmail))
	b.WriteString(fmt.Sprintf("  support-end-date: %q\n", cfg.SupportEndDate))
	b.WriteString(fmt.Sprintf("  csirt-contact: %q\n", cfg.CSIRTContact))

	return b.String()
}

// GenerateIncidentResponse generates INCIDENT-RESPONSE.md for CRA Article 14.
func GenerateIncidentResponse(cfg SecurityConfig) string {
	var b strings.Builder
	b.WriteString("# Incident Response Playbook\n\n")

	b.WriteString("## CRA Article 14 — Vulnerability Reporting Obligations\n\n")
	b.WriteString("This playbook documents the incident response process required by the\n")
	b.WriteString("EU Cyber Resilience Act (Regulation (EU) 2024/2847).\n\n")

	b.WriteString("## Reporting Timeline\n\n")
	b.WriteString("| Deadline | Requirement | Recipient |\n")
	b.WriteString("|----------|-------------|----------|\n")
	b.WriteString("| 24 hours | Early warning notification | ENISA / National CSIRT |\n")
	b.WriteString("| 72 hours | Vulnerability notification update | ENISA / National CSIRT |\n")
	b.WriteString("| 14 days  | Final report | ENISA / National CSIRT |\n\n")

	b.WriteString("## ENISA Single Reporting Platform\n\n")
	b.WriteString("- **URL:** https://vulnerability.enisa.europa.eu (TODO: confirm URL when platform launches)\n")

	csirtContact := cfg.CSIRTContact
	if csirtContact == "" {
		csirtContact = "TODO: Set CSIRT contact"
	}
	b.WriteString(fmt.Sprintf("- **National CSIRT Contact:** %s\n", csirtContact))

	securityEmail := cfg.SecurityEmail
	if securityEmail == "" {
		securityEmail = "TODO: Set security email"
	}
	b.WriteString(fmt.Sprintf("- **Manufacturer Security Contact:** %s\n\n", securityEmail))

	b.WriteString("## Early Warning Notification (24h)\n\n")
	b.WriteString("Required fields:\n")
	b.WriteString("1. Product identification (name, version, affected versions)\n")
	b.WriteString("2. General description of the vulnerability\n")
	b.WriteString("3. Whether the vulnerability is being actively exploited\n")
	b.WriteString("4. Severity assessment (CVSS score if available)\n")
	b.WriteString("5. Preliminary impact assessment\n\n")

	b.WriteString("## Vulnerability Notification (72h)\n\n")
	b.WriteString("Required fields (in addition to early warning):\n")
	b.WriteString("1. Detailed technical description\n")
	b.WriteString("2. Affected components and dependencies\n")
	b.WriteString("3. Known mitigations or workarounds\n")
	b.WriteString("4. Estimated timeline for fix availability\n")
	b.WriteString("5. Corrective measures taken or planned\n\n")

	b.WriteString("## Final Report (14 days)\n\n")
	b.WriteString("Required fields:\n")
	b.WriteString("1. Root cause analysis\n")
	b.WriteString("2. Complete remediation details\n")
	b.WriteString("3. Fixed version information\n")
	b.WriteString("4. Lessons learned\n")
	b.WriteString("5. Updated SBOM reflecting the fix\n\n")

	b.WriteString("## Internal Escalation Contacts\n\n")
	b.WriteString("| Role | Name | Contact |\n")
	b.WriteString("|------|------|----------|\n")
	b.WriteString("| Security Lead | TODO | TODO |\n")
	b.WriteString("| Engineering Lead | TODO | TODO |\n")
	b.WriteString("| Legal/Compliance | TODO | TODO |\n")
	b.WriteString("| Communications | TODO | TODO |\n\n")

	b.WriteString("## Checklist\n\n")
	b.WriteString("- [ ] Vulnerability confirmed and triaged\n")
	b.WriteString("- [ ] CSIRT notified within 24 hours\n")
	b.WriteString("- [ ] 72-hour update submitted\n")
	b.WriteString("- [ ] Fix developed and tested\n")
	b.WriteString("- [ ] Security advisory published\n")
	b.WriteString("- [ ] 14-day final report submitted\n")
	b.WriteString("- [ ] SBOM updated\n")
	b.WriteString("- [ ] Affected users notified\n")

	return b.String()
}

// WriteSecurityFiles writes all security files to the given root directory.
// Returns a list of files written and any error.
func WriteSecurityFiles(root string, cfg SecurityConfig) ([]string, error) {
	type fileEntry struct {
		relPath string
		content string
	}

	files := []fileEntry{
		{"SECURITY.md", GenerateSecurityMD(cfg)},
		{filepath.Join(".well-known", "security.txt"), GenerateSecurityTxt(cfg)},
		{".chainsaw.yaml", GenerateChainsawYAML(cfg)},
		{"INCIDENT-RESPONSE.md", GenerateIncidentResponse(cfg)},
	}

	var written []string
	for _, f := range files {
		fullPath := filepath.Join(root, f.relPath)
		dir := filepath.Dir(fullPath)
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return written, fmt.Errorf("creating directory %s: %w", dir, err)
		}
		if err := os.WriteFile(fullPath, []byte(f.content), 0o644); err != nil {
			return written, fmt.Errorf("writing %s: %w", f.relPath, err)
		}
		written = append(written, f.relPath)
	}

	return written, nil
}
