package cra

import (
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/chainsaw-dev/chainsaw/pkg/models"
)

// TechDocConfig holds inputs for Article 10 technical documentation.
type TechDocConfig struct {
	ProductName    string
	Manufacturer   string
	ProductVersion string
	Category       string
	SupportEndDate string
	Components     []models.Component
	CRAResult      models.CRAResult
}

// WriteTechDoc generates a Markdown skeleton for CRA Article 10(2) documentation.
func WriteTechDoc(w io.Writer, cfg TechDocConfig) error {
	date := time.Now().Format("2006-01-02")

	sections := []struct {
		heading string
		content string
	}{
		{
			"1. General Description of the Product",
			fmt.Sprintf("**Product Name:** %s\n**Manufacturer:** %s\n**Version:** %s\n**CRA Category:** %s\n**Date:** %s\n\n"+
				"[TODO: Describe the product's intended purpose, target users, and operating environment.]",
				cfg.ProductName, cfg.Manufacturer, cfg.ProductVersion, cfg.Category, date),
		},
		{
			"2. Design and Development Process",
			"[TODO: Describe the secure development lifecycle (SDLC) applied during design and development, including threat modelling, secure coding practices, and code review procedures.]\n\n" +
				"**Automated Security Scanning:** This project uses `chainsaw` for continuous supply chain security scanning including vulnerability detection, licence compliance, and CRA conformity assessment.",
		},
		{
			"3. Software Bill of Materials (SBOM)",
			fmt.Sprintf("An SBOM in CycloneDX 1.5 format is generated with each release.\n\n"+
				"**Total components:** %d\n\n"+
				"Generate the current SBOM:\n```\nchainsaw sbom --format json\n```\n\n"+
				"[TODO: Attach or reference the SBOM file.]", len(cfg.Components)),
		},
		{
			"4. Vulnerability Assessment",
			formatVulnAssessment(cfg.CRAResult),
		},
		{
			"5. Security Update Mechanism",
			"[TODO: Describe how security updates are delivered to users, including:\n" +
				"- Update distribution channels\n" +
				"- Automatic vs manual update process\n" +
				"- Rollback procedures\n" +
				"- Notification mechanism for critical security updates]",
		},
		{
			"6. Vulnerability Handling Process",
			"[TODO: Describe the vulnerability handling process per Article 14, including:\n" +
				"- 24-hour early warning to ENISA CSIRT\n" +
				"- 72-hour detailed vulnerability notification\n" +
				"- 14-day final report\n" +
				"- Coordinated vulnerability disclosure policy\n" +
				"- Security contact information]",
		},
		{
			"7. Support Period",
			fmt.Sprintf("**Support End Date:** %s\n\n"+
				"[TODO: Confirm the support period meets the minimum 5-year requirement or the expected product lifetime, whichever is longer. Describe the support commitment.]",
				cfg.SupportEndDate),
		},
		{
			"8. Conformity Assessment",
			formatConformitySection(cfg.Category),
		},
	}

	fmt.Fprintf(w, "# Technical Documentation — %s\n\n", cfg.ProductName)
	fmt.Fprintf(w, "> CRA Article 10(2) Technical Documentation\n")
	fmt.Fprintf(w, "> Generated: %s\n\n", date)

	for _, s := range sections {
		fmt.Fprintf(w, "## %s\n\n%s\n\n", s.heading, s.content)
	}

	return nil
}

func formatVulnAssessment(result models.CRAResult) string {
	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("**CRA Compliance Score:** %d/100\n\n", result.OverallScore))

	pass, fail, warn := 0, 0, 0
	for _, c := range result.Checks {
		switch c.Status {
		case models.CRAPass:
			pass++
		case models.CRAFail:
			fail++
		case models.CRAWarn:
			warn++
		}
	}
	sb.WriteString(fmt.Sprintf("**Check Results:** %d passed, %d failed, %d warnings\n\n", pass, fail, warn))
	sb.WriteString("Run the current assessment:\n```\nchainsaw comply\n```\n\n")
	sb.WriteString("[TODO: Include a summary of the vulnerability assessment results and any accepted risks.]")
	return sb.String()
}

func formatConformitySection(category string) string {
	switch category {
	case "important-class-1":
		return "**Assessment Route:** Self-assessment with harmonised standards (Module A), or EU-type examination (Module B + C).\n\n" +
			"[TODO: Document which harmonised standards (EN 40000) are applied and attach self-assessment evidence.]"
	case "important-class-2":
		return "**Assessment Route:** EU-type examination by Notified Body (Module B + C), or certification (Module H).\n\n" +
			"[TODO: Identify the Notified Body engaged and attach conformity certificates.]"
	case "critical":
		return "**Assessment Route:** Third-party conformity assessment by Notified Body required.\n\n" +
			"[TODO: Identify the Notified Body engaged and attach conformity assessment report.]"
	default:
		return "**Assessment Route:** Manufacturer self-assessment (Module A) based on internal analysis.\n\n" +
			"[TODO: Document the self-assessment procedure and attach supporting evidence.]"
	}
}
