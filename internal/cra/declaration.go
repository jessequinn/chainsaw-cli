package cra

import (
	"fmt"
	"io"
	"time"

	"github.com/chainsaw-dev/chainsaw/pkg/models"
)

// DeclarationConfig holds inputs for the EU Declaration of Conformity.
type DeclarationConfig struct {
	ProductName    string
	Manufacturer   string
	ProductVersion string
	Category       string
	Address        string
	CRAResult      models.CRAResult
}

// WriteDeclaration generates a Markdown EU Declaration of Conformity per CRA Article 28.
func WriteDeclaration(w io.Writer, cfg DeclarationConfig) error {
	date := time.Now().Format("2006-01-02")

	fmt.Fprintf(w, "# EU Declaration of Conformity\n\n")
	fmt.Fprintf(w, "> Regulation (EU) 2024/2847 — Cyber Resilience Act, Article 28\n\n")

	fmt.Fprintf(w, "## 1. Product Identification\n\n")
	fmt.Fprintf(w, "| Field | Value |\n|---|---|\n")
	fmt.Fprintf(w, "| Product Name | %s |\n", cfg.ProductName)
	fmt.Fprintf(w, "| Version | %s |\n", cfg.ProductVersion)
	fmt.Fprintf(w, "| Product Category | %s |\n", cfg.Category)
	fmt.Fprintf(w, "| Date of Declaration | %s |\n\n", date)

	fmt.Fprintf(w, "## 2. Manufacturer Information\n\n")
	fmt.Fprintf(w, "| Field | Value |\n|---|---|\n")
	fmt.Fprintf(w, "| Manufacturer | %s |\n", cfg.Manufacturer)
	if cfg.Address != "" {
		fmt.Fprintf(w, "| Address | %s |\n", cfg.Address)
	} else {
		fmt.Fprintf(w, "| Address | [TODO: Add registered address] |\n")
	}
	fmt.Fprintln(w)

	fmt.Fprintf(w, "## 3. Object of the Declaration\n\n")
	fmt.Fprintf(w, "This declaration of conformity is issued under the sole responsibility of the manufacturer for the product identified above.\n\n")

	fmt.Fprintf(w, "## 4. Applicable Legislation\n\n")
	fmt.Fprintf(w, "- Regulation (EU) 2024/2847 of the European Parliament and of the Council (Cyber Resilience Act)\n\n")

	fmt.Fprintf(w, "## 5. Standards Applied\n\n")
	fmt.Fprintf(w, "| Standard | Status |\n|---|---|\n")
	fmt.Fprintf(w, "| EN 40000 (Harmonised standard for CRA) | [TODO: Pending publication / Applied] |\n")
	fmt.Fprintf(w, "| ISO/IEC 27001 | [TODO: Applied / Not applied] |\n")
	fmt.Fprintf(w, "| ISO/IEC 62443 | [TODO: Applied / Not applied] |\n\n")

	fmt.Fprintf(w, "## 6. Essential Requirements Addressed\n\n")
	fmt.Fprintf(w, "**CRA Compliance Score:** %d/100\n\n", cfg.CRAResult.OverallScore)

	pass, fail, warn := 0, 0, 0
	for _, c := range cfg.CRAResult.Checks {
		switch c.Status {
		case models.CRAPass:
			pass++
		case models.CRAFail:
			fail++
		case models.CRAWarn:
			warn++
		}
	}
	fmt.Fprintf(w, "| Status | Count |\n|---|---|\n")
	fmt.Fprintf(w, "| Requirements met | %d |\n", pass)
	fmt.Fprintf(w, "| Requirements not met | %d |\n", fail)
	fmt.Fprintf(w, "| Warnings | %d |\n\n", warn)

	fmt.Fprintf(w, "## 7. Conformity Assessment Procedure\n\n")
	fmt.Fprintf(w, "%s\n\n", conformityProcedure(cfg.Category))

	fmt.Fprintf(w, "## 8. Signature\n\n")
	fmt.Fprintf(w, "Signed for and on behalf of: %s\n\n", cfg.Manufacturer)
	fmt.Fprintf(w, "Name: [TODO: Authorized signatory]\n\n")
	fmt.Fprintf(w, "Title: [TODO: Title/Position]\n\n")
	fmt.Fprintf(w, "Date: %s\n\n", date)
	fmt.Fprintf(w, "Signature: ____________________________\n")

	return nil
}

func conformityProcedure(category string) string {
	switch category {
	case "important-class-1":
		return "Module A (internal production control) based on harmonised standards, or Module B + C (EU-type examination)."
	case "important-class-2":
		return "Module B + C (EU-type examination) or Module H (full quality assurance) by designated Notified Body."
	case "critical":
		return "Third-party conformity assessment by designated Notified Body (mandatory)."
	default:
		return "Module A (internal production control) — manufacturer self-assessment based on internal analysis of essential requirements."
	}
}
