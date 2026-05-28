package analysis

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"strings"

	"github.com/chainsaw-dev/chainsaw/pkg/models"
)

// WriteSupplyChainReport writes a human-readable supply chain analysis.
func WriteSupplyChainReport(_ context.Context, w io.Writer, result models.SupplyChainResult) error {
	// Header
	fmt.Fprintf(w, "Supply Chain Analysis -- %s\n", result.Timestamp.Format("2006-01-02 15:04:05"))
	fmt.Fprintf(w, "Tool version: %s\n\n", result.ToolVersion)

	// Layer summary
	var appCount, infraCount, ciCount int
	for _, c := range result.Components {
		switch c.Layer {
		case "application":
			appCount++
		case "infrastructure":
			infraCount++
		case "ci-cd":
			ciCount++
		}
	}
	fmt.Fprintf(w, "Components: %d application, %d infrastructure, %d CI/CD\n",
		appCount, infraCount, ciCount)

	// Pinning score
	fmt.Fprintf(w, "Pinning score: %d/100\n\n", result.PinningScore)

	// Table of non-application components
	infraComponents := filterNonApp(result.Components)
	if len(infraComponents) > 0 {
		fmt.Fprintf(w, "%-14s %-12s %-40s %s\n", "PIN TYPE", "SOURCE", "COMPONENT", "BLAST RADIUS")
		fmt.Fprintf(w, "%s\n", strings.Repeat("-", 90))

		brByName := make(map[string]models.BlastRadius, len(result.BlastRadii))
		for _, br := range result.BlastRadii {
			brByName[br.Component.Name] = br
		}

		for _, ic := range infraComponents {
			label := truncate(ic.Name+"@"+ic.Version, 40)
			blastLabel := "n/a"
			if br, ok := brByName[ic.Name]; ok {
				blastLabel = blastSeverityLabel(br.Score)
				if ic.Mutable {
					blastLabel += " (mutable!)"
				}
			}
			fmt.Fprintf(w, "%-14s %-12s %-40s %s\n",
				string(ic.PinType), string(ic.SourceTrust), label, blastLabel)
		}
		fmt.Fprintln(w)
	}

	// Risk summary
	if len(result.BlastRadii) > 0 {
		var critical, high, medium, low int
		for _, br := range result.BlastRadii {
			switch {
			case br.Score >= 80:
				critical++
			case br.Score >= 60:
				high++
			case br.Score >= 40:
				medium++
			default:
				low++
			}
		}
		fmt.Fprintln(w, "Risk summary:")
		fmt.Fprintf(w, "  Critical (>=80): %d\n", critical)
		fmt.Fprintf(w, "  High     (>=60): %d\n", high)
		fmt.Fprintf(w, "  Medium   (>=40): %d\n", medium)
		fmt.Fprintf(w, "  Low      (<40):  %d\n\n", low)
	}

	// Recommendations
	var mutableComponents []models.InfraComponent
	for _, ic := range infraComponents {
		if ic.Mutable {
			mutableComponents = append(mutableComponents, ic)
		}
	}
	if len(mutableComponents) > 0 {
		fmt.Fprintln(w, "Recommendations:")
		for _, ic := range mutableComponents {
			fmt.Fprintf(w, "  - Pin %s (%s) to an immutable reference (commit SHA or digest)\n",
				ic.Name, string(ic.Ecosystem))
		}
		fmt.Fprintln(w)
	}

	return nil
}

// WriteSupplyChainJSON writes machine-readable JSON output.
func WriteSupplyChainJSON(_ context.Context, w io.Writer, result models.SupplyChainResult) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(result)
}

func filterNonApp(components []models.InfraComponent) []models.InfraComponent {
	var out []models.InfraComponent
	for _, c := range components {
		if c.Layer != "application" {
			out = append(out, c)
		}
	}
	return out
}

func truncate(s string, max int) string {
	if len(s) <= max {
		return s
	}
	return s[:max-3] + "..."
}

func blastSeverityLabel(score int) string {
	switch {
	case score >= 80:
		return "critical"
	case score >= 60:
		return "high"
	case score >= 40:
		return "medium"
	default:
		return "low"
	}
}
