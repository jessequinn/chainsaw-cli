package diff

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"sort"

	"github.com/chainsaw-dev/chainsaw/pkg/models"
)

// DiffResult holds the comparison between two scan results.
type DiffResult struct {
	NewVulnerabilities   []models.Finding   `json:"new_vulnerabilities"`
	FixedVulnerabilities []models.Finding   `json:"fixed_vulnerabilities"`
	NewComponents        []models.Component `json:"new_components"`
	RemovedComponents    []models.Component `json:"removed_components"`
	BaseComponentCount   int                `json:"base_component_count"`
	HeadComponentCount   int                `json:"head_component_count"`
	BaseVulnCount        int                `json:"base_vuln_count"`
	HeadVulnCount        int                `json:"head_vuln_count"`
}

func findingKey(f models.Finding) string {
	return f.ID + "|" + f.Component.Name + "|" + f.Component.Version
}

func componentKey(c models.Component) string {
	return c.Name + "|" + c.Version
}

// Compare compares two ScanResults and returns the diff.
func Compare(base, head models.ScanResult) DiffResult {
	baseFindings := make(map[string]models.Finding, len(base.Findings))
	for _, f := range base.Findings {
		baseFindings[findingKey(f)] = f
	}
	headFindings := make(map[string]models.Finding, len(head.Findings))
	for _, f := range head.Findings {
		headFindings[findingKey(f)] = f
	}

	var newVulns, fixedVulns []models.Finding
	for k, f := range headFindings {
		if _, ok := baseFindings[k]; !ok {
			newVulns = append(newVulns, f)
		}
	}
	for k, f := range baseFindings {
		if _, ok := headFindings[k]; !ok {
			fixedVulns = append(fixedVulns, f)
		}
	}

	sort.Slice(newVulns, func(i, j int) bool { return newVulns[i].ID < newVulns[j].ID })
	sort.Slice(fixedVulns, func(i, j int) bool { return fixedVulns[i].ID < fixedVulns[j].ID })

	baseComps := make(map[string]models.Component, len(base.Components))
	for _, c := range base.Components {
		baseComps[componentKey(c)] = c
	}
	headComps := make(map[string]models.Component, len(head.Components))
	for _, c := range head.Components {
		headComps[componentKey(c)] = c
	}

	var newComps, removedComps []models.Component
	for k, c := range headComps {
		if _, ok := baseComps[k]; !ok {
			newComps = append(newComps, c)
		}
	}
	for k, c := range baseComps {
		if _, ok := headComps[k]; !ok {
			removedComps = append(removedComps, c)
		}
	}

	sort.Slice(newComps, func(i, j int) bool { return newComps[i].Name < newComps[j].Name })
	sort.Slice(removedComps, func(i, j int) bool { return removedComps[i].Name < removedComps[j].Name })

	return DiffResult{
		NewVulnerabilities:   newVulns,
		FixedVulnerabilities: fixedVulns,
		NewComponents:        newComps,
		RemovedComponents:    removedComps,
		BaseComponentCount:   len(base.Components),
		HeadComponentCount:   len(head.Components),
		BaseVulnCount:        len(base.Findings),
		HeadVulnCount:        len(head.Findings),
	}
}

// LoadScanResult loads a ScanResult from a JSON file.
func LoadScanResult(path string) (models.ScanResult, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return models.ScanResult{}, fmt.Errorf("reading scan result %s: %w", path, err)
	}
	var result models.ScanResult
	if err := json.Unmarshal(data, &result); err != nil {
		return models.ScanResult{}, fmt.Errorf("parsing scan result %s: %w", path, err)
	}
	return result, nil
}

// WriteDiffReport writes a human-readable diff report.
func WriteDiffReport(_ context.Context, w io.Writer, result DiffResult) error {
	fmt.Fprintln(w, "Scan Diff Summary")
	fmt.Fprintln(w, "=================")
	fmt.Fprintf(w, "Components: %d -> %d (+%d new, %d removed)\n",
		result.BaseComponentCount, result.HeadComponentCount,
		len(result.NewComponents), len(result.RemovedComponents))
	fmt.Fprintf(w, "Vulnerabilities: %d -> %d (+%d new, %d fixed)\n",
		result.BaseVulnCount, result.HeadVulnCount,
		len(result.NewVulnerabilities), len(result.FixedVulnerabilities))

	fmt.Fprintln(w)
	fmt.Fprintln(w, "New Vulnerabilities:")
	if len(result.NewVulnerabilities) == 0 {
		fmt.Fprintln(w, "  (none)")
	} else {
		for _, f := range result.NewVulnerabilities {
			line := fmt.Sprintf("  [%s] %s in %s@%s", f.Severity, f.ID, f.Component.Name, f.Component.Version)
			if f.FixedIn != "" {
				line += fmt.Sprintf(" (fixed in %s)", f.FixedIn)
			}
			fmt.Fprintln(w, line)
		}
	}

	fmt.Fprintln(w)
	fmt.Fprintln(w, "Fixed Vulnerabilities:")
	if len(result.FixedVulnerabilities) == 0 {
		fmt.Fprintln(w, "  (none)")
	} else {
		for _, f := range result.FixedVulnerabilities {
			line := fmt.Sprintf("  [%s] %s in %s@%s", f.Severity, f.ID, f.Component.Name, f.Component.Version)
			if f.FixedIn != "" {
				line += fmt.Sprintf(" (fixed in %s)", f.FixedIn)
			}
			fmt.Fprintln(w, line)
		}
	}

	fmt.Fprintln(w)
	fmt.Fprintln(w, "New Components:")
	if len(result.NewComponents) == 0 {
		fmt.Fprintln(w, "  (none)")
	} else {
		for _, c := range result.NewComponents {
			fmt.Fprintf(w, "  %s@%s (%s)\n", c.Name, c.Version, c.Ecosystem)
		}
	}

	fmt.Fprintln(w)
	fmt.Fprintln(w, "Removed Components:")
	if len(result.RemovedComponents) == 0 {
		fmt.Fprintln(w, "  (none)")
	} else {
		for _, c := range result.RemovedComponents {
			fmt.Fprintf(w, "  %s@%s (%s)\n", c.Name, c.Version, c.Ecosystem)
		}
	}

	return nil
}

// WriteDiffJSON writes the diff as JSON.
func WriteDiffJSON(_ context.Context, w io.Writer, result DiffResult) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	if err := enc.Encode(result); err != nil {
		return fmt.Errorf("encoding diff JSON: %w", err)
	}
	return nil
}

// WriteDiffMarkdown writes the diff as markdown (for PR comments).
func WriteDiffMarkdown(_ context.Context, w io.Writer, result DiffResult) error {
	fmt.Fprintln(w, "## Scan Diff Summary")
	fmt.Fprintln(w)
	fmt.Fprintf(w, "**Components:** %d -> %d (+%d new, %d removed)\n",
		result.BaseComponentCount, result.HeadComponentCount,
		len(result.NewComponents), len(result.RemovedComponents))
	fmt.Fprintf(w, "**Vulnerabilities:** %d -> %d (+%d new, %d fixed)\n",
		result.BaseVulnCount, result.HeadVulnCount,
		len(result.NewVulnerabilities), len(result.FixedVulnerabilities))

	fmt.Fprintln(w)
	fmt.Fprintln(w, "### New Vulnerabilities")
	if len(result.NewVulnerabilities) == 0 {
		fmt.Fprintln(w, "None")
	} else {
		fmt.Fprintln(w, "| Severity | ID | Package | Fixed In |")
		fmt.Fprintln(w, "|----------|-----|---------|----------|")
		for _, f := range result.NewVulnerabilities {
			fixed := "-"
			if f.FixedIn != "" {
				fixed = f.FixedIn
			}
			fmt.Fprintf(w, "| **%s** | %s | %s@%s | %s |\n", f.Severity, f.ID, f.Component.Name, f.Component.Version, fixed)
		}
	}

	fmt.Fprintln(w)
	fmt.Fprintln(w, "### Fixed Vulnerabilities")
	if len(result.FixedVulnerabilities) == 0 {
		fmt.Fprintln(w, "None")
	} else {
		fmt.Fprintln(w, "| Severity | ID | Package |")
		fmt.Fprintln(w, "|----------|-----|---------|")
		for _, f := range result.FixedVulnerabilities {
			fmt.Fprintf(w, "| **%s** | %s | %s@%s |\n", f.Severity, f.ID, f.Component.Name, f.Component.Version)
		}
	}

	fmt.Fprintln(w)
	fmt.Fprintln(w, "### New Components")
	if len(result.NewComponents) == 0 {
		fmt.Fprintln(w, "None")
	} else {
		for _, c := range result.NewComponents {
			fmt.Fprintf(w, "- `%s@%s` (%s)\n", c.Name, c.Version, c.Ecosystem)
		}
	}

	fmt.Fprintln(w)
	fmt.Fprintln(w, "### Removed Components")
	if len(result.RemovedComponents) == 0 {
		fmt.Fprintln(w, "None")
	} else {
		for _, c := range result.RemovedComponents {
			fmt.Fprintf(w, "- `%s@%s` (%s)\n", c.Name, c.Version, c.Ecosystem)
		}
	}

	return nil
}
