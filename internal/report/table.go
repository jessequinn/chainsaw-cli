package report

import (
	"fmt"
	"io"

	"github.com/chainsaw-dev/chainsaw/pkg/models"
)

// truncate shortens s to maxLen, appending "..." if truncated.
func truncate(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	if maxLen <= 3 {
		return s[:maxLen]
	}
	return s[:maxLen-3] + "..."
}

// WriteTable writes scan results as a formatted plain-text table to w.
func WriteTable(w io.Writer, result models.ScanResult) error {
	if _, err := fmt.Fprintf(w, "Chainsaw Scan Results  %s\n", result.Timestamp.Format("2006-01-02 15:04:05 MST")); err != nil {
		return fmt.Errorf("writing header: %w", err)
	}

	vulnCount := len(result.Findings)
	hygieneCount := len(result.Hygiene)
	if _, err := fmt.Fprintf(w, "%d components scanned, %d vulnerabilities found, %d hygiene warnings\n\n",
		len(result.Components), vulnCount, hygieneCount); err != nil {
		return fmt.Errorf("writing summary: %w", err)
	}

	if err := writeVulnTable(w, result.Findings); err != nil {
		return err
	}

	if hygieneCount > 0 {
		if err := writeHygieneTable(w, result.Hygiene); err != nil {
			return err
		}
	}

	return nil
}

func writeVulnTable(w io.Writer, findings []models.Finding) error {
	header := fmt.Sprintf("%-10s %-20s %-40s %-12s %-12s %s\n",
		"SEVERITY", "ID", "PACKAGE", "VERSION", "FIXED IN", "SUMMARY")
	separator := fmt.Sprintf("%-10s %-20s %-40s %-12s %-12s %s\n",
		"--------", "--", "-------", "-------", "--------", "-------")

	if _, err := fmt.Fprint(w, header); err != nil {
		return fmt.Errorf("writing vuln header: %w", err)
	}
	if _, err := fmt.Fprint(w, separator); err != nil {
		return fmt.Errorf("writing vuln separator: %w", err)
	}

	for _, f := range findings {
		fixedIn := f.FixedIn
		if fixedIn == "" {
			fixedIn = "-"
		}
		line := fmt.Sprintf("%-10s %-20s %-40s %-12s %-12s %s\n",
			truncate(string(f.Severity), 10),
			truncate(f.ID, 20),
			truncate(f.Component.Name, 40),
			truncate(f.Component.Version, 12),
			truncate(fixedIn, 12),
			truncate(f.Summary, 60),
		)
		if _, err := fmt.Fprint(w, line); err != nil {
			return fmt.Errorf("writing vuln row: %w", err)
		}
	}

	if _, err := fmt.Fprintln(w); err != nil {
		return fmt.Errorf("writing vuln footer: %w", err)
	}
	return nil
}

func writeHygieneTable(w io.Writer, findings []models.Finding) error {
	if _, err := fmt.Fprintln(w, "Hygiene Warnings"); err != nil {
		return fmt.Errorf("writing hygiene title: %w", err)
	}

	header := fmt.Sprintf("%-10s %-20s %-40s %-12s %s\n",
		"SEVERITY", "ID", "PACKAGE", "VERSION", "SUMMARY")
	separator := fmt.Sprintf("%-10s %-20s %-40s %-12s %s\n",
		"--------", "--", "-------", "-------", "-------")

	if _, err := fmt.Fprint(w, header); err != nil {
		return fmt.Errorf("writing hygiene header: %w", err)
	}
	if _, err := fmt.Fprint(w, separator); err != nil {
		return fmt.Errorf("writing hygiene separator: %w", err)
	}

	for _, f := range findings {
		line := fmt.Sprintf("%-10s %-20s %-40s %-12s %s\n",
			truncate(string(f.Severity), 10),
			truncate(f.ID, 20),
			truncate(f.Component.Name, 40),
			truncate(f.Component.Version, 12),
			truncate(f.Summary, 60),
		)
		if _, err := fmt.Fprint(w, line); err != nil {
			return fmt.Errorf("writing hygiene row: %w", err)
		}
	}

	if _, err := fmt.Fprintln(w); err != nil {
		return fmt.Errorf("writing hygiene footer: %w", err)
	}
	return nil
}
