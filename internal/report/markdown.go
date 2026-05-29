package report

import (
	"context"
	"fmt"
	"io"
	"strings"

	"github.com/chainsaw-dev/chainsaw/pkg/models"
)

// WriteMarkdown writes scan results as Markdown tables.
func WriteMarkdown(_ context.Context, w io.Writer, result models.ScanResult) error {
	if _, err := fmt.Fprintf(w, "# Chainsaw Scan Report\n\n"); err != nil {
		return fmt.Errorf("writing title: %w", err)
	}

	// Summary
	if _, err := fmt.Fprintf(w, "## Summary\n\n"); err != nil {
		return fmt.Errorf("writing summary heading: %w", err)
	}
	if _, err := fmt.Fprintf(w, "| Metric | Value |\n"); err != nil {
		return fmt.Errorf("writing summary table header: %w", err)
	}
	if _, err := fmt.Fprintf(w, "|---|---|\n"); err != nil {
		return fmt.Errorf("writing summary table separator: %w", err)
	}
	if _, err := fmt.Fprintf(w, "| Components | %d |\n", len(result.Components)); err != nil {
		return fmt.Errorf("writing components count: %w", err)
	}
	if _, err := fmt.Fprintf(w, "| Vulnerabilities | %d |\n", len(result.Findings)); err != nil {
		return fmt.Errorf("writing vulnerabilities count: %w", err)
	}
	if _, err := fmt.Fprintf(w, "| Hygiene Issues | %d |\n\n", len(result.Hygiene)); err != nil {
		return fmt.Errorf("writing hygiene count: %w", err)
	}

	// Severity breakdown
	sev := map[models.Severity]int{}
	for _, f := range result.Findings {
		sev[f.Severity]++
	}
	if len(sev) > 0 {
		if _, err := fmt.Fprintf(w, "**Severity Breakdown:** "); err != nil {
			return fmt.Errorf("writing severity breakdown label: %w", err)
		}
		parts := []string{}
		for _, s := range []models.Severity{models.SeverityCritical, models.SeverityHigh, models.SeverityMedium, models.SeverityLow} {
			if c := sev[s]; c > 0 {
				parts = append(parts, fmt.Sprintf("%s: %d", s, c))
			}
		}
		if _, err := fmt.Fprintf(w, "%s\n\n", strings.Join(parts, " | ")); err != nil {
			return fmt.Errorf("writing severity breakdown: %w", err)
		}
	}

	// Findings table
	if len(result.Findings) > 0 {
		if _, err := fmt.Fprintf(w, "## Vulnerabilities\n\n"); err != nil {
			return fmt.Errorf("writing vulnerabilities heading: %w", err)
		}
		if _, err := fmt.Fprintf(w, "| ID | Package | Version | Severity | Summary |\n"); err != nil {
			return fmt.Errorf("writing vulnerabilities header: %w", err)
		}
		if _, err := fmt.Fprintf(w, "|---|---|---|---|---|\n"); err != nil {
			return fmt.Errorf("writing vulnerabilities separator: %w", err)
		}
		for _, f := range result.Findings {
			summary := escapeMarkdown(f.Summary)
			if len(summary) > 80 {
				summary = summary[:77] + "..."
			}
			if _, err := fmt.Fprintf(w, "| %s | %s | %s | %s | %s |\n",
				escapeMarkdown(f.ID), escapeMarkdown(f.Component.Name), escapeMarkdown(f.Component.Version), f.Severity, summary); err != nil {
				return fmt.Errorf("writing vulnerability row: %w", err)
			}
		}
		if _, err := fmt.Fprintln(w); err != nil {
			return fmt.Errorf("writing vulnerabilities footer: %w", err)
		}
	}

	// Hygiene table
	if len(result.Hygiene) > 0 {
		if _, err := fmt.Fprintf(w, "## Hygiene Issues\n\n"); err != nil {
			return fmt.Errorf("writing hygiene heading: %w", err)
		}
		if _, err := fmt.Fprintf(w, "| ID | Package | Severity | Summary |\n"); err != nil {
			return fmt.Errorf("writing hygiene header: %w", err)
		}
		if _, err := fmt.Fprintf(w, "|---|---|---|---|\n"); err != nil {
			return fmt.Errorf("writing hygiene separator: %w", err)
		}
		for _, f := range result.Hygiene {
			summary := escapeMarkdown(f.Summary)
			if len(summary) > 80 {
				summary = summary[:77] + "..."
			}
			if _, err := fmt.Fprintf(w, "| %s | %s | %s | %s |\n",
				escapeMarkdown(f.ID), escapeMarkdown(f.Component.Name), f.Severity, summary); err != nil {
				return fmt.Errorf("writing hygiene row: %w", err)
			}
		}
		if _, err := fmt.Fprintln(w); err != nil {
			return fmt.Errorf("writing hygiene footer: %w", err)
		}
	}

	// Components
	if _, err := fmt.Fprintf(w, "## Components\n\n"); err != nil {
		return fmt.Errorf("writing components heading: %w", err)
	}
	if _, err := fmt.Fprintf(w, "| Name | Version | Ecosystem | Direct |\n"); err != nil {
		return fmt.Errorf("writing components header: %w", err)
	}
	if _, err := fmt.Fprintf(w, "|---|---|---|---|\n"); err != nil {
		return fmt.Errorf("writing components separator: %w", err)
	}
	for _, c := range result.Components {
		direct := "No"
		if c.Direct {
			direct = "Yes"
		}
		if _, err := fmt.Fprintf(w, "| %s | %s | %s | %s |\n", escapeMarkdown(c.Name), escapeMarkdown(c.Version), c.Ecosystem, direct); err != nil {
			return fmt.Errorf("writing component row: %w", err)
		}
	}

	return nil
}

// WriteCRAMarkdown writes CRA results as Markdown.
func WriteCRAMarkdown(_ context.Context, w io.Writer, result models.CRAResult) error {
	if _, err := fmt.Fprintf(w, "# CRA Compliance Report\n\n"); err != nil {
		return fmt.Errorf("writing title: %w", err)
	}
	if _, err := fmt.Fprintf(w, "**Overall Score:** %d/100\n\n", result.OverallScore); err != nil {
		return fmt.Errorf("writing overall score: %w", err)
	}

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
	if _, err := fmt.Fprintf(w, "| Status | Count |\n"); err != nil {
		return fmt.Errorf("writing status header: %w", err)
	}
	if _, err := fmt.Fprintf(w, "|---|---|\n"); err != nil {
		return fmt.Errorf("writing status separator: %w", err)
	}
	if _, err := fmt.Fprintf(w, "| Pass | %d |\n| Fail | %d |\n| Warn | %d |\n\n", pass, fail, warn); err != nil {
		return fmt.Errorf("writing status rows: %w", err)
	}

	if _, err := fmt.Fprintf(w, "## Checks\n\n"); err != nil {
		return fmt.Errorf("writing checks heading: %w", err)
	}
	if _, err := fmt.Fprintf(w, "| ID | Article | Status | Title |\n"); err != nil {
		return fmt.Errorf("writing checks header: %w", err)
	}
	if _, err := fmt.Fprintf(w, "|---|---|---|---|\n"); err != nil {
		return fmt.Errorf("writing checks separator: %w", err)
	}
	for _, c := range result.Checks {
		status := statusString(c.Status)
		if _, err := fmt.Fprintf(w, "| %s | %s | %s | %s |\n", escapeMarkdown(c.ID), escapeMarkdown(c.Article), status, escapeMarkdown(c.Title)); err != nil {
			return fmt.Errorf("writing check row: %w", err)
		}
	}

	return nil
}

func statusString(s models.CRACheckStatus) string {
	switch s {
	case models.CRAPass:
		return "PASS"
	case models.CRAFail:
		return "FAIL"
	case models.CRAWarn:
		return "WARN"
	default:
		return "N/A"
	}
}

func escapeMarkdown(s string) string {
	r := strings.NewReplacer("|", "\\|", "\n", " ")
	return r.Replace(s)
}
