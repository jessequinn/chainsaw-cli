package cra

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"time"

	"github.com/chainsaw-dev/chainsaw/pkg/models"
)

// WriteComplianceReport writes a human-readable CRA compliance report.
func WriteComplianceReport(_ context.Context, w io.Writer, result models.CRAResult) error {
	fmt.Fprintf(w, "CRA Compliance Assessment -- %s\n", result.Date.Format("2006-01-02"))
	fmt.Fprintf(w, "Regulation: %s\n", result.Regulation)
	fmt.Fprintln(w, "")

	if result.ProductName != "" && result.ProductName != "unknown" {
		fmt.Fprintf(w, "Product:  %s", result.ProductName)
		if result.Version != "" {
			fmt.Fprintf(w, " %s", result.Version)
		}
		fmt.Fprintln(w, "")
	}

	status := "NON-COMPLIANT"
	if result.OverallScore >= 90 {
		status = "COMPLIANT"
	} else if result.OverallScore >= 50 {
		status = "PARTIAL"
	}
	fmt.Fprintf(w, "Overall Score: %d%% (%s)\n", result.OverallScore, status)
	fmt.Fprintln(w, "")

	// Group checks by article.
	groups := map[string][]models.CRACheck{}
	groupOrder := []string{}
	for _, ch := range result.Checks {
		if _, exists := groups[ch.Article]; !exists {
			groupOrder = append(groupOrder, ch.Article)
		}
		groups[ch.Article] = append(groups[ch.Article], ch)
	}

	for _, article := range groupOrder {
		fmt.Fprintf(w, "--- %s ---\n", article)
		for _, ch := range groups[article] {
			tag := statusTag(ch.Status)
			fmt.Fprintf(w, "  %s %s\n", tag, ch.Title)
			fmt.Fprintf(w, "         %s\n", ch.Details)
		}
		fmt.Fprintln(w, "")
	}

	// Recommendations: failing checks sorted by severity (critical first).
	var failing []models.CRACheck
	for _, ch := range result.Checks {
		if ch.Status == models.CRAFail || ch.Status == models.CRAWarn {
			failing = append(failing, ch)
		}
	}
	sort.Slice(failing, func(i, j int) bool {
		return models.SeverityRank(failing[i].Severity) > models.SeverityRank(failing[j].Severity)
	})

	if len(failing) > 0 {
		fmt.Fprintln(w, "--- Recommendations ---")
		for _, ch := range failing {
			if ch.Remediation != "" {
				fmt.Fprintf(w, "  [%s] %s: %s\n", ch.Severity, ch.Title, ch.Remediation)
			}
		}
		fmt.Fprintln(w, "")
	}

	// Display CRA compliance deadline timeline.
	now := time.Now().UTC()
	deadlineTable := FormatDeadlineTable("default", now)
	fmt.Fprint(w, deadlineTable)
	fmt.Fprintln(w, "")

	fmt.Fprintln(w, "")
	fmt.Fprintln(w, "Disclaimer: This is a technical assessment aid, not legal advice or certification.")

	return nil
}

// WriteComplianceJSON writes the CRA result as indented JSON with deadline countdown.
func WriteComplianceJSON(_ context.Context, w io.Writer, result models.CRAResult) error {
	// Create a wrapper struct that includes days_remaining.
	wrapper := struct {
		*models.CRAResult
		DaysRemaining int `json:"days_remaining,omitempty"`
	}{
		CRAResult: &result,
	}

	// Calculate days remaining if deadline is set.
	if result.NextDeadline != "" {
		deadline, err := time.Parse("2006-01-02", result.NextDeadline)
		if err == nil {
			wrapper.DaysRemaining = int(time.Until(deadline).Hours() / 24)
		}
	}

	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(wrapper)
}

func statusTag(s models.CRACheckStatus) string {
	switch s {
	case models.CRAPass:
		return "[PASS]"
	case models.CRAFail:
		return "[FAIL]"
	case models.CRAWarn:
		return "[WARN]"
	case models.CRANA:
		return "[N/A] "
	default:
		return "[????]"
	}
}
