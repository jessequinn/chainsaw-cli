package cra

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"strings"

	"github.com/chainsaw-dev/chainsaw/pkg/models"
)

// sarifLog represents a SARIF 2.1.0 log structure.
type sarifLog struct {
	Schema  string      `json:"$schema"`
	Version string      `json:"version"`
	Runs    []sarifRun  `json:"runs"`
}

type sarifRun struct {
	Tool    sarifTool     `json:"tool"`
	Results []sarifResult `json:"results"`
}

type sarifTool struct {
	Driver sarifDriver `json:"driver"`
}

type sarifDriver struct {
	Name           string      `json:"name"`
	Version        string      `json:"version"`
	InformationURI string      `json:"informationUri"`
	Rules          []sarifRule `json:"rules"`
}

type sarifRule struct {
	ID               string                 `json:"id"`
	Name             string                 `json:"name"`
	ShortDescription sarifMessage           `json:"shortDescription"`
	HelpURI          string                 `json:"helpUri,omitempty"`
	Properties       map[string]interface{} `json:"properties,omitempty"`
}

type sarifResult struct {
	RuleID     string                 `json:"ruleId"`
	Level      string                 `json:"level"`
	Message    sarifMessage           `json:"message"`
	Properties map[string]interface{} `json:"properties,omitempty"`
}

type sarifMessage struct {
	Text string `json:"text"`
}

// WriteCRASARIF writes the CRA compliance result as SARIF 2.1.0 format.
// Passing and N/A checks are included as rules but not emitted as results.
// Failing and warning checks appear as results in the SARIF log.
func WriteCRASARIF(ctx context.Context, w io.Writer, result models.CRAResult) error {
	_ = ctx // for consistency with other reporters

	rules := make([]sarifRule, 0, len(result.Checks))
	results := make([]sarifResult, 0)

	for _, check := range result.Checks {
		rule := sarifRule{
			ID:               check.ID,
			Name:             sanitizeRuleName(check.Title),
			ShortDescription: sarifMessage{Text: check.Title},
			HelpURI:          articleToURI(check.Article),
			Properties: map[string]interface{}{
				"article": check.Article,
			},
		}
		rules = append(rules, rule)

		// Only emit results for non-passing checks.
		if check.Status == models.CRAPass || check.Status == models.CRANA {
			continue
		}

		level := mapCRASeverityToSARIF(check.Severity, check.Status)
		msg := check.Details
		if check.Remediation != "" {
			msg += " Remediation: " + check.Remediation
		}

		result := sarifResult{
			RuleID:  check.ID,
			Level:   level,
			Message: sarifMessage{Text: msg},
			Properties: map[string]interface{}{
				"status":   string(check.Status),
				"article":  check.Article,
				"severity": string(check.Severity),
			},
		}
		results = append(results, result)
	}

	log := sarifLog{
		Schema:  "https://json.schemastore.org/sarif-2.1.0.json",
		Version: "2.1.0",
		Runs: []sarifRun{
			{
				Tool: sarifTool{
					Driver: sarifDriver{
						Name:           "chainsaw-cra",
						Version:        "0.5.0",
						InformationURI: "https://github.com/chainsaw-dev/chainsaw",
						Rules:          rules,
					},
				},
				Results: results,
			},
		},
	}

	encoder := json.NewEncoder(w)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(log); err != nil {
		return fmt.Errorf("encoding CRA SARIF: %w", err)
	}
	return nil
}

// mapCRASeverityToSARIF maps CRA severity and status to SARIF level.
func mapCRASeverityToSARIF(sev models.Severity, status models.CRACheckStatus) string {
	if status == models.CRAWarn {
		return "warning"
	}
	switch sev {
	case models.SeverityCritical, models.SeverityHigh:
		return "error"
	case models.SeverityMedium:
		return "warning"
	default:
		return "note"
	}
}

// articleToURI maps a CRA article reference to a EUR-Lex URI.
// Example: "Article 14" -> "https://eur-lex.europa.eu/eli/reg/2024/2847/oj#article-14"
func articleToURI(article string) string {
	base := "https://eur-lex.europa.eu/eli/reg/2024/2847/oj"
	if article == "" {
		return base
	}
	return base + "#" + strings.ReplaceAll(strings.ToLower(article), " ", "-")
}

// sanitizeRuleName converts a check title to a SARIF-compliant rule name.
// Replaces spaces with hyphens and removes parentheses.
func sanitizeRuleName(title string) string {
	r := strings.NewReplacer(
		" ", "-",
		"(", "",
		")", "",
		"/", "-",
	)
	return r.Replace(title)
}
