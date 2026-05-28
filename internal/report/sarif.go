package report

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"

	"github.com/chainsaw-dev/chainsaw/pkg/models"
)

const (
	sarifVersion = "2.1.0"
	sarifSchema  = "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/sarif-2.1/schema/sarif-schema-2.1.0.json"
)

type sarifLog struct {
	Version string     `json:"version"`
	Schema  string     `json:"$schema"`
	Runs    []sarifRun `json:"runs"`
}

type sarifRun struct {
	Tool    sarifTool     `json:"tool"`
	Results []sarifResult `json:"results"`
}

type sarifTool struct {
	Driver sarifDriver `json:"driver"`
}

type sarifDriver struct {
	Name            string      `json:"name"`
	Version         string      `json:"version"`
	SemanticVersion string      `json:"semanticVersion,omitempty"`
	InformationURI  string      `json:"informationUri,omitempty"`
	Rules           []sarifRule `json:"rules"`
}

type sarifRule struct {
	ID                   string             `json:"id"`
	ShortDescription     sarifMessage       `json:"shortDescription"`
	FullDescription      sarifMessage       `json:"fullDescription"`
	HelpURI              string             `json:"helpUri,omitempty"`
	Help                 *sarifMessage      `json:"help,omitempty"`
	DefaultConfiguration sarifConfiguration `json:"defaultConfiguration"`
}

type sarifConfiguration struct {
	Level string `json:"level"`
}

type sarifMessage struct {
	Text     string `json:"text"`
	Markdown string `json:"markdown,omitempty"`
}

type sarifResult struct {
	RuleID       string            `json:"ruleId"`
	RuleIndex    int               `json:"ruleIndex"`
	Level        string            `json:"level"`
	Message      sarifMessage      `json:"message"`
	Locations    []sarifLocation   `json:"locations,omitempty"`
	Fingerprints map[string]string `json:"fingerprints,omitempty"`
}

type sarifLocation struct {
	PhysicalLocation sarifPhysicalLocation `json:"physicalLocation"`
}

type sarifPhysicalLocation struct {
	ArtifactLocation sarifArtifactLocation `json:"artifactLocation"`
}

type sarifArtifactLocation struct {
	URI string `json:"uri"`
}

// severityToSARIFLevel maps a chainsaw Severity to a SARIF level string.
func severityToSARIFLevel(s models.Severity) string {
	switch s {
	case models.SeverityCritical, models.SeverityHigh:
		return "error"
	case models.SeverityMedium:
		return "warning"
	default:
		return "note"
	}
}

// WriteSARIF writes scan results in SARIF 2.1.0 format to w.
func WriteSARIF(_ context.Context, w io.Writer, result models.ScanResult) error {
	allFindings := make([]models.Finding, 0, len(result.Findings)+len(result.Hygiene))
	allFindings = append(allFindings, result.Findings...)
	allFindings = append(allFindings, result.Hygiene...)

	ruleIndex := make(map[string]int)
	var rules []sarifRule

	for _, f := range allFindings {
		if _, exists := ruleIndex[f.ID]; exists {
			continue
		}
		ruleIndex[f.ID] = len(rules)

		short := f.Summary
		full := f.Details
		if full == "" {
			full = f.Summary
		}

		rule := sarifRule{
			ID:               f.ID,
			ShortDescription: sarifMessage{Text: short},
			FullDescription:  sarifMessage{Text: full},
			HelpURI:          fmt.Sprintf("https://osv.dev/vulnerability/%s", f.ID),
			DefaultConfiguration: sarifConfiguration{
				Level: severityToSARIFLevel(f.Severity),
			},
		}

		if f.FixedIn != "" {
			helpText := fmt.Sprintf("Upgrade %s to %s.", f.Component.Name, f.FixedIn)
			helpMD := fmt.Sprintf("Upgrade `%s` to `%s`.", f.Component.Name, f.FixedIn)
			rule.Help = &sarifMessage{Text: helpText, Markdown: helpMD}
		}

		rules = append(rules, rule)
	}

	results := make([]sarifResult, 0, len(allFindings))
	for _, f := range allFindings {
		idx := ruleIndex[f.ID]
		msgText := fmt.Sprintf("%s %s@%s: %s", f.Severity, f.Component.Name, f.Component.Version, f.Summary)
		msgMD := fmt.Sprintf("**%s** `%s@%s`: %s", f.Severity, f.Component.Name, f.Component.Version, f.Summary)

		fpHash := sha256.Sum256([]byte(f.Component.Name + "|" + f.Component.Version + "|" + f.ID))

		r := sarifResult{
			RuleID:    f.ID,
			RuleIndex: idx,
			Level:     severityToSARIFLevel(f.Severity),
			Message:   sarifMessage{Text: msgText, Markdown: msgMD},
			Fingerprints: map[string]string{
				"primaryLocationLineHash": fmt.Sprintf("%x", fpHash),
			},
		}

		if f.Component.PkgURL != "" {
			r.Locations = []sarifLocation{{
				PhysicalLocation: sarifPhysicalLocation{
					ArtifactLocation: sarifArtifactLocation{
						URI: f.Component.PkgURL,
					},
				},
			}}
		}

		results = append(results, r)
	}

	log := sarifLog{
		Version: sarifVersion,
		Schema:  sarifSchema,
		Runs: []sarifRun{{
			Tool: sarifTool{
				Driver: sarifDriver{
					Name:            "chainsaw",
					Version:         result.ToolVersion,
					SemanticVersion: result.ToolVersion,
					InformationURI:  "https://github.com/chainsaw-dev/chainsaw",
					Rules:           rules,
				},
			},
			Results: results,
		}},
	}

	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	if err := enc.Encode(log); err != nil {
		return fmt.Errorf("encoding SARIF: %w", err)
	}
	return nil
}
