package vuln

import (
	"sort"

	"github.com/chainsaw-dev/chainsaw/pkg/models"
)

var severityOrder = map[models.Severity]int{
	"CRITICAL": 0,
	"HIGH":     1,
	"MEDIUM":   2,
	"LOW":      3,
	"UNKNOWN":  4,
}

// Matcher combines OSV vulnerability results with hygiene findings.
type Matcher struct {
	client *Client
}

// NewMatcher creates a Matcher backed by the given OSV client.
func NewMatcher(client *Client) *Matcher {
	return &Matcher{client: client}
}

// Match queries OSV for the given components, deduplicates findings, and
// returns them sorted by severity (CRITICAL first), then by ID.
func (m *Matcher) Match(components []models.Component) ([]models.Finding, error) {
	findings, err := m.client.QueryBatch(components)
	if err != nil {
		return nil, err
	}

	findings = deduplicate(findings)
	sortFindings(findings)

	return findings, nil
}

func deduplicate(findings []models.Finding) []models.Finding {
	type key struct {
		ID        string
		Component string
		Version   string
	}

	seen := make(map[key]struct{}, len(findings))
	out := make([]models.Finding, 0, len(findings))

	for _, f := range findings {
		k := key{
			ID:        f.ID,
			Component: f.Component.Name,
			Version:   f.Component.Version,
		}
		if _, exists := seen[k]; exists {
			continue
		}
		seen[k] = struct{}{}
		out = append(out, f)
	}

	return out
}

func sortFindings(findings []models.Finding) {
	sort.Slice(findings, func(i, j int) bool {
		si := severityOrder[findings[i].Severity]
		sj := severityOrder[findings[j].Severity]
		if si != sj {
			return si < sj
		}
		return findings[i].ID < findings[j].ID
	})
}
