package vuln

import (
	"context"
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

// Matcher combines OSV and Go vulnerability database results.
type Matcher struct {
	client       *Client
	goVulnClient *GoVulnClient
}

// NewMatcher creates a Matcher backed by OSV and the Go vuln DB.
func NewMatcher(client *Client) *Matcher {
	return &Matcher{
		client:       client,
		goVulnClient: NewGoVulnClient(),
	}
}

// Match queries OSV and the Go vuln DB for the given components,
// deduplicates findings, and returns them sorted by severity then ID.
func (m *Matcher) Match(ctx context.Context, components []models.Component) ([]models.Finding, error) {
	findings, err := m.client.QueryBatch(ctx, components)
	if err != nil {
		return nil, err
	}

	goFindings, err := m.goVulnClient.QueryAll(ctx, components)
	if err != nil {
		// Degrade gracefully: log but do not fail the scan.
		goFindings = nil
	}
	findings = append(findings, goFindings...)

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

	index := make(map[key]int, len(findings))
	out := make([]models.Finding, 0, len(findings))

	for _, f := range findings {
		k := key{
			ID:        f.ID,
			Component: f.Component.Name,
			Version:   f.Component.Version,
		}
		if idx, exists := index[k]; exists {
			// Prefer govulndb over osv for Go-specific findings.
			if f.Source == "govulndb" && out[idx].Source != "govulndb" {
				out[idx] = f
			}
			continue
		}
		index[k] = len(out)
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
