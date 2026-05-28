package vuln

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/chainsaw-dev/chainsaw/pkg/models"
)

const (
	osvAPIURL   = "https://api.osv.dev/v1/querybatch"
	maxBatchSize = 1000
)

type osvQuery struct {
	Package   osvPackage `json:"package"`
	Version   string     `json:"version"`
}

type osvPackage struct {
	Name      string `json:"name"`
	Ecosystem string `json:"ecosystem"`
}

type osvBatchRequest struct {
	Queries []osvQuery `json:"queries"`
}

type osvBatchResponse struct {
	Results []osvBatchResult `json:"results"`
}

type osvBatchResult struct {
	Vulns []osvVulnerability `json:"vulns"`
}

type osvVulnerability struct {
	ID        string            `json:"id"`
	Summary   string            `json:"summary"`
	Details   string            `json:"details"`
	Aliases   []string          `json:"aliases"`
	Severity  []osvSeverity     `json:"severity"`
	References []osvReference   `json:"references"`
	Affected  []osvAffected     `json:"affected"`
}

type osvSeverity struct {
	Type  string `json:"type"`
	Score string `json:"score"`
}

type osvReference struct {
	Type string `json:"type"`
	URL  string `json:"url"`
}

type osvAffected struct {
	Package  osvPackage       `json:"package"`
	Ranges   []osvRange       `json:"ranges"`
	Versions []string         `json:"versions"`
}

type osvRange struct {
	Type   string     `json:"type"`
	Events []osvEvent `json:"events"`
}

type osvEvent struct {
	Introduced string `json:"introduced,omitempty"`
	Fixed      string `json:"fixed,omitempty"`
}

// Client queries the OSV.dev API for known vulnerabilities.
type Client struct {
	httpClient *http.Client
	baseURL    string
}

// NewClient creates a Client with a 30-second HTTP timeout.
func NewClient() *Client {
	return &Client{
		httpClient: &http.Client{Timeout: 30 * time.Second},
		baseURL:    osvAPIURL,
	}
}

// QueryBatch looks up vulnerabilities for the given components via OSV.
func (c *Client) QueryBatch(ctx context.Context, components []models.Component) ([]models.Finding, error) {
	if len(components) == 0 {
		return nil, nil
	}

	var allFindings []models.Finding

	for start := 0; start < len(components); start += maxBatchSize {
		end := start + maxBatchSize
		if end > len(components) {
			end = len(components)
		}
		batch := components[start:end]

		findings, err := c.queryBatch(ctx, batch)
		if err != nil {
			return nil, err
		}
		allFindings = append(allFindings, findings...)
	}

	return allFindings, nil
}

func (c *Client) queryBatch(ctx context.Context, components []models.Component) ([]models.Finding, error) {
	// Filter components to only those with known OSV ecosystems
	var validComponents []models.Component
	var componentIndices []int
	for i, comp := range components {
		if osvEco := mapEcosystem(comp.Ecosystem); osvEco != "" {
			validComponents = append(validComponents, comp)
			componentIndices = append(componentIndices, i)
		}
	}

	if len(validComponents) == 0 {
		return nil, nil
	}

	queries := make([]osvQuery, len(validComponents))
	for i, comp := range validComponents {
		queries[i] = osvQuery{
			Package: osvPackage{
				Name:      comp.Name,
				Ecosystem: mapEcosystem(comp.Ecosystem),
			},
			Version: comp.Version,
		}
	}

	body, err := json.Marshal(osvBatchRequest{Queries: queries})
	if err != nil {
		return nil, fmt.Errorf("marshal osv request: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.baseURL, bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("creating osv request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("osv query: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("osv query returned status %d", resp.StatusCode)
	}

	var batchResp osvBatchResponse
	if err := json.NewDecoder(resp.Body).Decode(&batchResp); err != nil {
		return nil, fmt.Errorf("decode osv response: %w", err)
	}

	var findings []models.Finding
	for i, result := range batchResp.Results {
		if i >= len(validComponents) {
			break
		}
		comp := validComponents[i]
		for _, vuln := range result.Vulns {
			findings = append(findings, toFinding(vuln, comp))
		}
	}

	return findings, nil
}

func toFinding(vuln osvVulnerability, comp models.Component) models.Finding {
	severity := models.ParseSeverity(extractSeverity(vuln))
	fixedIn := extractFixedVersion(vuln)

	var aliases []string
	aliases = append(aliases, vuln.Aliases...)

	var refs []string
	for _, r := range vuln.References {
		refs = append(refs, r.URL)
	}

	return models.Finding{
		ID:         vuln.ID,
		Summary:    vuln.Summary,
		Details:    vuln.Details,
		Severity:   severity,
		Aliases:    aliases,
		References: refs,
		FixedIn:    fixedIn,
		Component:  comp,
		Source:     "osv",
	}
}

func extractSeverity(vuln osvVulnerability) string {
	for _, s := range vuln.Severity {
		if s.Type == "CVSS_V3" || s.Type == "CVSS_V2" {
			return cvssToSeverity(parseCVSSScore(s.Score))
		}
	}
	return "UNKNOWN"
}

func parseCVSSScore(score string) float64 {
	// CVSS vector strings start with "CVSS:3.x/..." but the score field
	// can also be a plain numeric value. Try numeric first.
	var f float64
	if _, err := fmt.Sscanf(score, "%f", &f); err == nil {
		return f
	}
	return 0
}

func cvssToSeverity(score float64) string {
	switch {
	case score >= 9.0:
		return "CRITICAL"
	case score >= 7.0:
		return "HIGH"
	case score >= 4.0:
		return "MEDIUM"
	case score > 0:
		return "LOW"
	default:
		return "UNKNOWN"
	}
}

func extractFixedVersion(vuln osvVulnerability) string {
	for _, a := range vuln.Affected {
		for _, r := range a.Ranges {
			if r.Type == "SEMVER" || r.Type == "ECOSYSTEM" {
				for _, e := range r.Events {
					if e.Fixed != "" {
						return e.Fixed
					}
				}
			}
		}
	}
	return ""
}

func mapEcosystem(eco models.Ecosystem) string {
	switch eco {
	case "go":
		return "Go"
	case "npm":
		return "npm"
	case "pypi":
		return "PyPI"
	case "hex":
		return "Hex"
	case "maven":
		return "Maven"
	case "nuget":
		return "NuGet"
	case "crates.io":
		return "crates.io"
	case "rubygems":
		return "RubyGems"
	default:
		return ""
	}
}
