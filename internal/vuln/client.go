package vuln

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"math"
	"math/rand"
	"net/http"
	"strconv"
	"time"

	"github.com/chainsaw-dev/chainsaw/pkg/models"
)

const (
	osvAPIURL   = "https://api.osv.dev/v1/querybatch"
	maxBatchSize = 1000
	maxRetries   = 3
)

// isRetryable returns true if the HTTP status code indicates a transient error
// that should be retried.
func isRetryable(statusCode int) bool {
	switch statusCode {
	case 429, 500, 502, 503, 504:
		return true
	}
	return false
}

// backoffDelay calculates exponential backoff with jitter.
// For attempt 0: 1s, attempt 1: 2s, attempt 2: 4s, etc.
// Jitter of up to 500ms is added to prevent thundering herd.
func backoffDelay(base time.Duration, attempt int) time.Duration {
	delay := base * time.Duration(1<<uint(attempt))
	jitter := time.Duration(rand.Int63n(int64(500 * time.Millisecond)))
	return delay + jitter
}

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

// doWithRetry wraps an HTTP request with exponential backoff retry logic.
// It retries on transient errors (429, 5xx) and respects the Retry-After header.
func (c *Client) doWithRetry(ctx context.Context, req *http.Request, body []byte) (*http.Response, error) {
	baseDelay := 1 * time.Second

	for attempt := 0; attempt <= maxRetries; attempt++ {
		if attempt > 0 {
			// Reset body for retry
			req.Body = io.NopCloser(bytes.NewReader(body))
		}

		resp, err := c.httpClient.Do(req)
		if err != nil {
			if attempt == maxRetries {
				return nil, err
			}
			delay := backoffDelay(baseDelay, attempt)
			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			case <-time.After(delay):
				continue
			}
		}

		// Check if retryable status
		if !isRetryable(resp.StatusCode) {
			return resp, nil
		}

		resp.Body.Close()

		if attempt == maxRetries {
			return nil, fmt.Errorf("osv query returned status %d after %d retries", resp.StatusCode, maxRetries)
		}

		delay := backoffDelay(baseDelay, attempt)
		// Honour Retry-After header
		if ra := resp.Header.Get("Retry-After"); ra != "" {
			if seconds, err := strconv.Atoi(ra); err == nil {
				delay = time.Duration(seconds) * time.Second
			}
		}

		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(delay):
		}
	}
	return nil, fmt.Errorf("osv query: max retries exceeded")
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

	resp, err := c.doWithRetry(ctx, req, body)
	if err != nil {
		return nil, fmt.Errorf("osv query: %w", err)
	}
	defer resp.Body.Close()

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
	// Try plain numeric first (backward compatibility)
	var f float64
	if _, err := fmt.Sscanf(score, "%f", &f); err == nil {
		return f
	}

	// Try CVSS v3 vector (e.g., "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")
	if len(score) > 0 && score[0:1] == "C" {
		if v3Score := parseCVSSv3Vector(score); v3Score > 0 {
			return v3Score
		}
	}

	return 0
}

func parseCVSSv3Vector(vector string) float64 {
	// Parse CVSS v3.x vector string and compute base score
	// Format: CVSS:3.x/AV:x/AC:x/PR:x/UI:x/S:x/C:x/I:x/A:x
	metrics := make(map[string]string)

	// Split by "/" and parse each metric
	parts := bytes.Split([]byte(vector), []byte("/"))
	for _, part := range parts {
		kv := bytes.Split(part, []byte(":"))
		if len(kv) == 2 {
			key := string(kv[0])
			val := string(kv[1])
			metrics[key] = val
		}
	}

	// Extract metric values with defaults
	av := getMetricValue(metrics["AV"], map[string]float64{"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.20})
	ac := getMetricValue(metrics["AC"], map[string]float64{"L": 0.77, "H": 0.44})
	ui := getMetricValue(metrics["UI"], map[string]float64{"N": 0.85, "R": 0.62})
	scope := metrics["S"]

	// PR depends on scope
	var pr float64
	if scope == "C" {
		pr = getMetricValue(metrics["PR"], map[string]float64{"N": 0.85, "L": 0.68, "H": 0.50})
	} else {
		pr = getMetricValue(metrics["PR"], map[string]float64{"N": 0.85, "L": 0.62, "H": 0.27})
	}

	// CIA metrics
	c := getMetricValue(metrics["C"], map[string]float64{"H": 0.56, "L": 0.22, "N": 0})
	i := getMetricValue(metrics["I"], map[string]float64{"H": 0.56, "L": 0.22, "N": 0})
	a := getMetricValue(metrics["A"], map[string]float64{"H": 0.56, "L": 0.22, "N": 0})

	// Calculate ISS (Impact Sub Score)
	iss := 1 - ((1-c)*(1-i)*(1-a))

	// Calculate Impact
	var impact float64
	if scope == "C" {
		// Scope Changed
		impact = 7.52*(iss-0.029) - 3.25*math.Pow(iss-0.02, 15)
	} else {
		// Scope Unchanged
		impact = 6.42 * iss
	}

	// If impact <= 0, base score is 0
	if impact <= 0 {
		return 0
	}

	// Calculate Exploitability
	exploitability := 8.22 * av * ac * pr * ui

	// Calculate Base Score
	var baseScore float64
	if scope == "C" {
		// Scope Changed
		baseScore = 1.08 * (impact + exploitability)
	} else {
		// Scope Unchanged
		baseScore = impact + exploitability
	}

	// Cap at 10.0
	if baseScore > 10.0 {
		baseScore = 10.0
	}

	// Round up to nearest 0.1 using ceiling
	return math.Ceil(baseScore*10) / 10
}

func getMetricValue(metric string, mapping map[string]float64) float64 {
	if val, ok := mapping[metric]; ok {
		return val
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
