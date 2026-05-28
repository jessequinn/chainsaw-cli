package vuln

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"golang.org/x/mod/semver"

	"github.com/chainsaw-dev/chainsaw/pkg/models"
)

const goVulnDBURL = "https://vuln.go.dev"

// goVulnModuleEntry is an entry from the Go vuln DB module index.
type goVulnModuleEntry struct {
	ID       string   `json:"id"`
	Modified string   `json:"modified"`
	Aliases  []string `json:"aliases"`
}

// goVulnDetail is the full OSV-format entry from the Go vuln DB.
type goVulnDetail struct {
	ID         string            `json:"id"`
	Aliases    []string          `json:"aliases"`
	Summary    string            `json:"summary"`
	Details    string            `json:"details"`
	Severity   []osvSeverity     `json:"severity"`
	References []osvReference    `json:"references"`
	Affected   []goVulnAffected  `json:"affected"`
}

type goVulnAffected struct {
	Package goVulnPackage `json:"package"`
	Ranges  []osvRange    `json:"ranges"`
}

type goVulnPackage struct {
	Name      string `json:"name"`
	Ecosystem string `json:"ecosystem"`
}

// GoVulnClient queries the Go vulnerability database.
type GoVulnClient struct {
	client  *http.Client
	baseURL string
}

// NewGoVulnClient creates a new Go vuln DB client.
func NewGoVulnClient() *GoVulnClient {
	return &GoVulnClient{
		client:  &http.Client{Timeout: 30 * time.Second},
		baseURL: goVulnDBURL,
	}
}

// QueryAll queries vulnerabilities for all Go components.
func (c *GoVulnClient) QueryAll(ctx context.Context, components []models.Component) ([]models.Finding, error) {
	var findings []models.Finding
	for _, comp := range components {
		if comp.Ecosystem != models.EcosystemGo {
			continue
		}
		f, err := c.QueryModule(ctx, comp)
		if err != nil {
			return nil, fmt.Errorf("go vuln db query for %s: %w", comp.Name, err)
		}
		findings = append(findings, f...)
	}
	return findings, nil
}

// QueryModule queries the Go vuln DB for vulnerabilities affecting a component.
func (c *GoVulnClient) QueryModule(ctx context.Context, comp models.Component) ([]models.Finding, error) {
	entries, err := c.fetchModuleIndex(ctx, comp.Name)
	if err != nil {
		return nil, err
	}
	if len(entries) == 0 {
		return nil, nil
	}

	var findings []models.Finding
	for _, entry := range entries {
		detail, err := c.fetchVulnDetail(ctx, entry.ID)
		if err != nil {
			return nil, err
		}
		if detail == nil {
			continue
		}
		if isAffected(detail, comp.Name, comp.Version) {
			findings = append(findings, goVulnToFinding(detail, comp))
		}
	}
	return findings, nil
}

func (c *GoVulnClient) fetchModuleIndex(ctx context.Context, modulePath string) ([]goVulnModuleEntry, error) {
	url := fmt.Sprintf("%s/index/modules/%s.json", c.baseURL, modulePath)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("creating go vuln db request: %w", err)
	}

	resp, err := c.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("go vuln db module index query: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		return nil, nil
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("go vuln db module index returned status %d", resp.StatusCode)
	}

	var entries []goVulnModuleEntry
	if err := json.NewDecoder(resp.Body).Decode(&entries); err != nil {
		return nil, fmt.Errorf("decode go vuln db module index: %w", err)
	}
	return entries, nil
}

func (c *GoVulnClient) fetchVulnDetail(ctx context.Context, id string) (*goVulnDetail, error) {
	url := fmt.Sprintf("%s/ID/%s.json", c.baseURL, id)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("creating go vuln db detail request: %w", err)
	}

	resp, err := c.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("go vuln db detail query: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		return nil, nil
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("go vuln db detail returned status %d", resp.StatusCode)
	}

	var detail goVulnDetail
	if err := json.NewDecoder(resp.Body).Decode(&detail); err != nil {
		return nil, fmt.Errorf("decode go vuln db detail: %w", err)
	}
	return &detail, nil
}

// canonicalVersion ensures the version has a "v" prefix for semver comparison.
func canonicalVersion(v string) string {
	if !strings.HasPrefix(v, "v") {
		v = "v" + v
	}
	return v
}

// isAffected checks whether the given module at the given version is affected.
func isAffected(detail *goVulnDetail, modulePath, version string) bool {
	ver := canonicalVersion(version)
	if !semver.IsValid(ver) {
		// Cannot compare; assume affected to be safe.
		return true
	}

	for _, a := range detail.Affected {
		if a.Package.Name != modulePath {
			continue
		}
		for _, r := range a.Ranges {
			if r.Type != "SEMVER" {
				continue
			}
			if matchesRange(ver, r.Events) {
				return true
			}
		}
	}
	return false
}

// matchesRange checks if ver falls within an introduced/fixed range.
func matchesRange(ver string, events []osvEvent) bool {
	affected := false
	for _, e := range events {
		if e.Introduced != "" {
			intro := canonicalVersion(e.Introduced)
			if e.Introduced == "0" || (semver.IsValid(intro) && semver.Compare(ver, intro) >= 0) {
				affected = true
			}
		}
		if e.Fixed != "" {
			fix := canonicalVersion(e.Fixed)
			if semver.IsValid(fix) && semver.Compare(ver, fix) >= 0 {
				affected = false
			}
		}
	}
	return affected
}

func goVulnToFinding(detail *goVulnDetail, comp models.Component) models.Finding {
	severity := extractGoVulnSeverity(detail)
	fixedIn := extractGoVulnFixed(detail, comp.Name)

	var refs []string
	for _, r := range detail.References {
		refs = append(refs, r.URL)
	}

	return models.Finding{
		ID:         detail.ID,
		Summary:    detail.Summary,
		Details:    detail.Details,
		Severity:   severity,
		Aliases:    detail.Aliases,
		References: refs,
		FixedIn:    fixedIn,
		Component:  comp,
		Source:     "govulndb",
	}
}

func extractGoVulnSeverity(detail *goVulnDetail) models.Severity {
	for _, s := range detail.Severity {
		if s.Type == "CVSS_V3" || s.Type == "CVSS_V2" {
			return models.ParseSeverity(cvssToSeverity(parseCVSSScore(s.Score)))
		}
	}
	return models.SeverityMedium
}

func extractGoVulnFixed(detail *goVulnDetail, modulePath string) string {
	for _, a := range detail.Affected {
		if a.Package.Name != modulePath {
			continue
		}
		for _, r := range a.Ranges {
			if r.Type == "SEMVER" {
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
