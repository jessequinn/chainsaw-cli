package licence

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/chainsaw-dev/chainsaw/pkg/models"
)

const (
	defaultNpmBaseURL  = "https://registry.npmjs.org"
	defaultPyPIBaseURL = "https://pypi.org"
)

// Detector resolves licences for components via registry APIs.
type Detector struct {
	client      *http.Client
	cache       map[string]string
	mu          sync.Mutex
	NpmBaseURL  string
	PyPIBaseURL string
}

// NewDetector creates a new licence detector with a 10-second HTTP timeout.
func NewDetector() *Detector {
	return &Detector{
		client:      &http.Client{Timeout: 10 * time.Second},
		cache:       make(map[string]string),
		NpmBaseURL:  defaultNpmBaseURL,
		PyPIBaseURL: defaultPyPIBaseURL,
	}
}

// DetectAll resolves licences for all components, modifying them in place.
// Returns the number of components with detected licences and any error.
// Errors are non-fatal: components with failed lookups get "unknown".
func (d *Detector) DetectAll(ctx context.Context, components []models.Component) (int, error) {
	detected := 0
	var errs []string

	for i := range components {
		comp := &components[i]
		lic, err := d.detect(ctx, comp.Ecosystem, comp.Name, comp.Version)
		if err != nil {
			errs = append(errs, fmt.Sprintf("%s@%s: %v", comp.Name, comp.Version, err))
			lic = "unknown"
		}
		if lic != "unknown" && lic != "" {
			detected++
		}
		if lic == "" {
			lic = "unknown"
		}
		// Set the licence if not already populated.
		if len(comp.Licenses) == 0 {
			comp.Licenses = []string{lic}
		}
	}

	if len(errs) > 0 {
		return detected, fmt.Errorf("licence detection had %d errors: %s", len(errs), strings.Join(errs, "; "))
	}
	return detected, nil
}

func (d *Detector) detect(ctx context.Context, eco models.Ecosystem, name, version string) (string, error) {
	key := fmt.Sprintf("%s/%s/%s", eco, name, version)

	d.mu.Lock()
	if cached, ok := d.cache[key]; ok {
		d.mu.Unlock()
		return cached, nil
	}
	d.mu.Unlock()

	var lic string
	var err error

	switch eco {
	case models.EcosystemNpm:
		lic, err = d.detectNpm(ctx, name, version)
	case models.EcosystemPyPI:
		lic, err = d.detectPyPI(ctx, name, version)
	default:
		lic = "unknown"
	}

	if err != nil {
		return "", err
	}

	d.mu.Lock()
	d.cache[key] = lic
	d.mu.Unlock()

	return lic, nil
}

// npmResponse is the subset of the npm registry response we care about.
type npmResponse struct {
	License interface{} `json:"license"`
}

func (d *Detector) detectNpm(ctx context.Context, name, version string) (string, error) {
	url := fmt.Sprintf("%s/%s/%s", d.NpmBaseURL, name, version)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return "", fmt.Errorf("creating npm request: %w", err)
	}

	resp, err := d.client.Do(req)
	if err != nil {
		return "", fmt.Errorf("npm registry query: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "unknown", nil
	}

	var data npmResponse
	if err := json.NewDecoder(resp.Body).Decode(&data); err != nil {
		return "", fmt.Errorf("decode npm response: %w", err)
	}

	switch v := data.License.(type) {
	case string:
		if v != "" {
			return v, nil
		}
	case map[string]interface{}:
		if t, ok := v["type"].(string); ok && t != "" {
			return t, nil
		}
	}

	return "unknown", nil
}

// pypiResponse is the subset of the PyPI JSON API response we care about.
type pypiResponse struct {
	Info struct {
		License string `json:"license"`
	} `json:"info"`
}

func (d *Detector) detectPyPI(ctx context.Context, name, version string) (string, error) {
	url := fmt.Sprintf("%s/pypi/%s/%s/json", d.PyPIBaseURL, name, version)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return "", fmt.Errorf("creating pypi request: %w", err)
	}

	resp, err := d.client.Do(req)
	if err != nil {
		return "", fmt.Errorf("pypi registry query: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "unknown", nil
	}

	var data pypiResponse
	if err := json.NewDecoder(resp.Body).Decode(&data); err != nil {
		return "", fmt.Errorf("decode pypi response: %w", err)
	}

	if data.Info.License != "" {
		return data.Info.License, nil
	}

	return "unknown", nil
}

// EvaluateLicences checks components against licence policy lists.
// In "deny" mode, flags any component whose licence is in denyList.
// In "allow" mode, flags any component whose licence is NOT in allowList (skips "unknown").
func EvaluateLicences(components []models.Component, mode string, allowList, denyList []string) []models.Finding {
	var findings []models.Finding

	switch mode {
	case "allow":
		allowed := make(map[string]bool, len(allowList))
		for _, l := range allowList {
			allowed[strings.ToUpper(l)] = true
		}
		for _, comp := range components {
			for _, lic := range comp.Licenses {
				if strings.EqualFold(lic, "unknown") {
					continue
				}
				if !allowed[strings.ToUpper(lic)] {
					findings = append(findings, licenceFinding(comp, lic, "not in allow list"))
				}
			}
		}
	case "deny":
		denied := make(map[string]bool, len(denyList))
		for _, l := range denyList {
			denied[strings.ToUpper(l)] = true
		}
		for _, comp := range components {
			for _, lic := range comp.Licenses {
				if denied[strings.ToUpper(lic)] {
					findings = append(findings, licenceFinding(comp, lic, "in deny list"))
				}
			}
		}
	}

	return findings
}

func licenceFinding(comp models.Component, licence, reason string) models.Finding {
	return models.Finding{
		ID:       fmt.Sprintf("LICENCE-%s-%s", comp.Name, licence),
		Summary:  fmt.Sprintf("Licence %q on %s@%s: %s", licence, comp.Name, comp.Version, reason),
		Severity: models.SeverityHigh,
		Component: models.Component{
			Name:      comp.Name,
			Version:   comp.Version,
			Ecosystem: comp.Ecosystem,
			PkgURL:    comp.PkgURL,
			Direct:    comp.Direct,
		},
		Source: "licence",
	}
}
