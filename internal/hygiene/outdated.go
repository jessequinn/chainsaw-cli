package hygiene

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/chainsaw-dev/chainsaw/pkg/models"
)

const (
	defaultOutdatedThreshold = 2 // major versions behind
)

// OutdatedConfig controls outdated detection behavior.
type OutdatedConfig struct {
	MajorThreshold  int    // number of major versions behind to flag
	BaseGoProxy     string // Go proxy base URL (e.g., https://proxy.golang.org)
	BaseNPMRegistry string // npm registry base URL (e.g., https://registry.npmjs.org)
	HTTPClient      *http.Client
}

// DefaultOutdatedConfig returns sensible defaults.
func DefaultOutdatedConfig() OutdatedConfig {
	return OutdatedConfig{
		MajorThreshold:  defaultOutdatedThreshold,
		BaseGoProxy:     "https://proxy.golang.org",
		BaseNPMRegistry: "https://registry.npmjs.org",
		HTTPClient:      &http.Client{Timeout: 10 * time.Second},
	}
}

// CheckOutdated queries registries for the latest version of each component
// and flags those that are significantly behind.
func CheckOutdated(ctx context.Context, components []models.Component, cfg OutdatedConfig) []models.Finding {
	// Fill in defaults if not provided
	if cfg.MajorThreshold <= 0 {
		cfg.MajorThreshold = defaultOutdatedThreshold
	}
	if cfg.BaseGoProxy == "" {
		cfg.BaseGoProxy = "https://proxy.golang.org"
	}
	if cfg.BaseNPMRegistry == "" {
		cfg.BaseNPMRegistry = "https://registry.npmjs.org"
	}
	if cfg.HTTPClient == nil {
		cfg.HTTPClient = &http.Client{Timeout: 10 * time.Second}
	}

	var findings []models.Finding

	for _, comp := range components {
		if !comp.Direct {
			continue // only check direct dependencies
		}

		latest, err := fetchLatestVersion(ctx, cfg, comp)
		if err != nil {
			continue // skip on error (graceful degradation)
		}

		if latest == "" || latest == comp.Version {
			continue
		}

		currentMajor := parseMajor(comp.Version)
		latestMajor := parseMajor(latest)

		if latestMajor-currentMajor >= cfg.MajorThreshold {
			findings = append(findings, models.Finding{
				ID:      fmt.Sprintf("OUTDATED-%s", comp.Name),
				Summary: fmt.Sprintf("%s@%s is %d major versions behind (latest: %s)", comp.Name, comp.Version, latestMajor-currentMajor, latest),
				Details: fmt.Sprintf("Current version: %s\nLatest version: %s\nMajor versions behind: %d\nThreshold: %d", comp.Version, latest, latestMajor-currentMajor, cfg.MajorThreshold),
				Severity: models.SeverityMedium,
				Component: models.Component{
					Name:      comp.Name,
					Version:   comp.Version,
					Ecosystem: comp.Ecosystem,
					PkgURL:    comp.PkgURL,
					Direct:    comp.Direct,
				},
				FixedIn: latest,
				Source:  "outdated",
			})
		}
	}

	return findings
}

func fetchLatestVersion(ctx context.Context, cfg OutdatedConfig, comp models.Component) (string, error) {
	switch comp.Ecosystem {
	case models.EcosystemGo:
		return fetchGoLatest(ctx, cfg, comp.Name)
	case models.EcosystemNpm:
		return fetchNPMLatest(ctx, cfg, comp.Name)
	default:
		return "", fmt.Errorf("unsupported ecosystem: %s", comp.Ecosystem)
	}
}

type goLatestInfo struct {
	Version string `json:"Version"`
}

func fetchGoLatest(ctx context.Context, cfg OutdatedConfig, module string) (string, error) {
	url := fmt.Sprintf("%s/%s/@latest", cfg.BaseGoProxy, module)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return "", err
	}

	resp, err := cfg.HTTPClient.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("HTTP %d", resp.StatusCode)
	}

	var info goLatestInfo
	if err := json.NewDecoder(resp.Body).Decode(&info); err != nil {
		return "", err
	}
	return info.Version, nil
}

type npmPackageInfo struct {
	DistTags struct {
		Latest string `json:"latest"`
	} `json:"dist-tags"`
}

func fetchNPMLatest(ctx context.Context, cfg OutdatedConfig, pkg string) (string, error) {
	url := fmt.Sprintf("%s/%s", cfg.BaseNPMRegistry, pkg)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("Accept", "application/vnd.npm.install-v1+json")

	resp, err := cfg.HTTPClient.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("HTTP %d", resp.StatusCode)
	}

	var info npmPackageInfo
	if err := json.NewDecoder(resp.Body).Decode(&info); err != nil {
		return "", err
	}
	return info.DistTags.Latest, nil
}

// parseMajor extracts the major version number from a semver string.
func parseMajor(version string) int {
	v := strings.TrimPrefix(version, "v")
	parts := strings.SplitN(v, ".", 2)
	if len(parts) == 0 {
		return 0
	}
	major, err := strconv.Atoi(parts[0])
	if err != nil || major < 0 {
		return 0
	}
	return major
}
