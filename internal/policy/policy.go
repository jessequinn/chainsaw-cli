package policy

import (
	"fmt"
	"os"

	"gopkg.in/yaml.v3"

	"github.com/chainsaw-dev/chainsaw/pkg/models"
)

// LicensePolicy defines which licenses are denied.
type LicensePolicy struct {
	Deny []string `yaml:"deny"`
}

// Policy defines the rules for evaluating scan results.
type Policy struct {
	FailOn   models.Severity `yaml:"fail_on"`
	Ignore   []string        `yaml:"ignore"`
	Licenses LicensePolicy   `yaml:"licenses"`
}

// LoadPolicy reads and parses a .chainsaw.yaml policy file.
func LoadPolicy(path string) (*Policy, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading policy file: %w", err)
	}

	var p Policy
	if err := yaml.Unmarshal(data, &p); err != nil {
		return nil, fmt.Errorf("parsing policy file: %w", err)
	}

	return &p, nil
}

// DefaultPolicy returns a permissive policy with no restrictions.
func DefaultPolicy() *Policy {
	return &Policy{
		FailOn: models.SeverityNone,
	}
}

// Evaluate checks a scan result against the policy, returning any violations
// and an appropriate exit code (0 = clean, 1 = violations found).
func (p *Policy) Evaluate(result models.ScanResult) ([]models.Finding, int) {
	ignored := make(map[string]bool, len(p.Ignore))
	for _, id := range p.Ignore {
		ignored[id] = true
	}

	denied := make(map[string]bool, len(p.Licenses.Deny))
	for _, lic := range p.Licenses.Deny {
		denied[lic] = true
	}

	failThreshold := models.SeverityRank(p.FailOn)
	var violations []models.Finding

	// Check findings from vulnerability scanners.
	allFindings := append(result.Findings, result.Hygiene...)
	for _, f := range allFindings {
		if ignored[f.ID] {
			continue
		}
		if models.SeverityRank(f.Severity) >= failThreshold && failThreshold > 0 {
			violations = append(violations, f)
		}
	}

	// Check component licenses against the deny list.
	for _, comp := range result.Components {
		for _, lic := range comp.Licenses {
			if denied[lic] {
				violations = append(violations, models.Finding{
					ID:       fmt.Sprintf("LICENSE-%s-%s", comp.Name, lic),
					Summary:  fmt.Sprintf("Denied license %q found in %s@%s", lic, comp.Name, comp.Version),
					Severity: models.SeverityHigh,
					Component: models.Component{
						Name:      comp.Name,
						Version:   comp.Version,
						Ecosystem: comp.Ecosystem,
						PkgURL:    comp.PkgURL,
					},
					Source: "policy",
				})
			}
		}
	}

	if len(violations) > 0 {
		return violations, 1
	}
	return nil, 0
}
