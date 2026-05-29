package policy

import (
	"context"
	"fmt"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/chainsaw-dev/chainsaw/pkg/models"
)

// IgnoreRule defines a time-bounded CVE ignore entry.
type IgnoreRule struct {
	ID      string `yaml:"id" json:"id"`
	Expires string `yaml:"expires,omitempty" json:"expires,omitempty"` // YYYY-MM-DD
	Reason  string `yaml:"reason,omitempty" json:"reason,omitempty"`
}

// IsExpired returns true if the rule has a set expiry date that is in the past.
func (r IgnoreRule) IsExpired(now time.Time) bool {
	if r.Expires == "" {
		return false
	}
	t, err := time.Parse("2006-01-02", r.Expires)
	if err != nil {
		return true // treat unparseable dates as expired
	}
	return now.After(t)
}

// UnmarshalYAML supports both bare string ("CVE-...") and object forms.
func (r *IgnoreRule) UnmarshalYAML(value *yaml.Node) error {
	if value.Kind == yaml.ScalarNode {
		r.ID = value.Value
		return nil
	}
	// Object form
	type plain IgnoreRule
	return value.Decode((*plain)(r))
}

// CRAPolicy defines CRA compliance thresholds.
type CRAPolicy struct {
	RequiredScore   int    `yaml:"required-score"`
	Manufacturer    string `yaml:"manufacturer"`
	SecurityContact string `yaml:"security-contact"`
	SupportEndDate  string `yaml:"support-end-date"`
	CSIRTContact    string `yaml:"csirt-contact"`
}

// SupplyChainPolicy defines supply chain pinning thresholds.
type SupplyChainPolicy struct {
	MinPinningScore int  `yaml:"min-pinning-score"`
	RequireSHAPins  bool `yaml:"require-sha-pins"`
}

// LicencePolicy defines licence evaluation mode and lists.
type LicencePolicy struct {
	Mode         string              `yaml:"mode"`
	AllowList    []string            `yaml:"allow-list"`
	DenyList     []string            `yaml:"deny-list"`
	PerEcosystem map[string][]string `yaml:"per-ecosystem"`
}

// EcosystemOverride allows per-ecosystem policy thresholds.
type EcosystemOverride struct {
	FailOn models.Severity `yaml:"fail-on"`
}

// Policy defines the rules for evaluating scan results.
type Policy struct {
	FailOn      models.Severity              `yaml:"fail-on"`
	Ignore      []IgnoreRule                 `yaml:"ignore"`
	Ecosystems  map[string]EcosystemOverride `yaml:"ecosystems"`

	// v2 fields
	CRA         CRAPolicy         `yaml:"cra"`
	SupplyChain SupplyChainPolicy `yaml:"supply-chain"`
	Licences    LicencePolicy     `yaml:"licences"`
}

// policyFile matches the on-disk YAML structure where `fail-on` and `ignore`
// are nested under a `policy:` key while `cra:`, `supply-chain:`, and
// `licences:` are top-level siblings. `extends:` allows inheriting from a parent policy.
type policyFile struct {
	Extends     string            `yaml:"extends"`
	Policy      policyCore        `yaml:"policy"`
	CRA         CRAPolicy         `yaml:"cra"`
	SupplyChain SupplyChainPolicy `yaml:"supply-chain"`
	Licences    LicencePolicy     `yaml:"licences"`
}

type policyCore struct {
	FailOn     models.Severity              `yaml:"fail-on"`
	Ignore     []IgnoreRule                 `yaml:"ignore"`
	Ecosystems map[string]EcosystemOverride `yaml:"ecosystems"`
	Licences   LicencePolicy                `yaml:"licences"`
}

// LoadPolicy reads and parses a .chainsaw.yaml policy file, resolving inheritance via extends.
func LoadPolicy(ctx context.Context, path string) (*Policy, error) {
	return loadPolicyWithInheritance(ctx, path, 0)
}

// validate checks that the policy fields have valid values.
func (p *Policy) validate() error {
	// Validate fail_on severity
	if p.FailOn != "" && p.FailOn != models.SeverityNone {
		valid := map[models.Severity]bool{
			models.SeverityCritical: true,
			models.SeverityHigh:     true,
			models.SeverityMedium:   true,
			models.SeverityLow:      true,
		}
		if !valid[p.FailOn] {
			return fmt.Errorf("invalid fail_on severity %q: must be CRITICAL, HIGH, MEDIUM, or LOW", p.FailOn)
		}
	}

	// Validate ecosystem overrides.
	for key, override := range p.Ecosystems {
		if override.FailOn != "" && override.FailOn != models.SeverityNone {
			valid := map[models.Severity]bool{
				models.SeverityCritical: true,
				models.SeverityHigh:     true,
				models.SeverityMedium:   true,
				models.SeverityLow:      true,
			}
			if !valid[override.FailOn] {
				return fmt.Errorf("invalid ecosystem %q fail_on severity %q: must be CRITICAL, HIGH, MEDIUM, or LOW", key, override.FailOn)
			}
		}
	}

	// Validate CRA required score
	if p.CRA.RequiredScore < 0 || p.CRA.RequiredScore > 100 {
		return fmt.Errorf("cra.required-score must be between 0 and 100, got %d", p.CRA.RequiredScore)
	}

	// Validate supply chain min pinning score
	if p.SupplyChain.MinPinningScore < 0 || p.SupplyChain.MinPinningScore > 100 {
		return fmt.Errorf("supply-chain.min-pinning-score must be between 0 and 100, got %d", p.SupplyChain.MinPinningScore)
	}

	// Validate licence mode
	if p.Licences.Mode != "" && p.Licences.Mode != "allow" && p.Licences.Mode != "deny" {
		return fmt.Errorf("licences.mode must be \"allow\" or \"deny\", got %q", p.Licences.Mode)
	}

	return nil
}

// DefaultPolicy returns a permissive policy with no restrictions.
func DefaultPolicy() *Policy {
	return &Policy{
		FailOn: models.SeverityNone,
		Licences: LicencePolicy{
			Mode: "deny",
		},
	}
}

// EvaluateCRA checks a CRA result against the policy. Returns true if passing.
func (p *Policy) EvaluateCRA(result models.CRAResult) (bool, string) {
	if p.CRA.RequiredScore <= 0 {
		return true, ""
	}
	if result.OverallScore < p.CRA.RequiredScore {
		return false, fmt.Sprintf("CRA score %d is below required threshold %d", result.OverallScore, p.CRA.RequiredScore)
	}
	return true, ""
}

// EvaluateSupplyChain checks a supply chain result against the policy. Returns true if passing.
func (p *Policy) EvaluateSupplyChain(result models.SupplyChainResult) (bool, string) {
	if p.SupplyChain.MinPinningScore <= 0 {
		return true, ""
	}
	if result.PinningScore < p.SupplyChain.MinPinningScore {
		return false, fmt.Sprintf("pinning score %d is below required threshold %d", result.PinningScore, p.SupplyChain.MinPinningScore)
	}
	return true, ""
}

// Evaluate checks a scan result against the policy, returning any violations
// and an appropriate exit code (0 = clean, 1 = violations found).
func (p *Policy) Evaluate(result models.ScanResult) ([]models.Finding, int) {
	now := time.Now()
	ignored := make(map[string]bool, len(p.Ignore))
	var warnings []string
	for _, rule := range p.Ignore {
		if rule.IsExpired(now) {
			continue // expired ignores are no longer active
		}
		if rule.Reason == "" {
			warnings = append(warnings, fmt.Sprintf("ignore rule for %s has no reason", rule.ID))
		}
		ignored[rule.ID] = true
	}
	_ = warnings // warnings logged in future (structured logging not yet wired)

	denied := make(map[string]bool, len(p.Licences.DenyList))
	for _, lic := range p.Licences.DenyList {
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
		threshold := failThreshold
		if override, ok := p.Ecosystems[string(f.Component.Ecosystem)]; ok {
			threshold = models.SeverityRank(override.FailOn)
		}
		if threshold > 0 && models.SeverityRank(f.Severity) >= threshold {
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
						Direct:    comp.Direct,
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
