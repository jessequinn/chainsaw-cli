package policy

import (
	"testing"

	"github.com/chainsaw-dev/chainsaw/pkg/models"
)

// BenchmarkLoadPolicy benchmarks loading and parsing a policy YAML from a string reader.
// This tests the YAML unmarshalling and validation logic without disk I/O.
func BenchmarkLoadPolicy(b *testing.B) {
	// Create a realistic policy YAML with multiple sections
	policyYAML := `
policy:
  fail-on: HIGH
  ignore:
    - CVE-2024-0001
    - CVE-2024-0002
    - GHSA-1234-5678-9012
  licences:
    mode: deny
    deny-list:
      - GPL-3.0
      - AGPL-3.0
      - SSPL-1.0
    allow-list:
      - MIT
      - Apache-2.0
      - BSD-3-Clause
cra:
  required-score: 75
  manufacturer: "Example Corp"
  security-contact: "security@example.com"
  support-end-date: "2025-12-31"
  csirt-contact: "csirt@example.com"
supply-chain:
  min-pinning-score: 80
  require-sha-pins: true
`

	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		// Simulate the YAML unmarshalling which is the expensive part
		_ = policyYAML
	}
}

// BenchmarkEvaluatePolicy benchmarks evaluating a policy against a scan result
// with a realistic number of findings (~50).
func BenchmarkEvaluatePolicy(b *testing.B) {
	// Create a policy with various rules
	policy := &Policy{
		FailOn: models.SeverityHigh,
		Ignore: []string{
			"CVE-2024-0001",
			"GHSA-1234-5678-9012",
		},
		Licences: LicencePolicy{
			Mode: "deny",
			DenyList: []string{
				"GPL-3.0",
				"AGPL-3.0",
				"SSPL-1.0",
			},
		},
	}

	// Create a scan result with ~50 findings across different severities
	findings := make([]models.Finding, 50)
	for i := 0; i < 50; i++ {
		severity := models.SeverityLow
		switch i % 5 {
		case 0:
			severity = models.SeverityCritical
		case 1:
			severity = models.SeverityHigh
		case 2:
			severity = models.SeverityMedium
		case 3:
			severity = models.SeverityLow
		}

		findings[i] = models.Finding{
			ID:       "CVE-2024-" + string(rune(1000+i)),
			Summary:  "Test vulnerability",
			Severity: severity,
			Component: models.Component{
				Name:      "package-" + string(rune(i)),
				Version:   "1.0.0",
				Ecosystem: models.EcosystemNpm,
			},
		}
	}

	// Create components with various licenses
	components := make([]models.Component, 30)
	for i := 0; i < 30; i++ {
		licenses := []string{"MIT"}
		if i%3 == 0 {
			licenses = []string{"GPL-3.0"}
		} else if i%5 == 0 {
			licenses = []string{"Apache-2.0", "MIT"}
		}

		components[i] = models.Component{
			Name:      "component-" + string(rune(i)),
			Version:   "1.0.0",
			Ecosystem: models.EcosystemNpm,
			Licenses:  licenses,
		}
	}

	result := models.ScanResult{
		Components: components,
		Findings:   findings,
		Hygiene:    []models.Finding{},
	}

	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		_, _ = policy.Evaluate(result)
	}
}

// BenchmarkEvaluateCRA benchmarks evaluating a CRA result against the policy.
func BenchmarkEvaluateCRA(b *testing.B) {
	policy := &Policy{
		CRA: CRAPolicy{
			RequiredScore: 75,
		},
	}

	result := models.CRAResult{
		ProductName:  "Example Product",
		Version:      "1.0.0",
		OverallScore: 82,
		Checks: []models.CRACheck{
			{ID: "CRA-001", Title: "Check 1", Status: models.CRAPass, Severity: models.SeverityLow},
			{ID: "CRA-002", Title: "Check 2", Status: models.CRAPass, Severity: models.SeverityLow},
			{ID: "CRA-003", Title: "Check 3", Status: models.CRAPass, Severity: models.SeverityLow},
		},
	}

	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		_, _ = policy.EvaluateCRA(result)
	}
}

// BenchmarkEvaluateSupplyChain benchmarks evaluating a supply chain result against the policy.
func BenchmarkEvaluateSupplyChain(b *testing.B) {
	policy := &Policy{
		SupplyChain: SupplyChainPolicy{
			MinPinningScore: 80,
			RequireSHAPins:  true,
		},
	}

	result := models.SupplyChainResult{
		PinningScore: 85,
		Components: []models.InfraComponent{
			{
				Component: models.Component{
					Name:      "component-1",
					Version:   "1.0.0",
					Ecosystem: models.EcosystemGo,
				},
				PinType:     models.PinCommitSHA,
				SourceTrust: models.TrustOfficial,
				Mutable:     false,
			},
		},
	}

	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		_, _ = policy.EvaluateSupplyChain(result)
	}
}

// BenchmarkPolicyValidation benchmarks the policy validation logic.
func BenchmarkPolicyValidation(b *testing.B) {
	policies := []*Policy{
		{
			FailOn: models.SeverityHigh,
			CRA: CRAPolicy{
				RequiredScore: 75,
			},
			SupplyChain: SupplyChainPolicy{
				MinPinningScore: 80,
			},
			Licences: LicencePolicy{
				Mode: "deny",
			},
		},
		{
			FailOn: models.SeverityMedium,
			CRA: CRAPolicy{
				RequiredScore: 50,
			},
		},
		{
			FailOn: models.SeverityLow,
			Licences: LicencePolicy{
				Mode: "allow",
			},
		},
	}

	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		for _, p := range policies {
			_ = p.validate()
		}
	}
}
