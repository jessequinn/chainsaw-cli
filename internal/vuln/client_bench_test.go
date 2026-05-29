package vuln

import (
	"testing"
)

// BenchmarkParseCVSSVector benchmarks parsing a typical CVSS:3.1 vector string.
// This is CPU-intensive as it parses the vector, extracts metrics, and computes
// the base score using floating-point arithmetic.
func BenchmarkParseCVSSVector(b *testing.B) {
	// Typical CVSS:3.1 vector with all metrics specified
	vector := "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"

	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		_ = parseCVSSv3Vector(vector)
	}
}

// BenchmarkParseCVSSScore benchmarks the score parsing function which handles
// both plain numeric scores and CVSS vector strings.
func BenchmarkParseCVSSScore(b *testing.B) {
	scores := []string{
		"9.8",                                                    // plain numeric
		"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",         // CVSS v3 vector
		"CVSS:3.1/AV:A/AC:H/PR:L/UI:R/S:C/C:L/I:L/A:N",         // different metrics
		"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H",         // local attack
	}

	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		for _, score := range scores {
			_ = parseCVSSScore(score)
		}
	}
}

// BenchmarkCVSSToSeverity benchmarks the conversion from CVSS score to severity level.
func BenchmarkCVSSToSeverity(b *testing.B) {
	scores := []float64{9.8, 7.5, 4.3, 2.1, 0.0}

	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		for _, score := range scores {
			_ = cvssToSeverity(score)
		}
	}
}

// BenchmarkExtractSeverity benchmarks extracting severity from an OSV vulnerability
// which may have multiple severity entries.
func BenchmarkExtractSeverity(b *testing.B) {
	vuln := osvVulnerability{
		ID:      "GHSA-1234",
		Summary: "Test vulnerability",
		Severity: []osvSeverity{
			{Type: "CVSS_V3", Score: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"},
			{Type: "CVSS_V2", Score: "7.5"},
		},
	}

	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		_ = extractSeverity(vuln)
	}
}

// BenchmarkExtractFixedVersion benchmarks extracting the fixed version from
// an OSV vulnerability's affected ranges.
func BenchmarkExtractFixedVersion(b *testing.B) {
	vuln := osvVulnerability{
		ID: "GHSA-1234",
		Affected: []osvAffected{
			{
				Ranges: []osvRange{
					{
						Type: "SEMVER",
						Events: []osvEvent{
							{Introduced: "0"},
							{Fixed: "1.2.3"},
						},
					},
				},
			},
		},
	}

	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		_ = extractFixedVersion(vuln)
	}
}
