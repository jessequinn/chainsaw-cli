package models

import (
	"testing"
)

// BenchmarkSeverityRank benchmarks the SeverityRank function which converts
// a Severity to a numeric rank for comparison.
func BenchmarkSeverityRank(b *testing.B) {
	severities := []Severity{
		SeverityCritical,
		SeverityHigh,
		SeverityMedium,
		SeverityLow,
		SeverityNone,
		Severity("UNKNOWN"),
	}

	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		for _, s := range severities {
			_ = SeverityRank(s)
		}
	}
}

// BenchmarkParseSeverity benchmarks parsing string values to Severity enums.
// This includes case-insensitive matching and default handling.
func BenchmarkParseSeverity(b *testing.B) {
	inputs := []string{
		"CRITICAL",
		"critical",
		"CrItIcAl",
		"HIGH",
		"high",
		"MEDIUM",
		"medium",
		"LOW",
		"low",
		"NONE",
		"none",
		"UNKNOWN",
		"",
		"invalid",
	}

	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		for _, input := range inputs {
			_ = ParseSeverity(input)
		}
	}
}
