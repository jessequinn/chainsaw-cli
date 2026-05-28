package models

import (
	"strings"
	"time"
)

type Ecosystem string

const (
	EcosystemGo  Ecosystem = "go"
	EcosystemNpm Ecosystem = "npm"
)

type Severity string

const (
	SeverityCritical Severity = "CRITICAL"
	SeverityHigh     Severity = "HIGH"
	SeverityMedium   Severity = "MEDIUM"
	SeverityLow      Severity = "LOW"
	SeverityNone     Severity = "NONE"
)

// SeverityRank returns numeric rank for comparison (higher = more severe).
func SeverityRank(s Severity) int {
	switch s {
	case SeverityCritical:
		return 4
	case SeverityHigh:
		return 3
	case SeverityMedium:
		return 2
	case SeverityLow:
		return 1
	default:
		return 0
	}
}

// ParseSeverity parses a string to Severity (case-insensitive), defaults to NONE.
func ParseSeverity(s string) Severity {
	switch Severity(strings.ToUpper(s)) {
	case SeverityCritical:
		return SeverityCritical
	case SeverityHigh:
		return SeverityHigh
	case SeverityMedium:
		return SeverityMedium
	case SeverityLow:
		return SeverityLow
	default:
		return SeverityNone
	}
}

type Component struct {
	Name      string    `json:"name"`
	Version   string    `json:"version"`
	Ecosystem Ecosystem `json:"ecosystem"`
	Hash      string    `json:"hash,omitempty"`
	Licenses  []string  `json:"licenses,omitempty"`
	PkgURL    string    `json:"purl"`
}

type Finding struct {
	ID         string    `json:"id"`
	Aliases    []string  `json:"aliases,omitempty"`
	Summary    string    `json:"summary"`
	Details    string    `json:"details,omitempty"`
	Severity   Severity  `json:"severity"`
	Component  Component `json:"component"`
	FixedIn    string    `json:"fixed_in,omitempty"`
	References []string  `json:"references,omitempty"`
	Source     string    `json:"source"`
}

type ScanResult struct {
	Components  []Component `json:"components"`
	Findings    []Finding   `json:"findings"`
	Hygiene     []Finding   `json:"hygiene"`
	Timestamp   time.Time   `json:"timestamp"`
	ToolVersion string      `json:"tool_version"`
}
