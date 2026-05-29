package models

import (
	"strings"
	"time"
)

type Ecosystem string

const (
	EcosystemGo            Ecosystem = "go"
	EcosystemNpm           Ecosystem = "npm"
	EcosystemPyPI          Ecosystem = "pypi"
	EcosystemDocker        Ecosystem = "docker"
	EcosystemTerraform     Ecosystem = "terraform"
	EcosystemAnsible       Ecosystem = "ansible"
	EcosystemGitHubActions Ecosystem = "github-actions"
	EcosystemHex           Ecosystem = "hex"
)

// PinType classifies how tightly a dependency is pinned.
type PinType string

const (
	PinCommitSHA  PinType = "commit-sha"  // immutable (GH Actions SHA, Docker digest)
	PinVersionTag PinType = "version-tag" // semi-mutable (semver tag, Docker tag)
	PinBranch     PinType = "branch"      // fully mutable (main, latest)
	PinRange      PinType = "range"       // resolved at install time (>=1.0,<2.0)
	PinNone       PinType = "none"        // unspecified
)

// SourceTrust classifies publisher trust level.
type SourceTrust string

const (
	TrustOfficial  SourceTrust = "official"  // first-party (actions/*, hashicorp/*)
	TrustVerified  SourceTrust = "verified"  // verified publisher
	TrustCommunity SourceTrust = "community" // third-party, public
	TrustUnknown   SourceTrust = "unknown"   // no provenance information
)

// InfraComponent extends Component with supply chain metadata.
type InfraComponent struct {
	Component
	PinType       PinType     `json:"pin_type"`
	SourceTrust   SourceTrust `json:"source_trust"`
	Mutable       bool        `json:"mutable"`
	ProvenanceURL string      `json:"provenance_url,omitempty"`
	Layer         string      `json:"layer"` // "application", "infrastructure", "ci-cd"
}

// BlastRadius estimates the impact of a compromised component.
type BlastRadius struct {
	Component     InfraComponent `json:"component"`
	Scope         string         `json:"scope"`          // "build-only", "deploy", "runtime", "infrastructure"
	SecretsAccess bool           `json:"secrets_access"`
	NetworkAccess bool           `json:"network_access"`
	WriteAccess   bool           `json:"write_access"`
	Score         int            `json:"score"` // 0-100
}

// CRACheckStatus represents the result of a CRA compliance check.
type CRACheckStatus string

const (
	CRAPass CRACheckStatus = "pass"
	CRAFail CRACheckStatus = "fail"
	CRAWarn CRACheckStatus = "warn"
	CRANA   CRACheckStatus = "n/a"
)

// CRACheck is a single CRA compliance check result.
type CRACheck struct {
	ID          string         `json:"id"`
	Title       string         `json:"title"`
	Article     string         `json:"article"`
	Status      CRACheckStatus `json:"status"`
	Details     string         `json:"details"`
	Severity    Severity       `json:"severity"`
	Remediation string         `json:"remediation,omitempty"`
}

// CRAResult aggregates all CRA compliance checks.
type CRAResult struct {
	ProductName  string     `json:"product_name"`
	Version      string     `json:"version"`
	Date         time.Time  `json:"assessment_date"`
	Regulation   string     `json:"regulation"`
	OverallScore int        `json:"overall_score"` // 0-100
	Checks       []CRACheck `json:"checks"`
	NextDeadline string     `json:"next_deadline"`
	NextDeadDesc string     `json:"next_deadline_description"`
}

// SupplyChainResult aggregates infrastructure supply chain analysis.
type SupplyChainResult struct {
	Components   []InfraComponent `json:"components"`
	PinningScore int              `json:"pinning_score"` // 0-100
	BlastRadii   []BlastRadius    `json:"blast_radii"`
	Timestamp    time.Time        `json:"timestamp"`
	ToolVersion  string           `json:"tool_version"`
}

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
	Location  string    `json:"location,omitempty"`
	Direct    bool      `json:"direct,omitempty"`
	DependsOn []string  `json:"depends_on,omitempty"`
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
	Warnings    []string    `json:"warnings,omitempty"`
	Timestamp   time.Time   `json:"timestamp"`
	ToolVersion string      `json:"tool_version"`
}
