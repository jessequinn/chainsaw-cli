package models

import (
	"testing"
)

func TestSeverityRank(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		severity Severity
		want     int
	}{
		{
			name:     "CRITICAL returns 4",
			severity: SeverityCritical,
			want:     4,
		},
		{
			name:     "HIGH returns 3",
			severity: SeverityHigh,
			want:     3,
		},
		{
			name:     "MEDIUM returns 2",
			severity: SeverityMedium,
			want:     2,
		},
		{
			name:     "LOW returns 1",
			severity: SeverityLow,
			want:     1,
		},
		{
			name:     "NONE returns 0",
			severity: SeverityNone,
			want:     0,
		},
		{
			name:     "unknown string returns 0",
			severity: Severity("UNKNOWN"),
			want:     0,
		},
		{
			name:     "empty string returns 0",
			severity: Severity(""),
			want:     0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := SeverityRank(tt.severity)
			if got != tt.want {
				t.Errorf("SeverityRank(%q) = %d, want %d", tt.severity, got, tt.want)
			}
		})
	}
}

func TestParseSeverity(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		in   string
		want Severity
	}{
		{
			name: "uppercase CRITICAL",
			in:   "CRITICAL",
			want: SeverityCritical,
		},
		{
			name: "lowercase critical",
			in:   "critical",
			want: SeverityCritical,
		},
		{
			name: "mixed case CrItIcAl",
			in:   "CrItIcAl",
			want: SeverityCritical,
		},
		{
			name: "uppercase HIGH",
			in:   "HIGH",
			want: SeverityHigh,
		},
		{
			name: "lowercase high",
			in:   "high",
			want: SeverityHigh,
		},
		{
			name: "mixed case HiGh",
			in:   "HiGh",
			want: SeverityHigh,
		},
		{
			name: "uppercase MEDIUM",
			in:   "MEDIUM",
			want: SeverityMedium,
		},
		{
			name: "lowercase medium",
			in:   "medium",
			want: SeverityMedium,
		},
		{
			name: "mixed case MeDiUm",
			in:   "MeDiUm",
			want: SeverityMedium,
		},
		{
			name: "uppercase LOW",
			in:   "LOW",
			want: SeverityLow,
		},
		{
			name: "lowercase low",
			in:   "low",
			want: SeverityLow,
		},
		{
			name: "mixed case LoW",
			in:   "LoW",
			want: SeverityLow,
		},
		{
			name: "uppercase NONE",
			in:   "NONE",
			want: SeverityNone,
		},
		{
			name: "lowercase none",
			in:   "none",
			want: SeverityNone,
		},
		{
			name: "mixed case NoNe",
			in:   "NoNe",
			want: SeverityNone,
		},
		{
			name: "unknown string UNKNOWN",
			in:   "UNKNOWN",
			want: SeverityNone,
		},
		{
			name: "unknown string invalid",
			in:   "invalid",
			want: SeverityNone,
		},
		{
			name: "empty string",
			in:   "",
			want: SeverityNone,
		},
		{
			name: "whitespace only",
			in:   "   ",
			want: SeverityNone,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ParseSeverity(tt.in)
			if got != tt.want {
				t.Errorf("ParseSeverity(%q) = %q, want %q", tt.in, got, tt.want)
			}
		})
	}
}

func TestParseSeverity_idempotent(t *testing.T) {
	t.Parallel()

	severities := []Severity{
		SeverityCritical,
		SeverityHigh,
		SeverityMedium,
		SeverityLow,
		SeverityNone,
	}

	for _, sev := range severities {
		t.Run(string(sev), func(t *testing.T) {
			// ParseSeverity(string(ParseSeverity(x))) == ParseSeverity(x)
			first := ParseSeverity(string(sev))
			second := ParseSeverity(string(first))
			if first != second {
				t.Errorf("ParseSeverity not idempotent: first=%q, second=%q", first, second)
			}
		})
	}
}

func TestSeverityRank_ordering(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		sev1 Severity
		sev2 Severity
	}{
		{
			name: "CRITICAL > HIGH",
			sev1: SeverityCritical,
			sev2: SeverityHigh,
		},
		{
			name: "HIGH > MEDIUM",
			sev1: SeverityHigh,
			sev2: SeverityMedium,
		},
		{
			name: "MEDIUM > LOW",
			sev1: SeverityMedium,
			sev2: SeverityLow,
		},
		{
			name: "LOW > NONE",
			sev1: SeverityLow,
			sev2: SeverityNone,
		},
		{
			name: "CRITICAL > MEDIUM",
			sev1: SeverityCritical,
			sev2: SeverityMedium,
		},
		{
			name: "CRITICAL > LOW",
			sev1: SeverityCritical,
			sev2: SeverityLow,
		},
		{
			name: "CRITICAL > NONE",
			sev1: SeverityCritical,
			sev2: SeverityNone,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rank1 := SeverityRank(tt.sev1)
			rank2 := SeverityRank(tt.sev2)
			if rank1 <= rank2 {
				t.Errorf("SeverityRank(%q)=%d should be > SeverityRank(%q)=%d", tt.sev1, rank1, tt.sev2, rank2)
			}
		})
	}
}

func TestEcosystem_constants(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		got      Ecosystem
		expected string
	}{
		{
			name:     "EcosystemGo is lowercase",
			got:      EcosystemGo,
			expected: "go",
		},
		{
			name:     "EcosystemNpm is lowercase",
			got:      EcosystemNpm,
			expected: "npm",
		},
		{
			name:     "EcosystemPyPI is lowercase",
			got:      EcosystemPyPI,
			expected: "pypi",
		},
		{
			name:     "EcosystemDocker is lowercase",
			got:      EcosystemDocker,
			expected: "docker",
		},
		{
			name:     "EcosystemTerraform is lowercase",
			got:      EcosystemTerraform,
			expected: "terraform",
		},
		{
			name:     "EcosystemAnsible is lowercase",
			got:      EcosystemAnsible,
			expected: "ansible",
		},
		{
			name:     "EcosystemGitHubActions is kebab-case",
			got:      EcosystemGitHubActions,
			expected: "github-actions",
		},
		{
			name:     "EcosystemHex is lowercase",
			got:      EcosystemHex,
			expected: "hex",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if string(tt.got) != tt.expected {
				t.Errorf("got %q, want %q", tt.got, tt.expected)
			}
		})
	}
}

func TestPinType_constants(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		got      PinType
		expected string
	}{
		{
			name:     "PinCommitSHA is commit-sha",
			got:      PinCommitSHA,
			expected: "commit-sha",
		},
		{
			name:     "PinVersionTag is version-tag",
			got:      PinVersionTag,
			expected: "version-tag",
		},
		{
			name:     "PinBranch is branch",
			got:      PinBranch,
			expected: "branch",
		},
		{
			name:     "PinRange is range",
			got:      PinRange,
			expected: "range",
		},
		{
			name:     "PinNone is none",
			got:      PinNone,
			expected: "none",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if string(tt.got) != tt.expected {
				t.Errorf("got %q, want %q", tt.got, tt.expected)
			}
		})
	}
}

func TestCRACheckStatus_constants(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		got      CRACheckStatus
		expected string
	}{
		{
			name:     "CRAPass is pass",
			got:      CRAPass,
			expected: "pass",
		},
		{
			name:     "CRAFail is fail",
			got:      CRAFail,
			expected: "fail",
		},
		{
			name:     "CRAWarn is warn",
			got:      CRAWarn,
			expected: "warn",
		},
		{
			name:     "CRANA is n/a",
			got:      CRANA,
			expected: "n/a",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if string(tt.got) != tt.expected {
				t.Errorf("got %q, want %q", tt.got, tt.expected)
			}
		})
	}
}

func TestSourceTrust_constants(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		got      SourceTrust
		expected string
	}{
		{
			name:     "TrustOfficial is official",
			got:      TrustOfficial,
			expected: "official",
		},
		{
			name:     "TrustVerified is verified",
			got:      TrustVerified,
			expected: "verified",
		},
		{
			name:     "TrustCommunity is community",
			got:      TrustCommunity,
			expected: "community",
		},
		{
			name:     "TrustUnknown is unknown",
			got:      TrustUnknown,
			expected: "unknown",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if string(tt.got) != tt.expected {
				t.Errorf("got %q, want %q", tt.got, tt.expected)
			}
		})
	}
}
