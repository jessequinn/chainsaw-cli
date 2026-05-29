package hygiene

import (
	"testing"

	"github.com/chainsaw-dev/chainsaw/pkg/models"
)

func TestLevenshteinDistance(t *testing.T) {
	tests := []struct {
		a, b string
		want int
	}{
		{"", "", 0},
		{"abc", "", 3},
		{"", "abc", 3},
		{"abc", "abc", 0},
		{"abc", "abd", 1},
		{"kitten", "sitting", 3},
		{"express", "exrpess", 2},
		{"requests", "reqeusts", 2},
	}
	for _, tt := range tests {
		t.Run(tt.a+"_"+tt.b, func(t *testing.T) {
			got := levenshtein(tt.a, tt.b)
			if got != tt.want {
				t.Errorf("levenshtein(%q, %q) = %d, want %d", tt.a, tt.b, got, tt.want)
			}
		})
	}
}

func TestCheckTyposquatting_NoMatches(t *testing.T) {
	components := []models.Component{
		{Name: "my-totally-unique-package-xyz", Version: "1.0.0", Ecosystem: models.EcosystemNpm},
		{Name: "github.com/someorg/somepkg", Version: "0.1.0", Ecosystem: models.EcosystemGo},
	}
	findings := CheckTyposquatting(components)
	if len(findings) != 0 {
		t.Errorf("expected 0 findings, got %d: %v", len(findings), findings)
	}
}

func TestCheckTyposquatting_DetectsTyposquat(t *testing.T) {
	tests := []struct {
		name      string
		component models.Component
	}{
		{
			"npm typosquat of express",
			models.Component{Name: "exrpess", Version: "4.0.0", Ecosystem: models.EcosystemNpm},
		},
		{
			"pypi typosquat of requests",
			models.Component{Name: "reqeusts", Version: "2.0.0", Ecosystem: models.EcosystemPyPI},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			findings := CheckTyposquatting([]models.Component{tt.component})
			if len(findings) == 0 {
				t.Error("expected typosquatting finding, got none")
			}
			for _, f := range findings {
				if f.Source != "hygiene" {
					t.Errorf("source = %q, want %q", f.Source, "hygiene")
				}
				if f.Severity != models.SeverityHigh {
					t.Errorf("severity = %q, want %q", f.Severity, models.SeverityHigh)
				}
			}
		})
	}
}

func TestCheckTyposquatting_SkipsPopularPackages(t *testing.T) {
	// Popular packages that are close in edit distance to OTHER popular
	// packages must not be flagged (e.g. golang.org/x/text vs golang.org/x/net,
	// hashicorp/aws vs hashicorp/tls).
	components := []models.Component{
		{Name: "golang.org/x/text", Version: "v0.14.0", Ecosystem: models.EcosystemGo},
		{Name: "golang.org/x/net", Version: "v0.20.0", Ecosystem: models.EcosystemGo},
		{Name: "hashicorp/aws", Version: "5.31.0", Ecosystem: models.EcosystemTerraform},
		{Name: "hashicorp/tls", Version: "4.0.0", Ecosystem: models.EcosystemTerraform},
	}
	findings := CheckTyposquatting(components)
	if len(findings) != 0 {
		t.Errorf("popular packages should not flag each other, got %d findings:", len(findings))
		for _, f := range findings {
			t.Logf("  %s: %s", f.ID, f.Summary)
		}
	}
}

func TestCheckTyposquatting_IgnoresExactMatch(t *testing.T) {
	components := []models.Component{
		{Name: "express", Version: "4.18.0", Ecosystem: models.EcosystemNpm},
		{Name: "requests", Version: "2.31.0", Ecosystem: models.EcosystemPyPI},
		{Name: "github.com/spf13/cobra", Version: "1.8.0", Ecosystem: models.EcosystemGo},
	}
	findings := CheckTyposquatting(components)
	if len(findings) != 0 {
		t.Errorf("exact matches should not flag, got %d findings", len(findings))
	}
}
