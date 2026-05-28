package analysis

import (
	"testing"

	"github.com/chainsaw-dev/chainsaw/pkg/models"
)

func TestClassifyPin(t *testing.T) {
	tests := []struct {
		name string
		comp models.Component
		want models.PinType
	}{
		{"docker digest", models.Component{Ecosystem: models.EcosystemDocker, Version: "sha256:abc123"}, models.PinCommitSHA},
		{"docker latest", models.Component{Ecosystem: models.EcosystemDocker, Version: "latest"}, models.PinNone},
		{"docker empty", models.Component{Ecosystem: models.EcosystemDocker, Version: ""}, models.PinNone},
		{"docker semver", models.Component{Ecosystem: models.EcosystemDocker, Version: "3.19"}, models.PinVersionTag},
		{"docker branch", models.Component{Ecosystem: models.EcosystemDocker, Version: "nightly"}, models.PinBranch},
		{"gha sha", models.Component{Ecosystem: models.EcosystemGitHubActions, Version: "abc123def456abc123def456abc123def456abcd"}, models.PinCommitSHA},
		{"gha tag", models.Component{Ecosystem: models.EcosystemGitHubActions, Version: "v4"}, models.PinVersionTag},
		{"gha branch", models.Component{Ecosystem: models.EcosystemGitHubActions, Version: "main"}, models.PinBranch},
		{"gha empty", models.Component{Ecosystem: models.EcosystemGitHubActions, Version: ""}, models.PinNone},
		{"terraform semver", models.Component{Ecosystem: models.EcosystemTerraform, Version: "1.5.0"}, models.PinVersionTag},
		{"terraform empty", models.Component{Ecosystem: models.EcosystemTerraform, Version: ""}, models.PinNone},
		{"terraform branch", models.Component{Ecosystem: models.EcosystemTerraform, Version: "main"}, models.PinBranch},
		{"ansible empty", models.Component{Ecosystem: models.EcosystemAnsible, Version: ""}, models.PinNone},
		{"ansible unspecified", models.Component{Ecosystem: models.EcosystemAnsible, Version: "unspecified"}, models.PinNone},
		{"ansible range", models.Component{Ecosystem: models.EcosystemAnsible, Version: ">=1.0,<2.0"}, models.PinRange},
		{"ansible version", models.Component{Ecosystem: models.EcosystemAnsible, Version: "2.14.0"}, models.PinVersionTag},
		{"go version", models.Component{Ecosystem: models.EcosystemGo, Version: "v1.2.3"}, models.PinVersionTag},
		{"go empty", models.Component{Ecosystem: models.EcosystemGo, Version: ""}, models.PinNone},
		{"npm version", models.Component{Ecosystem: models.EcosystemNpm, Version: "4.17.21"}, models.PinVersionTag},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ClassifyPin(tt.comp)
			if got != tt.want {
				t.Errorf("ClassifyPin() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestClassifyTrust(t *testing.T) {
	tests := []struct {
		name string
		comp models.Component
		want models.SourceTrust
	}{
		{"gha official", models.Component{Ecosystem: models.EcosystemGitHubActions, Name: "actions/checkout"}, models.TrustOfficial},
		{"gha github", models.Component{Ecosystem: models.EcosystemGitHubActions, Name: "github/codeql-action"}, models.TrustOfficial},
		{"gha verified", models.Component{Ecosystem: models.EcosystemGitHubActions, Name: "aws-actions/configure"}, models.TrustVerified},
		{"gha community", models.Component{Ecosystem: models.EcosystemGitHubActions, Name: "random/action"}, models.TrustCommunity},
		{"docker official", models.Component{Ecosystem: models.EcosystemDocker, Name: "library/golang"}, models.TrustOfficial},
		{"docker distroless", models.Component{Ecosystem: models.EcosystemDocker, Name: "gcr.io/distroless/static"}, models.TrustVerified},
		{"docker community", models.Component{Ecosystem: models.EcosystemDocker, Name: "myuser/myimage"}, models.TrustCommunity},
		{"terraform official", models.Component{Ecosystem: models.EcosystemTerraform, Name: "hashicorp/aws"}, models.TrustOfficial},
		{"terraform community", models.Component{Ecosystem: models.EcosystemTerraform, Name: "random/module"}, models.TrustCommunity},
		{"ansible official", models.Component{Ecosystem: models.EcosystemAnsible, Name: "ansible.builtin"}, models.TrustOfficial},
		{"ansible verified", models.Component{Ecosystem: models.EcosystemAnsible, Name: "community.general"}, models.TrustVerified},
		{"ansible community", models.Component{Ecosystem: models.EcosystemAnsible, Name: "custom.collection"}, models.TrustCommunity},
		{"go default", models.Component{Ecosystem: models.EcosystemGo, Name: "github.com/foo/bar"}, models.TrustCommunity},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ClassifyTrust(tt.comp)
			if got != tt.want {
				t.Errorf("ClassifyTrust() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestEnrichComponent(t *testing.T) {
	c := models.Component{
		Name:      "actions/checkout",
		Version:   "v4",
		Ecosystem: models.EcosystemGitHubActions,
	}
	ic := EnrichComponent(c)

	if ic.Layer != "ci-cd" {
		t.Errorf("Layer = %q, want %q", ic.Layer, "ci-cd")
	}
	if ic.PinType != models.PinVersionTag {
		t.Errorf("PinType = %q, want %q", ic.PinType, models.PinVersionTag)
	}
	if ic.SourceTrust != models.TrustOfficial {
		t.Errorf("SourceTrust = %q, want %q", ic.SourceTrust, models.TrustOfficial)
	}
	if ic.Mutable {
		t.Error("Mutable should be false for version-tag pin")
	}

	// Mutable component.
	c2 := models.Component{Name: "myuser/myimage", Version: "latest", Ecosystem: models.EcosystemDocker}
	ic2 := EnrichComponent(c2)
	if !ic2.Mutable {
		t.Error("Mutable should be true for PinNone")
	}
}

func TestCalculatePinningScore(t *testing.T) {
	tests := []struct {
		name       string
		components []models.InfraComponent
		want       int
	}{
		{"empty", nil, 100},
		{"all sha", []models.InfraComponent{
			{Component: models.Component{Ecosystem: models.EcosystemGitHubActions}, PinType: models.PinCommitSHA, Layer: "ci-cd"},
			{Component: models.Component{Ecosystem: models.EcosystemDocker}, PinType: models.PinCommitSHA, Layer: "infrastructure"},
		}, 100},
		{"all none", []models.InfraComponent{
			{Component: models.Component{Ecosystem: models.EcosystemGitHubActions}, PinType: models.PinNone, Layer: "ci-cd"},
		}, 0},
		{"mixed", []models.InfraComponent{
			{Component: models.Component{Ecosystem: models.EcosystemGitHubActions}, PinType: models.PinCommitSHA, Layer: "ci-cd"},
			{Component: models.Component{Ecosystem: models.EcosystemDocker}, PinType: models.PinVersionTag, Layer: "infrastructure"},
		}, 85}, // (100+70)/2
		{"app only skipped", []models.InfraComponent{
			{Component: models.Component{Ecosystem: models.EcosystemGo}, PinType: models.PinNone, Layer: "application"},
		}, 100},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := CalculatePinningScore(tt.components)
			if got != tt.want {
				t.Errorf("CalculatePinningScore() = %d, want %d", got, tt.want)
			}
		})
	}
}

func TestLayerForEcosystem(t *testing.T) {
	tests := []struct {
		eco  models.Ecosystem
		want string
	}{
		{models.EcosystemDocker, "infrastructure"},
		{models.EcosystemTerraform, "infrastructure"},
		{models.EcosystemAnsible, "infrastructure"},
		{models.EcosystemGitHubActions, "ci-cd"},
		{models.EcosystemGo, "application"},
		{models.EcosystemNpm, "application"},
		{models.EcosystemPyPI, "application"},
		{models.EcosystemHex, "application"},
	}

	for _, tt := range tests {
		t.Run(string(tt.eco), func(t *testing.T) {
			got := LayerForEcosystem(tt.eco)
			if got != tt.want {
				t.Errorf("LayerForEcosystem(%q) = %q, want %q", tt.eco, got, tt.want)
			}
		})
	}
}
