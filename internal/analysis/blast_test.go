package analysis

import (
	"testing"

	"github.com/chainsaw-dev/chainsaw/pkg/models"
)

func TestAssessBlastRadius(t *testing.T) {
	tests := []struct {
		name          string
		ic            models.InfraComponent
		wantScope     string
		wantSecrets   bool
		wantWrite     bool
		wantMinScore  int
	}{
		{
			name: "docker runtime",
			ic: models.InfraComponent{
				Component: models.Component{Name: "library/golang", Ecosystem: models.EcosystemDocker},
				Layer:     "infrastructure",
			},
			wantScope: "runtime", wantSecrets: false, wantWrite: false, wantMinScore: 30,
		},
		{
			name: "gha build",
			ic: models.InfraComponent{
				Component: models.Component{Name: "actions/checkout", Ecosystem: models.EcosystemGitHubActions},
				Layer:     "ci-cd",
			},
			wantScope: "build-only", wantSecrets: true, wantWrite: true, wantMinScore: 60,
		},
		{
			name: "gha deploy",
			ic: models.InfraComponent{
				Component: models.Component{Name: "some/deploy-action", Ecosystem: models.EcosystemGitHubActions},
				Layer:     "ci-cd",
			},
			wantScope: "deploy", wantSecrets: true, wantWrite: true, wantMinScore: 70,
		},
		{
			name: "terraform",
			ic: models.InfraComponent{
				Component: models.Component{Name: "hashicorp/aws", Ecosystem: models.EcosystemTerraform},
				Layer:     "infrastructure",
			},
			wantScope: "infrastructure", wantSecrets: true, wantWrite: true, wantMinScore: 70,
		},
		{
			name: "ansible",
			ic: models.InfraComponent{
				Component: models.Component{Name: "ansible.builtin", Ecosystem: models.EcosystemAnsible},
				Layer:     "infrastructure",
			},
			wantScope: "infrastructure", wantSecrets: false, wantWrite: false, wantMinScore: 30,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			br := AssessBlastRadius(tt.ic)
			if br.Scope != tt.wantScope {
				t.Errorf("Scope = %q, want %q", br.Scope, tt.wantScope)
			}
			if br.SecretsAccess != tt.wantSecrets {
				t.Errorf("SecretsAccess = %v, want %v", br.SecretsAccess, tt.wantSecrets)
			}
			if br.WriteAccess != tt.wantWrite {
				t.Errorf("WriteAccess = %v, want %v", br.WriteAccess, tt.wantWrite)
			}
			if br.Score < tt.wantMinScore {
				t.Errorf("Score = %d, want >= %d", br.Score, tt.wantMinScore)
			}
			if !br.NetworkAccess {
				t.Error("NetworkAccess should default to true")
			}
		})
	}
}

func TestAssessAll(t *testing.T) {
	components := []models.InfraComponent{
		{Component: models.Component{Name: "actions/checkout", Ecosystem: models.EcosystemGitHubActions}, Layer: "ci-cd"},
		{Component: models.Component{Name: "library/golang", Ecosystem: models.EcosystemDocker}, Layer: "infrastructure"},
		{Component: models.Component{Name: "lodash", Ecosystem: models.EcosystemNpm}, Layer: "application"},
	}

	results := AssessAll(components)

	// Application layer should be excluded.
	if len(results) != 2 {
		t.Errorf("AssessAll returned %d results, want 2 (app excluded)", len(results))
	}
}

func TestAssessBlastRadius_CICDWithSecrets(t *testing.T) {
	mutable := models.InfraComponent{
		Component: models.Component{Name: "actions/checkout", Ecosystem: models.EcosystemGitHubActions},
		PinType:   models.PinBranch,
		Mutable:   true,
		Layer:     "ci-cd",
	}
	immutable := models.InfraComponent{
		Component: models.Component{Name: "actions/checkout", Ecosystem: models.EcosystemGitHubActions},
		PinType:   models.PinCommitSHA,
		Mutable:   false,
		Layer:     "ci-cd",
	}

	brMutable := AssessBlastRadius(mutable)
	brImmutable := AssessBlastRadius(immutable)

	if brMutable.Score <= brImmutable.Score {
		t.Errorf("mutable score (%d) should be > immutable score (%d)", brMutable.Score, brImmutable.Score)
	}
	if !brMutable.SecretsAccess {
		t.Error("CI/CD component should have secrets access")
	}
}
