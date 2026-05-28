package analysis

import (
	"strings"

	"github.com/chainsaw-dev/chainsaw/pkg/models"
)

// AssessBlastRadius estimates the impact of a compromised component.
func AssessBlastRadius(ic models.InfraComponent) models.BlastRadius {
	br := models.BlastRadius{
		Component:     ic,
		NetworkAccess: true, // conservative default
	}

	// Scope
	switch ic.Ecosystem {
	case models.EcosystemGitHubActions:
		if strings.Contains(strings.ToLower(ic.Name), "deploy") {
			br.Scope = "deploy"
		} else {
			br.Scope = "build-only"
		}
	case models.EcosystemDocker:
		br.Scope = "runtime"
	case models.EcosystemTerraform, models.EcosystemAnsible:
		br.Scope = "infrastructure"
	default:
		br.Scope = "runtime"
	}

	// SecretsAccess
	switch ic.Ecosystem {
	case models.EcosystemGitHubActions, models.EcosystemTerraform:
		br.SecretsAccess = true
	}

	// WriteAccess
	switch ic.Ecosystem {
	case models.EcosystemGitHubActions, models.EcosystemTerraform:
		br.WriteAccess = true
	}

	// Score
	score := 30
	if ic.Mutable {
		score += 30
	}
	if br.SecretsAccess {
		score += 15
	}
	if br.WriteAccess {
		score += 15
	}
	if br.Scope == "infrastructure" || br.Scope == "deploy" {
		score += 10
	}
	if score > 100 {
		score = 100
	}
	br.Score = score

	return br
}

// AssessAll computes blast radius for all non-application components.
func AssessAll(components []models.InfraComponent) []models.BlastRadius {
	var results []models.BlastRadius
	for _, ic := range components {
		if ic.Layer == "application" {
			continue
		}
		results = append(results, AssessBlastRadius(ic))
	}
	return results
}
