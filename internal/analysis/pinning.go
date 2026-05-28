package analysis

import (
	"regexp"
	"strings"

	"github.com/chainsaw-dev/chainsaw/pkg/models"
)

var (
	semverRe = regexp.MustCompile(`^v?\d+(\.\d+)*`)
	hexSHARe = regexp.MustCompile(`^[0-9a-f]{40}$`)
)

// ClassifyPin determines the PinType for a component based on its ecosystem and version.
func ClassifyPin(c models.Component) models.PinType {
	v := strings.TrimSpace(c.Version)

	switch c.Ecosystem {
	case models.EcosystemDocker:
		if strings.Contains(v, "sha256:") {
			return models.PinCommitSHA
		}
		if v == "latest" || v == "" {
			return models.PinNone
		}
		if len(v) > 0 && (v[0] >= '0' && v[0] <= '9' || v[0] == 'v') {
			return models.PinVersionTag
		}
		return models.PinBranch

	case models.EcosystemGitHubActions:
		if hexSHARe.MatchString(v) {
			return models.PinCommitSHA
		}
		if strings.HasPrefix(v, "v") {
			return models.PinVersionTag
		}
		if v == "" {
			return models.PinNone
		}
		return models.PinBranch

	case models.EcosystemTerraform:
		if v == "" {
			return models.PinNone
		}
		if semverRe.MatchString(v) {
			return models.PinVersionTag
		}
		return models.PinBranch

	case models.EcosystemAnsible:
		if v == "" || v == "unspecified" {
			return models.PinNone
		}
		if strings.ContainsAny(v, "><") || strings.Contains(v, ">=") || strings.Contains(v, "<=") {
			return models.PinRange
		}
		return models.PinVersionTag

	default: // go, npm, pypi, hex
		if v == "" {
			return models.PinNone
		}
		return models.PinVersionTag
	}
}

// ClassifyTrust determines the SourceTrust for a component.
func ClassifyTrust(c models.Component) models.SourceTrust {
	name := c.Name

	switch c.Ecosystem {
	case models.EcosystemGitHubActions:
		if strings.HasPrefix(name, "actions/") || strings.HasPrefix(name, "github/") {
			return models.TrustOfficial
		}
		if strings.HasPrefix(name, "docker/") ||
			strings.HasPrefix(name, "aws-actions/") ||
			strings.HasPrefix(name, "google-github-actions/") ||
			strings.HasPrefix(name, "azure/") {
			return models.TrustVerified
		}
		return models.TrustCommunity

	case models.EcosystemDocker:
		if strings.HasPrefix(name, "library/") {
			return models.TrustOfficial
		}
		if strings.Contains(name, "gcr.io/distroless") {
			return models.TrustVerified
		}
		return models.TrustCommunity

	case models.EcosystemTerraform:
		if strings.HasPrefix(name, "hashicorp/") {
			return models.TrustOfficial
		}
		return models.TrustCommunity

	case models.EcosystemAnsible:
		if strings.HasPrefix(name, "ansible.") {
			return models.TrustOfficial
		}
		if strings.HasPrefix(name, "community.") {
			return models.TrustVerified
		}
		return models.TrustCommunity

	default:
		return models.TrustCommunity
	}
}

// LayerForEcosystem returns the supply chain layer for an ecosystem.
func LayerForEcosystem(eco models.Ecosystem) string {
	switch eco {
	case models.EcosystemDocker, models.EcosystemTerraform, models.EcosystemAnsible:
		return "infrastructure"
	case models.EcosystemGitHubActions:
		return "ci-cd"
	default:
		return "application"
	}
}

// EnrichComponent converts a Component to an InfraComponent with supply chain metadata.
func EnrichComponent(c models.Component) models.InfraComponent {
	pin := ClassifyPin(c)
	return models.InfraComponent{
		Component:   c,
		PinType:     pin,
		SourceTrust: ClassifyTrust(c),
		Mutable:     pin == models.PinBranch || pin == models.PinNone,
		Layer:       LayerForEcosystem(c.Ecosystem),
	}
}

// CalculatePinningScore computes overall pinning score (0-100).
// Only infrastructure and ci-cd layer components are scored.
func CalculatePinningScore(components []models.InfraComponent) int {
	var total, count int
	for _, ic := range components {
		if ic.Layer == "application" {
			continue
		}
		count++
		switch ic.PinType {
		case models.PinCommitSHA:
			total += 100
		case models.PinVersionTag:
			total += 70
		case models.PinRange:
			total += 40
		case models.PinBranch:
			total += 20
		case models.PinNone:
			// 0
		}
	}
	if count == 0 {
		return 100
	}
	return total / count
}
