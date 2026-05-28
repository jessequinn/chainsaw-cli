package hygiene

import (
	"fmt"

	"github.com/chainsaw-dev/chainsaw/pkg/models"
)

// CheckIntegrity verifies that every component has an integrity hash.
// Components missing a hash receive a MEDIUM severity finding.
func CheckIntegrity(components []models.Component) []models.Finding {
	var findings []models.Finding

	for _, comp := range components {
		if comp.Hash != "" {
			continue
		}
		findings = append(findings, models.Finding{
			ID:       fmt.Sprintf("INTEGRITY-%s-%s-%s", comp.Ecosystem, comp.Name, comp.Version),
			Summary:  fmt.Sprintf("Missing integrity hash for %s@%s", comp.Name, comp.Version),
			Severity: models.SeverityMedium,
			Component: models.Component{
				Name:      comp.Name,
				Version:   comp.Version,
				Ecosystem: comp.Ecosystem,
				PkgURL:    comp.PkgURL,
			},
			Source: "hygiene",
		})
	}

	return findings
}
