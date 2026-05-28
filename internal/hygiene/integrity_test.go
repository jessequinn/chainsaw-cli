package hygiene

import (
	"testing"

	"github.com/chainsaw-dev/chainsaw/pkg/models"
)

func TestCheckIntegrity_AllHaveHashes(t *testing.T) {
	components := []models.Component{
		{Name: "lodash", Version: "4.17.21", Ecosystem: models.EcosystemNpm, Hash: "sha512-abc123"},
		{Name: "express", Version: "4.18.0", Ecosystem: models.EcosystemNpm, Hash: "sha512-def456"},
	}
	findings := CheckIntegrity(components)
	if len(findings) != 0 {
		t.Errorf("expected 0 findings, got %d", len(findings))
	}
}

func TestCheckIntegrity_MissingHash(t *testing.T) {
	components := []models.Component{
		{Name: "lodash", Version: "4.17.21", Ecosystem: models.EcosystemNpm},
	}
	findings := CheckIntegrity(components)
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}
	if findings[0].Severity != models.SeverityMedium {
		t.Errorf("severity = %q, want %q", findings[0].Severity, models.SeverityMedium)
	}
	if findings[0].Source != "hygiene" {
		t.Errorf("source = %q, want %q", findings[0].Source, "hygiene")
	}
}

func TestCheckIntegrity_MixedComponents(t *testing.T) {
	components := []models.Component{
		{Name: "lodash", Version: "4.17.21", Ecosystem: models.EcosystemNpm, Hash: "sha512-abc"},
		{Name: "express", Version: "4.18.0", Ecosystem: models.EcosystemNpm},
		{Name: "react", Version: "18.0.0", Ecosystem: models.EcosystemNpm},
	}
	findings := CheckIntegrity(components)
	if len(findings) != 2 {
		t.Errorf("expected 2 findings for missing hashes, got %d", len(findings))
	}
}
