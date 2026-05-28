package sbom

import (
	"encoding/json"
	"testing"

	"github.com/chainsaw-dev/chainsaw/pkg/models"
)

func TestGenerateCycloneDX_Basic(t *testing.T) {
	components := []models.Component{
		{Name: "lodash", Version: "4.17.21", Ecosystem: models.EcosystemNpm, PkgURL: "pkg:npm/lodash@4.17.21"},
		{Name: "express", Version: "4.18.0", Ecosystem: models.EcosystemNpm, PkgURL: "pkg:npm/express@4.18.0"},
	}

	data, err := GenerateCycloneDX(components, "0.1.0")
	if err != nil {
		t.Fatalf("GenerateCycloneDX error: %v", err)
	}

	var bom cdxBOM
	if err := json.Unmarshal(data, &bom); err != nil {
		t.Fatalf("output is not valid JSON: %v", err)
	}
	if bom.BOMFormat != "CycloneDX" {
		t.Errorf("bomFormat = %q, want %q", bom.BOMFormat, "CycloneDX")
	}
	if bom.SpecVersion != "1.5" {
		t.Errorf("specVersion = %q, want %q", bom.SpecVersion, "1.5")
	}
	if len(bom.Components) != 2 {
		t.Errorf("component count = %d, want 2", len(bom.Components))
	}
}

func TestGenerateCycloneDX_EmptyComponents(t *testing.T) {
	data, err := GenerateCycloneDX(nil, "0.1.0")
	if err != nil {
		t.Fatalf("GenerateCycloneDX error: %v", err)
	}

	var bom cdxBOM
	if err := json.Unmarshal(data, &bom); err != nil {
		t.Fatalf("output is not valid JSON: %v", err)
	}
	if bom.BOMFormat != "CycloneDX" {
		t.Errorf("bomFormat = %q, want %q", bom.BOMFormat, "CycloneDX")
	}
	if len(bom.Components) != 0 {
		t.Errorf("component count = %d, want 0", len(bom.Components))
	}
}

func TestGenerateCycloneDX_VerifyComponents(t *testing.T) {
	components := []models.Component{
		{Name: "lodash", Version: "4.17.21", Ecosystem: models.EcosystemNpm, PkgURL: "pkg:npm/lodash@4.17.21", Hash: "abc123"},
		{Name: "express", Version: "4.18.0", Ecosystem: models.EcosystemNpm, PkgURL: "pkg:npm/express@4.18.0"},
	}

	data, err := GenerateCycloneDX(components, "0.1.0")
	if err != nil {
		t.Fatalf("GenerateCycloneDX error: %v", err)
	}

	var bom cdxBOM
	if err := json.Unmarshal(data, &bom); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}

	for i, c := range bom.Components {
		if c.Type != "library" {
			t.Errorf("component[%d].type = %q, want %q", i, c.Type, "library")
		}
		if c.Name == "" {
			t.Errorf("component[%d].name is empty", i)
		}
		if c.Version == "" {
			t.Errorf("component[%d].version is empty", i)
		}
		if c.Purl == "" {
			t.Errorf("component[%d].purl is empty", i)
		}
	}

	// First component has a hash
	if len(bom.Components[0].Hashes) != 1 {
		t.Fatalf("component[0] should have 1 hash, got %d", len(bom.Components[0].Hashes))
	}
	if bom.Components[0].Hashes[0].Algorithm != "SHA-256" {
		t.Errorf("hash algorithm = %q, want SHA-256", bom.Components[0].Hashes[0].Algorithm)
	}
	if bom.Components[0].Hashes[0].Content != "abc123" {
		t.Errorf("hash content = %q, want %q", bom.Components[0].Hashes[0].Content, "abc123")
	}

	// Second component has no hash
	if len(bom.Components[1].Hashes) != 0 {
		t.Errorf("component[1] should have 0 hashes, got %d", len(bom.Components[1].Hashes))
	}
}

func TestGenerateCycloneDX_ToolMetadata(t *testing.T) {
	data, err := GenerateCycloneDX(nil, "1.2.3")
	if err != nil {
		t.Fatalf("GenerateCycloneDX error: %v", err)
	}

	var bom cdxBOM
	if err := json.Unmarshal(data, &bom); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}

	tools := bom.Metadata.Tools.Components
	if len(tools) != 1 {
		t.Fatalf("expected 1 tool, got %d", len(tools))
	}
	if tools[0].Name != "chainsaw" {
		t.Errorf("tool name = %q, want %q", tools[0].Name, "chainsaw")
	}
	if tools[0].Version != "1.2.3" {
		t.Errorf("tool version = %q, want %q", tools[0].Version, "1.2.3")
	}
	if bom.Metadata.Timestamp == "" {
		t.Error("metadata.timestamp is empty")
	}
}

func TestGenerateCycloneDX_MultiEcosystem(t *testing.T) {
	components := []models.Component{
		{Name: "golang.org/x/text", Version: "0.14.0", Ecosystem: models.EcosystemGo, PkgURL: "pkg:golang/golang.org/x/text@0.14.0"},
		{Name: "lodash", Version: "4.17.21", Ecosystem: models.EcosystemNpm, PkgURL: "pkg:npm/lodash@4.17.21"},
		{Name: "requests", Version: "2.31.0", Ecosystem: models.EcosystemPyPI, PkgURL: "pkg:pypi/requests@2.31.0"},
	}

	data, err := GenerateCycloneDX(components, "0.1.0")
	if err != nil {
		t.Fatalf("GenerateCycloneDX error: %v", err)
	}

	var bom cdxBOM
	if err := json.Unmarshal(data, &bom); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}

	if len(bom.Components) != 3 {
		t.Fatalf("component count = %d, want 3", len(bom.Components))
	}

	names := map[string]bool{}
	for _, c := range bom.Components {
		names[c.Name] = true
	}
	for _, want := range []string{"golang.org/x/text", "lodash", "requests"} {
		if !names[want] {
			t.Errorf("missing component %q", want)
		}
	}
}
