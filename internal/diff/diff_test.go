package diff

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/chainsaw-dev/chainsaw/pkg/models"
)

var (
	compA = models.Component{Name: "lodash", Version: "4.17.20", Ecosystem: models.EcosystemNpm}
	compB = models.Component{Name: "axios", Version: "1.6.0", Ecosystem: models.EcosystemNpm}
	compC = models.Component{Name: "helmet", Version: "7.1.0", Ecosystem: models.EcosystemNpm}

	vulnA = models.Finding{
		ID: "CVE-2024-1234", Severity: models.SeverityHigh,
		Component: compA, FixedIn: "4.17.21", Source: "osv",
	}
	vulnB = models.Finding{
		ID: "CVE-2024-5678", Severity: models.SeverityCritical,
		Component: compB, Source: "osv",
	}
)

func baseScan(comps []models.Component, findings []models.Finding) models.ScanResult {
	return models.ScanResult{Components: comps, Findings: findings, ToolVersion: "test"}
}

func TestCompare_NoChanges(t *testing.T) {
	base := baseScan([]models.Component{compA}, []models.Finding{vulnA})
	result := Compare(base, base)

	if len(result.NewVulnerabilities) != 0 {
		t.Errorf("expected 0 new vulns, got %d", len(result.NewVulnerabilities))
	}
	if len(result.FixedVulnerabilities) != 0 {
		t.Errorf("expected 0 fixed vulns, got %d", len(result.FixedVulnerabilities))
	}
	if len(result.NewComponents) != 0 {
		t.Errorf("expected 0 new components, got %d", len(result.NewComponents))
	}
	if len(result.RemovedComponents) != 0 {
		t.Errorf("expected 0 removed components, got %d", len(result.RemovedComponents))
	}
}

func TestCompare_NewVulnerability(t *testing.T) {
	base := baseScan([]models.Component{compA, compB}, nil)
	head := baseScan([]models.Component{compA, compB}, []models.Finding{vulnB})
	result := Compare(base, head)

	if len(result.NewVulnerabilities) != 1 {
		t.Fatalf("expected 1 new vuln, got %d", len(result.NewVulnerabilities))
	}
	if result.NewVulnerabilities[0].ID != "CVE-2024-5678" {
		t.Errorf("expected CVE-2024-5678, got %s", result.NewVulnerabilities[0].ID)
	}
}

func TestCompare_FixedVulnerability(t *testing.T) {
	base := baseScan([]models.Component{compA}, []models.Finding{vulnA})
	head := baseScan([]models.Component{compA}, nil)
	result := Compare(base, head)

	if len(result.FixedVulnerabilities) != 1 {
		t.Fatalf("expected 1 fixed vuln, got %d", len(result.FixedVulnerabilities))
	}
	if result.FixedVulnerabilities[0].ID != "CVE-2024-1234" {
		t.Errorf("expected CVE-2024-1234, got %s", result.FixedVulnerabilities[0].ID)
	}
}

func TestCompare_NewComponent(t *testing.T) {
	base := baseScan([]models.Component{compA}, nil)
	head := baseScan([]models.Component{compA, compB}, nil)
	result := Compare(base, head)

	if len(result.NewComponents) != 1 {
		t.Fatalf("expected 1 new component, got %d", len(result.NewComponents))
	}
	if result.NewComponents[0].Name != "axios" {
		t.Errorf("expected axios, got %s", result.NewComponents[0].Name)
	}
}

func TestCompare_RemovedComponent(t *testing.T) {
	base := baseScan([]models.Component{compA, compB}, nil)
	head := baseScan([]models.Component{compA}, nil)
	result := Compare(base, head)

	if len(result.RemovedComponents) != 1 {
		t.Fatalf("expected 1 removed component, got %d", len(result.RemovedComponents))
	}
	if result.RemovedComponents[0].Name != "axios" {
		t.Errorf("expected axios, got %s", result.RemovedComponents[0].Name)
	}
}

func TestCompare_Mixed(t *testing.T) {
	base := baseScan([]models.Component{compA, compB}, []models.Finding{vulnA})
	head := baseScan([]models.Component{compA, compC}, []models.Finding{vulnB})
	result := Compare(base, head)

	if len(result.NewVulnerabilities) != 1 {
		t.Errorf("expected 1 new vuln, got %d", len(result.NewVulnerabilities))
	}
	if len(result.FixedVulnerabilities) != 1 {
		t.Errorf("expected 1 fixed vuln, got %d", len(result.FixedVulnerabilities))
	}
	if len(result.NewComponents) != 1 {
		t.Errorf("expected 1 new component, got %d", len(result.NewComponents))
	}
	if len(result.RemovedComponents) != 1 {
		t.Errorf("expected 1 removed component, got %d", len(result.RemovedComponents))
	}
	if result.BaseComponentCount != 2 || result.HeadComponentCount != 2 {
		t.Errorf("unexpected component counts: %d -> %d", result.BaseComponentCount, result.HeadComponentCount)
	}
}

func TestLoadScanResult(t *testing.T) {
	scan := baseScan([]models.Component{compA}, []models.Finding{vulnA})
	data, err := json.MarshalIndent(scan, "", "  ")
	if err != nil {
		t.Fatal(err)
	}

	path := filepath.Join(t.TempDir(), "scan.json")
	if err := os.WriteFile(path, data, 0o644); err != nil {
		t.Fatal(err)
	}

	loaded, err := LoadScanResult(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(loaded.Components) != 1 {
		t.Errorf("expected 1 component, got %d", len(loaded.Components))
	}
	if len(loaded.Findings) != 1 {
		t.Errorf("expected 1 finding, got %d", len(loaded.Findings))
	}
}

func TestWriteDiffReport(t *testing.T) {
	result := DiffResult{
		FixedVulnerabilities: []models.Finding{vulnA},
		NewComponents:        []models.Component{compB, compC},
		BaseComponentCount:   10,
		HeadComponentCount:   12,
		BaseVulnCount:        3,
		HeadVulnCount:        2,
	}

	var buf bytes.Buffer
	if err := WriteDiffReport(context.Background(), &buf, result); err != nil {
		t.Fatal(err)
	}

	out := buf.String()
	if !strings.Contains(out, "Scan Diff Summary") {
		t.Error("missing header")
	}
	if !strings.Contains(out, "CVE-2024-1234") {
		t.Error("missing fixed vuln")
	}
	if !strings.Contains(out, "axios@1.6.0") {
		t.Error("missing new component")
	}
	if !strings.Contains(out, "10 -> 12") {
		t.Error("missing component count transition")
	}
}

func TestWriteDiffJSON(t *testing.T) {
	result := DiffResult{
		NewVulnerabilities: []models.Finding{vulnB},
		BaseVulnCount:      0,
		HeadVulnCount:      1,
	}

	var buf bytes.Buffer
	if err := WriteDiffJSON(context.Background(), &buf, result); err != nil {
		t.Fatal(err)
	}

	var parsed DiffResult
	if err := json.Unmarshal(buf.Bytes(), &parsed); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}
	if len(parsed.NewVulnerabilities) != 1 {
		t.Errorf("expected 1 new vuln in JSON, got %d", len(parsed.NewVulnerabilities))
	}
}

func TestWriteDiffMarkdown(t *testing.T) {
	result := DiffResult{
		NewVulnerabilities:   []models.Finding{vulnB},
		FixedVulnerabilities: []models.Finding{vulnA},
		NewComponents:        []models.Component{compC},
		RemovedComponents:    []models.Component{compB},
		BaseComponentCount:   5,
		HeadComponentCount:   5,
		BaseVulnCount:        1,
		HeadVulnCount:        1,
	}

	var buf bytes.Buffer
	if err := WriteDiffMarkdown(context.Background(), &buf, result); err != nil {
		t.Fatal(err)
	}

	out := buf.String()
	if !strings.Contains(out, "## Scan Diff Summary") {
		t.Error("missing markdown header")
	}
	if !strings.Contains(out, "**CRITICAL**") {
		t.Error("missing severity bold")
	}
	if !strings.Contains(out, "`helmet@7.1.0`") {
		t.Error("missing new component in markdown")
	}
}
