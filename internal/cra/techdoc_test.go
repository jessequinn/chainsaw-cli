package cra

import (
	"bytes"
	"strings"
	"testing"

	"github.com/chainsaw-dev/chainsaw/pkg/models"
)

func TestWriteTechDoc_contains_all_sections(t *testing.T) {
	cfg := TechDocConfig{
		ProductName:    "TestProduct",
		Manufacturer:   "TestCorp",
		ProductVersion: "1.0.0",
		Category:       "default",
		SupportEndDate: "2030-12-31",
		Components:     []models.Component{},
		CRAResult: models.CRAResult{
			OverallScore: 75,
			Checks:       []models.CRACheck{},
		},
	}

	var buf bytes.Buffer
	err := WriteTechDoc(&buf, cfg)
	if err != nil {
		t.Fatalf("WriteTechDoc failed: %v", err)
	}

	output := buf.String()
	expectedSections := []string{
		"1. General Description of the Product",
		"2. Design and Development Process",
		"3. Software Bill of Materials (SBOM)",
		"4. Vulnerability Assessment",
		"5. Security Update Mechanism",
		"6. Vulnerability Handling Process",
		"7. Support Period",
		"8. Conformity Assessment",
	}

	for _, section := range expectedSections {
		if !strings.Contains(output, section) {
			t.Errorf("expected section %q not found in output", section)
		}
	}
}

func TestWriteTechDoc_contains_product_info(t *testing.T) {
	cfg := TechDocConfig{
		ProductName:    "MyProduct",
		Manufacturer:   "MyCorp",
		ProductVersion: "2.1.3",
		Category:       "important-class-1",
		SupportEndDate: "2029-06-15",
		Components:     []models.Component{},
		CRAResult: models.CRAResult{
			OverallScore: 80,
			Checks:       []models.CRACheck{},
		},
	}

	var buf bytes.Buffer
	err := WriteTechDoc(&buf, cfg)
	if err != nil {
		t.Fatalf("WriteTechDoc failed: %v", err)
	}

	output := buf.String()

	tests := []string{
		"MyProduct",
		"MyCorp",
		"2.1.3",
		"important-class-1",
		"2029-06-15",
	}

	for _, expected := range tests {
		if !strings.Contains(output, expected) {
			t.Errorf("expected value %q not found in output", expected)
		}
	}
}

func TestWriteTechDoc_component_count(t *testing.T) {
	components := []models.Component{
		{Name: "lib1", Version: "1.0"},
		{Name: "lib2", Version: "2.0"},
		{Name: "lib3", Version: "3.0"},
		{Name: "lib4", Version: "4.0"},
		{Name: "lib5", Version: "5.0"},
	}

	cfg := TechDocConfig{
		ProductName:    "TestProduct",
		Manufacturer:   "TestCorp",
		ProductVersion: "1.0.0",
		Category:       "default",
		SupportEndDate: "2030-12-31",
		Components:     components,
		CRAResult: models.CRAResult{
			OverallScore: 75,
			Checks:       []models.CRACheck{},
		},
	}

	var buf bytes.Buffer
	err := WriteTechDoc(&buf, cfg)
	if err != nil {
		t.Fatalf("WriteTechDoc failed: %v", err)
	}

	output := buf.String()
	expectedCount := "**Total components:** 5"

	if !strings.Contains(output, expectedCount) {
		t.Errorf("expected %q in output, got: %s", expectedCount, output)
	}
}

func TestWriteTechDoc_conformity_default(t *testing.T) {
	cfg := TechDocConfig{
		ProductName:    "TestProduct",
		Manufacturer:   "TestCorp",
		ProductVersion: "1.0.0",
		Category:       "default",
		SupportEndDate: "2030-12-31",
		Components:     []models.Component{},
		CRAResult: models.CRAResult{
			OverallScore: 75,
			Checks:       []models.CRACheck{},
		},
	}

	var buf bytes.Buffer
	err := WriteTechDoc(&buf, cfg)
	if err != nil {
		t.Fatalf("WriteTechDoc failed: %v", err)
	}

	output := buf.String()

	if !strings.Contains(output, "self-assessment") {
		t.Errorf("expected 'self-assessment' in output for default category")
	}
	if !strings.Contains(output, "Module A") {
		t.Errorf("expected 'Module A' in output for default category")
	}
}

func TestWriteTechDoc_conformity_critical(t *testing.T) {
	cfg := TechDocConfig{
		ProductName:    "TestProduct",
		Manufacturer:   "TestCorp",
		ProductVersion: "1.0.0",
		Category:       "critical",
		SupportEndDate: "2030-12-31",
		Components:     []models.Component{},
		CRAResult: models.CRAResult{
			OverallScore: 75,
			Checks:       []models.CRACheck{},
		},
	}

	var buf bytes.Buffer
	err := WriteTechDoc(&buf, cfg)
	if err != nil {
		t.Fatalf("WriteTechDoc failed: %v", err)
	}

	output := buf.String()

	if !strings.Contains(output, "Notified Body") {
		t.Errorf("expected 'Notified Body' in output for critical category")
	}
	if !strings.Contains(output, "Third-party conformity assessment") {
		t.Errorf("expected 'Third-party conformity assessment' in output for critical category")
	}
}

func TestWriteTechDoc_contains_header(t *testing.T) {
	cfg := TechDocConfig{
		ProductName:    "TestProduct",
		Manufacturer:   "TestCorp",
		ProductVersion: "1.0.0",
		Category:       "default",
		SupportEndDate: "2030-12-31",
		Components:     []models.Component{},
		CRAResult: models.CRAResult{
			OverallScore: 75,
			Checks:       []models.CRACheck{},
		},
	}

	var buf bytes.Buffer
	err := WriteTechDoc(&buf, cfg)
	if err != nil {
		t.Fatalf("WriteTechDoc failed: %v", err)
	}

	output := buf.String()

	if !strings.Contains(output, "# Technical Documentation — TestProduct") {
		t.Errorf("expected main header not found")
	}

	if !strings.Contains(output, "CRA Article 10(2) Technical Documentation") {
		t.Errorf("expected CRA reference not found")
	}

	if !strings.Contains(output, "Generated:") {
		t.Errorf("expected generated date not found")
	}
}

func TestWriteTechDoc_vuln_assessment_scores(t *testing.T) {
	checks := []models.CRACheck{
		{Status: models.CRAPass, Title: "Check1"},
		{Status: models.CRAPass, Title: "Check2"},
		{Status: models.CRAFail, Title: "Check3"},
		{Status: models.CRAWarn, Title: "Check4"},
		{Status: models.CRAWarn, Title: "Check5"},
	}

	cfg := TechDocConfig{
		ProductName:    "TestProduct",
		Manufacturer:   "TestCorp",
		ProductVersion: "1.0.0",
		Category:       "default",
		SupportEndDate: "2030-12-31",
		Components:     []models.Component{},
		CRAResult: models.CRAResult{
			OverallScore: 65,
			Checks:       checks,
		},
	}

	var buf bytes.Buffer
	err := WriteTechDoc(&buf, cfg)
	if err != nil {
		t.Fatalf("WriteTechDoc failed: %v", err)
	}

	output := buf.String()

	// Verify score appears
	if !strings.Contains(output, "65/100") {
		t.Errorf("expected CRA score '65/100' in output")
	}

	// Verify check counts: 2 passed, 1 failed, 2 warnings
	if !strings.Contains(output, "2 passed, 1 failed, 2 warnings") {
		t.Errorf("expected check count summary in output")
	}
}

func TestWriteTechDoc_important_class_1_category(t *testing.T) {
	cfg := TechDocConfig{
		ProductName:    "TestProduct",
		Manufacturer:   "TestCorp",
		ProductVersion: "1.0.0",
		Category:       "important-class-1",
		SupportEndDate: "2030-12-31",
		Components:     []models.Component{},
		CRAResult: models.CRAResult{
			OverallScore: 75,
			Checks:       []models.CRACheck{},
		},
	}

	var buf bytes.Buffer
	err := WriteTechDoc(&buf, cfg)
	if err != nil {
		t.Fatalf("WriteTechDoc failed: %v", err)
	}

	output := buf.String()

	if !strings.Contains(output, "Module A") || !strings.Contains(output, "Module B + C") {
		t.Errorf("expected Module A or B+C options for important-class-1")
	}
	if !strings.Contains(output, "harmonised standards") {
		t.Errorf("expected harmonised standards reference")
	}
}

func TestWriteTechDoc_important_class_2_category(t *testing.T) {
	cfg := TechDocConfig{
		ProductName:    "TestProduct",
		Manufacturer:   "TestCorp",
		ProductVersion: "1.0.0",
		Category:       "important-class-2",
		SupportEndDate: "2030-12-31",
		Components:     []models.Component{},
		CRAResult: models.CRAResult{
			OverallScore: 75,
			Checks:       []models.CRACheck{},
		},
	}

	var buf bytes.Buffer
	err := WriteTechDoc(&buf, cfg)
	if err != nil {
		t.Fatalf("WriteTechDoc failed: %v", err)
	}

	output := buf.String()

	if !strings.Contains(output, "EU-type examination by Notified Body") {
		t.Errorf("expected EU-type examination reference for important-class-2")
	}
	if !strings.Contains(output, "Module H") {
		t.Errorf("expected Module H reference for important-class-2")
	}
}
