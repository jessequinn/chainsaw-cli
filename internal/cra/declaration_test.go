package cra

import (
	"bytes"
	"strings"
	"testing"
	"time"

	"github.com/chainsaw-dev/chainsaw/pkg/models"
)

func TestWriteDeclaration_contains_sections(t *testing.T) {
	checks := []models.CRACheck{
		{ID: "test1", Title: "Test Check", Status: models.CRAPass},
	}
	result := models.CRAResult{
		ProductName:  "TestProduct",
		Version:      "1.0.0",
		Date:         time.Now(),
		OverallScore: 75,
		Checks:       checks,
	}
	cfg := DeclarationConfig{
		ProductName:    "TestProduct",
		Manufacturer:   "Test Manufacturer",
		ProductVersion: "1.0.0",
		Category:       "important-class-1",
		Address:        "123 Test St",
		CRAResult:      result,
	}

	var buf bytes.Buffer
	err := WriteDeclaration(&buf, cfg)
	if err != nil {
		t.Fatalf("WriteDeclaration error: %v", err)
	}

	out := buf.String()
	wantSections := []string{
		"# EU Declaration of Conformity",
		"## 1. Product Identification",
		"## 2. Manufacturer Information",
		"## 3. Object of the Declaration",
		"## 4. Applicable Legislation",
		"## 5. Standards Applied",
		"## 6. Essential Requirements Addressed",
		"## 7. Conformity Assessment Procedure",
		"## 8. Signature",
	}

	for _, want := range wantSections {
		if !strings.Contains(out, want) {
			t.Errorf("output missing section %q", want)
		}
	}
}

func TestWriteDeclaration_product_info(t *testing.T) {
	checks := []models.CRACheck{
		{ID: "test1", Title: "Test", Status: models.CRAPass},
	}
	result := models.CRAResult{
		ProductName:  "MyProduct",
		Version:      "2.3.4",
		Date:         time.Now(),
		OverallScore: 80,
		Checks:       checks,
	}
	cfg := DeclarationConfig{
		ProductName:    "MyProduct",
		Manufacturer:   "My Company",
		ProductVersion: "2.3.4",
		Category:       "default",
		Address:        "456 Main Ave",
		CRAResult:      result,
	}

	var buf bytes.Buffer
	err := WriteDeclaration(&buf, cfg)
	if err != nil {
		t.Fatalf("WriteDeclaration error: %v", err)
	}

	out := buf.String()
	for _, want := range []string{"MyProduct", "2.3.4", "My Company", "456 Main Ave"} {
		if !strings.Contains(out, want) {
			t.Errorf("output missing %q", want)
		}
	}
}

func TestWriteDeclaration_cra_score(t *testing.T) {
	checks := []models.CRACheck{
		{ID: "test1", Title: "Test", Status: models.CRAPass},
	}
	result := models.CRAResult{
		ProductName:  "TestProduct",
		Version:      "1.0.0",
		Date:         time.Now(),
		OverallScore: 75,
		Checks:       checks,
	}
	cfg := DeclarationConfig{
		ProductName:    "TestProduct",
		Manufacturer:   "Test Co",
		ProductVersion: "1.0.0",
		Category:       "default",
		Address:        "123 Test St",
		CRAResult:      result,
	}

	var buf bytes.Buffer
	err := WriteDeclaration(&buf, cfg)
	if err != nil {
		t.Fatalf("WriteDeclaration error: %v", err)
	}

	out := buf.String()
	if !strings.Contains(out, "75/100") {
		t.Errorf("output missing score '75/100'")
	}
}

func TestWriteDeclaration_conformity_default(t *testing.T) {
	checks := []models.CRACheck{
		{ID: "test1", Title: "Test", Status: models.CRAPass},
	}
	result := models.CRAResult{
		ProductName:  "TestProduct",
		Version:      "1.0.0",
		Date:         time.Now(),
		OverallScore: 75,
		Checks:       checks,
	}
	cfg := DeclarationConfig{
		ProductName:    "TestProduct",
		Manufacturer:   "Test Co",
		ProductVersion: "1.0.0",
		Category:       "default",
		Address:        "123 Test St",
		CRAResult:      result,
	}

	var buf bytes.Buffer
	err := WriteDeclaration(&buf, cfg)
	if err != nil {
		t.Fatalf("WriteDeclaration error: %v", err)
	}

	out := buf.String()
	if !strings.Contains(out, "self-assessment") {
		t.Errorf("output missing 'self-assessment' for default category")
	}
}

func TestWriteDeclaration_conformity_critical(t *testing.T) {
	checks := []models.CRACheck{
		{ID: "test1", Title: "Test", Status: models.CRAPass},
	}
	result := models.CRAResult{
		ProductName:  "TestProduct",
		Version:      "1.0.0",
		Date:         time.Now(),
		OverallScore: 75,
		Checks:       checks,
	}
	cfg := DeclarationConfig{
		ProductName:    "TestProduct",
		Manufacturer:   "Test Co",
		ProductVersion: "1.0.0",
		Category:       "critical",
		Address:        "123 Test St",
		CRAResult:      result,
	}

	var buf bytes.Buffer
	err := WriteDeclaration(&buf, cfg)
	if err != nil {
		t.Fatalf("WriteDeclaration error: %v", err)
	}

	out := buf.String()
	if !strings.Contains(out, "Notified Body") {
		t.Errorf("output missing 'Notified Body' for critical category")
	}
}

func TestWriteDeclaration_address_shown(t *testing.T) {
	checks := []models.CRACheck{
		{ID: "test1", Title: "Test", Status: models.CRAPass},
	}
	result := models.CRAResult{
		ProductName:  "TestProduct",
		Version:      "1.0.0",
		Date:         time.Now(),
		OverallScore: 75,
		Checks:       checks,
	}
	cfg := DeclarationConfig{
		ProductName:    "TestProduct",
		Manufacturer:   "Test Co",
		ProductVersion: "1.0.0",
		Category:       "default",
		Address:        "789 Oak Road, Berlin, Germany",
		CRAResult:      result,
	}

	var buf bytes.Buffer
	err := WriteDeclaration(&buf, cfg)
	if err != nil {
		t.Fatalf("WriteDeclaration error: %v", err)
	}

	out := buf.String()
	if !strings.Contains(out, "789 Oak Road, Berlin, Germany") {
		t.Errorf("output missing provided address")
	}
}

func TestWriteDeclaration_address_todo(t *testing.T) {
	checks := []models.CRACheck{
		{ID: "test1", Title: "Test", Status: models.CRAPass},
	}
	result := models.CRAResult{
		ProductName:  "TestProduct",
		Version:      "1.0.0",
		Date:         time.Now(),
		OverallScore: 75,
		Checks:       checks,
	}
	cfg := DeclarationConfig{
		ProductName:    "TestProduct",
		Manufacturer:   "Test Co",
		ProductVersion: "1.0.0",
		Category:       "default",
		Address:        "", // Empty address
		CRAResult:      result,
	}

	var buf bytes.Buffer
	err := WriteDeclaration(&buf, cfg)
	if err != nil {
		t.Fatalf("WriteDeclaration error: %v", err)
	}

	out := buf.String()
	if !strings.Contains(out, "[TODO: Add registered address]") {
		t.Errorf("output missing TODO marker for empty address")
	}
}

func TestWriteDeclaration_check_counts(t *testing.T) {
	checks := []models.CRACheck{
		{ID: "c1", Title: "Pass Check", Status: models.CRAPass},
		{ID: "c2", Title: "Fail Check", Status: models.CRAFail},
		{ID: "c3", Title: "Warn Check", Status: models.CRAWarn},
		{ID: "c4", Title: "Another Pass", Status: models.CRAPass},
	}
	result := models.CRAResult{
		ProductName:  "TestProduct",
		Version:      "1.0.0",
		Date:         time.Now(),
		OverallScore: 50,
		Checks:       checks,
	}
	cfg := DeclarationConfig{
		ProductName:    "TestProduct",
		Manufacturer:   "Test Co",
		ProductVersion: "1.0.0",
		Category:       "default",
		Address:        "123 Test St",
		CRAResult:      result,
	}

	var buf bytes.Buffer
	err := WriteDeclaration(&buf, cfg)
	if err != nil {
		t.Fatalf("WriteDeclaration error: %v", err)
	}

	out := buf.String()
	// Should show: 2 passed, 1 failed, 1 warning
	for _, want := range []string{"Requirements met | 2", "Requirements not met | 1", "Warnings | 1"} {
		if !strings.Contains(out, want) {
			t.Errorf("output missing %q", want)
		}
	}
}
