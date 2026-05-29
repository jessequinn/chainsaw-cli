package schema

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestScanResultSchema_valid_json(t *testing.T) {
	s := ScanResultSchema()
	data, err := json.Marshal(s)
	if err != nil {
		t.Fatalf("Failed to marshal ScanResultSchema: %v", err)
	}

	// Verify it's valid JSON by unmarshaling back
	var result map[string]interface{}
	if err := json.Unmarshal(data, &result); err != nil {
		t.Fatalf("Invalid JSON generated: %v", err)
	}

	// Verify $schema field exists
	if _, ok := result["$schema"]; !ok {
		t.Error("Missing $schema field")
	}
}

func TestCRAResultSchema_has_required_fields(t *testing.T) {
	s := CRAResultSchema()

	// Verify Required contains "overall_score" and "checks"
	hasOverallScore := false
	hasChecks := false
	for _, req := range s.Required {
		if req == "overall_score" {
			hasOverallScore = true
		}
		if req == "checks" {
			hasChecks = true
		}
	}

	if !hasOverallScore {
		t.Error("CRAResultSchema missing 'overall_score' in Required")
	}
	if !hasChecks {
		t.Error("CRAResultSchema missing 'checks' in Required")
	}
}

func TestPolicySchema_has_cra_section(t *testing.T) {
	s := PolicySchema()

	// Verify "cra" property exists
	if _, ok := s.Properties["cra"]; !ok {
		t.Error("PolicySchema missing 'cra' property")
	}

	// Verify it has sub-properties
	craProp := s.Properties["cra"]
	if craProp.Type != "object" {
		t.Errorf("cra property type should be 'object', got %q", craProp.Type)
	}
	if len(craProp.Properties) == 0 {
		t.Error("cra property has no sub-properties")
	}
}

func TestAllSchemas_returns_four(t *testing.T) {
	schemas := AllSchemas()

	if len(schemas) != 4 {
		t.Errorf("Expected 4 schemas, got %d", len(schemas))
	}

	expected := []string{"scan-result", "cra-result", "supply-chain-result", "policy"}
	for _, key := range expected {
		if _, ok := schemas[key]; !ok {
			t.Errorf("Missing schema: %s", key)
		}
	}
}

func TestWriteAllSchemas_creates_files(t *testing.T) {
	tmpDir := t.TempDir()

	written, err := WriteAllSchemas(tmpDir)
	if err != nil {
		t.Fatalf("WriteAllSchemas failed: %v", err)
	}

	if len(written) != 4 {
		t.Errorf("Expected 4 files written, got %d", len(written))
	}

	// Verify files exist
	for _, path := range written {
		if _, err := os.Stat(path); err != nil {
			t.Errorf("File not created: %s", path)
		}

		// Verify each file contains valid JSON
		data, err := os.ReadFile(path)
		if err != nil {
			t.Errorf("Could not read file %s: %v", path, err)
			continue
		}

		var s Schema
		if err := json.Unmarshal(data, &s); err != nil {
			t.Errorf("Invalid JSON in %s: %v", path, err)
		}
	}
}

func TestWriteSchema_valid_json(t *testing.T) {
	tmpFile := filepath.Join(t.TempDir(), "test.schema.json")
	f, err := os.Create(tmpFile)
	if err != nil {
		t.Fatalf("Failed to create temp file: %v", err)
	}
	defer f.Close()

	s := ScanResultSchema()
	if err := WriteSchema(f, s); err != nil {
		t.Fatalf("WriteSchema failed: %v", err)
	}
	f.Close()

	// Verify it's valid JSON
	data, err := os.ReadFile(tmpFile)
	if err != nil {
		t.Fatalf("Could not read temp file: %v", err)
	}

	var result map[string]interface{}
	if err := json.Unmarshal(data, &result); err != nil {
		t.Fatalf("Invalid JSON written: %v", err)
	}

	// Verify $schema field
	if schema, ok := result["$schema"]; !ok {
		t.Error("Missing $schema field in output")
	} else if schema != "http://json-schema.org/draft-07/schema#" {
		t.Errorf("Incorrect $schema value: %v", schema)
	}
}

func TestSupplyChainResultSchema_valid(t *testing.T) {
	s := SupplyChainResultSchema()

	if s.Type != "object" {
		t.Errorf("Expected type 'object', got %q", s.Type)
	}

	if _, ok := s.Properties["pinning_score"]; !ok {
		t.Error("Missing pinning_score property")
	}

	if _, ok := s.Properties["findings"]; !ok {
		t.Error("Missing findings property")
	}

	// Verify Required
	if len(s.Required) != 1 || s.Required[0] != "pinning_score" {
		t.Errorf("Expected Required=[pinning_score], got %v", s.Required)
	}
}
