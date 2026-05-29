package evidence

import (
	"archive/zip"
	"bytes"
	"context"
	"encoding/json"
	"regexp"
	"testing"
	"time"

	"github.com/chainsaw-dev/chainsaw/pkg/models"
)

func TestGenerateBundle_creates_valid_zip(t *testing.T) {
	cfg := BundleConfig{
		ProductName: "TestProduct",
		ToolVersion: "1.0.0",
		ScanResult: models.ScanResult{
			Components: []models.Component{
				{
					Name:      "test-pkg",
					Version:   "1.0.0",
					Ecosystem: models.EcosystemGo,
				},
			},
			Findings:    []models.Finding{},
			Hygiene:     []models.Finding{},
			Timestamp:   time.Now(),
			ToolVersion: "1.0.0",
		},
		CRAResult: models.CRAResult{
			ProductName:  "TestProduct",
			OverallScore: 85,
			Checks:       []models.CRACheck{},
		},
		SupplyChain: models.SupplyChainResult{
			Components:   []models.InfraComponent{},
			PinningScore: 80,
			BlastRadii:   []models.BlastRadius{},
		},
		SBOMData: []byte(`{"format":"CycloneDX","version":"1.5"}`),
	}

	buf := &bytes.Buffer{}
	err := GenerateBundle(context.Background(), buf, cfg)
	if err != nil {
		t.Fatalf("GenerateBundle failed: %v", err)
	}

	// Open as zip
	zr, err := zip.NewReader(bytes.NewReader(buf.Bytes()), int64(buf.Len()))
	if err != nil {
		t.Fatalf("Failed to open generated zip: %v", err)
	}

	// Verify 5 files exist
	expectedFiles := map[string]bool{
		"scan-results.json":   false,
		"cra-assessment.json": false,
		"supply-chain.json":   false,
		"sbom-cyclonedx.json": false,
		"manifest.json":       false,
	}

	for _, f := range zr.File {
		if _, ok := expectedFiles[f.Name]; ok {
			expectedFiles[f.Name] = true
		}
	}

	for file, found := range expectedFiles {
		if !found {
			t.Errorf("Expected file %q not found in zip", file)
		}
	}
}

func TestGenerateBundle_manifest_has_sha256(t *testing.T) {
	cfg := BundleConfig{
		ProductName: "TestProduct",
		ToolVersion: "1.0.0",
		ScanResult: models.ScanResult{
			Components:  []models.Component{},
			Findings:    []models.Finding{},
			Hygiene:     []models.Finding{},
			Timestamp:   time.Now(),
			ToolVersion: "1.0.0",
		},
		CRAResult: models.CRAResult{
			ProductName: "TestProduct",
			Checks:      []models.CRACheck{},
		},
		SupplyChain: models.SupplyChainResult{
			Components: []models.InfraComponent{},
			BlastRadii: []models.BlastRadius{},
			Timestamp:  time.Now(),
		},
		SBOMData: []byte(`{}`),
	}

	buf := &bytes.Buffer{}
	err := GenerateBundle(context.Background(), buf, cfg)
	if err != nil {
		t.Fatalf("GenerateBundle failed: %v", err)
	}

	// Parse manifest
	zr, err := zip.NewReader(bytes.NewReader(buf.Bytes()), int64(buf.Len()))
	if err != nil {
		t.Fatalf("Failed to open zip: %v", err)
	}

	var manifestFile *zip.File
	for _, f := range zr.File {
		if f.Name == "manifest.json" {
			manifestFile = f
			break
		}
	}
	if manifestFile == nil {
		t.Fatal("manifest.json not found")
	}

	rc, err := manifestFile.Open()
	if err != nil {
		t.Fatalf("Failed to open manifest: %v", err)
	}
	defer rc.Close()

	var manifest Manifest
	if err := json.NewDecoder(rc).Decode(&manifest); err != nil {
		t.Fatalf("Failed to decode manifest: %v", err)
	}

	// SHA-256 hashes are 64 hex characters
	hexRegex := regexp.MustCompile(`^[a-f0-9]{64}$`)
	for filename, hash := range manifest.Files {
		if !hexRegex.MatchString(hash) {
			t.Errorf("File %q has invalid SHA-256 hash: %q", filename, hash)
		}
	}
}

func TestGenerateBundle_no_sbom(t *testing.T) {
	cfg := BundleConfig{
		ProductName: "TestProduct",
		ToolVersion: "1.0.0",
		ScanResult: models.ScanResult{
			Components:  []models.Component{},
			Findings:    []models.Finding{},
			Hygiene:     []models.Finding{},
			Timestamp:   time.Now(),
			ToolVersion: "1.0.0",
		},
		CRAResult: models.CRAResult{
			ProductName: "TestProduct",
			Checks:      []models.CRACheck{},
		},
		SupplyChain: models.SupplyChainResult{
			Components: []models.InfraComponent{},
			BlastRadii: []models.BlastRadius{},
			Timestamp:  time.Now(),
		},
		// No SBOMData
	}

	buf := &bytes.Buffer{}
	err := GenerateBundle(context.Background(), buf, cfg)
	if err != nil {
		t.Fatalf("GenerateBundle failed: %v", err)
	}

	// Open as zip
	zr, err := zip.NewReader(bytes.NewReader(buf.Bytes()), int64(buf.Len()))
	if err != nil {
		t.Fatalf("Failed to open zip: %v", err)
	}

	// Count files, should be 4 (no SBOM)
	if len(zr.File) != 4 {
		t.Errorf("Expected 4 files (no SBOM), got %d", len(zr.File))
	}

	// Verify SBOM is not present
	for _, f := range zr.File {
		if f.Name == "sbom-cyclonedx.json" {
			t.Error("SBOM file should not be present when SBOMData is empty")
		}
	}
}

func TestGenerateBundle_json_valid(t *testing.T) {
	cfg := BundleConfig{
		ProductName: "TestProduct",
		ToolVersion: "1.0.0",
		ScanResult: models.ScanResult{
			Components: []models.Component{
				{
					Name:      "pkg1",
					Version:   "1.0.0",
					Ecosystem: models.EcosystemGo,
				},
			},
			Findings: []models.Finding{
				{
					ID:       "CVE-2021-1234",
					Summary:  "Test CVE",
					Severity: models.SeverityHigh,
					Component: models.Component{
						Name:      "pkg1",
						Version:   "1.0.0",
						Ecosystem: models.EcosystemGo,
					},
				},
			},
			Hygiene:     []models.Finding{},
			Timestamp:   time.Now(),
			ToolVersion: "1.0.0",
		},
		CRAResult: models.CRAResult{
			ProductName:  "TestProduct",
			OverallScore: 75,
			Checks: []models.CRACheck{
				{
					ID:     "CRA-1",
					Title:  "Vulnerabilities",
					Status: models.CRAPass,
				},
			},
		},
		SupplyChain: models.SupplyChainResult{
			Components:   []models.InfraComponent{},
			PinningScore: 90,
			BlastRadii:   []models.BlastRadius{},
			Timestamp:    time.Now(),
		},
		SBOMData: []byte(`{}`),
	}

	buf := &bytes.Buffer{}
	err := GenerateBundle(context.Background(), buf, cfg)
	if err != nil {
		t.Fatalf("GenerateBundle failed: %v", err)
	}

	// Open and validate each JSON file
	zr, err := zip.NewReader(bytes.NewReader(buf.Bytes()), int64(buf.Len()))
	if err != nil {
		t.Fatalf("Failed to open zip: %v", err)
	}

	jsonFiles := []string{
		"scan-results.json",
		"cra-assessment.json",
		"supply-chain.json",
		"manifest.json",
	}

	for _, expectedName := range jsonFiles {
		found := false
		for _, f := range zr.File {
			if f.Name == expectedName {
				found = true
				rc, err := f.Open()
				if err != nil {
					t.Fatalf("Failed to open %q: %v", f.Name, err)
				}
				defer rc.Close()

				var obj interface{}
				if err := json.NewDecoder(rc).Decode(&obj); err != nil {
					t.Errorf("File %q contains invalid JSON: %v", f.Name, err)
				}
				break
			}
		}
		if !found {
			t.Errorf("Expected JSON file %q not found in zip", expectedName)
		}
	}
}
