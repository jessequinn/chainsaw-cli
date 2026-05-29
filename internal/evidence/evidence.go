package evidence

import (
	"archive/zip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"time"

	"github.com/chainsaw-dev/chainsaw/pkg/models"
)

// Manifest describes the contents of an evidence archive.
type Manifest struct {
	Version     string            `json:"version"`
	Tool        string            `json:"tool"`
	ToolVersion string            `json:"tool_version"`
	Product     string            `json:"product"`
	Date        time.Time         `json:"assessment_date"`
	Files       map[string]string `json:"files"` // filename -> SHA-256
}

// BundleConfig holds inputs for evidence generation.
type BundleConfig struct {
	ProductName string
	ToolVersion string
	ScanResult  models.ScanResult
	CRAResult   models.CRAResult
	SupplyChain models.SupplyChainResult
	SBOMData    []byte // pre-rendered CycloneDX JSON
}

// GenerateBundle writes a ZIP archive containing all evidence files
// plus a manifest with SHA-256 checksums.
func GenerateBundle(_ context.Context, w io.Writer, cfg BundleConfig) error {
	zw := zip.NewWriter(w)
	defer zw.Close()

	manifest := Manifest{
		Version:     "1.0",
		Tool:        "chainsaw",
		ToolVersion: cfg.ToolVersion,
		Product:     cfg.ProductName,
		Date:        time.Now(),
		Files:       make(map[string]string),
	}

	// Write scan results
	if err := addJSON(zw, &manifest, "scan-results.json", cfg.ScanResult); err != nil {
		return fmt.Errorf("writing scan results: %w", err)
	}

	// Write CRA assessment
	if err := addJSON(zw, &manifest, "cra-assessment.json", cfg.CRAResult); err != nil {
		return fmt.Errorf("writing CRA assessment: %w", err)
	}

	// Write supply chain analysis
	if err := addJSON(zw, &manifest, "supply-chain.json", cfg.SupplyChain); err != nil {
		return fmt.Errorf("writing supply chain: %w", err)
	}

	// Write SBOM
	if len(cfg.SBOMData) > 0 {
		if err := addRaw(zw, &manifest, "sbom-cyclonedx.json", cfg.SBOMData); err != nil {
			return fmt.Errorf("writing SBOM: %w", err)
		}
	}

	// Write manifest last
	mdata, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		return fmt.Errorf("marshaling manifest: %w", err)
	}
	fw, err := zw.Create("manifest.json")
	if err != nil {
		return err
	}
	_, err = fw.Write(mdata)
	return err
}

func addJSON(zw *zip.Writer, m *Manifest, name string, v interface{}) error {
	data, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	return addRaw(zw, m, name, data)
}

func addRaw(zw *zip.Writer, m *Manifest, name string, data []byte) error {
	hash := sha256.Sum256(data)
	m.Files[name] = hex.EncodeToString(hash[:])

	fw, err := zw.Create(name)
	if err != nil {
		return err
	}
	_, err = fw.Write(data)
	return err
}
