package schema

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
)

// Schema represents a JSON Schema v7 document.
type Schema struct {
	Schema      string                `json:"$schema"`
	Title       string                `json:"title"`
	Description string                `json:"description"`
	Type        string                `json:"type"`
	Properties  map[string]Property   `json:"properties"`
	Required    []string              `json:"required,omitempty"`
}

// Property describes a single field in a JSON schema.
type Property struct {
	Type        string              `json:"type,omitempty"`
	Description string              `json:"description,omitempty"`
	Items       *Property           `json:"items,omitempty"`
	Properties  map[string]Property `json:"properties,omitempty"`
	Enum        []string            `json:"enum,omitempty"`
	Format      string              `json:"format,omitempty"`
}

// ScanResultSchema returns the JSON schema for ScanResult output.
func ScanResultSchema() Schema {
	return Schema{
		Schema:      "http://json-schema.org/draft-07/schema#",
		Title:       "Chainsaw Scan Result",
		Description: "Output schema for chainsaw scan --format json",
		Type:        "object",
		Properties: map[string]Property{
			"components": {Type: "array", Description: "Discovered components", Items: &Property{Type: "object"}},
			"findings":   {Type: "array", Description: "Vulnerability findings", Items: &Property{Type: "object"}},
			"hygiene":    {Type: "array", Description: "Hygiene findings", Items: &Property{Type: "object"}},
		},
		Required: []string{"components", "findings"},
	}
}

// CRAResultSchema returns the JSON schema for CRA comply output.
func CRAResultSchema() Schema {
	return Schema{
		Schema:      "http://json-schema.org/draft-07/schema#",
		Title:       "Chainsaw CRA Result",
		Description: "Output schema for chainsaw comply --format json",
		Type:        "object",
		Properties: map[string]Property{
			"overall_score": {Type: "integer", Description: "CRA compliance score (0-100)"},
			"date":          {Type: "string", Description: "Assessment date", Format: "date"},
			"checks":        {Type: "array", Description: "Individual CRA check results", Items: &Property{Type: "object"}},
		},
		Required: []string{"overall_score", "checks"},
	}
}

// SupplyChainResultSchema returns the JSON schema for supply chain output.
func SupplyChainResultSchema() Schema {
	return Schema{
		Schema:      "http://json-schema.org/draft-07/schema#",
		Title:       "Chainsaw Supply Chain Result",
		Description: "Output schema for chainsaw supply-chain --format json",
		Type:        "object",
		Properties: map[string]Property{
			"pinning_score": {Type: "integer", Description: "Dependency pinning score (0-100)"},
			"findings":      {Type: "array", Description: "Supply chain findings", Items: &Property{Type: "object"}},
		},
		Required: []string{"pinning_score"},
	}
}

// PolicySchema returns the JSON schema for .chainsaw.yaml policy file.
func PolicySchema() Schema {
	return Schema{
		Schema:      "http://json-schema.org/draft-07/schema#",
		Title:       "Chainsaw Policy",
		Description: "Schema for .chainsaw.yaml configuration",
		Type:        "object",
		Properties: map[string]Property{
			"policy": {
				Type:        "object",
				Description: "Core policy settings",
				Properties: map[string]Property{
					"fail-on": {Type: "string", Description: "Minimum severity to fail", Enum: []string{"CRITICAL", "HIGH", "MEDIUM", "LOW", "NONE"}},
					"ignore":  {Type: "array", Description: "CVE IDs or ignore rules to suppress", Items: &Property{Type: "object"}},
				},
			},
			"cra": {
				Type:        "object",
				Description: "CRA compliance settings",
				Properties: map[string]Property{
					"required-score":   {Type: "integer", Description: "Minimum CRA compliance score (0-100)"},
					"manufacturer":     {Type: "string", Description: "Manufacturer name"},
					"security-contact": {Type: "string", Description: "Security contact email"},
					"support-end-date": {Type: "string", Description: "Product support end date", Format: "date"},
					"csirt-contact":    {Type: "string", Description: "CSIRT notification contact"},
				},
			},
			"supply-chain": {
				Type:        "object",
				Description: "Supply chain policy",
				Properties: map[string]Property{
					"min-pinning-score": {Type: "integer", Description: "Minimum pinning score (0-100)"},
					"require-sha-pins":  {Type: "boolean", Description: "Require SHA-based pins"},
				},
			},
		},
	}
}

// WriteSchema writes a schema as indented JSON to the writer.
func WriteSchema(w io.Writer, s Schema) error {
	encoder := json.NewEncoder(w)
	encoder.SetIndent("", "  ")
	return encoder.Encode(s)
}

// AllSchemas returns all available schemas by name.
func AllSchemas() map[string]Schema {
	return map[string]Schema{
		"scan-result":         ScanResultSchema(),
		"cra-result":          CRAResultSchema(),
		"supply-chain-result": SupplyChainResultSchema(),
		"policy":              PolicySchema(),
	}
}

// WriteAllSchemas writes all schemas to the given directory.
func WriteAllSchemas(dir string) ([]string, error) {
	schemas := AllSchemas()
	var written []string

	for name, s := range schemas {
		path := fmt.Sprintf("%s/%s.schema.json", dir, name)
		f, err := createFile(path)
		if err != nil {
			return written, err
		}
		if err := WriteSchema(f, s); err != nil {
			f.Close()
			return written, err
		}
		f.Close()
		written = append(written, path)
	}
	return written, nil
}

func createFile(path string) (*os.File, error) {
	return os.Create(path)
}
