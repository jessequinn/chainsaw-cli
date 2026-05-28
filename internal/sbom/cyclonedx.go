package sbom

import (
	"encoding/json"
	"time"

	"github.com/chainsaw-dev/chainsaw/pkg/models"
)

type cdxHash struct {
	Algorithm string `json:"alg"`
	Content   string `json:"content"`
}

type cdxComponent struct {
	Type    string    `json:"type"`
	Name    string    `json:"name"`
	Version string    `json:"version"`
	Purl    string    `json:"purl,omitempty"`
	Hashes  []cdxHash `json:"hashes,omitempty"`
}

type cdxToolComponent struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}

type cdxTools struct {
	Components []cdxToolComponent `json:"components"`
}

type cdxMetadata struct {
	Timestamp string   `json:"timestamp"`
	Tools     cdxTools `json:"tools"`
}

type cdxBOM struct {
	BOMFormat   string         `json:"bomFormat"`
	SpecVersion string         `json:"specVersion"`
	Version     int            `json:"version"`
	Metadata    cdxMetadata    `json:"metadata"`
	Components  []cdxComponent `json:"components"`
}

// GenerateCycloneDX produces a CycloneDX 1.5 JSON SBOM from the given components.
func GenerateCycloneDX(components []models.Component, toolVersion string) ([]byte, error) {
	cdxComponents := make([]cdxComponent, 0, len(components))
	for _, c := range components {
		cc := cdxComponent{
			Type:    "library",
			Name:    c.Name,
			Version: c.Version,
			Purl:    c.PkgURL,
		}
		if c.Hash != "" {
			cc.Hashes = []cdxHash{
				{Algorithm: "SHA-256", Content: c.Hash},
			}
		}
		cdxComponents = append(cdxComponents, cc)
	}

	bom := cdxBOM{
		BOMFormat:   "CycloneDX",
		SpecVersion: "1.5",
		Version:     1,
		Metadata: cdxMetadata{
			Timestamp: time.Now().UTC().Format(time.RFC3339),
			Tools: cdxTools{
				Components: []cdxToolComponent{
					{Name: "chainsaw", Version: toolVersion},
				},
			},
		},
		Components: cdxComponents,
	}

	return json.MarshalIndent(bom, "", "  ")
}
