package scanner

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/chainsaw-dev/chainsaw/pkg/models"
)

// TerraformScanner implements Scanner for Terraform lockfiles.
type TerraformScanner struct{}

func init() {
	Register(&TerraformScanner{})
}

func (t *TerraformScanner) Ecosystem() models.Ecosystem {
	return models.EcosystemTerraform
}

// DetectManifests walks root and returns paths to .terraform.lock.hcl files,
// skipping .terraform/ directories.
func (t *TerraformScanner) DetectManifests(ctx context.Context, root string) ([]string, error) {
	var manifests []string
	err := filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() && info.Name() == ".terraform" {
			return filepath.SkipDir
		}
		if !info.IsDir() && info.Name() == ".terraform.lock.hcl" {
			manifests = append(manifests, path)
		}
		return nil
	})
	return manifests, err
}

var (
	providerRe = regexp.MustCompile(`provider\s+"registry\.terraform\.io/([^"]+)"\s*\{`)
	versionRe  = regexp.MustCompile(`version\s*=\s*"([^"]+)"`)
	zhHashRe   = regexp.MustCompile(`"(zh:[^"]+)"`)
)

// ParseDependencies parses a .terraform.lock.hcl file using regex and
// returns components for each provider block.
func (t *TerraformScanner) ParseDependencies(ctx context.Context, manifestPath string) ([]models.Component, error) {
	data, err := os.ReadFile(manifestPath)
	if err != nil {
		return nil, fmt.Errorf("reading %s: %w", manifestPath, err)
	}

	content := string(data)
	var components []models.Component

	// Find all provider blocks
	providerMatches := providerRe.FindAllStringSubmatchIndex(content, -1)
	for i, loc := range providerMatches {
		source := content[loc[2]:loc[3]] // captured group: e.g. "hashicorp/aws"

		// Determine the block extent: from opening { to next provider or EOF
		blockStart := loc[1]
		blockEnd := len(content)
		if i+1 < len(providerMatches) {
			blockEnd = providerMatches[i+1][0]
		}
		block := content[blockStart:blockEnd]

		// Extract version
		version := ""
		if m := versionRe.FindStringSubmatch(block); len(m) > 1 {
			version = m[1]
		}

		// Extract first zh: hash
		hash := ""
		if m := zhHashRe.FindStringSubmatch(block); len(m) > 1 {
			hash = m[1]
		}

		// Build purl
		parts := strings.SplitN(source, "/", 2)
		purl := fmt.Sprintf("pkg:terraform/%s/%s@%s", parts[0], parts[1], version)

		components = append(components, models.Component{
			Name:      source,
			Version:   version,
			Ecosystem: models.EcosystemTerraform,
			Hash:      hash,
			PkgURL:    purl,
			Direct:    false,
		})
	}

	return components, nil
}
