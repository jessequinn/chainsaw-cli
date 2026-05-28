package scanner

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/chainsaw-dev/chainsaw/pkg/models"
	"gopkg.in/yaml.v3"
)

// AnsibleScanner implements Scanner for Ansible Galaxy requirements files.
type AnsibleScanner struct{}

func init() {
	Register(&AnsibleScanner{})
}

func (a *AnsibleScanner) Ecosystem() models.Ecosystem {
	return models.EcosystemAnsible
}

// DetectManifests walks root and returns paths to Ansible requirements.yml
// files, skipping .ansible/ and molecule/ directories.
func (a *AnsibleScanner) DetectManifests(root string) ([]string, error) {
	var manifests []string
	err := filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() {
			switch info.Name() {
			case ".ansible", "molecule":
				return filepath.SkipDir
			}
			return nil
		}
		if info.Name() == "requirements.yml" {
			manifests = append(manifests, path)
		}
		return nil
	})
	return manifests, err
}

// ansibleRequirements is the structure of an Ansible requirements.yml.
type ansibleRequirements struct {
	Collections []ansibleEntry `yaml:"collections"`
	Roles       []ansibleEntry `yaml:"roles"`
}

type ansibleEntry struct {
	Name    string `yaml:"name"`
	Version string `yaml:"version"`
}

// ParseDependencies parses an Ansible requirements.yml and returns
// components for each collection and role.
func (a *AnsibleScanner) ParseDependencies(manifestPath string) ([]models.Component, error) {
	data, err := os.ReadFile(manifestPath)
	if err != nil {
		return nil, fmt.Errorf("reading %s: %w", manifestPath, err)
	}

	var reqs ansibleRequirements
	if err := yaml.Unmarshal(data, &reqs); err != nil {
		return nil, fmt.Errorf("parsing %s: %w", manifestPath, err)
	}

	var components []models.Component

	for _, entries := range [][]ansibleEntry{reqs.Collections, reqs.Roles} {
		for _, entry := range entries {
			if entry.Name == "" {
				continue
			}
			// Skip URL-based references
			if strings.HasPrefix(entry.Name, "http") || strings.HasPrefix(entry.Name, "git") {
				continue
			}

			version := entry.Version
			if version == "" {
				version = "unspecified"
			}

			purl := fmt.Sprintf("pkg:ansible/%s@%s", entry.Name, version)

			components = append(components, models.Component{
				Name:      entry.Name,
				Version:   version,
				Ecosystem: models.EcosystemAnsible,
				PkgURL:    purl,
			})
		}
	}

	return components, nil
}
