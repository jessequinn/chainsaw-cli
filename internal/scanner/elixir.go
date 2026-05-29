package scanner

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/chainsaw-dev/chainsaw/pkg/models"
)

// ElixirScanner implements Scanner for the Elixir/Hex ecosystem.
type ElixirScanner struct{}

func init() {
	Register(&ElixirScanner{})
}

func (e *ElixirScanner) Ecosystem() models.Ecosystem {
	return models.EcosystemHex
}

// DetectManifests walks root and returns paths to mix.lock files, skipping
// _build/, deps/, and .elixir_ls/ directories.
func (e *ElixirScanner) DetectManifests(ctx context.Context, root string) ([]string, error) {
	var manifests []string
	err := filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() {
			switch info.Name() {
			case "_build", "deps", ".elixir_ls":
				return filepath.SkipDir
			}
		}
		if !info.IsDir() && info.Name() == "mix.lock" {
			manifests = append(manifests, path)
		}
		return nil
	})
	return manifests, err
}

// ParseDependencies reads a mix.lock file and returns one Component per
// hex dependency. Git-sourced dependencies are skipped.
func (e *ElixirScanner) ParseDependencies(ctx context.Context, manifestPath string) ([]models.Component, error) {
	data, err := os.ReadFile(manifestPath)
	if err != nil {
		return nil, fmt.Errorf("read mix.lock: %w", err)
	}

	// Regex to match hex tuple lines:
	// "name": {:hex, :name, "version", "hash", ...}
	// Captures: (1) name, (2) version, (3) hash
	hexPattern := regexp.MustCompile(`"(\w+)":\s*\{:hex,\s*:\w+,\s*"([^"]+)",\s*"([^"]+)"`)

	var components []models.Component
	scanner := bufio.NewScanner(strings.NewReader(string(data)))
	for scanner.Scan() {
		line := scanner.Text()

		// Skip git-sourced dependencies (they contain :git)
		if strings.Contains(line, "{:git,") {
			continue
		}

		matches := hexPattern.FindStringSubmatch(line)
		if len(matches) != 4 {
			continue
		}

		name := matches[1]
		version := matches[2]
		hash := matches[3]

		c := models.Component{
			Name:      name,
			Version:   version,
			Ecosystem: models.EcosystemHex,
			PkgURL:    "pkg:hex/" + name + "@" + version,
			Hash:      hash,
			Direct:    false,
		}
		components = append(components, c)
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("scan mix.lock: %w", err)
	}

	return components, nil
}
