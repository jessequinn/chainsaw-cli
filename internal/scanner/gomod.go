package scanner

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/mod/modfile"

	"github.com/chainsaw-dev/chainsaw/pkg/models"
)

// GoScanner implements Scanner for the Go ecosystem.
type GoScanner struct{}

func init() {
	Register(&GoScanner{})
}

func (g *GoScanner) Ecosystem() models.Ecosystem {
	return models.EcosystemGo
}

// DetectManifests walks root and returns paths to go.mod files, skipping
// vendor/ directories.
func (g *GoScanner) DetectManifests(ctx context.Context, root string) ([]string, error) {
	var manifests []string
	err := filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() && info.Name() == "vendor" {
			return filepath.SkipDir
		}
		if !info.IsDir() && info.Name() == "go.mod" {
			manifests = append(manifests, path)
		}
		return nil
	})
	return manifests, err
}

// ParseDependencies reads a go.mod file and returns one Component per
// non-indirect require directive. It also attempts to read go.sum from the
// same directory to populate hash values.
func (g *GoScanner) ParseDependencies(ctx context.Context, manifestPath string) ([]models.Component, error) {
	data, err := os.ReadFile(manifestPath)
	if err != nil {
		return nil, fmt.Errorf("read go.mod: %w", err)
	}

	f, err := modfile.Parse(manifestPath, data, nil)
	if err != nil {
		return nil, fmt.Errorf("parse go.mod: %w", err)
	}

	hashes := readGoSumHashes(filepath.Join(filepath.Dir(manifestPath), "go.sum"))

	var components []models.Component
	for _, req := range f.Require {
		if req.Indirect {
			continue
		}
		mod := req.Mod
		c := models.Component{
			Name:      mod.Path,
			Version:   mod.Version,
			Ecosystem: models.EcosystemGo,
			PkgURL:    "pkg:golang/" + mod.Path + "@" + mod.Version,
		}
		if h, ok := hashes[mod.Path+"@"+mod.Version]; ok {
			c.Hash = h
		}
		components = append(components, c)
	}
	return components, nil
}

// readGoSumHashes parses a go.sum file and returns a map of
// "module@version" -> hash. It prefers the direct module hash over the
// /go.mod hash.
func readGoSumHashes(path string) map[string]string {
	out := make(map[string]string)

	f, err := os.Open(path)
	if err != nil {
		return out
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		// Each line: module version hash
		parts := strings.Fields(line)
		if len(parts) != 3 {
			continue
		}
		mod, ver, hash := parts[0], parts[1], parts[2]

		key := mod + "@" + ver
		if strings.HasSuffix(ver, "/go.mod") {
			// go.mod entry – use only if we don't already have the direct hash.
			trimmed := mod + "@" + strings.TrimSuffix(ver, "/go.mod")
			if _, exists := out[trimmed]; !exists {
				out[trimmed] = hash
			}
		} else {
			// Direct module hash – always preferred.
			out[key] = hash
		}
	}
	return out
}
