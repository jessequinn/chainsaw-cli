package scanner

import (
	"context"
	"fmt"
	"path/filepath"
	"strings"
	"sync"

	"github.com/chainsaw-dev/chainsaw/pkg/models"
)

// Scanner detects and parses dependency manifests for a specific ecosystem.
type Scanner interface {
	Ecosystem() models.Ecosystem
	DetectManifests(ctx context.Context, root string) ([]string, error)
	ParseDependencies(ctx context.Context, manifestPath string) ([]models.Component, error)
}

var (
	mu       sync.RWMutex
	scanners []Scanner
)

// Register adds a scanner to the global registry.
func Register(s Scanner) {
	mu.Lock()
	defer mu.Unlock()
	scanners = append(scanners, s)
}

// GetAll returns all registered scanners.
func GetAll() []Scanner {
	mu.RLock()
	defer mu.RUnlock()
	out := make([]Scanner, len(scanners))
	copy(out, scanners)
	return out
}

// GetByEcosystem returns the scanner for the given ecosystem, if registered.
func GetByEcosystem(eco models.Ecosystem) (Scanner, bool) {
	mu.RLock()
	defer mu.RUnlock()
	for _, s := range scanners {
		if s.Ecosystem() == eco {
			return s, true
		}
	}
	return nil, false
}

// DetectAll runs every registered scanner against root and returns a
// deduplicated list of components.
func DetectAll(ctx context.Context, root string) ([]models.Component, error) {
	mu.RLock()
	all := make([]Scanner, len(scanners))
	copy(all, scanners)
	mu.RUnlock()

	seen := make(map[string]struct{})
	var components []models.Component

	for _, s := range all {
		manifests, err := s.DetectManifests(ctx, root)
		if err != nil {
			return nil, fmt.Errorf("detect manifests (%s): %w", s.Ecosystem(), err)
		}
		for _, m := range manifests {
			deps, err := s.ParseDependencies(ctx, m)
			if err != nil {
				return nil, fmt.Errorf("parse %s: %w", m, err)
			}
			relPath := manifestRelPath(root, m)
			for _, c := range deps {
				key := string(c.Ecosystem) + "|" + c.Name + "|" + c.Version
				if _, dup := seen[key]; dup {
					continue
				}
				seen[key] = struct{}{}
				c.Location = relPath
				components = append(components, c)
			}
		}
	}
	return components, nil
}

// manifestRelPath returns the manifest path relative to root, using
// forward slashes (SARIF convention). Falls back to the base name.
func manifestRelPath(root, manifest string) string {
	absRoot, err := filepath.Abs(root)
	if err != nil {
		return filepath.Base(manifest)
	}
	absManifest, err := filepath.Abs(manifest)
	if err != nil {
		return filepath.Base(manifest)
	}
	rel, err := filepath.Rel(absRoot, absManifest)
	if err != nil {
		return filepath.Base(manifest)
	}
	return strings.ReplaceAll(rel, string(filepath.Separator), "/")
}
