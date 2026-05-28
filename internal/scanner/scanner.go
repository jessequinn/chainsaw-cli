package scanner

import (
	"fmt"
	"sync"

	"github.com/chainsaw-dev/chainsaw/pkg/models"
)

// Scanner detects and parses dependency manifests for a specific ecosystem.
type Scanner interface {
	Ecosystem() models.Ecosystem
	DetectManifests(root string) ([]string, error)
	ParseDependencies(manifestPath string) ([]models.Component, error)
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
func DetectAll(root string) ([]models.Component, error) {
	mu.RLock()
	all := make([]Scanner, len(scanners))
	copy(all, scanners)
	mu.RUnlock()

	seen := make(map[string]struct{})
	var components []models.Component

	for _, s := range all {
		manifests, err := s.DetectManifests(root)
		if err != nil {
			return nil, fmt.Errorf("detect manifests (%s): %w", s.Ecosystem(), err)
		}
		for _, m := range manifests {
			deps, err := s.ParseDependencies(m)
			if err != nil {
				return nil, fmt.Errorf("parse %s: %w", m, err)
			}
			for _, c := range deps {
				key := string(c.Ecosystem) + "|" + c.Name + "|" + c.Version
				if _, dup := seen[key]; dup {
					continue
				}
				seen[key] = struct{}{}
				components = append(components, c)
			}
		}
	}
	return components, nil
}
