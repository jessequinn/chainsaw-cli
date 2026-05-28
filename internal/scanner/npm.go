package scanner

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/chainsaw-dev/chainsaw/pkg/models"
)

// NpmScanner implements Scanner for the npm ecosystem.
type NpmScanner struct{}

func init() {
	Register(&NpmScanner{})
}

func (n *NpmScanner) Ecosystem() models.Ecosystem {
	return models.EcosystemNpm
}

// DetectManifests walks root and returns paths to package-lock.json files,
// skipping node_modules/ directories.
func (n *NpmScanner) DetectManifests(ctx context.Context, root string) ([]string, error) {
	var manifests []string
	err := filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() && info.Name() == "node_modules" {
			return filepath.SkipDir
		}
		if !info.IsDir() && info.Name() == "package-lock.json" {
			manifests = append(manifests, path)
		}
		return nil
	})
	return manifests, err
}

// npmLockfile is the subset of package-lock.json we need.
type npmLockfile struct {
	LockfileVersion int                    `json:"lockfileVersion"`
	Packages        map[string]npmPackage  `json:"packages"`
}

type npmPackage struct {
	Version   string `json:"version"`
	Resolved  string `json:"resolved"`
	Integrity string `json:"integrity"`
}

// ParseDependencies reads a package-lock.json (lockfileVersion 2 or 3) and
// returns one Component per entry in the "packages" map.
func (n *NpmScanner) ParseDependencies(ctx context.Context, manifestPath string) ([]models.Component, error) {
	data, err := os.ReadFile(manifestPath)
	if err != nil {
		return nil, fmt.Errorf("read package-lock.json: %w", err)
	}

	var lf npmLockfile
	if err := json.Unmarshal(data, &lf); err != nil {
		return nil, fmt.Errorf("parse package-lock.json: %w", err)
	}

	if lf.Packages == nil {
		return nil, nil
	}

	var components []models.Component
	for key, pkg := range lf.Packages {
		// The root project entry has an empty key – skip it.
		if key == "" {
			continue
		}
		if pkg.Version == "" {
			continue
		}

		name := npmPackageName(key)
		c := models.Component{
			Name:      name,
			Version:   pkg.Version,
			Ecosystem: models.EcosystemNpm,
			Hash:      pkg.Integrity,
			PkgURL:    npmPkgURL(name, pkg.Version),
		}
		components = append(components, c)
	}
	return components, nil
}

// npmPackageName strips the leading "node_modules/" segments from a
// package-lock.json packages key, handling nested node_modules.
// e.g. "node_modules/@babel/core" -> "@babel/core"
//
//	"node_modules/a/node_modules/b" -> "b"
func npmPackageName(key string) string {
	const prefix = "node_modules/"
	// The last node_modules/ segment determines the actual package name.
	idx := strings.LastIndex(key, prefix)
	if idx >= 0 {
		return key[idx+len(prefix):]
	}
	return key
}

// npmPkgURL builds a purl for an npm package. Scoped packages use %40
// instead of @ in the namespace portion.
// e.g. "@babel/core" 7.0.0 -> "pkg:npm/%40babel/core@7.0.0"
func npmPkgURL(name, version string) string {
	if strings.HasPrefix(name, "@") {
		// Scoped package: @scope/pkg -> %40scope/pkg
		encoded := "%40" + name[1:]
		return "pkg:npm/" + encoded + "@" + version
	}
	return "pkg:npm/" + name + "@" + version
}
