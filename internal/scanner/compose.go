package scanner

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/chainsaw-dev/chainsaw/pkg/models"
	"gopkg.in/yaml.v3"
)

// ComposeScanner implements Scanner for Docker Compose files.
type ComposeScanner struct{}

func init() {
	Register(&ComposeScanner{})
}

func (c *ComposeScanner) Ecosystem() models.Ecosystem {
	return models.EcosystemDocker
}

// DetectManifests walks root and returns paths to docker-compose YAML files,
// skipping .git/ and node_modules/ directories.
func (c *ComposeScanner) DetectManifests(ctx context.Context, root string) ([]string, error) {
	var manifests []string
	err := filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() {
			switch info.Name() {
			case ".git", "node_modules":
				return filepath.SkipDir
			}
			return nil
		}
		name := info.Name()
		if name == "compose.yml" || name == "compose.yaml" {
			manifests = append(manifests, path)
			return nil
		}
		if strings.HasPrefix(name, "docker-compose") &&
			(strings.HasSuffix(name, ".yml") || strings.HasSuffix(name, ".yaml")) {
			manifests = append(manifests, path)
		}
		return nil
	})
	return manifests, err
}

// composeFile is the subset of a docker-compose file we need.
type composeFile struct {
	Services map[string]composeService `yaml:"services"`
}

type composeService struct {
	Image string      `yaml:"image"`
	Build interface{} `yaml:"build"`
}

// ParseDependencies parses a docker-compose file and returns components
// for each service that specifies an image.
func (c *ComposeScanner) ParseDependencies(ctx context.Context, manifestPath string) ([]models.Component, error) {
	data, err := os.ReadFile(manifestPath)
	if err != nil {
		return nil, fmt.Errorf("reading %s: %w", manifestPath, err)
	}

	var cf composeFile
	if err := yaml.Unmarshal(data, &cf); err != nil {
		return nil, fmt.Errorf("parsing %s: %w", manifestPath, err)
	}

	var components []models.Component
	for _, svc := range cf.Services {
		if svc.Image == "" {
			continue
		}
		comp, ok := parseImageRef(svc.Image)
		if !ok {
			continue
		}
		components = append(components, comp)
	}
	return components, nil
}

// parseImageRef parses a Docker image reference into a Component.
// Returns false if the reference contains unresolved variables.
func parseImageRef(image string) (models.Component, bool) {
	if strings.Contains(image, "${") {
		return models.Component{}, false
	}

	// Strip digest (image@sha256:abc...)
	ref := image
	if idx := strings.Index(ref, "@"); idx != -1 {
		ref = ref[:idx]
	}

	// Split tag
	name := ref
	version := "latest"
	if idx := strings.LastIndex(ref, ":"); idx != -1 {
		name = ref[:idx]
		version = ref[idx+1:]
	}

	// Official images have no slash; prefix with library/
	if !strings.Contains(name, "/") {
		name = "library/" + name
	}

	// Build purl: pkg:docker/namespace/name@version
	// Split into namespace and short name for purl
	parts := strings.SplitN(name, "/", 2)
	purl := fmt.Sprintf("pkg:docker/%s/%s@%s", parts[0], parts[1], version)

	return models.Component{
		Name:      name,
		Version:   version,
		Ecosystem: models.EcosystemDocker,
		PkgURL:    purl,
	}, true
}
