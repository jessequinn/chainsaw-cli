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

// DockerfileScanner implements Scanner for the Docker ecosystem.
type DockerfileScanner struct{}

func init() {
	Register(&DockerfileScanner{})
}

func (d *DockerfileScanner) Ecosystem() models.Ecosystem {
	return models.EcosystemDocker
}

// skipDockerDirs contains directories to skip when detecting Dockerfiles.
var skipDockerDirs = map[string]bool{
	".git":         true,
	"vendor":       true,
	"node_modules": true,
}

// dockerfilePattern matches Dockerfile, Dockerfile.*, and *.dockerfile.
var dockerfilePattern = regexp.MustCompile(
	`^(Dockerfile(\..*)?|.*\.dockerfile)$`,
)

func (d *DockerfileScanner) DetectManifests(ctx context.Context, root string) ([]string, error) {
	var manifests []string
	err := filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() {
			if skipDockerDirs[info.Name()] {
				return filepath.SkipDir
			}
			return nil
		}
		if dockerfilePattern.MatchString(info.Name()) {
			manifests = append(manifests, path)
		}
		return nil
	})
	return manifests, err
}

// fromLine matches FROM directives, with optional --platform flag and AS alias.
var fromLine = regexp.MustCompile(`(?i)^FROM\s+(?:--platform=\S+\s+)?(\S+)(?:\s+AS\s+\S+)?$`)

// argVarPattern detects unresolved ${...} ARG variables.
var argVarPattern = regexp.MustCompile(`\$\{[^}]+\}`)

func (d *DockerfileScanner) ParseDependencies(ctx context.Context, manifestPath string) ([]models.Component, error) {
	f, err := os.Open(manifestPath)
	if err != nil {
		return nil, fmt.Errorf("open Dockerfile: %w", err)
	}
	defer f.Close()

	var components []models.Component
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		m := fromLine.FindStringSubmatch(line)
		if m == nil {
			continue
		}
		imageRef := m[1]

		// Skip scratch base.
		if strings.EqualFold(imageRef, "scratch") {
			continue
		}
		// Skip unresolved ARG variables.
		if argVarPattern.MatchString(imageRef) {
			continue
		}

		c, ok := parseDockerImageRef(imageRef)
		if !ok {
			continue
		}
		components = append(components, c)
	}
	return components, sc.Err()
}

// parseDockerImageRef parses a Docker image reference into a Component.
// Format: [registry/]name[:tag][@digest]
func parseDockerImageRef(ref string) (models.Component, bool) {
	var name, tag, digest string

	// Split off digest.
	if idx := strings.Index(ref, "@"); idx >= 0 {
		digest = ref[idx+1:]
		ref = ref[:idx]
	}

	// Split off tag.
	// Be careful with registry:port/image:tag patterns.
	tagIdx := strings.LastIndex(ref, ":")
	if tagIdx >= 0 {
		// Only treat as tag if there is no slash after the colon (not a port).
		afterColon := ref[tagIdx+1:]
		if !strings.Contains(afterColon, "/") {
			tag = afterColon
			ref = ref[:tagIdx]
		}
	}

	name = ref

	// For official images (no slash), prefix with library/.
	if !strings.Contains(name, "/") {
		name = "library/" + name
	}

	// Determine version string: prefer tag, fall back to digest.
	version := tag
	if version == "" {
		version = digest
	}
	if version == "" {
		version = "latest"
	}

	// Build purl. Split name into namespace and image.
	parts := strings.SplitN(name, "/", 2)
	var purl string
	if len(parts) == 2 {
		purl = "pkg:docker/" + parts[0] + "/" + parts[1] + "@" + version
	} else {
		purl = "pkg:docker/" + name + "@" + version
	}

	c := models.Component{
		Name:      name,
		Version:   version,
		Ecosystem: models.EcosystemDocker,
		PkgURL:    purl,
		Direct:    false,
	}
	if digest != "" {
		c.Hash = digest
	}

	return c, true
}
