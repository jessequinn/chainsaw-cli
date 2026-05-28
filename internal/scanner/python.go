package scanner

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/chainsaw-dev/chainsaw/pkg/models"
)

// PythonScanner implements Scanner for the PyPI ecosystem.
type PythonScanner struct{}

func init() {
	Register(&PythonScanner{})
}

func (p *PythonScanner) Ecosystem() models.Ecosystem {
	return models.EcosystemPyPI
}

// skipPythonDirs contains directories to skip when walking the tree.
var skipPythonDirs = map[string]bool{
	"venv":        true,
	".venv":       true,
	"__pycache__": true,
	".tox":        true,
	".eggs":       true,
}

// pythonManifests are the filenames recognised as Python dependency manifests.
var pythonManifests = map[string]bool{
	"requirements.txt": true,
	"Pipfile.lock":     true,
	"poetry.lock":      true,
}

func (p *PythonScanner) DetectManifests(ctx context.Context, root string) ([]string, error) {
	var manifests []string
	err := filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() {
			if skipPythonDirs[info.Name()] {
				return filepath.SkipDir
			}
			return nil
		}
		if pythonManifests[info.Name()] {
			manifests = append(manifests, path)
		}
		return nil
	})
	return manifests, err
}

func (p *PythonScanner) ParseDependencies(ctx context.Context, manifestPath string) ([]models.Component, error) {
	base := filepath.Base(manifestPath)
	switch base {
	case "requirements.txt":
		return parseRequirementsTxt(manifestPath)
	case "Pipfile.lock":
		return parsePipfileLock(manifestPath)
	case "poetry.lock":
		return parsePoetryLock(manifestPath)
	default:
		return nil, fmt.Errorf("unknown Python manifest: %s", base)
	}
}

// normalizePyPIName applies PEP 503 normalisation: lowercase, replace
// underscores/dots/runs of [-_.] with a single hyphen.
func normalizePyPIName(name string) string {
	name = strings.ToLower(name)
	// PEP 503: any run of [-_.] is replaced with a single hyphen.
	re := regexp.MustCompile(`[-_.]+`)
	return re.ReplaceAllString(name, "-")
}

func pypiPurl(name, version string) string {
	return "pkg:pypi/" + normalizePyPIName(name) + "@" + version
}

// requirementLine matches "package==version" with an optional hash.
var requirementLine = regexp.MustCompile(
	`^\s*([A-Za-z0-9]([A-Za-z0-9._-]*[A-Za-z0-9])?)\s*==\s*([^\s;#\\]+)`,
)

// hashPattern extracts --hash=sha256:xxx from a requirements line.
var hashPattern = regexp.MustCompile(`--hash=sha256:([0-9a-fA-F]+)`)

func parseRequirementsTxt(path string) ([]models.Component, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open requirements.txt: %w", err)
	}
	defer f.Close()

	var components []models.Component
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		// Skip -r includes, -e editable installs, URL-based installs.
		if strings.HasPrefix(line, "-r") || strings.HasPrefix(line, "-e") ||
			strings.HasPrefix(line, "-c") || strings.HasPrefix(line, "-f") ||
			strings.HasPrefix(line, "--") && !strings.HasPrefix(line, "--hash") ||
			strings.Contains(line, "://") && !strings.Contains(line, "==") {
			continue
		}
		m := requirementLine.FindStringSubmatch(line)
		if m == nil {
			continue
		}
		name, version := m[1], m[3]
		c := models.Component{
			Name:      normalizePyPIName(name),
			Version:   version,
			Ecosystem: models.EcosystemPyPI,
			PkgURL:    pypiPurl(name, version),
		}
		if hm := hashPattern.FindStringSubmatch(line); hm != nil {
			c.Hash = "sha256:" + hm[1]
		}
		components = append(components, c)
	}
	return components, sc.Err()
}

// pipfileLock represents the structure of Pipfile.lock.
type pipfileLock struct {
	Default map[string]pipfilePkg `json:"default"`
	Develop map[string]pipfilePkg `json:"develop"`
}

type pipfilePkg struct {
	Version string   `json:"version"`
	Hashes  []string `json:"hashes"`
}

func parsePipfileLock(path string) ([]models.Component, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read Pipfile.lock: %w", err)
	}
	var lock pipfileLock
	if err := json.Unmarshal(data, &lock); err != nil {
		return nil, fmt.Errorf("parse Pipfile.lock: %w", err)
	}

	var components []models.Component
	for name, pkg := range lock.Default {
		components = append(components, pipfileComponent(name, pkg))
	}
	for name, pkg := range lock.Develop {
		components = append(components, pipfileComponent(name, pkg))
	}
	return components, nil
}

func pipfileComponent(name string, pkg pipfilePkg) models.Component {
	version := strings.TrimPrefix(pkg.Version, "==")
	c := models.Component{
		Name:      normalizePyPIName(name),
		Version:   version,
		Ecosystem: models.EcosystemPyPI,
		PkgURL:    pypiPurl(name, version),
	}
	if len(pkg.Hashes) > 0 {
		c.Hash = pkg.Hashes[0]
	}
	return c
}

// Poetry lock regex patterns. Avoids a TOML dependency.
var (
	poetryPkgHeader  = regexp.MustCompile(`^\[\[package\]\]`)
	poetryNameField  = regexp.MustCompile(`^name\s*=\s*"([^"]+)"`)
	poetryVersionField = regexp.MustCompile(`^version\s*=\s*"([^"]+)"`)
)

func parsePoetryLock(path string) ([]models.Component, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open poetry.lock: %w", err)
	}
	defer f.Close()

	var components []models.Component
	sc := bufio.NewScanner(f)

	var name, version string
	inPackage := false

	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())

		if poetryPkgHeader.MatchString(line) {
			// Emit previous package if complete.
			if inPackage && name != "" && version != "" {
				components = append(components, models.Component{
					Name:      normalizePyPIName(name),
					Version:   version,
					Ecosystem: models.EcosystemPyPI,
					PkgURL:    pypiPurl(name, version),
				})
			}
			name, version = "", ""
			inPackage = true
			continue
		}

		if !inPackage {
			continue
		}

		if m := poetryNameField.FindStringSubmatch(line); m != nil {
			name = m[1]
		} else if m := poetryVersionField.FindStringSubmatch(line); m != nil {
			version = m[1]
		}
	}
	// Emit last package.
	if inPackage && name != "" && version != "" {
		components = append(components, models.Component{
			Name:      normalizePyPIName(name),
			Version:   version,
			Ecosystem: models.EcosystemPyPI,
			PkgURL:    pypiPurl(name, version),
		})
	}
	return components, sc.Err()
}
