package scanner

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/chainsaw-dev/chainsaw/pkg/models"
)

// GitHubActionsScanner implements Scanner for the github-actions ecosystem.
type GitHubActionsScanner struct{}

func init() {
	Register(&GitHubActionsScanner{})
}

func (g *GitHubActionsScanner) Ecosystem() models.Ecosystem {
	return models.EcosystemGitHubActions
}

func (g *GitHubActionsScanner) DetectManifests(ctx context.Context, root string) ([]string, error) {
	workflowDir := filepath.Join(root, ".github", "workflows")
	info, err := os.Stat(workflowDir)
	if err != nil || !info.IsDir() {
		return nil, nil
	}

	var manifests []string
	entries, err := os.ReadDir(workflowDir)
	if err != nil {
		return nil, fmt.Errorf("read workflows dir: %w", err)
	}
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		ext := filepath.Ext(e.Name())
		if ext == ".yml" || ext == ".yaml" {
			manifests = append(manifests, filepath.Join(workflowDir, e.Name()))
		}
	}
	return manifests, nil
}

// workflow is a minimal representation of a GitHub Actions workflow file.
type workflow struct {
	Jobs map[string]workflowJob `yaml:"jobs"`
}

type workflowJob struct {
	Steps []workflowStep `yaml:"steps"`
}

type workflowStep struct {
	Uses string `yaml:"uses"`
}

// commitSHAPattern matches a 40-character hex string.
var commitSHAPattern = regexp.MustCompile(`^[0-9a-fA-F]{40}$`)

// versionTagPattern matches vN or vN.N.N style tags.
var versionTagPattern = regexp.MustCompile(`^v\d+(\.\d+)*$`)

func (g *GitHubActionsScanner) ParseDependencies(ctx context.Context, manifestPath string) ([]models.Component, error) {
	data, err := os.ReadFile(manifestPath)
	if err != nil {
		return nil, fmt.Errorf("read workflow file: %w", err)
	}

	var wf workflow
	if err := yaml.Unmarshal(data, &wf); err != nil {
		return nil, fmt.Errorf("parse workflow YAML: %w", err)
	}

	var components []models.Component
	for _, job := range wf.Jobs {
		for _, step := range job.Steps {
			if step.Uses == "" {
				continue
			}
			c, ok := parseUsesDirective(step.Uses)
			if !ok {
				continue
			}
			components = append(components, c)
		}
	}
	return components, nil
}

// parseUsesDirective parses a single `uses:` value and returns a Component.
// Returns false if the directive should be skipped (docker://, local action).
func parseUsesDirective(uses string) (models.Component, bool) {
	// Skip Docker container references.
	if strings.HasPrefix(uses, "docker://") {
		return models.Component{}, false
	}
	// Skip local actions.
	if strings.HasPrefix(uses, "./") {
		return models.Component{}, false
	}

	// Expected format: owner/repo@ref or owner/repo/path@ref
	atIdx := strings.LastIndex(uses, "@")
	if atIdx < 0 {
		return models.Component{}, false
	}
	ownerRepoPath := uses[:atIdx]
	ref := uses[atIdx+1:]

	// Extract owner/repo (strip subpath if present).
	parts := strings.SplitN(ownerRepoPath, "/", 3)
	if len(parts) < 2 {
		return models.Component{}, false
	}
	name := parts[0] + "/" + parts[1]

	c := models.Component{
		Name:      name,
		Version:   ref,
		Ecosystem: models.EcosystemGitHubActions,
		PkgURL:    "pkg:githubactions/" + name + "@" + ref,
		Direct:    false,
	}

	// Classify pin type and store as hash for SHA pins.
	switch {
	case commitSHAPattern.MatchString(ref):
		c.Hash = ref
	case versionTagPattern.MatchString(ref):
		// version tag -- no special handling needed
	default:
		// branch reference -- no special handling needed
	}

	return c, true
}
