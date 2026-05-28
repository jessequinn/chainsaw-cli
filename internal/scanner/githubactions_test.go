package scanner

import (
	"context"
	"os"
	"path/filepath"
	"sort"
	"testing"

	"github.com/chainsaw-dev/chainsaw/pkg/models"
)

func TestGitHubActionsScanner_Ecosystem(t *testing.T) {
	s := &GitHubActionsScanner{}
	if got := s.Ecosystem(); got != models.EcosystemGitHubActions {
		t.Fatalf("Ecosystem() = %q, want %q", got, models.EcosystemGitHubActions)
	}
}

func TestGitHubActionsScanner_DetectManifests(t *testing.T) {
	dir := t.TempDir()
	wfDir := filepath.Join(dir, ".github", "workflows")
	if err := os.MkdirAll(wfDir, 0o755); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"ci.yml", "deploy.yaml", "notes.txt"} {
		if err := os.WriteFile(filepath.Join(wfDir, name), []byte(""), 0o644); err != nil {
			t.Fatal(err)
		}
	}

	ctx := context.Background()
	s := &GitHubActionsScanner{}
	manifests, err := s.DetectManifests(ctx, dir)
	if err != nil {
		t.Fatalf("DetectManifests: %v", err)
	}
	if len(manifests) != 2 {
		t.Fatalf("got %d manifests, want 2: %v", len(manifests), manifests)
	}
}

func TestGitHubActionsScanner_DetectManifests_NoWorkflowDir(t *testing.T) {
	dir := t.TempDir()
	ctx := context.Background()
	s := &GitHubActionsScanner{}
	manifests, err := s.DetectManifests(ctx, dir)
	if err != nil {
		t.Fatalf("DetectManifests: %v", err)
	}
	if len(manifests) != 0 {
		t.Fatalf("expected 0 manifests for missing workflow dir, got %d", len(manifests))
	}
}

func TestGitHubActionsScanner_ParseDependencies(t *testing.T) {
	ctx := context.Background()
	s := &GitHubActionsScanner{}
	manifestPath := filepath.Join("..", "..", "testdata", "githubactions", ".github", "workflows", "ci.yml")

	components, err := s.ParseDependencies(ctx, manifestPath)
	if err != nil {
		t.Fatalf("ParseDependencies: %v", err)
	}

	// Sort for deterministic order
	sort.Slice(components, func(i, j int) bool {
		return components[i].Name < components[j].Name
	})

	want := []struct {
		name    string
		version string
	}{
		{"actions/checkout", "v4"},
		{"actions/setup-go", "v5"},
		{"docker/build-push-action", "abc123def456789012345678901234567890abcd"},
	}

	if len(components) != len(want) {
		t.Fatalf("got %d components, want %d: %+v", len(components), len(want), components)
	}
	for i, w := range want {
		c := components[i]
		if c.Name != w.name {
			t.Errorf("[%d] Name = %q, want %q", i, c.Name, w.name)
		}
		if c.Version != w.version {
			t.Errorf("[%d] Version = %q, want %q", i, c.Version, w.version)
		}
	}
}

func TestGitHubActionsScanner_SHAPinDetection(t *testing.T) {
	tests := []struct {
		name     string
		uses     string
		wantHash string
	}{
		{
			name:     "SHA-pinned action has hash set",
			uses:     "docker/build-push-action@abc123def456789012345678901234567890abcd",
			wantHash: "abc123def456789012345678901234567890abcd",
		},
		{
			name:     "tag-pinned action has no hash",
			uses:     "actions/checkout@v4",
			wantHash: "",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c, ok := parseUsesDirective(tt.uses)
			if !ok {
				t.Fatal("parseUsesDirective returned false")
			}
			if c.Hash != tt.wantHash {
				t.Errorf("Hash = %q, want %q", c.Hash, tt.wantHash)
			}
		})
	}
}

func TestGitHubActionsScanner_SkipsRunSteps(t *testing.T) {
	dir := t.TempDir()
	wfDir := filepath.Join(dir, ".github", "workflows")
	if err := os.MkdirAll(wfDir, 0o755); err != nil {
		t.Fatal(err)
	}
	content := `
name: Test
on: push
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - run: echo hello
      - run: go test ./...
`
	if err := os.WriteFile(filepath.Join(wfDir, "test.yml"), []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}

	ctx := context.Background()
	s := &GitHubActionsScanner{}
	components, err := s.ParseDependencies(ctx, filepath.Join(wfDir, "test.yml"))
	if err != nil {
		t.Fatalf("ParseDependencies: %v", err)
	}
	if len(components) != 0 {
		t.Fatalf("expected 0 components for run-only steps, got %d: %+v", len(components), components)
	}
}
