package scanner

import (
	"context"
	"os"
	"path/filepath"
	"sort"
	"testing"

	"github.com/chainsaw-dev/chainsaw/pkg/models"
)

func TestComposeScanner_Ecosystem(t *testing.T) {
	s := &ComposeScanner{}
	if got := s.Ecosystem(); got != models.EcosystemDocker {
		t.Fatalf("Ecosystem() = %q, want %q", got, models.EcosystemDocker)
	}
}

func TestComposeScanner_DetectManifests(t *testing.T) {
	dir := t.TempDir()

	names := []string{
		"docker-compose.yml",
		"docker-compose.yaml",
		"docker-compose.override.yml",
		"compose.yml",
		"compose.yaml",
		"README.md",
	}
	for _, name := range names {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(""), 0o644); err != nil {
			t.Fatal(err)
		}
	}

	ctx := context.Background()
	s := &ComposeScanner{}
	manifests, err := s.DetectManifests(ctx, dir)
	if err != nil {
		t.Fatalf("DetectManifests: %v", err)
	}

	want := map[string]bool{
		"docker-compose.yml":          true,
		"docker-compose.yaml":         true,
		"docker-compose.override.yml": true,
		"compose.yml":                 true,
		"compose.yaml":                true,
	}
	if len(manifests) != len(want) {
		t.Fatalf("got %d manifests, want %d: %v", len(manifests), len(want), manifests)
	}
	for _, m := range manifests {
		if !want[filepath.Base(m)] {
			t.Errorf("unexpected manifest: %s", filepath.Base(m))
		}
	}
}

func TestComposeScanner_ParseDependencies(t *testing.T) {
	ctx := context.Background()
	s := &ComposeScanner{}
	manifestPath := filepath.Join("..", "..", "testdata", "compose", "docker-compose.yml")

	components, err := s.ParseDependencies(ctx, manifestPath)
	if err != nil {
		t.Fatalf("ParseDependencies: %v", err)
	}

	// Sort for deterministic comparison (map iteration order varies).
	sort.Slice(components, func(i, j int) bool {
		return components[i].Name < components[j].Name
	})

	want := []struct {
		name    string
		version string
	}{
		{"library/nginx", "1.25"},
		{"library/postgres", "16.1"},
		{"library/redis", "7.2-alpine"},
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
		if c.Ecosystem != models.EcosystemDocker {
			t.Errorf("[%d] Ecosystem = %q, want %q", i, c.Ecosystem, models.EcosystemDocker)
		}
	}
}

func TestComposeScanner_SkipsBuildOnlyServices(t *testing.T) {
	dir := t.TempDir()
	content := `
services:
  app:
    build: ./app
  worker:
    build:
      context: ./worker
`
	if err := os.WriteFile(filepath.Join(dir, "docker-compose.yml"), []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}

	ctx := context.Background()
	s := &ComposeScanner{}
	components, err := s.ParseDependencies(ctx, filepath.Join(dir, "docker-compose.yml"))
	if err != nil {
		t.Fatalf("ParseDependencies: %v", err)
	}
	if len(components) != 0 {
		t.Fatalf("expected 0 components for build-only services, got %d: %+v", len(components), components)
	}
}
