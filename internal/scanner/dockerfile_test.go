package scanner

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/chainsaw-dev/chainsaw/pkg/models"
)

func TestDockerfileScanner_Ecosystem(t *testing.T) {
	s := &DockerfileScanner{}
	if got := s.Ecosystem(); got != models.EcosystemDocker {
		t.Fatalf("Ecosystem() = %q, want %q", got, models.EcosystemDocker)
	}
}

func TestDockerfileScanner_DetectManifests(t *testing.T) {
	t.Helper()
	dir := t.TempDir()

	// Create files: Dockerfile, Dockerfile.prod, app.dockerfile, README.md
	for _, name := range []string{"Dockerfile", "Dockerfile.prod", "app.dockerfile", "README.md"} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(""), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	// Create .git dir that should be skipped
	if err := os.MkdirAll(filepath.Join(dir, ".git"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, ".git", "Dockerfile"), []byte(""), 0o644); err != nil {
		t.Fatal(err)
	}

	ctx := context.Background()
	s := &DockerfileScanner{}
	manifests, err := s.DetectManifests(ctx, dir)
	if err != nil {
		t.Fatalf("DetectManifests: %v", err)
	}

	want := map[string]bool{
		"Dockerfile":     true,
		"Dockerfile.prod": true,
		"app.dockerfile": true,
	}
	if len(manifests) != len(want) {
		t.Fatalf("got %d manifests, want %d: %v", len(manifests), len(want), manifests)
	}
	for _, m := range manifests {
		base := filepath.Base(m)
		if !want[base] {
			t.Errorf("unexpected manifest: %s", base)
		}
	}
}

func TestDockerfileScanner_ParseDependencies(t *testing.T) {
	ctx := context.Background()
	s := &DockerfileScanner{}
	manifestPath := filepath.Join("..", "..", "testdata", "docker", "Dockerfile")

	components, err := s.ParseDependencies(ctx, manifestPath)
	if err != nil {
		t.Fatalf("ParseDependencies: %v", err)
	}

	tests := []struct {
		name    string
		version string
	}{
		{"library/golang", "1.22-alpine"},
		{"library/alpine", "3.19"},
	}

	if len(components) != len(tests) {
		t.Fatalf("got %d components, want %d: %+v", len(components), len(tests), components)
	}
	for i, tt := range tests {
		c := components[i]
		if c.Name != tt.name {
			t.Errorf("component[%d].Name = %q, want %q", i, c.Name, tt.name)
		}
		if c.Version != tt.version {
			t.Errorf("component[%d].Version = %q, want %q", i, c.Version, tt.version)
		}
		if c.Ecosystem != models.EcosystemDocker {
			t.Errorf("component[%d].Ecosystem = %q, want %q", i, c.Ecosystem, models.EcosystemDocker)
		}
	}
}

func TestDockerfileScanner_ParseDependencies_Pinned(t *testing.T) {
	ctx := context.Background()
	s := &DockerfileScanner{}
	manifestPath := filepath.Join("..", "..", "testdata", "docker", "Dockerfile.pinned")

	components, err := s.ParseDependencies(ctx, manifestPath)
	if err != nil {
		t.Fatalf("ParseDependencies: %v", err)
	}

	tests := []struct {
		name    string
		version string
		hash    string
	}{
		{"library/golang", "1.22-alpine", "sha256:abc123def456"},
		{"library/alpine", "sha256:def789abc012", "sha256:def789abc012"},
	}

	if len(components) != len(tests) {
		t.Fatalf("got %d components, want %d: %+v", len(components), len(tests), components)
	}
	for i, tt := range tests {
		c := components[i]
		if c.Name != tt.name {
			t.Errorf("[%d] Name = %q, want %q", i, c.Name, tt.name)
		}
		if c.Version != tt.version {
			t.Errorf("[%d] Version = %q, want %q", i, c.Version, tt.version)
		}
		if c.Hash != tt.hash {
			t.Errorf("[%d] Hash = %q, want %q", i, c.Hash, tt.hash)
		}
	}
}
