package scanner

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/chainsaw-dev/chainsaw/pkg/models"
)

func TestTerraformScanner_Ecosystem(t *testing.T) {
	s := &TerraformScanner{}
	if got := s.Ecosystem(); got != models.EcosystemTerraform {
		t.Fatalf("Ecosystem() = %q, want %q", got, models.EcosystemTerraform)
	}
}

func TestTerraformScanner_DetectManifests(t *testing.T) {
	dir := t.TempDir()

	// Create .terraform.lock.hcl and a decoy file
	for _, name := range []string{".terraform.lock.hcl", "main.tf"} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(""), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	// .terraform/ dir should be skipped
	terraDir := filepath.Join(dir, ".terraform")
	if err := os.MkdirAll(terraDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(terraDir, ".terraform.lock.hcl"), []byte(""), 0o644); err != nil {
		t.Fatal(err)
	}

	ctx := context.Background()
	s := &TerraformScanner{}
	manifests, err := s.DetectManifests(ctx, dir)
	if err != nil {
		t.Fatalf("DetectManifests: %v", err)
	}
	if len(manifests) != 1 {
		t.Fatalf("got %d manifests, want 1: %v", len(manifests), manifests)
	}
	if filepath.Base(manifests[0]) != ".terraform.lock.hcl" {
		t.Errorf("unexpected manifest: %s", manifests[0])
	}
}

func TestTerraformScanner_ParseDependencies(t *testing.T) {
	ctx := context.Background()
	s := &TerraformScanner{}
	manifestPath := filepath.Join("..", "..", "testdata", "terraform", ".terraform.lock.hcl")

	components, err := s.ParseDependencies(ctx, manifestPath)
	if err != nil {
		t.Fatalf("ParseDependencies: %v", err)
	}

	tests := []struct {
		name    string
		version string
		hash    string
	}{
		{"hashicorp/aws", "5.31.0", "zh:def456"},
		{"hashicorp/random", "3.6.0", ""},
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
		if c.Ecosystem != models.EcosystemTerraform {
			t.Errorf("[%d] Ecosystem = %q, want %q", i, c.Ecosystem, models.EcosystemTerraform)
		}
	}
}
