package scanner

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/chainsaw-dev/chainsaw/pkg/models"
)

func TestAnsibleScanner_Ecosystem(t *testing.T) {
	s := &AnsibleScanner{}
	if got := s.Ecosystem(); got != models.EcosystemAnsible {
		t.Fatalf("Ecosystem() = %q, want %q", got, models.EcosystemAnsible)
	}
}

func TestAnsibleScanner_DetectManifests(t *testing.T) {
	dir := t.TempDir()

	if err := os.WriteFile(filepath.Join(dir, "requirements.yml"), []byte(""), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "playbook.yml"), []byte(""), 0o644); err != nil {
		t.Fatal(err)
	}
	// .ansible/ and molecule/ should be skipped
	for _, skip := range []string{".ansible", "molecule"} {
		d := filepath.Join(dir, skip)
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(d, "requirements.yml"), []byte(""), 0o644); err != nil {
			t.Fatal(err)
		}
	}

	ctx := context.Background()
	s := &AnsibleScanner{}
	manifests, err := s.DetectManifests(ctx, dir)
	if err != nil {
		t.Fatalf("DetectManifests: %v", err)
	}
	if len(manifests) != 1 {
		t.Fatalf("got %d manifests, want 1: %v", len(manifests), manifests)
	}
}

func TestAnsibleScanner_ParseDependencies(t *testing.T) {
	ctx := context.Background()
	s := &AnsibleScanner{}
	manifestPath := filepath.Join("..", "..", "testdata", "ansible", "requirements.yml")

	components, err := s.ParseDependencies(ctx, manifestPath)
	if err != nil {
		t.Fatalf("ParseDependencies: %v", err)
	}

	tests := []struct {
		name    string
		version string
	}{
		{"community.general", "8.3.0"},
		{"amazon.aws", "7.2.0"},
		{"ansible.posix", "unspecified"},
		{"geerlingguy.docker", "6.1.0"},
		{"geerlingguy.nginx", "unspecified"},
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
		if c.Ecosystem != models.EcosystemAnsible {
			t.Errorf("[%d] Ecosystem = %q, want %q", i, c.Ecosystem, models.EcosystemAnsible)
		}
	}
}
