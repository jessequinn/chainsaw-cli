package scanner

import (
	"context"
	"path/filepath"
	"sort"
	"testing"

	"github.com/chainsaw-dev/chainsaw/pkg/models"
)

func TestElixirScanner_Ecosystem(t *testing.T) {
	s := &ElixirScanner{}
	if got := s.Ecosystem(); got != models.EcosystemHex {
		t.Errorf("Ecosystem() = %q, want %q", got, models.EcosystemHex)
	}
}

func TestElixirScanner_DetectManifests(t *testing.T) {
	t.Run("finds mix.lock files", func(t *testing.T) {
		dir := t.TempDir()
		writeFile(t, filepath.Join(dir, "mix.lock"), "%{}\n")
		writeFile(t, filepath.Join(dir, "sub", "mix.lock"), "%{}\n")

		s := &ElixirScanner{}
		got, err := s.DetectManifests(context.Background(), dir)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(got) != 2 {
			t.Fatalf("got %d manifests, want 2", len(got))
		}
	})

	t.Run("skips _build directory", func(t *testing.T) {
		dir := t.TempDir()
		writeFile(t, filepath.Join(dir, "mix.lock"), "%{}\n")
		writeFile(t, filepath.Join(dir, "_build", "mix.lock"), "%{}\n")

		s := &ElixirScanner{}
		got, err := s.DetectManifests(context.Background(), dir)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(got) != 1 {
			t.Fatalf("got %d manifests, want 1 (_build should be skipped)", len(got))
		}
	})

	t.Run("skips deps directory", func(t *testing.T) {
		dir := t.TempDir()
		writeFile(t, filepath.Join(dir, "mix.lock"), "%{}\n")
		writeFile(t, filepath.Join(dir, "deps", "mix.lock"), "%{}\n")

		s := &ElixirScanner{}
		got, err := s.DetectManifests(context.Background(), dir)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(got) != 1 {
			t.Fatalf("got %d manifests, want 1 (deps should be skipped)", len(got))
		}
	})

	t.Run("skips .elixir_ls directory", func(t *testing.T) {
		dir := t.TempDir()
		writeFile(t, filepath.Join(dir, "mix.lock"), "%{}\n")
		writeFile(t, filepath.Join(dir, ".elixir_ls", "mix.lock"), "%{}\n")

		s := &ElixirScanner{}
		got, err := s.DetectManifests(context.Background(), dir)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(got) != 1 {
			t.Fatalf("got %d manifests, want 1 (.elixir_ls should be skipped)", len(got))
		}
	})

	t.Run("empty directory returns no manifests", func(t *testing.T) {
		dir := t.TempDir()
		s := &ElixirScanner{}
		got, err := s.DetectManifests(context.Background(), dir)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(got) != 0 {
			t.Fatalf("got %d manifests, want 0", len(got))
		}
	})
}

func TestElixirScanner_ParseDependencies(t *testing.T) {
	fixtureDir, err := filepath.Abs("../../testdata/elixir")
	if err != nil {
		t.Fatalf("abs path: %v", err)
	}
	manifestPath := filepath.Join(fixtureDir, "mix.lock")

	s := &ElixirScanner{}
	components, err := s.ParseDependencies(context.Background(), manifestPath)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Should contain 3 hex packages (castore, phoenix, ecto_sql), git dep skipped.
	if len(components) != 3 {
		t.Fatalf("got %d components, want 3", len(components))
	}

	sort.Slice(components, func(i, j int) bool {
		return components[i].Name < components[j].Name
	})

	tests := []struct {
		name    string
		version string
		purl    string
		hash    string
	}{
		{
			name:    "castore",
			version: "1.0.4",
			purl:    "pkg:hex/castore@1.0.4",
			hash:    "ff4dedf6c81c7e9f355d3bde1f38c27b7e2f4454d0a1a963e3033180729f87f9",
		},
		{
			name:    "ecto_sql",
			version: "3.11.1",
			purl:    "pkg:hex/ecto_sql@3.11.1",
			hash:    "4be357c0c300d84bee7aa7e3e4c09e0838fe68e0f5e78e0bc4b4393fea13b7ab",
		},
		{
			name:    "phoenix",
			version: "1.7.10",
			purl:    "pkg:hex/phoenix@1.7.10",
			hash:    "02189140a61b2ce85bb633a9b6fd02dfa64590c51c4bcf3e468a3112a44a9b38",
		},
	}

	for i, tt := range tests {
		if components[i].Name != tt.name {
			t.Errorf("component[%d].Name = %q, want %q", i, components[i].Name, tt.name)
		}
		if components[i].Version != tt.version {
			t.Errorf("component[%d].Version = %q, want %q", i, components[i].Version, tt.version)
		}
		if components[i].PkgURL != tt.purl {
			t.Errorf("component[%d].PkgURL = %q, want %q", i, components[i].PkgURL, tt.purl)
		}
		if components[i].Hash != tt.hash {
			t.Errorf("component[%d].Hash = %q, want %q", i, components[i].Hash, tt.hash)
		}
		if components[i].Ecosystem != models.EcosystemHex {
			t.Errorf("component[%d].Ecosystem = %q, want %q", i, components[i].Ecosystem, models.EcosystemHex)
		}
	}
}

func TestElixirScanner_ParseDependencies_SkipsGitDeps(t *testing.T) {
	fixtureDir, err := filepath.Abs("../../testdata/elixir")
	if err != nil {
		t.Fatalf("abs path: %v", err)
	}
	manifestPath := filepath.Join(fixtureDir, "mix.lock")

	s := &ElixirScanner{}
	components, err := s.ParseDependencies(context.Background(), manifestPath)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Verify that git dependency (some_git_dep) is not included
	for _, c := range components {
		if c.Name == "some_git_dep" {
			t.Errorf("git dependency should be skipped, but found: %v", c)
		}
	}
}
