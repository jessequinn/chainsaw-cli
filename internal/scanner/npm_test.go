package scanner

import (
	"context"
	"path/filepath"
	"sort"
	"testing"

	"github.com/chainsaw-dev/chainsaw/pkg/models"
)

func TestNpmScanner_Ecosystem(t *testing.T) {
	s := &NpmScanner{}
	if got := s.Ecosystem(); got != models.EcosystemNpm {
		t.Errorf("Ecosystem() = %q, want %q", got, models.EcosystemNpm)
	}
}

func TestNpmScanner_DetectManifests(t *testing.T) {
	t.Run("finds package-lock.json", func(t *testing.T) {
		dir := t.TempDir()
		writeFile(t, filepath.Join(dir, "package-lock.json"), "{}")

		s := &NpmScanner{}
		got, err := s.DetectManifests(context.Background(), dir)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(got) != 1 {
			t.Fatalf("got %d manifests, want 1", len(got))
		}
	})

	t.Run("skips node_modules", func(t *testing.T) {
		dir := t.TempDir()
		writeFile(t, filepath.Join(dir, "package-lock.json"), "{}")
		writeFile(t, filepath.Join(dir, "node_modules", "package-lock.json"), "{}")

		s := &NpmScanner{}
		got, err := s.DetectManifests(context.Background(), dir)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(got) != 1 {
			t.Fatalf("got %d manifests, want 1 (node_modules should be skipped)", len(got))
		}
	})

	t.Run("empty directory", func(t *testing.T) {
		dir := t.TempDir()
		s := &NpmScanner{}
		got, err := s.DetectManifests(context.Background(), dir)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(got) != 0 {
			t.Fatalf("got %d manifests, want 0", len(got))
		}
	})
}

func TestNpmScanner_ParseDependencies(t *testing.T) {
	fixtureDir, err := filepath.Abs("../../testdata/npm")
	if err != nil {
		t.Fatalf("abs path: %v", err)
	}

	s := &NpmScanner{}
	components, err := s.ParseDependencies(context.Background(), filepath.Join(fixtureDir, "package-lock.json"))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// 3 packages: express, lodash, @babel/core (root entry skipped).
	if len(components) != 3 {
		t.Fatalf("got %d components, want 3", len(components))
	}

	sort.Slice(components, func(i, j int) bool {
		return components[i].Name < components[j].Name
	})

	tests := []struct {
		name      string
		version   string
		purl      string
		integrity string
	}{
		{
			name:      "@babel/core",
			version:   "7.24.0",
			purl:      "pkg:npm/%40babel/core@7.24.0",
			integrity: "sha512-fQfkg0Gjkza3nf0c7/w6Xf34BW4YvzNfACRLmmb7XRLa6XHdR+K9AlJlxneFfWYf6uhOzuzZVTjF/8KfndRDA==",
		},
		{
			name:      "express",
			version:   "4.18.2",
			purl:      "pkg:npm/express@4.18.2",
			integrity: "sha512-5/PsL6iGPdfQ/lKM1UuielYgv3BUoJfz1aUwU9vHZ+J7gyvwdQXFEBIEIaxeGf0GIcreATNyBExtalisDbuMg==",
		},
		{
			name:      "lodash",
			version:   "4.17.21",
			purl:      "pkg:npm/lodash@4.17.21",
			integrity: "sha512-v2kDEe57lecTulaDIuNTPy3Ry4gLGJ6Z1O3vE1krgXZNrsQ+LFTGHVxVjcXPs17LhbZVGedAJv8XZ1tvj5cvA==",
		},
	}

	for i, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := components[i]
			if c.Name != tt.name {
				t.Errorf("Name = %q, want %q", c.Name, tt.name)
			}
			if c.Version != tt.version {
				t.Errorf("Version = %q, want %q", c.Version, tt.version)
			}
			if c.Ecosystem != models.EcosystemNpm {
				t.Errorf("Ecosystem = %q, want %q", c.Ecosystem, models.EcosystemNpm)
			}
			if c.PkgURL != tt.purl {
				t.Errorf("PkgURL = %q, want %q", c.PkgURL, tt.purl)
			}
			if c.Hash != tt.integrity {
				t.Errorf("Hash = %q, want %q", c.Hash, tt.integrity)
			}
		})
	}
}

func TestNpmScanner_ParseDependencies_EmptyPackages(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, "package-lock.json"), `{"lockfileVersion":3,"packages":{}}`)

	s := &NpmScanner{}
	components, err := s.ParseDependencies(context.Background(), filepath.Join(dir, "package-lock.json"))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(components) != 0 {
		t.Fatalf("got %d components, want 0", len(components))
	}
}

func TestNpmPackageName(t *testing.T) {
	tests := []struct {
		key  string
		want string
	}{
		{"node_modules/express", "express"},
		{"node_modules/@babel/core", "@babel/core"},
		{"node_modules/a/node_modules/b", "b"},
		{"plain-key", "plain-key"},
	}
	for _, tt := range tests {
		t.Run(tt.key, func(t *testing.T) {
			if got := npmPackageName(tt.key); got != tt.want {
				t.Errorf("npmPackageName(%q) = %q, want %q", tt.key, got, tt.want)
			}
		})
	}
}

func TestNpmPkgURL(t *testing.T) {
	tests := []struct {
		name, version, want string
	}{
		{"express", "4.18.2", "pkg:npm/express@4.18.2"},
		{"@babel/core", "7.24.0", "pkg:npm/%40babel/core@7.24.0"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := npmPkgURL(tt.name, tt.version); got != tt.want {
				t.Errorf("npmPkgURL(%q, %q) = %q, want %q", tt.name, tt.version, got, tt.want)
			}
		})
	}
}
