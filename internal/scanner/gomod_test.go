package scanner

import (
	"context"
	"os"
	"path/filepath"
	"sort"
	"testing"

	"github.com/chainsaw-dev/chainsaw/pkg/models"
)

func TestGoScanner_Ecosystem(t *testing.T) {
	s := &GoScanner{}
	if got := s.Ecosystem(); got != models.EcosystemGo {
		t.Errorf("Ecosystem() = %q, want %q", got, models.EcosystemGo)
	}
}

func TestGoScanner_DetectManifests(t *testing.T) {
	t.Run("finds go.mod files", func(t *testing.T) {
		dir := t.TempDir()
		writeFile(t, filepath.Join(dir, "go.mod"), "module test\n")
		writeFile(t, filepath.Join(dir, "sub", "go.mod"), "module test/sub\n")

		s := &GoScanner{}
		got, err := s.DetectManifests(context.Background(), dir)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(got) != 2 {
			t.Fatalf("got %d manifests, want 2", len(got))
		}
	})

	t.Run("skips vendor directory", func(t *testing.T) {
		dir := t.TempDir()
		writeFile(t, filepath.Join(dir, "go.mod"), "module test\n")
		writeFile(t, filepath.Join(dir, "vendor", "go.mod"), "module vendored\n")

		s := &GoScanner{}
		got, err := s.DetectManifests(context.Background(), dir)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(got) != 1 {
			t.Fatalf("got %d manifests, want 1", len(got))
		}
	})

	t.Run("empty directory returns no manifests", func(t *testing.T) {
		dir := t.TempDir()
		s := &GoScanner{}
		got, err := s.DetectManifests(context.Background(), dir)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(got) != 0 {
			t.Fatalf("got %d manifests, want 0", len(got))
		}
	})
}

func TestGoScanner_ParseDependencies(t *testing.T) {
	fixtureDir, err := filepath.Abs("../../testdata/gomod")
	if err != nil {
		t.Fatalf("abs path: %v", err)
	}
	manifestPath := filepath.Join(fixtureDir, "go.mod")

	s := &GoScanner{}
	components, err := s.ParseDependencies(context.Background(), manifestPath)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Should only contain direct dependencies (not indirect).
	if len(components) != 2 {
		t.Fatalf("got %d components, want 2", len(components))
	}

	sort.Slice(components, func(i, j int) bool {
		return components[i].Name < components[j].Name
	})

	tests := []struct {
		name    string
		version string
		purl    string
		hasHash bool
		direct  bool
	}{
		{
			name:    "github.com/gin-gonic/gin",
			version: "v1.9.1",
			purl:    "pkg:golang/github.com/gin-gonic/gin@v1.9.1",
			hasHash: true,
			direct:  true,
		},
		{
			name:    "golang.org/x/text",
			version: "v0.14.0",
			purl:    "pkg:golang/golang.org/x/text@v0.14.0",
			hasHash: true,
			direct:  true,
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
			if c.Ecosystem != models.EcosystemGo {
				t.Errorf("Ecosystem = %q, want %q", c.Ecosystem, models.EcosystemGo)
			}
			if c.PkgURL != tt.purl {
				t.Errorf("PkgURL = %q, want %q", c.PkgURL, tt.purl)
			}
			if tt.hasHash && c.Hash == "" {
				t.Error("expected non-empty Hash from go.sum")
			}
			if c.Direct != tt.direct {
				t.Errorf("Direct = %v, want %v", c.Direct, tt.direct)
			}
		})
	}
}

func TestGoScanner_ParseDependencies_NoGoSum(t *testing.T) {
	dir := t.TempDir()
	gomod := `module example.com/nosumtest

go 1.22

require golang.org/x/text v0.14.0
`
	writeFile(t, filepath.Join(dir, "go.mod"), gomod)

	s := &GoScanner{}
	components, err := s.ParseDependencies(context.Background(), filepath.Join(dir, "go.mod"))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(components) != 1 {
		t.Fatalf("got %d components, want 1", len(components))
	}
	if components[0].Hash != "" {
		t.Errorf("expected empty Hash without go.sum, got %q", components[0].Hash)
	}
}

// writeFile creates parent dirs and writes content to path.
func writeFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}
}
