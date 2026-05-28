package scanner

import (
	"context"
	"path/filepath"
	"sort"
	"testing"

	"github.com/chainsaw-dev/chainsaw/pkg/models"
)

func TestPythonScanner_Ecosystem(t *testing.T) {
	s := &PythonScanner{}
	if got := s.Ecosystem(); got != models.EcosystemPyPI {
		t.Errorf("Ecosystem() = %q, want %q", got, models.EcosystemPyPI)
	}
}

func TestPythonScanner_DetectManifests(t *testing.T) {
	t.Run("finds requirements.txt and poetry.lock", func(t *testing.T) {
		dir := t.TempDir()
		writeFile(t, filepath.Join(dir, "requirements.txt"), "requests==2.31.0\n")
		writeFile(t, filepath.Join(dir, "sub", "poetry.lock"), "[[package]]\n")

		s := &PythonScanner{}
		got, err := s.DetectManifests(context.Background(), dir)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(got) != 2 {
			t.Fatalf("got %d manifests, want 2", len(got))
		}
	})

	t.Run("skips venv and __pycache__", func(t *testing.T) {
		dir := t.TempDir()
		writeFile(t, filepath.Join(dir, "requirements.txt"), "requests==2.31.0\n")
		writeFile(t, filepath.Join(dir, "venv", "requirements.txt"), "internal\n")
		writeFile(t, filepath.Join(dir, ".venv", "requirements.txt"), "internal\n")
		writeFile(t, filepath.Join(dir, "__pycache__", "requirements.txt"), "internal\n")

		s := &PythonScanner{}
		got, err := s.DetectManifests(context.Background(), dir)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(got) != 1 {
			t.Fatalf("got %d manifests, want 1", len(got))
		}
	})

	t.Run("empty directory", func(t *testing.T) {
		dir := t.TempDir()
		s := &PythonScanner{}
		got, err := s.DetectManifests(context.Background(), dir)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(got) != 0 {
			t.Fatalf("got %d manifests, want 0", len(got))
		}
	})
}

func TestPythonScanner_ParseRequirements(t *testing.T) {
	fixtureDir, err := filepath.Abs("../../testdata/python")
	if err != nil {
		t.Fatalf("abs path: %v", err)
	}

	s := &PythonScanner{}
	components, err := s.ParseDependencies(context.Background(), filepath.Join(fixtureDir, "requirements.txt"))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Should parse: requests==2.31.0, numpy==1.26.4, boto3==1.34.0, Flask_Cors==4.0.0
	// Should skip: flask>=3.0.0 (no ==), comment, -e editable
	if len(components) != 4 {
		t.Fatalf("got %d components, want 4; components: %+v", len(components), components)
	}

	sort.Slice(components, func(i, j int) bool {
		return components[i].Name < components[j].Name
	})

	tests := []struct {
		name    string
		version string
		purl    string
	}{
		{"boto3", "1.34.0", "pkg:pypi/boto3@1.34.0"},
		{"flask-cors", "4.0.0", "pkg:pypi/flask-cors@4.0.0"},
		{"numpy", "1.26.4", "pkg:pypi/numpy@1.26.4"},
		{"requests", "2.31.0", "pkg:pypi/requests@2.31.0"},
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
			if c.Ecosystem != models.EcosystemPyPI {
				t.Errorf("Ecosystem = %q, want %q", c.Ecosystem, models.EcosystemPyPI)
			}
			if c.PkgURL != tt.purl {
				t.Errorf("PkgURL = %q, want %q", c.PkgURL, tt.purl)
			}
		})
	}
}

func TestPythonScanner_ParsePoetryLock(t *testing.T) {
	fixtureDir, err := filepath.Abs("../../testdata/python")
	if err != nil {
		t.Fatalf("abs path: %v", err)
	}

	s := &PythonScanner{}
	components, err := s.ParseDependencies(context.Background(), filepath.Join(fixtureDir, "poetry.lock"))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(components) != 3 {
		t.Fatalf("got %d components, want 3", len(components))
	}

	sort.Slice(components, func(i, j int) bool {
		return components[i].Name < components[j].Name
	})

	tests := []struct {
		name    string
		version string
	}{
		{"flask", "3.0.2"},
		{"numpy", "1.26.4"},
		{"requests", "2.31.0"},
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
			if c.Ecosystem != models.EcosystemPyPI {
				t.Errorf("Ecosystem = %q, want %q", c.Ecosystem, models.EcosystemPyPI)
			}
		})
	}
}

func TestNormalizePyPIName(t *testing.T) {
	tests := []struct {
		input, want string
	}{
		{"Flask_Cors", "flask-cors"},
		{"requests", "requests"},
		{"My.Package", "my-package"},
		{"some__dashed---pkg", "some-dashed-pkg"},
		{"UPPER_CASE", "upper-case"},
	}
	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			if got := normalizePyPIName(tt.input); got != tt.want {
				t.Errorf("normalizePyPIName(%q) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}

func TestPythonScanner_ParseRequirements_WithHashes(t *testing.T) {
	dir := t.TempDir()
	content := `requests==2.31.0 --hash=sha256:abcdef1234567890
`
	writeFile(t, filepath.Join(dir, "requirements.txt"), content)

	s := &PythonScanner{}
	components, err := s.ParseDependencies(context.Background(), filepath.Join(dir, "requirements.txt"))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(components) != 1 {
		t.Fatalf("got %d components, want 1", len(components))
	}
	if components[0].Hash != "sha256:abcdef1234567890" {
		t.Errorf("Hash = %q, want %q", components[0].Hash, "sha256:abcdef1234567890")
	}
}

func TestPythonScanner_ParseDependencies_UnknownManifest(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, "setup.py"), "")

	s := &PythonScanner{}
	_, err := s.ParseDependencies(context.Background(), filepath.Join(dir, "setup.py"))
	if err == nil {
		t.Fatal("expected error for unknown manifest type")
	}
}
