package initcmd

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestWriteGitLabCI_creates_file(t *testing.T) {
	dir := t.TempDir()
	path, err := WriteGitLabCI(dir)
	if err != nil {
		t.Fatalf("WriteGitLabCI: %v", err)
	}

	// Verify path is correct
	expected := filepath.Join(dir, ".gitlab-ci.yml")
	if path != expected {
		t.Errorf("expected path %q, got %q", expected, path)
	}

	// Verify file exists
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("file not created: %v", err)
	}
}

func TestWriteGitLabCI_contains_stages(t *testing.T) {
	dir := t.TempDir()
	path, err := WriteGitLabCI(dir)
	if err != nil {
		t.Fatalf("WriteGitLabCI: %v", err)
	}

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("reading file: %v", err)
	}

	content := string(data)
	checks := []string{
		"stages:",
		"- build",
		"- scan",
		"- comply",
		"build:",
		"scan:",
		"comply:",
	}

	for _, want := range checks {
		if !strings.Contains(content, want) {
			t.Errorf("GitLab CI missing %q", want)
		}
	}
}

func TestWriteGitLabCI_no_overwrite(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, ".gitlab-ci.yml")

	// Create file first
	if err := os.WriteFile(path, []byte("existing"), 0644); err != nil {
		t.Fatalf("creating initial file: %v", err)
	}

	// Try to write again
	_, err := WriteGitLabCI(dir)
	if err == nil {
		t.Fatal("expected error when file already exists")
	}
	if !strings.Contains(err.Error(), ".gitlab-ci.yml already exists") {
		t.Errorf("expected overwrite error, got: %v", err)
	}
}

func TestWriteGitLabCI_contains_sarif(t *testing.T) {
	dir := t.TempDir()
	path, err := WriteGitLabCI(dir)
	if err != nil {
		t.Fatalf("WriteGitLabCI: %v", err)
	}

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("reading file: %v", err)
	}

	content := string(data)
	if !strings.Contains(content, "sarif") {
		t.Error("GitLab CI missing sarif")
	}
	if !strings.Contains(content, "--format sarif") {
		t.Error("GitLab CI missing --format sarif flag")
	}
	if !strings.Contains(content, "sast:") {
		t.Error("GitLab CI missing sast report type")
	}
}

func TestWriteGitLabCI_contains_sbom(t *testing.T) {
	dir := t.TempDir()
	path, err := WriteGitLabCI(dir)
	if err != nil {
		t.Fatalf("WriteGitLabCI: %v", err)
	}

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("reading file: %v", err)
	}

	content := string(data)
	if !strings.Contains(content, "sbom:") {
		t.Error("GitLab CI missing sbom stage")
	}
	if !strings.Contains(content, "sbom --format json") {
		t.Error("GitLab CI missing sbom command")
	}
	if !strings.Contains(content, "sbom.cdx.json") {
		t.Error("GitLab CI missing SBOM artifact")
	}
}
