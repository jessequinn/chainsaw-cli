package initcmd

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestGenerateSecurityMD(t *testing.T) {
	cfg := DefaultSecurityConfig()
	cfg.SecurityEmail = "sec@acme.com"
	out := GenerateSecurityMD(cfg)

	required := []string{
		"# Security Policy",
		"## Supported Versions",
		"## Reporting a Vulnerability",
		"sec@acme.com",
		"## Response Timeline",
		"48 hours",
		"90 days",
		"## Disclosure Policy",
		"## Scope",
	}
	for _, s := range required {
		if !strings.Contains(out, s) {
			t.Errorf("SECURITY.md missing %q", s)
		}
	}
}

func TestGenerateSecurityTxt(t *testing.T) {
	cfg := DefaultSecurityConfig()
	cfg.SecurityEmail = "sec@acme.com"
	out := GenerateSecurityTxt(cfg)

	required := []string{
		"Contact: mailto:sec@acme.com",
		"Expires:",
		"Preferred-Languages: en",
		"Canonical:",
		"Policy:",
	}
	for _, s := range required {
		if !strings.Contains(out, s) {
			t.Errorf("security.txt missing %q", s)
		}
	}
}

func TestGenerateChainsawYAML(t *testing.T) {
	cfg := DefaultSecurityConfig()
	cfg.OrgName = "Acme Corp"
	cfg.SecurityEmail = "sec@acme.com"
	out := GenerateChainsawYAML(cfg)

	if !strings.Contains(out, "cra:") {
		t.Error("missing cra section")
	}
	if !strings.Contains(out, "Acme Corp") {
		t.Error("missing org name")
	}
	if !strings.Contains(out, "sec@acme.com") {
		t.Error("missing security email")
	}
}

func TestWriteSecurityFiles(t *testing.T) {
	dir := t.TempDir()
	cfg := DefaultSecurityConfig()

	written, err := WriteSecurityFiles(dir, cfg)
	if err != nil {
		t.Fatalf("WriteSecurityFiles: %v", err)
	}

	expected := []string{
		"SECURITY.md",
		filepath.Join(".well-known", "security.txt"),
		".chainsaw.yaml",
	}

	if len(written) != len(expected) {
		t.Fatalf("expected %d files, got %d", len(expected), len(written))
	}

	for i, rel := range expected {
		if written[i] != rel {
			t.Errorf("written[%d] = %q, want %q", i, written[i], rel)
		}
		full := filepath.Join(dir, rel)
		info, err := os.Stat(full)
		if err != nil {
			t.Errorf("file %s not found: %v", rel, err)
			continue
		}
		if info.Size() == 0 {
			t.Errorf("file %s is empty", rel)
		}
	}
}
