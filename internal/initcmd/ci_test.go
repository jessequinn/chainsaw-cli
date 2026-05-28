package initcmd

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestGenerateGitHubWorkflow(t *testing.T) {
	cfg := DefaultCIConfig()
	out := GenerateGitHubWorkflow(cfg)

	checks := []string{
		"name: Chainsaw Supply Chain Scan",
		"actions/checkout@v4",
		"actions/setup-go@v5",
		"go install github.com/chainsaw-dev/chainsaw/cmd/chainsaw@latest",
		"--fail-on HIGH",
		"--format sarif",
		"upload-sarif@v3",
		"results.sarif",
		"chainsaw comply --format json",
		"chainsaw supply-chain --format json",
		"upload-artifact@v4",
		"compliance.json",
		"supply-chain.json",
		"continue-on-error: true",
		"permissions:",
		"security-events: write",
	}
	for _, want := range checks {
		if !strings.Contains(out, want) {
			t.Errorf("workflow missing %q", want)
		}
	}
}

func TestGenerateGitHubWorkflow_customConfig(t *testing.T) {
	cfg := CIConfig{
		GoVersion:  "1.23",
		FailOn:     "CRITICAL",
		PolicyPath: "policy.yaml",
		Ecosystems: "go,npm",
	}
	out := GenerateGitHubWorkflow(cfg)

	checks := []string{
		`go-version: "1.23"`,
		"--fail-on CRITICAL",
		"--policy policy.yaml",
		"--ecosystem go,npm",
	}
	for _, want := range checks {
		if !strings.Contains(out, want) {
			t.Errorf("workflow missing %q", want)
		}
	}
}

func TestWriteCIFiles(t *testing.T) {
	dir := t.TempDir()
	cfg := DefaultCIConfig()

	written, err := WriteCIFiles(dir, cfg)
	if err != nil {
		t.Fatalf("WriteCIFiles: %v", err)
	}

	if len(written) != 1 {
		t.Fatalf("expected 1 file, got %d", len(written))
	}

	expected := filepath.Join(".github", "workflows", "chainsaw.yml")
	if written[0] != expected {
		t.Errorf("expected path %q, got %q", expected, written[0])
	}

	fullPath := filepath.Join(dir, expected)
	data, err := os.ReadFile(fullPath)
	if err != nil {
		t.Fatalf("reading workflow file: %v", err)
	}

	if !strings.Contains(string(data), "Chainsaw Supply Chain Scan") {
		t.Error("workflow file missing expected content")
	}
}
