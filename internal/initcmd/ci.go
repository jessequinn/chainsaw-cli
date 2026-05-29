package initcmd

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// CIConfig holds configuration for CI workflow generation.
type CIConfig struct {
	GoVersion  string // e.g., "1.26"
	FailOn     string // severity threshold, e.g., "HIGH"
	PolicyPath string // path to .chainsaw.yaml
	Ecosystems string // comma-separated, empty = auto-detect
}

// DefaultCIConfig returns sensible defaults.
func DefaultCIConfig() CIConfig {
	return CIConfig{
		GoVersion:  "1.26",
		FailOn:     "HIGH",
		PolicyPath: ".chainsaw.yaml",
		Ecosystems: "",
	}
}

// GenerateGitHubWorkflow generates a .github/workflows/chainsaw.yml content string.
func GenerateGitHubWorkflow(cfg CIConfig) string {
	scanCmd := fmt.Sprintf("chainsaw scan --format sarif --fail-on %s", cfg.FailOn)
	if cfg.PolicyPath != "" {
		scanCmd += fmt.Sprintf(" --policy %s", cfg.PolicyPath)
	}
	if cfg.Ecosystems != "" {
		scanCmd += fmt.Sprintf(" --ecosystem %s", cfg.Ecosystems)
	}
	scanCmd += " > results.sarif"

	complyCmd := "chainsaw comply --format json"
	if cfg.PolicyPath != "" {
		complyCmd += fmt.Sprintf(" --policy %s", cfg.PolicyPath)
	}
	complyCmd += " > compliance.json"

	var b strings.Builder
	b.WriteString(`name: Chainsaw Supply Chain Scan

on:
  pull_request:
    branches: [main]
  push:
    branches: [main]

permissions:
  contents: read
  security-events: write

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v6

      - name: Set up Go
        uses: actions/setup-go@v6
        with:
          go-version: "`)
	b.WriteString(cfg.GoVersion)
	b.WriteString(`"

      - name: Install chainsaw
        run: go install github.com/chainsaw-dev/chainsaw/cmd/chainsaw@latest

      - name: Scan dependencies
        run: `)
	b.WriteString(scanCmd)
	b.WriteString(`
        continue-on-error: true

      - name: Upload SARIF
        uses: github/codeql-action/upload-sarif@v4
        with:
          sarif_file: results.sarif
        if: always()

      - name: CRA compliance check
        run: `)
	b.WriteString(complyCmd)
	b.WriteString(`

      - name: Supply chain analysis
        run: chainsaw supply-chain --format json > supply-chain.json

      - name: Upload artifacts
        uses: actions/upload-artifact@v7
        with:
          name: chainsaw-results
          path: |
            results.sarif
            compliance.json
            supply-chain.json
`)
	return b.String()
}

// WriteCIFiles writes the workflow file to the given root directory.
// It returns the list of created file paths relative to root.
func WriteCIFiles(root string, cfg CIConfig) ([]string, error) {
	workflowDir := filepath.Join(root, ".github", "workflows")
	if err := os.MkdirAll(workflowDir, 0o755); err != nil {
		return nil, fmt.Errorf("creating workflow directory: %w", err)
	}

	workflowPath := filepath.Join(workflowDir, "chainsaw.yml")
	content := GenerateGitHubWorkflow(cfg)

	if err := os.WriteFile(workflowPath, []byte(content), 0o644); err != nil {
		return nil, fmt.Errorf("writing workflow file: %w", err)
	}

	rel, err := filepath.Rel(root, workflowPath)
	if err != nil {
		rel = workflowPath
	}

	return []string{rel}, nil
}
