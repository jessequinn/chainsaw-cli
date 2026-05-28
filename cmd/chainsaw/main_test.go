package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// executeCommand runs the CLI with the given args and returns stdout, stderr,
// and any error. Note: many commands write directly to os.Stdout instead of
// cmd.OutOrStdout(), so captured stdout may be empty for those commands.
func executeCommand(t *testing.T, args ...string) (string, string, error) {
	t.Helper()
	cmd := rootCmd()

	outBuf := new(bytes.Buffer)
	errBuf := new(bytes.Buffer)
	cmd.SetOut(outBuf)
	cmd.SetErr(errBuf)
	cmd.SetArgs(args)

	err := cmd.Execute()
	return outBuf.String(), errBuf.String(), err
}

func TestVersionCommand(t *testing.T) {
	// versionCmd uses fmt.Printf (os.Stdout), so capture via pipe.
	old := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w

	_, _, err := executeCommand(t, "version")

	w.Close()
	os.Stdout = old

	var buf bytes.Buffer
	buf.ReadFrom(r)
	output := buf.String()

	if err != nil {
		t.Fatalf("version command returned error: %v", err)
	}
	if !strings.Contains(output, "chainsaw") {
		t.Errorf("expected output to contain 'chainsaw', got: %q", output)
	}
}

func TestHelpCommand(t *testing.T) {
	stdout, _, err := executeCommand(t, "--help")
	if err != nil {
		t.Fatalf("help command returned error: %v", err)
	}

	for _, sub := range []string{"scan", "sbom", "comply", "supply-chain", "diff", "init-security", "init-ci", "version"} {
		if !strings.Contains(stdout, sub) {
			t.Errorf("help output missing command %q", sub)
		}
	}
}

func TestScanCommand_CurrentDir(t *testing.T) {
	// scan writes to os.Stdout directly; just verify no error.
	// Also may call os.Exit on policy violations, so we only test the
	// happy path with the repo root which should have no critical vulns.
	old := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w

	_, _, err := executeCommand(t, "scan", "--ecosystem", "go", ".")

	w.Close()
	os.Stdout = old

	var buf bytes.Buffer
	buf.ReadFrom(r)

	if err != nil {
		t.Fatalf("scan command returned error: %v", err)
	}
}

func TestScanCommand_WithFormat_JSON(t *testing.T) {
	old := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w

	_, _, err := executeCommand(t, "scan", "--format", "json", "--ecosystem", "go", ".")

	w.Close()
	os.Stdout = old

	var buf bytes.Buffer
	buf.ReadFrom(r)
	output := buf.String()

	if err != nil {
		t.Fatalf("scan --format json returned error: %v", err)
	}
	// JSON output should start with { or [
	trimmed := strings.TrimSpace(output)
	if len(trimmed) == 0 {
		t.Fatal("expected JSON output, got empty string")
	}
	if trimmed[0] != '{' && trimmed[0] != '[' {
		t.Errorf("expected JSON output starting with '{' or '[', got: %.100s", trimmed)
	}
}

func TestScanCommand_WithFormat_SARIF(t *testing.T) {
	old := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w

	_, _, err := executeCommand(t, "scan", "--format", "sarif", "--ecosystem", "go", ".")

	w.Close()
	os.Stdout = old

	var buf bytes.Buffer
	buf.ReadFrom(r)
	output := buf.String()

	if err != nil {
		t.Fatalf("scan --format sarif returned error: %v", err)
	}
	if !strings.Contains(output, "$schema") && !strings.Contains(output, "sarifLog") && !strings.Contains(output, "sarif") {
		t.Errorf("expected SARIF output, got: %.200s", output)
	}
}

func TestScanCommand_InvalidFormat(t *testing.T) {
	_, _, err := executeCommand(t, "scan", "--format", "xml", "--ecosystem", "go", ".")
	if err == nil {
		t.Fatal("expected error for invalid format 'xml', got nil")
	}
	if !strings.Contains(err.Error(), "unsupported") {
		t.Errorf("expected 'unsupported' in error, got: %v", err)
	}
}

func TestScanCommand_InvalidPath(t *testing.T) {
	// Should not panic on a nonexistent path.
	_, _, _ = executeCommand(t, "scan", "--ecosystem", "go", "/nonexistent/path/that/does/not/exist")
}

func TestScanCommand_WithEcosystem(t *testing.T) {
	old := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w

	_, _, err := executeCommand(t, "scan", "--ecosystem", "go", ".")

	w.Close()
	os.Stdout = old

	var buf bytes.Buffer
	buf.ReadFrom(r)

	if err != nil {
		t.Fatalf("scan --ecosystem go returned error: %v", err)
	}
}

func TestSbomCommand(t *testing.T) {
	old := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w

	_, _, err := executeCommand(t, "sbom", ".")

	w.Close()
	os.Stdout = old

	var buf bytes.Buffer
	buf.ReadFrom(r)
	output := buf.String()

	if err != nil {
		t.Fatalf("sbom command returned error: %v", err)
	}
	if !strings.Contains(output, "CycloneDX") && !strings.Contains(output, "cyclonedx") && !strings.Contains(output, "bomFormat") {
		t.Errorf("expected CycloneDX output, got: %.200s", output)
	}
}

func TestComplyCommand(t *testing.T) {
	old := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w

	_, _, err := executeCommand(t, "comply", ".")

	w.Close()
	os.Stdout = old

	var buf bytes.Buffer
	buf.ReadFrom(r)
	output := buf.String()

	if err != nil {
		t.Fatalf("comply command returned error: %v", err)
	}
	if !strings.Contains(output, "CRA") && !strings.Contains(output, "Compliance") && !strings.Contains(output, "compliance") {
		t.Errorf("expected CRA compliance output, got: %.200s", output)
	}
}

func TestSupplyChainCommand(t *testing.T) {
	old := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w

	_, _, err := executeCommand(t, "supply-chain", ".")

	w.Close()
	os.Stdout = old

	var buf bytes.Buffer
	buf.ReadFrom(r)
	output := buf.String()

	if err != nil {
		t.Fatalf("supply-chain command returned error: %v", err)
	}
	if !strings.Contains(output, "Supply Chain") && !strings.Contains(output, "Pinning") && !strings.Contains(output, "pinning") {
		t.Errorf("expected supply chain output, got: %.200s", output)
	}
}

func TestDiffCommand_MissingFlags(t *testing.T) {
	_, _, err := executeCommand(t, "diff")
	if err == nil {
		t.Fatal("expected error for diff without --base/--head, got nil")
	}
}

func TestInitSecurityCommand(t *testing.T) {
	tmpDir := t.TempDir()

	old := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w

	_, _, err := executeCommand(t, "init-security", tmpDir, "--non-interactive")

	w.Close()
	os.Stdout = old

	var buf bytes.Buffer
	buf.ReadFrom(r)

	if err != nil {
		t.Fatalf("init-security returned error: %v", err)
	}

	securityMD := filepath.Join(tmpDir, "SECURITY.md")
	if _, statErr := os.Stat(securityMD); os.IsNotExist(statErr) {
		t.Errorf("expected SECURITY.md to exist in %s", tmpDir)
	}
}

func TestInitCICommand(t *testing.T) {
	tmpDir := t.TempDir()

	old := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w

	_, _, err := executeCommand(t, "init-ci", tmpDir)

	w.Close()
	os.Stdout = old

	var buf bytes.Buffer
	buf.ReadFrom(r)

	if err != nil {
		t.Fatalf("init-ci returned error: %v", err)
	}

	workflow := filepath.Join(tmpDir, ".github", "workflows", "chainsaw.yml")
	if _, statErr := os.Stat(workflow); os.IsNotExist(statErr) {
		t.Errorf("expected chainsaw.yml to exist at %s", workflow)
	}
}
