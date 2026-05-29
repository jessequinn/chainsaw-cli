package cra

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/chainsaw-dev/chainsaw/pkg/models"
)

func TestSecureDefaults_NoDockerfilesNoWorkflows(t *testing.T) {
	dir := t.TempDir()
	checker := &SecureDefaultsChecker{}
	actx := &AssessmentContext{RootPath: dir}

	checks := checker.Check(actx)

	if len(checks) != 2 {
		t.Fatalf("expected 2 checks, got %d", len(checks))
	}

	// Both should be N/A
	if checks[0].Status != models.CRANA {
		t.Errorf("Dockerfile check status = %q, want %q", checks[0].Status, models.CRANA)
	}
	if checks[1].Status != models.CRANA {
		t.Errorf("GitHub Actions check status = %q, want %q", checks[1].Status, models.CRANA)
	}
}

func TestSecureDefaults_DockerfileWithUserDirective(t *testing.T) {
	dir := t.TempDir()
	dockerfile := `FROM alpine:latest
RUN apk add --no-cache curl
USER appuser
ENTRYPOINT ["curl"]
`
	if err := os.WriteFile(filepath.Join(dir, "Dockerfile"), []byte(dockerfile), 0o644); err != nil {
		t.Fatal(err)
	}

	checker := &SecureDefaultsChecker{}
	actx := &AssessmentContext{RootPath: dir}

	checks := checker.Check(actx)
	dockerfileCheck := checks[0]

	if dockerfileCheck.Status != models.CRAPass {
		t.Errorf("Dockerfile check status = %q, want %q", dockerfileCheck.Status, models.CRAPass)
	}
}

func TestSecureDefaults_DockerfileWithoutUserDirective(t *testing.T) {
	dir := t.TempDir()
	dockerfile := `FROM alpine:latest
RUN apk add --no-cache curl
ENTRYPOINT ["curl"]
`
	if err := os.WriteFile(filepath.Join(dir, "Dockerfile"), []byte(dockerfile), 0o644); err != nil {
		t.Fatal(err)
	}

	checker := &SecureDefaultsChecker{}
	actx := &AssessmentContext{RootPath: dir}

	checks := checker.Check(actx)
	dockerfileCheck := checks[0]

	if dockerfileCheck.Status != models.CRAWarn {
		t.Errorf("Dockerfile check status = %q, want %q", dockerfileCheck.Status, models.CRAWarn)
	}
	if !strings.Contains(dockerfileCheck.Details, "No USER directive") {
		t.Errorf("Details should mention missing USER directive, got: %s", dockerfileCheck.Details)
	}
}

func TestSecureDefaults_DockerfileWithPrivileged(t *testing.T) {
	dir := t.TempDir()
	dockerfile := `FROM alpine:latest
RUN apk add --no-cache curl
USER appuser
RUN --privileged echo "test"
`
	if err := os.WriteFile(filepath.Join(dir, "Dockerfile"), []byte(dockerfile), 0o644); err != nil {
		t.Fatal(err)
	}

	checker := &SecureDefaultsChecker{}
	actx := &AssessmentContext{RootPath: dir}

	checks := checker.Check(actx)
	dockerfileCheck := checks[0]

	if dockerfileCheck.Status != models.CRAWarn {
		t.Errorf("Dockerfile check status = %q, want %q", dockerfileCheck.Status, models.CRAWarn)
	}
	if !strings.Contains(dockerfileCheck.Details, "--privileged") {
		t.Errorf("Details should mention --privileged flag, got: %s", dockerfileCheck.Details)
	}
}

func TestSecureDefaults_WorkflowWithPermissionsBlock(t *testing.T) {
	dir := t.TempDir()
	wfDir := filepath.Join(dir, ".github", "workflows")
	if err := os.MkdirAll(wfDir, 0o755); err != nil {
		t.Fatal(err)
	}

	workflow := `name: CI
on: push
permissions:
  contents: read
  actions: read
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
`
	if err := os.WriteFile(filepath.Join(wfDir, "ci.yml"), []byte(workflow), 0o644); err != nil {
		t.Fatal(err)
	}

	checker := &SecureDefaultsChecker{}
	actx := &AssessmentContext{RootPath: dir}

	checks := checker.Check(actx)
	workflowCheck := checks[1]

	if workflowCheck.Status != models.CRAPass {
		t.Errorf("Workflow check status = %q, want %q", workflowCheck.Status, models.CRAPass)
	}
}

func TestSecureDefaults_WorkflowWithoutPermissionsBlock(t *testing.T) {
	dir := t.TempDir()
	wfDir := filepath.Join(dir, ".github", "workflows")
	if err := os.MkdirAll(wfDir, 0o755); err != nil {
		t.Fatal(err)
	}

	workflow := `name: CI
on: push
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
`
	if err := os.WriteFile(filepath.Join(wfDir, "ci.yml"), []byte(workflow), 0o644); err != nil {
		t.Fatal(err)
	}

	checker := &SecureDefaultsChecker{}
	actx := &AssessmentContext{RootPath: dir}

	checks := checker.Check(actx)
	workflowCheck := checks[1]

	if workflowCheck.Status != models.CRAWarn {
		t.Errorf("Workflow check status = %q, want %q", workflowCheck.Status, models.CRAWarn)
	}
	if !strings.Contains(workflowCheck.Details, "No permissions block") {
		t.Errorf("Details should mention missing permissions block, got: %s", workflowCheck.Details)
	}
}

func TestSecureDefaults_WorkflowWithWriteAll(t *testing.T) {
	dir := t.TempDir()
	wfDir := filepath.Join(dir, ".github", "workflows")
	if err := os.MkdirAll(wfDir, 0o755); err != nil {
		t.Fatal(err)
	}

	workflow := `name: CI
on: push
permissions: write-all
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
`
	if err := os.WriteFile(filepath.Join(wfDir, "ci.yml"), []byte(workflow), 0o644); err != nil {
		t.Fatal(err)
	}

	checker := &SecureDefaultsChecker{}
	actx := &AssessmentContext{RootPath: dir}

	checks := checker.Check(actx)
	workflowCheck := checks[1]

	if workflowCheck.Status != models.CRAWarn {
		t.Errorf("Workflow check status = %q, want %q", workflowCheck.Status, models.CRAWarn)
	}
	if !strings.Contains(workflowCheck.Details, "write-all") {
		t.Errorf("Details should mention write-all, got: %s", workflowCheck.Details)
	}
}
