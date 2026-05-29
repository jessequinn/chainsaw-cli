package hygiene

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/chainsaw-dev/chainsaw/pkg/models"
)

func TestCheckDockerfiles_WithUserDirective(t *testing.T) {
	tmpdir := t.TempDir()
	dockerfile := filepath.Join(tmpdir, "Dockerfile")
	content := `FROM ubuntu:22.04
RUN apt-get update && apt-get install -y curl=7.88.1-10
USER appuser
`
	if err := os.WriteFile(dockerfile, []byte(content), 0644); err != nil {
		t.Fatalf("failed to write Dockerfile: %v", err)
	}

	findings := CheckDockerfiles(tmpdir)
	if len(findings) != 0 {
		t.Errorf("expected no findings, got %d", len(findings))
	}
}

func TestCheckDockerfiles_NoUserDirective(t *testing.T) {
	tmpdir := t.TempDir()
	dockerfile := filepath.Join(tmpdir, "Dockerfile")
	content := `FROM ubuntu:22.04
RUN apt-get update && apt-get install -y curl=7.88.1-10
`
	if err := os.WriteFile(dockerfile, []byte(content), 0644); err != nil {
		t.Fatalf("failed to write Dockerfile: %v", err)
	}

	findings := CheckDockerfiles(tmpdir)
	if len(findings) != 1 {
		t.Errorf("expected 1 finding, got %d", len(findings))
	}
	if findings[0].Severity != models.SeverityMedium {
		t.Errorf("expected MEDIUM severity, got %s", findings[0].Severity)
	}
	if findings[0].ID != "DOCKER-ROOT-Dockerfile" {
		t.Errorf("expected DOCKER-ROOT-Dockerfile, got %s", findings[0].ID)
	}
}

func TestCheckDockerfiles_SensitivePort(t *testing.T) {
	tmpdir := t.TempDir()
	dockerfile := filepath.Join(tmpdir, "Dockerfile")
	content := `FROM ubuntu:22.04
EXPOSE 22
USER appuser
`
	if err := os.WriteFile(dockerfile, []byte(content), 0644); err != nil {
		t.Fatalf("failed to write Dockerfile: %v", err)
	}

	findings := CheckDockerfiles(tmpdir)
	if len(findings) != 1 {
		t.Errorf("expected 1 finding, got %d", len(findings))
	}
	if findings[0].Severity != models.SeverityLow {
		t.Errorf("expected LOW severity, got %s", findings[0].Severity)
	}
	if findings[0].ID != "DOCKER-PORT-22-Dockerfile" {
		t.Errorf("expected DOCKER-PORT-22-Dockerfile, got %s", findings[0].ID)
	}
}

func TestCheckDockerfiles_UnpinnedAptGet(t *testing.T) {
	tmpdir := t.TempDir()
	dockerfile := filepath.Join(tmpdir, "Dockerfile")
	content := `FROM ubuntu:22.04
RUN apt-get update && apt-get install -y curl
USER appuser
`
	if err := os.WriteFile(dockerfile, []byte(content), 0644); err != nil {
		t.Fatalf("failed to write Dockerfile: %v", err)
	}

	findings := CheckDockerfiles(tmpdir)
	if len(findings) != 1 {
		t.Errorf("expected 1 finding, got %d", len(findings))
	}
	if findings[0].Severity != models.SeverityLow {
		t.Errorf("expected LOW severity, got %s", findings[0].Severity)
	}
	if findings[0].ID != "DOCKER-UNPIN-Dockerfile" {
		t.Errorf("expected DOCKER-UNPIN-Dockerfile, got %s", findings[0].ID)
	}
}

func TestCheckDockerfiles_PinnedAptGet(t *testing.T) {
	tmpdir := t.TempDir()
	dockerfile := filepath.Join(tmpdir, "Dockerfile")
	content := `FROM ubuntu:22.04
RUN apt-get update && apt-get install -y curl=7.88.1-10
USER appuser
`
	if err := os.WriteFile(dockerfile, []byte(content), 0644); err != nil {
		t.Fatalf("failed to write Dockerfile: %v", err)
	}

	findings := CheckDockerfiles(tmpdir)
	if len(findings) != 0 {
		t.Errorf("expected no findings, got %d", len(findings))
	}
}

func TestCheckDockerfiles_NoDockerfiles(t *testing.T) {
	tmpdir := t.TempDir()

	findings := CheckDockerfiles(tmpdir)
	if len(findings) != 0 {
		t.Errorf("expected no findings, got %d", len(findings))
	}
}

func TestCheckDockerfiles_MultipleIssues(t *testing.T) {
	tmpdir := t.TempDir()
	dockerfile := filepath.Join(tmpdir, "Dockerfile")
	content := `FROM ubuntu:22.04
EXPOSE 22 3306
RUN apt-get update && apt-get install -y curl
`
	if err := os.WriteFile(dockerfile, []byte(content), 0644); err != nil {
		t.Fatalf("failed to write Dockerfile: %v", err)
	}

	findings := CheckDockerfiles(tmpdir)
	// Should have: no USER (1), EXPOSE 22 (1), EXPOSE 3306 (1), unpinned apt-get (1) = 4 total
	if len(findings) != 4 {
		t.Errorf("expected 4 findings, got %d", len(findings))
	}
}

func TestCheckDockerfiles_SubdirectoryDockerfile(t *testing.T) {
	tmpdir := t.TempDir()
	subdir := filepath.Join(tmpdir, "docker")
	if err := os.Mkdir(subdir, 0755); err != nil {
		t.Fatalf("failed to create subdir: %v", err)
	}

	dockerfile := filepath.Join(subdir, "Dockerfile")
	content := `FROM ubuntu:22.04
`
	if err := os.WriteFile(dockerfile, []byte(content), 0644); err != nil {
		t.Fatalf("failed to write Dockerfile: %v", err)
	}

	findings := CheckDockerfiles(tmpdir)
	if len(findings) != 1 {
		t.Errorf("expected 1 finding, got %d", len(findings))
	}
}
