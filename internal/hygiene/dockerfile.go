package hygiene

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/chainsaw-dev/chainsaw/pkg/models"
)

// sensitivePorts are commonly exposed ports that may indicate security issues.
var sensitivePorts = map[string]string{
	"22":    "SSH",
	"3306":  "MySQL",
	"5432":  "PostgreSQL",
	"6379":  "Redis",
	"27017": "MongoDB",
}

// CheckDockerfiles scans Dockerfiles in the root path for security issues.
func CheckDockerfiles(root string) []models.Finding {
	var findings []models.Finding

	// Find Dockerfiles
	patterns := []string{"Dockerfile", "Dockerfile.*", "*.dockerfile"}
	var dockerfiles []string
	for _, p := range patterns {
		matches, _ := filepath.Glob(filepath.Join(root, p))
		dockerfiles = append(dockerfiles, matches...)
	}

	// Also check subdirectories one level deep
	entries, _ := os.ReadDir(root)
	for _, e := range entries {
		if e.IsDir() {
			for _, p := range patterns {
				matches, _ := filepath.Glob(filepath.Join(root, e.Name(), p))
				dockerfiles = append(dockerfiles, matches...)
			}
		}
	}

	for _, df := range dockerfiles {
		findings = append(findings, lintDockerfile(df)...)
	}

	return findings
}

func lintDockerfile(path string) []models.Finding {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil
	}

	content := string(data)
	lines := strings.Split(content, "\n")
	var findings []models.Finding
	relPath := filepath.Base(path)

	// Check 1: No USER directive (runs as root)
	hasUser := false
	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(strings.ToUpper(trimmed), "USER ") {
			hasUser = true
			break
		}
	}
	if !hasUser {
		findings = append(findings, models.Finding{
			ID:      "DOCKER-ROOT-" + relPath,
			Summary: fmt.Sprintf("%s: no USER directive, container runs as root", relPath),
			Details: "Add a USER directive to run the container as a non-root user.",
			Severity: models.SeverityMedium,
			Component: models.Component{Name: relPath, Ecosystem: models.EcosystemDocker},
			Source:   "hygiene",
		})
	}

	// Check 2: Sensitive port exposure
	exposeRe := regexp.MustCompile(`(?i)^EXPOSE\s+(.+)`)
	for _, line := range lines {
		matches := exposeRe.FindStringSubmatch(strings.TrimSpace(line))
		if matches == nil {
			continue
		}
		ports := strings.Fields(matches[1])
		for _, port := range ports {
			// Strip protocol suffix like /tcp
			port = strings.Split(port, "/")[0]
			if svc, ok := sensitivePorts[port]; ok {
				findings = append(findings, models.Finding{
					ID:      fmt.Sprintf("DOCKER-PORT-%s-%s", port, relPath),
					Summary: fmt.Sprintf("%s: exposes %s port %s", relPath, svc, port),
					Details: fmt.Sprintf("Exposing %s port %s may indicate a security risk. Consider using a non-default port or removing the EXPOSE directive.", svc, port),
					Severity: models.SeverityLow,
					Component: models.Component{Name: relPath, Ecosystem: models.EcosystemDocker},
					Source:   "hygiene",
				})
			}
		}
	}

	// Check 3: Unpinned package installs
	aptGetRe := regexp.MustCompile(`(?i)apt-get\s+install`)
	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if aptGetRe.MatchString(trimmed) && !strings.Contains(trimmed, "=") {
			findings = append(findings, models.Finding{
				ID:      "DOCKER-UNPIN-" + relPath,
				Summary: fmt.Sprintf("%s: unpinned apt-get install", relPath),
				Details: "Pin package versions in apt-get install (e.g., 'curl=7.88.1-10') for reproducible builds.",
				Severity: models.SeverityLow,
				Component: models.Component{Name: relPath, Ecosystem: models.EcosystemDocker},
				Source:   "hygiene",
			})
			break // Only report once per file
		}
	}

	return findings
}
