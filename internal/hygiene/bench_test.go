package hygiene

import (
	"testing"

	"github.com/chainsaw-dev/chainsaw/pkg/models"
)

// BenchmarkLevenshtein benchmarks the Levenshtein distance computation.
// This is a CPU-intensive algorithm used for typosquatting detection.
func BenchmarkLevenshtein(b *testing.B) {
	pairs := []struct {
		a, b string
	}{
		{"express", "exrpess"},           // 2 edits
		{"requests", "reqeusts"},         // 2 edits
		{"lodash", "loadsh"},             // 1 edit
		{"kitten", "sitting"},            // 3 edits
		{"github.com/spf13/cobra", "github.com/spf13/cobre"},  // 1 edit
		{"", ""},                         // empty strings
		{"a", "b"},                       // single char
		{"verylongpackagename", "verylongpackagename"},  // identical long strings
	}

	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		for _, pair := range pairs {
			_ = levenshtein(pair.a, pair.b)
		}
	}
}

// BenchmarkCheckTyposquatting benchmarks the full typosquatting check against
// a realistic component list. This exercises the Levenshtein distance computation
// against multiple popular packages per ecosystem.
func BenchmarkCheckTyposquatting(b *testing.B) {
	// Create a realistic component list with ~50 components across ecosystems
	components := []models.Component{
		// npm packages
		{Name: "express", Version: "4.18.0", Ecosystem: models.EcosystemNpm},
		{Name: "exrpess", Version: "1.0.0", Ecosystem: models.EcosystemNpm},  // typo
		{Name: "react", Version: "18.0.0", Ecosystem: models.EcosystemNpm},
		{Name: "recat", Version: "1.0.0", Ecosystem: models.EcosystemNpm},    // typo
		{Name: "lodash", Version: "4.17.0", Ecosystem: models.EcosystemNpm},
		{Name: "axios", Version: "1.0.0", Ecosystem: models.EcosystemNpm},
		{Name: "webpack", Version: "5.0.0", Ecosystem: models.EcosystemNpm},
		{Name: "typescript", Version: "5.0.0", Ecosystem: models.EcosystemNpm},
		{Name: "jest", Version: "29.0.0", Ecosystem: models.EcosystemNpm},
		{Name: "mocha", Version: "10.0.0", Ecosystem: models.EcosystemNpm},

		// Go packages
		{Name: "github.com/gin-gonic/gin", Version: "1.9.0", Ecosystem: models.EcosystemGo},
		{Name: "github.com/gorilla/mux", Version: "1.8.0", Ecosystem: models.EcosystemGo},
		{Name: "github.com/spf13/cobra", Version: "1.8.0", Ecosystem: models.EcosystemGo},
		{Name: "github.com/spf13/cobre", Version: "1.0.0", Ecosystem: models.EcosystemGo},  // typo
		{Name: "github.com/stretchr/testify", Version: "1.8.0", Ecosystem: models.EcosystemGo},
		{Name: "go.uber.org/zap", Version: "1.26.0", Ecosystem: models.EcosystemGo},
		{Name: "golang.org/x/net", Version: "0.0.0", Ecosystem: models.EcosystemGo},
		{Name: "golang.org/x/crypto", Version: "0.0.0", Ecosystem: models.EcosystemGo},
		{Name: "google.golang.org/grpc", Version: "1.50.0", Ecosystem: models.EcosystemGo},

		// PyPI packages
		{Name: "requests", Version: "2.31.0", Ecosystem: models.EcosystemPyPI},
		{Name: "reqeusts", Version: "1.0.0", Ecosystem: models.EcosystemPyPI},  // typo
		{Name: "boto3", Version: "1.26.0", Ecosystem: models.EcosystemPyPI},
		{Name: "numpy", Version: "1.24.0", Ecosystem: models.EcosystemPyPI},
		{Name: "pandas", Version: "2.0.0", Ecosystem: models.EcosystemPyPI},
		{Name: "flask", Version: "2.3.0", Ecosystem: models.EcosystemPyPI},
		{Name: "django", Version: "4.2.0", Ecosystem: models.EcosystemPyPI},
		{Name: "pyyaml", Version: "6.0.0", Ecosystem: models.EcosystemPyPI},
		{Name: "cryptography", Version: "41.0.0", Ecosystem: models.EcosystemPyPI},
		{Name: "pillow", Version: "10.0.0", Ecosystem: models.EcosystemPyPI},

		// GitHub Actions
		{Name: "actions/checkout", Version: "v4", Ecosystem: models.EcosystemGitHubActions},
		{Name: "actions/setup-node", Version: "v4", Ecosystem: models.EcosystemGitHubActions},
		{Name: "actions/setup-go", Version: "v4", Ecosystem: models.EcosystemGitHubActions},
		{Name: "actions/setup-python", Version: "v4", Ecosystem: models.EcosystemGitHubActions},
		{Name: "docker/build-push-action", Version: "v5", Ecosystem: models.EcosystemGitHubActions},
		{Name: "codecov/codecov-action", Version: "v3", Ecosystem: models.EcosystemGitHubActions},

		// Docker images
		{Name: "ubuntu", Version: "22.04", Ecosystem: models.EcosystemDocker},
		{Name: "alpine", Version: "3.18", Ecosystem: models.EcosystemDocker},
		{Name: "debian", Version: "12", Ecosystem: models.EcosystemDocker},
		{Name: "node", Version: "20", Ecosystem: models.EcosystemDocker},
		{Name: "python", Version: "3.11", Ecosystem: models.EcosystemDocker},
		{Name: "golang", Version: "1.21", Ecosystem: models.EcosystemDocker},
		{Name: "nginx", Version: "latest", Ecosystem: models.EcosystemDocker},
		{Name: "redis", Version: "7.0", Ecosystem: models.EcosystemDocker},
		{Name: "postgres", Version: "15", Ecosystem: models.EcosystemDocker},

		// Terraform modules
		{Name: "hashicorp/aws", Version: "5.0.0", Ecosystem: models.EcosystemTerraform},
		{Name: "hashicorp/azurerm", Version: "3.0.0", Ecosystem: models.EcosystemTerraform},
		{Name: "hashicorp/google", Version: "5.0.0", Ecosystem: models.EcosystemTerraform},
		{Name: "hashicorp/kubernetes", Version: "2.0.0", Ecosystem: models.EcosystemTerraform},
	}

	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		_ = CheckTyposquatting(components)
	}
}

// BenchmarkCheckIntegrity benchmarks the integrity check which scans all components
// for missing hashes.
func BenchmarkCheckIntegrity(b *testing.B) {
	// Create a realistic component list with ~50 components
	components := make([]models.Component, 50)
	for i := 0; i < 50; i++ {
		components[i] = models.Component{
			Name:      "package-" + string(rune(i)),
			Version:   "1.0.0",
			Ecosystem: models.EcosystemNpm,
			// Alternate between having and missing hashes
			Hash: func() string {
				if i%2 == 0 {
					return "sha256:abc123def456"
				}
				return ""
			}(),
		}
	}

	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		_ = CheckIntegrity(components)
	}
}
