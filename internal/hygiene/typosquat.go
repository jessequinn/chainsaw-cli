package hygiene

import (
	"fmt"

	"github.com/chainsaw-dev/chainsaw/pkg/models"
)

var popularGo = []string{
	"github.com/gin-gonic/gin",
	"github.com/gorilla/mux",
	"github.com/spf13/cobra",
	"github.com/spf13/viper",
	"github.com/stretchr/testify",
	"github.com/sirupsen/logrus",
	"go.uber.org/zap",
	"github.com/go-chi/chi",
	"github.com/labstack/echo",
	"github.com/gofiber/fiber",
	"golang.org/x/net",
	"golang.org/x/crypto",
	"golang.org/x/text",
	"golang.org/x/sys",
	"golang.org/x/sync",
	"golang.org/x/mod",
	"google.golang.org/grpc",
	"google.golang.org/protobuf",
}

var popularNpm = []string{
	"express",
	"react",
	"lodash",
	"axios",
	"moment",
	"webpack",
	"typescript",
	"eslint",
	"prettier",
	"jest",
	"mocha",
	"next",
	"vue",
	"angular",
	"jquery",
	"underscore",
	"chalk",
	"commander",
	"debug",
	"dotenv",
}

var popularPyPI = []string{
	"requests", "boto3", "urllib3", "setuptools", "wheel", "pip",
	"certifi", "idna", "charset-normalizer", "typing-extensions",
	"numpy", "pandas", "pyyaml", "cryptography", "flask", "django",
	"jinja2", "pillow", "scipy", "matplotlib",
}

var popularActions = []string{
	"actions/checkout", "actions/setup-node", "actions/setup-go",
	"actions/setup-python", "actions/setup-java", "actions/cache",
	"actions/upload-artifact", "actions/download-artifact",
	"actions/github-script", "actions/labeler",
	"docker/build-push-action", "docker/setup-buildx-action",
	"docker/login-action", "codecov/codecov-action",
	"softprops/action-gh-release", "peter-evans/create-pull-request",
	"hashicorp/setup-terraform", "aws-actions/configure-aws-credentials",
	"google-github-actions/auth", "azure/login",
}

var popularDocker = []string{
	"ubuntu", "alpine", "debian", "node", "python", "golang", "nginx",
	"redis", "postgres", "mysql", "mongo", "httpd", "busybox",
	"amazoncorretto", "eclipse-temurin", "docker", "registry",
	"traefik", "haproxy", "memcached",
}

var popularTerraform = []string{
	"hashicorp/aws", "hashicorp/azurerm", "hashicorp/google",
	"hashicorp/kubernetes", "hashicorp/helm", "hashicorp/null",
	"hashicorp/random", "hashicorp/local", "hashicorp/external",
	"hashicorp/tls", "hashicorp/vault", "hashicorp/consul",
	"hashicorp/nomad", "integrations/github",
}

var popularAnsible = []string{
	"community.general", "community.aws", "amazon.aws",
	"ansible.posix", "ansible.netcommon", "community.docker",
	"community.postgresql", "community.mysql", "community.crypto",
	"kubernetes.core", "ansible.windows", "community.vmware",
}

var popularHex = []string{
	"phoenix", "ecto", "plug", "phoenix_html", "phoenix_live_view",
	"jason", "telemetry", "phoenix_pubsub", "swoosh", "bamboo",
	"ex_machina", "credo", "dialyxir", "absinthe", "guardian",
	"httpoison", "tesla", "oban", "broadway", "nx",
}

// levenshtein computes the Levenshtein edit distance between two strings.
func levenshtein(a, b string) int {
	la := len(a)
	lb := len(b)

	if la == 0 {
		return lb
	}
	if lb == 0 {
		return la
	}

	// Two-row approach to save memory.
	prev := make([]int, lb+1)
	curr := make([]int, lb+1)

	for j := 0; j <= lb; j++ {
		prev[j] = j
	}

	for i := 1; i <= la; i++ {
		curr[0] = i
		for j := 1; j <= lb; j++ {
			cost := 1
			if a[i-1] == b[j-1] {
				cost = 0
			}
			del := prev[j] + 1
			ins := curr[j-1] + 1
			sub := prev[j-1] + cost

			m := del
			if ins < m {
				m = ins
			}
			if sub < m {
				m = sub
			}
			curr[j] = m
		}
		prev, curr = curr, prev
	}

	return prev[lb]
}

// popularListForEcosystem returns the popular package list for the given ecosystem.
func popularListForEcosystem(eco models.Ecosystem) []string {
	switch eco {
	case models.EcosystemGo:
		return popularGo
	case models.EcosystemNpm:
		return popularNpm
	case models.EcosystemPyPI:
		return popularPyPI
	case models.EcosystemGitHubActions:
		return popularActions
	case models.EcosystemDocker:
		return popularDocker
	case models.EcosystemTerraform:
		return popularTerraform
	case models.EcosystemAnsible:
		return popularAnsible
	case models.EcosystemHex:
		return popularHex
	default:
		return nil
	}
}

// CheckTyposquatting detects potential typosquatting by comparing component
// names against popular packages using Levenshtein distance.
func CheckTyposquatting(components []models.Component) []models.Finding {
	var findings []models.Finding

	for _, comp := range components {
		popular := popularListForEcosystem(comp.Ecosystem)
		for _, pkg := range popular {
			if comp.Name == pkg {
				continue
			}
			dist := levenshtein(comp.Name, pkg)
			if dist > 0 && dist <= 2 {
				findings = append(findings, models.Finding{
					ID:       fmt.Sprintf("TYPO-%s-%s", comp.Ecosystem, comp.Name),
					Summary:  fmt.Sprintf("Suspected typosquatting: %q is within edit distance %d of popular package %q", comp.Name, dist, pkg),
					Severity: models.SeverityHigh,
					Component: models.Component{
						Name:      comp.Name,
						Version:   comp.Version,
						Ecosystem: comp.Ecosystem,
						PkgURL:    comp.PkgURL,
						Direct:    comp.Direct,
					},
					Source: "hygiene",
				})
			}
		}
	}

	return findings
}
