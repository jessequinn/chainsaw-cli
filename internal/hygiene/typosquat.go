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
					},
					Source: "hygiene",
				})
			}
		}
	}

	return findings
}
