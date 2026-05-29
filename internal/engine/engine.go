package engine

import (
	"context"
	"os"
	"strings"

	"github.com/chainsaw-dev/chainsaw/internal/policy"
	"github.com/chainsaw-dev/chainsaw/internal/scanner"
	"github.com/chainsaw-dev/chainsaw/pkg/models"
)

// ResolveScanners returns scanners, optionally filtered by ecosystem.
func ResolveScanners(ecosystemFlag string) []scanner.Scanner {
	if ecosystemFlag == "" {
		return scanner.GetAll()
	}

	ecos := strings.Split(ecosystemFlag, ",")
	var out []scanner.Scanner
	for _, e := range ecos {
		eco := models.Ecosystem(strings.TrimSpace(e))
		if s, ok := scanner.GetByEcosystem(eco); ok {
			out = append(out, s)
		}
	}
	return out
}

// LoadPolicy loads a policy from the given path, or returns the default policy.
func LoadPolicy(ctx context.Context, path string) (*policy.Policy, error) {
	if path != "" {
		return policy.LoadPolicy(ctx, path)
	}
	// Try default policy file.
	if _, err := os.Stat(".chainsaw.yaml"); err == nil {
		return policy.LoadPolicy(ctx, ".chainsaw.yaml")
	}
	return policy.DefaultPolicy(), nil
}

// DefaultPolicy returns a permissive policy with no restrictions.
func DefaultPolicy() *policy.Policy {
	return policy.DefaultPolicy()
}
