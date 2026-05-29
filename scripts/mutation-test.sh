#!/usr/bin/env bash
# mutation-test.sh -- Run mutation testing on high-stakes packages.
#
# Tool: go-gremlins (github.com/go-gremlins/gremlins)
# Install: go install github.com/go-gremlins/gremlins/cmd/gremlins@latest
#
# go-mutesting was also evaluated but crashes on Go 1.26+ due to its
# pinned dependency on golang.org/x/tools v0.0.0-20191018 which is
# incompatible with the modern go/types API.
#
# High-stakes paths per AGENTS.md:
#   - Vulnerability matching / CVSS parsing (internal/vuln)
#   - Policy evaluation (internal/policy)
#   - Typosquatting detection (internal/hygiene)
#   - Severity scoring (pkg/models)

set -euo pipefail

cd "$(git -C "$(dirname "$0")" rev-parse --show-toplevel)"

if ! command -v gremlins &>/dev/null; then
  echo "ERROR: gremlins not found. Install with:"
  echo "  go install github.com/go-gremlins/gremlins/cmd/gremlins@latest"
  exit 2
fi

PACKAGES=(
  ./internal/vuln/
  ./internal/policy/
  ./internal/hygiene/
  ./pkg/models/
)

TIMEOUT_COEFF="${MUTATION_TIMEOUT_COEFF:-10}"
OVERALL_EXIT=0

echo "=== Chainsaw Mutation Testing ==="
echo "Tool: gremlins (go-gremlins)"
echo "Timeout coefficient: ${TIMEOUT_COEFF}"
echo ""

for pkg in "${PACKAGES[@]}"; do
  echo "--- ${pkg} ---"
  if ! gremlins unleash --timeout-coefficient "${TIMEOUT_COEFF}" "${pkg}" 2>&1; then
    OVERALL_EXIT=1
  fi
  echo ""
done

echo "=== Done ==="
exit "${OVERALL_EXIT}"
