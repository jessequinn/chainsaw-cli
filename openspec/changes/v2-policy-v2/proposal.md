# Change Proposal: v2-policy-v2

**Status:** Proposed
**Date:** 2026-05-28
**Author:** Agent

## Strategic Context

> Current `.chainsaw.yaml` policy engine is minimal: severity threshold, CVE ignore list, licence deny list. CRA compliance requires richer policy: manufacturer info, support end-dates, pinning requirements, supply chain analysis thresholds. Priority: HIGH — enables CRA compliance scoring and supply chain hardening.

## Summary

Enhance `.chainsaw.yaml` schema with CRA-specific rules: compliance score threshold, supply chain pinning requirements, per-ecosystem licence rules, and structured policy evaluation results. New `comply` and `supply-chain` commands respect policy thresholds.

## Motivation

CRA compliance requires:
- Manufacturer identification and support tracking
- Vulnerability disclosure policy
- Supply chain security (pinning, blast radius)
- Licence compliance per ecosystem

Current policy engine cannot express these requirements. Enhanced schema enables:
- Compliance scoring (0-100%)
- Supply chain hardening (pinning requirements)
- Ecosystem-specific licence rules
- Structured pass/fail evaluation

## Proposed Changes

### Enhanced `.chainsaw.yaml` Schema

```yaml
# Existing fields
fail-on: high
ignore-cves:
  - CVE-2024-1234
licences:
  deny:
    - GPL-3.0

# New CRA section
cra:
  manufacturer: "ACME Corp"
  support-end-date: "2027-12-31"
  security-contact: "security@acme.com"
  csirt-contact: "csirt@acme.com"
  vulnerability-disclosure-policy: "https://acme.com/security"
  required-score: 80  # Minimum compliance percentage (0-100)

# New supply chain section
supply-chain:
  min-pinning-score: 75  # Minimum pinning percentage (0-100)
  require-sha-pins:     # Require SHA pins for specific ecosystems
    - github-actions
    - docker
  allow-git-refs:       # Allow git refs (branches/tags) in these ecosystems
    - go
    - npm

# Enhanced licence section
licences:
  mode: deny  # "deny" (default) or "allow"
  deny:
    - GPL-3.0
    - AGPL-3.0
  allow:
    - MIT
    - Apache-2.0
    - BSD-2-Clause
    - BSD-3-Clause
    - ISC
    - MPL-2.0
  per-ecosystem:
    npm:
      deny:
        - GPL-3.0
      allow: []
    python:
      deny:
        - AGPL-3.0
      allow: []
```

### Policy Evaluation Result

Structured result from policy evaluation:

```go
type PolicyResult struct {
    Pass                bool
    ComplianceScore     int       // 0-100
    PinningScore        int       // 0-100
    BlastRadius         string    // "low", "medium", "high"
    ViolatedRules       []string
    FailureReason       string
    Findings            []Finding
    SupplyChainMetrics  SupplyChainMetrics
}

type SupplyChainMetrics struct {
    TotalDependencies   int
    PinnedDependencies  int
    UnpinnedDependencies int
    GitRefDependencies  int
    BlastRadiusScore    float64
}
```

### New Commands

#### `chainsaw comply`

Evaluate compliance against CRA policy:

```bash
chainsaw comply --policy .chainsaw.yaml --format json .
```

Output: JSON with compliance score, violated rules, recommendations.

Exit code: 0 if score >= `required-score`, 1 otherwise.

#### `chainsaw supply-chain`

Analyze supply chain security:

```bash
chainsaw supply-chain --policy .chainsaw.yaml --format json .
```

Output: JSON with pinning score, blast radius, per-ecosystem metrics.

Exit code: 0 if pinning score >= `min-pinning-score`, 1 otherwise.

### Policy Evaluation Logic

1. **Compliance Score:** (20 checks, each 5 points)
   - Manufacturer identified (5)
   - Support end-date set (5)
   - Security contact present (5)
   - SBOM generated (5)
   - Vulnerability disclosure policy (5)
   - No critical vulnerabilities (5)
   - No GPL-3.0 licences (5)
   - No typosquatting (5)
   - Lockfile integrity verified (5)
   - No abandoned dependencies (5)
   - Pinning score >= 50% (5)
   - Blast radius < high (5)
   - No unpatched CVEs (5)
   - No licence violations (5)
   - No integrity failures (5)
   - No typosquatting (5)
   - Supported version (5)
   - Security contact reachable (5)
   - Policy file present (5)
   - Scan completed successfully (5)

2. **Pinning Score:** (percentage of dependencies with SHA/commit pins)
   - Go: require `go.sum` entries with specific versions
   - npm: require `package-lock.json` with integrity hashes
   - Python: require `poetry.lock` or `pipfile.lock` with hashes
   - Docker: require image digests (not tags)
   - GitHub Actions: require commit SHAs (not tags/branches)

3. **Blast Radius:** (transitive dependency count)
   - Low: < 50 transitive deps
   - Medium: 50-200 transitive deps
   - High: > 200 transitive deps

### Backwards Compatibility

- Existing `.chainsaw.yaml` files without CRA section continue to work
- Default `required-score`: 0 (no minimum)
- Default `min-pinning-score`: 0 (no minimum)
- Default licence mode: "deny" (existing behaviour)

### Exit Codes

- 0: Scan successful, policy satisfied
- 1: Scan successful, policy violated (findings above threshold)
- 2: Scan error or incomplete

## Non-goals

- OPA (Open Policy Agent) integration (future)
- Runtime policy evaluation (static analysis only)
- Policy inheritance or composition (future)
- Automatic policy generation from git history (future)
- Machine learning-based risk scoring (future)

## Risks

- Policy schema complexity may confuse users. Mitigation: provide templates and examples, document each field
- Compliance score calculation is opinionated. Mitigation: document rationale, allow customization in future
- Pinning requirements may be too strict for some projects. Mitigation: make configurable per ecosystem, document trade-offs

## Acceptance Criteria

- `.chainsaw.yaml` schema supports CRA section, supply chain section, per-ecosystem licences
- `comply` command evaluates compliance score (0-100)
- `supply-chain` command evaluates pinning score and blast radius
- Policy evaluation returns structured result with violated rules
- Exit codes: 0 (pass), 1 (fail), 2 (error)
- Backwards compatible with existing policy files
- Unit tests for all 20 compliance checks
- Unit tests for pinning score calculation
- Unit tests for blast radius estimation

## Tasks

- [ ] Update `.chainsaw.yaml` schema in `internal/policy/policy.go` (2h)
- [ ] Implement `PolicyResult` struct and evaluation logic (2h)
- [ ] Implement compliance score calculation (20 checks) (2h)
- [ ] Implement pinning score calculation (2h)
- [ ] Implement blast radius estimation (1h)
- [ ] Create `cmd/chainsaw/comply.go` command (1h)
- [ ] Create `cmd/chainsaw/supply_chain.go` command (1h)
- [ ] Add JSON output formatter for policy results (1h)
- [ ] Add unit tests for compliance checks (2h)
- [ ] Add unit tests for pinning score (1h)
- [ ] Add unit tests for blast radius (1h)
- [ ] Update documentation and examples (1h)
