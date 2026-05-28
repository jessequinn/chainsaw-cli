# Change Proposal: v2-infra-supply-chain

**Status:** Proposed
**Date:** 2026-05-28
**Author:** Agent

## Summary

Add deep infrastructure supply chain analysis to chainsaw, treating
Terraform providers, Ansible collections, GitHub Actions, Dockerfiles,
and Docker Compose images as first-class supply chain components — not
just "another file format to parse."

This proposal defines the unified model and cross-cutting analysis that
differentiates chainsaw from regex-based IaC scanners. The individual
ecosystem scanners (v2-terraform, v2-ansible, v2-github-actions,
v2-dockerfile, v2-docker-compose) provide the parsing; this proposal
provides the intelligence.

## Motivation

### The Gap

Traditional SCA tools (Trivy, Grype, osv-scanner) treat application
dependencies as the supply chain. Infrastructure dependencies — the
Terraform providers that create your cloud resources, the GitHub Actions
that build and deploy your code, the base images your containers run
on — are either ignored or scanned superficially for misconfigurations.

Supply-chain-guard has regex-based IaC scanning but treats it as
pattern matching ("does this Dockerfile have `curl | bash`?"), not as
supply chain analysis ("which infrastructure dependencies are mutable,
unverified, or unpinned?").

### The Risk

Infrastructure supply chain attacks are high-impact:

| Incident | Vector | Impact |
|---|---|---|
| SolarWinds (2020) | Compromised build pipeline | 18,000 organizations |
| Codecov (2021) | Compromised CI action | Credential theft across thousands of repos |
| tj-actions/changed-files (2024) | Tag-rewriting on GH Action | Secret exfiltration in CI |
| xz-utils (2024) | Compromised upstream maintainer | Backdoor in system library |
| Megalodon (2026) | Injected GH Actions workflows | 5,561 repos compromised |

In every case, the attack entered through the infrastructure/CI layer,
not through an application dependency.

### Why Static Analysis Is Enough

Infrastructure dependencies have a useful property: their provenance
and pinning status are fully observable from static artifacts. You
don't need to pull a Docker image or execute a Terraform plan to know
whether a dependency is pinned, verified, and trustworthy. This makes
deep static analysis viable and valuable.

## Proposed Changes

### 1. Unified Supply Chain Model

Extend `pkg/models/models.go` with supply chain metadata:

```go
type PinType string

const (
    PinCommitSHA  PinType = "commit-sha"   // immutable (GH Actions SHA, Docker digest)
    PinVersionTag PinType = "version-tag"   // semi-mutable (semver tag, Docker tag)
    PinBranch     PinType = "branch"        // fully mutable (main, latest)
    PinRange      PinType = "range"         // resolved at install time (>=1.0,<2.0)
    PinNone       PinType = "none"          // unspecified
)

type SourceTrust string

const (
    TrustOfficial    SourceTrust = "official"     // first-party (actions/*, hashicorp/*)
    TrustVerified    SourceTrust = "verified"     // verified publisher
    TrustCommunity   SourceTrust = "community"    // third-party, public
    TrustUnknown     SourceTrust = "unknown"      // no provenance information
)

type InfraComponent struct {
    Component                       // embeds base Component
    PinType       PinType           `json:"pin_type"`
    SourceTrust   SourceTrust       `json:"source_trust"`
    Mutable       bool              `json:"mutable"`        // can change without version bump
    ProvenanceURL string            `json:"provenance_url,omitempty"`
    LastVerified  time.Time         `json:"last_verified,omitempty"`
    Layer         string            `json:"layer"`          // "application", "infrastructure", "ci-cd"
}
```

Every infrastructure dependency gets classified on two axes:
- **Pin type**: how tightly is it pinned? (SHA > tag > branch > none)
- **Source trust**: who published it? (official > verified > community > unknown)

### 2. Supply Chain Graph (`internal/graph/`)

Build a unified dependency graph that spans application and
infrastructure layers:

```go
type SupplyChainGraph struct {
    Nodes []SupplyChainNode
    Edges []SupplyChainEdge
}

type SupplyChainNode struct {
    ID        string
    Component InfraComponent
    Layer     string          // "application", "infrastructure", "ci-cd"
}

type SupplyChainEdge struct {
    From     string          // node ID
    To       string          // node ID
    Relation string          // "depends-on", "builds", "deploys", "configures"
}
```

The graph connects:
- Application deps (Go modules, npm packages)
- Infrastructure deps (Terraform providers, Ansible collections)
- CI/CD deps (GitHub Actions, base images)
- Build relationships (Dockerfile builds app, GH Action deploys it)

This enables cross-layer analysis:
- "Your CI pipeline uses an unpinned action that deploys to
  infrastructure provisioned by an unverified Terraform module"
- "Your Dockerfile base image has a known CVE in a system library
  that your Go binary links against"

### 3. Pinning Analysis Engine (`internal/analysis/pinning.go`)

Unified pinning analysis across all infrastructure ecosystems:

```
chainsaw scan --analysis pinning .
```

For every infrastructure component, assess:

| Question | Good | Bad |
|---|---|---|
| Is the dependency pinned to an immutable reference? | Docker digest, GH Action SHA | Docker `latest`, GH Action `@v4` |
| Can the publisher silently change what you get? | No (SHA-pinned) | Yes (tag can be force-pushed) |
| Is there an integrity hash? | go.sum, npm integrity, Docker digest | Missing |
| Is the source a verified/official publisher? | `actions/*`, `hashicorp/*` | `random-user/action` |

Output: pinning score (0-100) with per-component breakdown.

### 4. Provenance Assessment (`internal/analysis/provenance.go`)

Check for supply chain provenance artifacts:

| Artifact | What it proves | Where to check |
|---|---|---|
| SLSA provenance | Build was reproducible | GitHub attestations API |
| Sigstore signature | Artifact is signed | cosign/rekor verification |
| npm provenance | Package published from CI | npm registry metadata |
| Docker Content Trust | Image is signed | Docker Hub / registry |
| Go module checksum DB | Module matches global checksums | sum.golang.org |

Implementation in v2: check for the existence and configuration of
provenance mechanisms, not full cryptographic verification (which
requires network access to registries and transparency logs). Full
verification is a v3 enhancement.

### 5. Blast Radius Analysis (`internal/analysis/blast.go`)

For each infrastructure component, estimate blast radius:

```go
type BlastRadius struct {
    Component     InfraComponent
    Scope         string   // "build-only", "deploy", "runtime", "infrastructure"
    SecretsAccess bool     // does this component have access to secrets?
    NetworkAccess bool     // does this component have network access?
    WriteAccess   bool     // does this component have write access to repo/infra?
    Score         int      // 0-100 blast radius score
}
```

Heuristics:
- GitHub Action with `permissions: write-all` + `secrets` access ->
  HIGH blast radius
- Terraform provider managing IAM/networking -> HIGH blast radius
- Docker base image for production service -> HIGH blast radius
- Docker base image for build stage only -> MEDIUM blast radius
- Ansible role for development environment -> LOW blast radius

### 6. New Command: `chainsaw supply-chain [path]`

```
chainsaw supply-chain .                    # full supply chain analysis
chainsaw supply-chain --layer infra .      # infrastructure only
chainsaw supply-chain --layer ci .         # CI/CD only
chainsaw supply-chain --format json .      # machine-readable
chainsaw supply-chain --graph .            # output dependency graph (DOT format)
```

Output:

```
Supply Chain Analysis — 2026-05-28
Layers: application (142 deps), infrastructure (23 deps), CI/CD (8 deps)

PINNING SCORE: 62/100

INFRASTRUCTURE DEPENDENCIES:
  PIN TYPE     SOURCE     COMPONENT                           BLAST RADIUS
  commit-sha   official   actions/checkout@abc123...          medium
  version-tag  official   actions/setup-go@v5                 medium (mutable!)
  version-tag  community  docker/build-push-action@v5        high (mutable!)
  branch       community  myorg/deploy-action@main           critical (mutable!)
  version-tag  official   hashicorp/aws v5.31.0              high (has lockfile hash)
  none         community  terraform-aws-modules/vpc/aws      high (no pin!)

CI/CD RISK:
  [CRITICAL] 1 action pinned to branch (fully mutable)
  [HIGH]     2 actions pinned to tags (mutable via force-push)
  [MEDIUM]   No SLSA provenance on build pipeline
  [INFO]     3 actions from official sources

INFRASTRUCTURE RISK:
  [HIGH]     1 Terraform module with no version constraint
  [MEDIUM]   2 Docker images without digest pinning
  [PASS]     All Terraform providers have lockfile hashes

RECOMMENDATIONS:
  1. Pin docker/build-push-action to commit SHA
  2. Pin myorg/deploy-action to commit SHA or version tag
  3. Add version constraint to terraform-aws-modules/vpc/aws
  4. Add SLSA provenance to CI pipeline
```

### 7. CRA Integration

Infrastructure supply chain findings feed into the CRA compliance
engine (v2-cra-compliance):

- Unpinned infrastructure dependencies violate Annex I Part 2(1)
  (identify and document components)
- Mutable CI/CD dependencies violate Annex I Part 2(7) (secure
  update distribution mechanisms)
- Missing provenance violates Annex I Part 1(2)(a) (no known
  exploitable vulnerabilities — you can't verify if you can't
  trace provenance)

## Dependency on Other Proposals

This proposal depends on the individual scanner proposals for parsing:
- v2-terraform: `.terraform.lock.hcl` and `*.tf` parsing
- v2-ansible: `requirements.yml` parsing
- v2-github-actions: workflow `uses:` parsing
- v2-dockerfile: `FROM` directive parsing
- v2-docker-compose: `services.*.image` parsing

The scanners produce `Component` objects. This proposal adds the
`InfraComponent` enrichment, graph construction, and cross-layer
analysis.

## Non-goals

- Full cryptographic provenance verification (requires network access
  to transparency logs, registries). Deferred to v3.
- Runtime dependency analysis (what actually runs in production).
- Infrastructure drift detection (comparing declared vs. actual state).
- Secret scanning (TruffleHog/gitleaks territory).
- IaC misconfiguration detection (Trivy/Checkov territory). Chainsaw
  analyzes the supply chain of IaC, not the security of IaC output.

## Risks

- Graph construction across layers is complex. Mitigation: start with
  flat analysis per layer, add cross-layer edges incrementally.
- Blast radius scoring is inherently heuristic. Mitigation: document
  scoring methodology, allow policy overrides.
- Some infrastructure ecosystems have poor provenance support (Ansible,
  Terraform modules). Mitigation: report absence honestly, don't
  penalize ecosystems for ecosystem limitations.

## Acceptance Criteria

- `chainsaw supply-chain .` produces a multi-layer analysis
- Infrastructure components include pin type and source trust metadata
- Pinning score reflects actual supply chain security posture
- Blast radius estimates are reasonable for common CI/CD patterns
- Output integrates with CRA compliance checks
- Supply chain graph is exportable in machine-readable format
- Unit tests for pinning classification and blast radius scoring

## Tasks

- [ ] Extend `pkg/models/models.go` with `PinType`, `SourceTrust`,
      `InfraComponent`
- [ ] Implement supply chain graph (`internal/graph/graph.go`)
- [ ] Implement pinning analysis (`internal/analysis/pinning.go`)
- [ ] Implement provenance assessment (`internal/analysis/provenance.go`)
- [ ] Implement blast radius scoring (`internal/analysis/blast.go`)
- [ ] Add `supply-chain` command to CLI
- [ ] Implement supply chain report formatter
- [ ] Add DOT graph export
- [ ] Wire infrastructure scanners into enrichment pipeline
- [ ] CRA integration: map findings to Annex I requirements
- [ ] Unit tests for each analysis module
- [ ] Integration test with a multi-layer fixture project
