# Change Proposal: v2-terraform

**Status:** Proposed
**Date:** 2026-05-28
**Author:** Agent

## Summary

Add Terraform provider and module scanning to chainsaw. Parse
`.terraform.lock.hcl` for provider versions and hashes, and
`*.tf` files for module source references.

## Motivation

Terraform manages infrastructure across cloud providers. A compromised
Terraform provider or module can grant an attacker full control over
infrastructure provisioning — IAM roles, network rules, storage buckets.
CRA-scoped organizations using IaC need supply chain visibility into
their Terraform dependencies.

Recent incidents (e.g., compromised community providers, typosquatted
module registries) demonstrate real supply chain risk in the Terraform
ecosystem.

## Proposed Changes

### New Ecosystem Constant

Add `EcosystemTerraform Ecosystem = "terraform"` to `pkg/models/models.go`.

### New Scanner: `internal/scanner/terraform.go`

Implement `TerraformScanner` satisfying the `Scanner` interface.

**DetectManifests** finds:
1. `.terraform.lock.hcl` — provider lockfile (primary)
2. `*.tf` files — for module source references (secondary)

Skip `.terraform/` directory (downloaded providers).

**ParseDependencies** handles two sources:

#### Provider lockfile (`.terraform.lock.hcl`)

```hcl
provider "registry.terraform.io/hashicorp/aws" {
  version     = "5.31.0"
  constraints = "~> 5.0"
  hashes = [
    "h1:abc123...",
    "zh:def456...",
  ]
}
```

Parse with regex or the `hashicorp/hcl/v2` library:
- Extract provider source (e.g., `hashicorp/aws`)
- Extract version
- Extract hashes (zh: prefixed are the canonical ones)
- Construct purl: `pkg:terraform/hashicorp/aws@5.31.0`

Note: There is no official purl type for Terraform yet. Use
`pkg:terraform/namespace/name@version` as a reasonable convention
until PURL spec adds one.

#### Module references (`*.tf` files)

```hcl
module "vpc" {
  source  = "terraform-aws-modules/vpc/aws"
  version = "5.4.0"
}

module "custom" {
  source = "git::https://github.com/org/module.git?ref=v1.0.0"
}
```

Parse module blocks from `.tf` files:
- Registry modules: extract `source` and `version`, construct component
- Git modules: extract URL and ref, flag if ref is a branch (not a tag
  or commit SHA) as a hygiene warning
- Local modules (`source = "./modules/foo"`): skip
- S3/GCS modules: extract URL, flag as informational

### OSV Ecosystem Mapping

There is no Terraform ecosystem in OSV currently. For providers that
wrap Go libraries, query with ecosystem `"Go"` using the provider's
underlying Go module path if detectable. Otherwise, skip OSV and rely
on hygiene checks.

This is honest: vulnerability databases have limited Terraform coverage.
The value here is dependency enumeration, integrity verification, and
SBOM generation — not vuln matching.

### Hygiene Checks

Add Terraform-specific hygiene checks to `internal/hygiene/`:
- **Unpinned providers:** provider in `.tf` without a lockfile entry
- **Branch refs:** module sourced from a git branch instead of tag/SHA
- **Missing lockfile:** `.tf` files exist but no `.terraform.lock.hcl`
  (severity: HIGH — providers are unverified)
- **Third-party registry:** module from a non-Hashicorp registry
  (informational)

### Typosquatting List

Add top 15 popular Terraform providers:
`hashicorp/aws`, `hashicorp/azurerm`, `hashicorp/google`,
`hashicorp/kubernetes`, `hashicorp/helm`, `hashicorp/null`,
`hashicorp/random`, `hashicorp/local`, `hashicorp/external`,
`hashicorp/tls`, `hashicorp/vault`, `hashicorp/consul`,
`hashicorp/nomad`, `hashicorp/cloudflare`, `integrations/github`.

### Dependencies

- `github.com/hashicorp/hcl/v2` for proper HCL parsing (optional —
  regex is viable for the lockfile format, but HCL library is more
  robust for `.tf` module blocks)

## Non-goals

- Scanning Terraform state files (`terraform.tfstate`) — contains
  secrets, should never be committed
- Scanning Terraform Cloud/Enterprise workspace configurations
- OpenTofu-specific features (compatible lockfile format, same scanner)
- Provider binary verification (requires downloading providers)

## Risks

- No official PURL type for Terraform providers/modules. Mitigation:
  use `pkg:terraform/` convention, document it, update when PURL spec
  adds support.
- Limited OSV coverage for Terraform. Mitigation: be honest about it;
  the value is enumeration + integrity + SBOM, not vuln matching.
- HCL parsing complexity for `.tf` files. Mitigation: use the official
  `hashicorp/hcl/v2` library; fall back to regex for the lockfile.

## Acceptance Criteria

- `chainsaw scan --ecosystem terraform .` detects Terraform dependencies
- Parses `.terraform.lock.hcl` provider entries with versions and hashes
- Extracts module references from `*.tf` files
- Flags missing lockfile, unpinned providers, branch-based module refs
- Components appear in SBOM output
- Unit tests with fixture HCL files

## Tasks

- [ ] Add `EcosystemTerraform` constant to `pkg/models/models.go`
- [ ] Implement `TerraformScanner` in `internal/scanner/terraform.go`
- [ ] Parse `.terraform.lock.hcl` provider blocks
- [ ] Parse `*.tf` module blocks
- [ ] Add Terraform-specific hygiene checks
- [ ] Add popular Terraform providers to typosquatting list
- [ ] Add `hashicorp/hcl/v2` dependency to `go.mod`
- [ ] Unit tests with fixture HCL files in `testdata/terraform/`
