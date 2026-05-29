# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Common Changelog](https://common-changelog.org/).

## [Unreleased]

## [0.3.1] - 2026-05-28

### Fixed

Fix CI workflow: build from source instead of `go install` (module
path does not match repository URL)

Upgrade `github/codeql-action` from v3 to v4 (v3 deprecated
December 2026)

Add SARIF fallback in CI to prevent upload failure when scan
produces no output

Use `./chainsaw` for all workflow commands after local build

## [0.3.0] - 2026-05-28

### Added

Add `chainsaw init-security` command scaffolding SECURITY.md,
`.well-known/security.txt` (RFC 9116), and `.chainsaw.yaml` CRA
section with coordinated disclosure template

Add `chainsaw init-ci` command generating GitHub Actions workflow
with SARIF upload, CRA compliance check, and supply chain analysis

Add `chainsaw diff` command comparing two JSON scan results showing
new/fixed vulnerabilities, added/removed components, with table,
JSON, and markdown output formats

Add Elixir/Hex scanner parsing `mix.lock` with SHA-256 integrity
hashes and popular Hex typosquatting list

Add licence detection via npm registry and PyPI JSON API with
caching, allow/deny policy evaluation, and `--detect-licences`
flag on scan command

Add Go vulnerability database integration alongside OSV for Go
modules with version range checking via `golang.org/x/mod/semver`

Add enhanced policy engine with CRA required-score threshold,
supply chain min-pinning-score, require-sha-pins, and licence
allow/deny mode with per-ecosystem overrides

Add SARIF enrichment: helpUri (OSV links), remediation text,
informationUri, semanticVersion, fingerprints for cross-run
deduplication, and markdown messages

Add comprehensive test suite across all packages: scanner,
vulnerability client/matcher, policy engine, hygiene checks,
report formatters, CRA compliance, and supply chain analysis

Propagate `context.Context` to all I/O-bound functions: Scanner
interface, OSV client, vulnerability matcher, policy loader,
report writers, CRA engine, and supply chain analysis

## [0.2.0] - 2026-05-28

### Added

Add CRA compliance engine with `chainsaw comply` command for EU Cyber
Resilience Act (Regulation 2024/2847) readiness assessment covering
Annex I, Article 14, and Annex II requirements

Add infrastructure supply chain analysis with `chainsaw supply-chain`
command including pinning analysis, provenance assessment, and blast
radius scoring across CI/CD, container, and IaC layers

Add GitHub Actions workflow scanner detecting SHA, tag, and branch
pinning with blast radius classification for actions with secrets
access

Add Dockerfile scanner parsing FROM directives with digest, tag, and
branch pin classification and multi-stage build support

Add Docker Compose scanner parsing service image references with
shared image reference parser

Add Terraform scanner parsing `.terraform.lock.hcl` provider entries
and `*.tf` module source references

Add Ansible scanner parsing `requirements.yml` Galaxy collections
and roles with version pinning enforcement

Add Python ecosystem scanner supporting `requirements.txt`,
`Pipfile.lock`, and `poetry.lock` with PyPI name normalization

Add infrastructure supply chain types: PinType, SourceTrust,
InfraComponent, BlastRadius to shared models

Add new ecosystem constants: PyPI, Docker, Terraform, Ansible,
GitHubActions

## [0.1.0] - 2026-05-28

### Added

Add Go module scanner parsing `go.mod` and `go.sum` for dependency
enumeration with integrity hash extraction

Add npm lockfile scanner parsing `package-lock.json` (lockfileVersion
2 and 3) with integrity hash extraction

Add OSV API client with batch vulnerability queries (max 1000 per
request, 30s timeout)

Add vulnerability matcher with deduplication and severity sorting

Add typosquatting detection via Levenshtein distance against curated
lists of popular Go and npm packages

Add lockfile integrity verification flagging missing checksums

Add YAML policy engine loading `.chainsaw.yaml` with severity
threshold, CVE ignore list, and licence deny list

Add CycloneDX 1.5 SBOM generation via `chainsaw sbom` command

Add table, JSON, and SARIF 2.1.0 output formatters

Add `scan`, `sbom`, and `version` CLI commands via Cobra
