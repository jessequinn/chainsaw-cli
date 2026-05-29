# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Common Changelog](https://common-changelog.org/).

## [Unreleased]

## [0.4.0] - 2026-05-29

### Added

Add `chainsaw check` unified meta-command running scan, comply, and
supply-chain analysis in a single invocation with combined exit code

Add CRA Article 14 incident reporting validation: CSIRT contact,
security contact, SECURITY.md keyword scanning, security.txt presence,
24-hour early warning process readiness

Add CRA product category classification checker (Annex III/IV):
default, important-class-1, important-class-2, critical with
conformity assessment requirements per Article 32

Add transitive/direct dependency distinction: `Direct` field on
Component, Go scanner marks indirect deps, CycloneDX SBOM sets scope
(required/optional), SBOM checker reports direct vs transitive counts

Add secure-by-default configuration checks (CRA Annex I Part 1):
Dockerfile USER directive, GitHub Actions permissions scope

Add CRA compliance trend tracking: stores assessment history in
`.chainsaw/history/`, `--trend` flag on comply shows score progression

Add incident response playbook generator (`INCIDENT-RESPONSE.md`) to
`init-security` with ENISA Single Reporting Platform details, Article
14 reporting timelines (24h/72h/14d), and internal escalation template

Add GitHub Actions security analysis: detect unpinned actions using
mutable tags instead of commit SHA pins

Add Dockerfile security linting: missing USER directive, sensitive
port exposure (SSH, MySQL, PostgreSQL, Redis, MongoDB), unpinned
apt-get installs

Add `--output`/`-o` flag to all commands (scan, comply, supply-chain,
check, sbom, diff) for writing output to file instead of stdout

Add `--quiet`/`-q` flag to scan, comply, supply-chain, and check
commands to suppress progress messages

Add scan progress indication to stderr showing current scanner,
vulnerability query status, and analysis phase

Add CRA deadline countdown to compliance reports showing days
remaining until Article 14 deadline with urgency level
(RED/YELLOW/green)

Add policy file schema validation: validates fail_on severity, CRA
score ranges, supply-chain score ranges, licence mode, and detects
unknown YAML fields

Add exponential backoff retry logic to OSV API client (max 3 retries,
jitter, Retry-After header support)

Add graceful degradation: scanner and API failures collect warnings
instead of aborting the entire scan

Extract shared scan logic into `internal/engine` package with
`ResolveScanners()` and `LoadPolicy()` functions

### Fixed

Fix CVSS vector string parsing: properly compute base scores from
CVSS v3.x vector strings (e.g. `CVSS:3.1/AV:N/AC:L/...`) instead
of returning 0 and classifying as UNKNOWN severity

Fix `comply` command to read CRA config from policy file (was
creating empty `CRAConfig{}` ignoring all user-provided manufacturer,
security-contact, support-end-date, csirt-contact fields)

### Changed

**Breaking:** Remove deprecated `licenses` policy field; use
`licences` with `deny-list` instead of `deny`

Unify `LicensePolicy`/`LicencePolicy` into single `LicencePolicy`
type with mode, allow-list, deny-list, and per-ecosystem overrides

## [0.3.3] - 2026-05-29

### Changed

Upgrade GitHub Actions to Node.js 24-compatible versions:
`actions/checkout` v4 to v6, `actions/setup-go` v5 to v6,
`actions/upload-artifact` v4 to v7, `codeql-action/upload-sarif`
v3 to v4

Update `init-ci` scaffold template with the same action versions

## [0.3.2] - 2026-05-28

### Fixed

Fix SARIF artifact locations to use file paths instead of package
URLs (GitHub Code Scanning requires `file:` scheme URIs, not `pkg:`)

Add `Location` field to Component tracking the source manifest path
relative to the project root

Add ecosystem-based fallback paths for SARIF when Location is not set

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
