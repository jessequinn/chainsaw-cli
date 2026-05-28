# Chainsaw — OpenSpec v1.0

## Overview

Chainsaw is a Go-based CLI tool for software supply chain security scanning. It enumerates dependencies from project manifests, matches them against known vulnerability databases, generates SBOMs for CRA compliance, and performs supply chain hygiene checks.

## Problem Statement

Organizations subject to the EU Cyber Resilience Act (CRA) need to:
- Maintain accurate software bills of materials (SBOMs)
- Continuously scan dependencies for known vulnerabilities
- Enforce license compliance policies
- Detect supply chain integrity issues (typosquatting, checksum mismatches)

Existing tools (Grype, Trivy, osv-scanner) solve parts of this but lack integrated CRA-oriented workflow, policy enforcement, and supply chain hygiene heuristics in a single binary.

## Goals

1. **Single binary** — no runtime dependencies, no daemon, no cloud account required
2. **Multi-ecosystem** — Go and npm in v1, extensible to Python/Java/Rust
3. **CI-native** — structured output (JSON, SARIF), meaningful exit codes, `--fail-on` threshold
4. **CRA-aligned** — CycloneDX SBOM generation out of the box
5. **Supply chain hygiene** — typosquatting detection and lockfile integrity verification

## Non-Goals (v1)

- Behavioral/dynamic analysis of packages
- Container image scanning
- SAST/DAST
- NVD/CVSS enrichment (deferred to v2)
- OPA-based policy engine (deferred to v2/v3)

---

## Architecture

### CLI Interface

```
chainsaw scan [path]                         # auto-detect manifests, table output
chainsaw scan --format json|sarif|table .    # structured output
chainsaw scan --fail-on [critical|high|medium|low] .
chainsaw scan --ecosystem go,npm .           # scope to ecosystems
chainsaw sbom [path]                         # generate SBOM only
chainsaw sbom --format cyclonedx|spdx .      # SBOM format selection
chainsaw version                             # print version info
```

Exit codes:
- `0` — no findings above threshold
- `1` — findings above threshold (or policy violation)
- `2` — execution error (invalid input, network failure)

### Project Structure

```
chainsaw/
├── cmd/
│   └── chainsaw/
│       └── main.go
├── internal/
│   ├── scanner/
│   │   ├── scanner.go        # Scanner interface
│   │   ├── gomod.go          # Go module parser
│   │   └── npm.go            # npm lockfile parser
│   ├── vuln/
│   │   ├── client.go         # OSV API client
│   │   └── matcher.go        # vulnerability matching logic
│   ├── sbom/
│   │   ├── cyclonedx.go      # CycloneDX serializer
│   │   └── sbom.go           # SBOM generation interface
│   ├── hygiene/
│   │   ├── typosquat.go      # typosquatting detection
│   │   └── integrity.go      # lockfile checksum verification
│   ├── report/
│   │   ├── table.go          # terminal table output
│   │   ├── json.go           # JSON output
│   │   └── sarif.go          # SARIF output
│   ├── policy/
│   │   └── policy.go         # .chainsaw.yaml policy engine
│   └── config/
│       └── config.go         # configuration loading
├── pkg/
│   └── models/
│       └── models.go         # Component, Finding, Severity, SBOM types
├── .chainsaw.yaml            # default config example
├── Makefile
├── SPEC.md
├── go.mod
└── go.sum
```

### Core Types

```go
type Ecosystem string

const (
    EcosystemGo  Ecosystem = "go"
    EcosystemNpm Ecosystem = "npm"
)

type Component struct {
    Name      string
    Version   string
    Ecosystem Ecosystem
    Hash      string    // checksum from lockfile
    Licenses  []string
    PkgURL    string    // Package URL (purl) format
}

type Severity string

const (
    SeverityCritical Severity = "CRITICAL"
    SeverityHigh     Severity = "HIGH"
    SeverityMedium   Severity = "MEDIUM"
    SeverityLow      Severity = "LOW"
    SeverityNone     Severity = "NONE"
)

type Finding struct {
    ID          string      // CVE or GHSA ID
    Aliases     []string    // cross-referenced IDs
    Summary     string
    Details     string
    Severity    Severity
    Component   Component
    FixedIn     string      // version that fixes this
    References  []string
    Source       string     // "osv", "hygiene", etc.
}

type ScanResult struct {
    Components []Component
    Findings   []Finding
    Hygiene    []Finding   // typosquat/integrity warnings
    Timestamp  time.Time
    ToolVersion string
}
```

### Scanner Interface

```go
type Scanner interface {
    // Ecosystem returns which ecosystem this scanner handles
    Ecosystem() Ecosystem

    // DetectManifests finds relevant manifest files under the given root
    DetectManifests(root string) ([]string, error)

    // ParseDependencies extracts components from a manifest file
    ParseDependencies(manifestPath string) ([]Component, error)
}
```

### Vulnerability Data Source

**OSV API** (https://api.osv.dev) — v1 only.

```
POST https://api.osv.dev/v1/querybatch
{
  "queries": [
    {"package": {"name": "example", "ecosystem": "Go"}, "version": "1.2.3"},
    ...
  ]
}
```

Batch queries are used to minimize round-trips. Max batch size: 1000 packages per request.

### Supply Chain Hygiene Checks

**Typosquatting detection:**
- Maintain a curated list of top 500 Go modules and top 500 npm packages
- For each scanned dependency, compute Levenshtein distance against the popular list
- Flag any dependency with edit distance <= 2 from a popular package (but not the package itself)
- Reported as findings with source="hygiene" and severity=HIGH

**Lockfile integrity:**
- For Go: verify `go.sum` entries exist for all modules in `go.mod`
- For npm: verify `package-lock.json` integrity hashes are present and non-empty
- Flag missing or empty checksums as findings with severity=MEDIUM

### Policy Engine (v1 — YAML-based)

```yaml
# .chainsaw.yaml
policy:
  fail-on: high
  ignore:
    - CVE-2024-1234
    - GHSA-xxxx-yyyy
  licenses:
    deny:
      - GPL-3.0-only
      - AGPL-3.0-only
```

Policy evaluation:
1. Filter out ignored CVEs/GHSAs
2. Check remaining findings against `fail-on` threshold
3. Check component licenses against deny list
4. Return exit code 1 if any policy violation exists

### Output Formats

**Table** (default for TTY):
```
SEVERITY  ID              PACKAGE            VERSION  FIXED IN
CRITICAL  CVE-2023-44487  golang.org/x/net   0.16.0   0.17.0
HIGH      GHSA-xxxx       lodash             4.17.20  4.17.21
```

**JSON** (for programmatic consumption):
```json
{
  "tool": "chainsaw",
  "version": "0.1.0",
  "timestamp": "2025-01-15T10:30:00Z",
  "components_scanned": 142,
  "findings": [...],
  "hygiene": [...]
}
```

**SARIF** (for CI/CD integration — GitLab, GitHub):
Standard SARIF 2.1.0 schema with findings mapped to `result` objects.

---

## Dependencies

| Concern              | Library                               |
|----------------------|---------------------------------------|
| CLI framework        | `github.com/spf13/cobra`              |
| Configuration        | `github.com/spf13/viper`              |
| Go module parsing    | `golang.org/x/mod`                    |
| Table output         | `github.com/olekukonez/tablewriter`   |
| Color output         | `github.com/fatih/color`              |
| CycloneDX SBOM       | `github.com/CycloneDX/cyclonedx-go`  |
| HTTP client          | `net/http` (stdlib)                   |
| JSON                 | `encoding/json` (stdlib)              |

---

## Development Phases

### Phase 1 — Core (this implementation)
- [x] Project scaffold
- [x] Shared models
- [x] Go module scanner (go.mod + go.sum)
- [x] npm scanner (package-lock.json)
- [x] OSV API client with batch queries
- [x] Table + JSON + SARIF output
- [x] `scan` command with `--format`, `--fail-on`, `--ecosystem`
- [x] CycloneDX SBOM generation (`sbom` command)
- [x] Policy engine (.chainsaw.yaml)
- [x] Typosquatting detection
- [x] Lockfile integrity checks
- [x] Makefile

### Phase 2 — Hardening (future)
- NVD enrichment / CVSS scoring
- Python ecosystem (requirements.txt, poetry.lock)
- SPDX SBOM format
- OpenSSF Scorecard integration
- `--config` flag for custom config path
- Caching layer for OSV responses

### Phase 3 — Enterprise (future)
- OPA policy engine backend
- Rust/Java ecosystem support
- Provenance verification (SLSA/Sigstore)
- License detection from package metadata
- Dashboard / reporting server mode

---

## Testing Strategy

- **Unit tests** for each scanner (parse known lockfiles, verify component extraction)
- **Unit tests** for OSV client (mock HTTP responses)
- **Unit tests** for policy evaluation
- **Integration test** with a fixture project containing known vulnerable dependencies
- **Golden file tests** for output formatters (table, JSON, SARIF)

---

## Security Considerations

- No credentials stored or transmitted (OSV API is unauthenticated)
- All HTTP requests use TLS
- Binary is statically linked — no shared library supply chain risk
- The tool itself should pass its own scan (dogfooding)
