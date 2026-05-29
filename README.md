# Chainsaw

CRA-ready supply chain compliance for software and infrastructure.

Chainsaw is a Go CLI that scans your entire supply chain -- application
dependencies, infrastructure-as-code, and CI/CD pipelines -- and
assesses readiness against the EU Cyber Resilience Act (Regulation
2024/2847).

## Why Chainsaw

Existing tools scan application dependencies for known CVEs. Chainsaw
goes further:

- **CRA compliance assessment** -- checks your project against Annex I
  requirements, Article 14 reporting readiness, SBOM completeness,
  vulnerability disclosure process, and support period documentation.
  Article 14 reporting obligations apply **September 11, 2026**.

- **Infrastructure supply chain analysis** -- treats Terraform providers,
  GitHub Actions, Dockerfiles, Ansible collections, and Docker Compose
  images as first-class supply chain components with pinning analysis,
  provenance checks, and blast radius scoring.

- **Application dependency scanning** -- vulnerability matching against
  OSV and Go vulnerability database for Go, npm, Python, and Elixir
  ecosystems with typosquatting detection and lockfile integrity verification.

- **Policy enforcement** -- YAML-based policy engine with severity
  thresholds, CVE ignore lists, licence deny lists, inheritance chains,
  and per-ecosystem overrides. Breaks builds when policy is violated.

- **Licence detection** -- resolves actual licences from npm and PyPI
  registries with allow/deny policy evaluation.

- **Scan diffing** -- compares scan results between runs to surface
  new/fixed vulnerabilities and component changes for PR workflows.

- **Security scaffolding** -- generates SECURITY.md, security.txt
  (RFC 9116), and CI workflow templates to bootstrap CRA compliance.

- **SBOM generation** -- CycloneDX 1.5 SBOMs covering application and
  infrastructure components.

- **Evidence export** -- ZIP bundles with scan results, CRA assessment,
  supply chain analysis, SBOM, and manifest with SHA-256 checksums for
  audit trails and regulatory documentation.

- **CRA documentation generation** -- Article 10(2) technical documentation
  skeleton and EU Declaration of Conformity per Article 28 to accelerate
  compliance workflows.

- **Watch mode** -- polling-based re-scan on lockfile changes for real-time
  feedback during development.

- **Baseline tracking** -- save findings as baseline for delta reporting and
  triage workflows.

## Install

### Homebrew (macOS and Linux)

```
brew tap jessequinn/chainsaw-cli
brew install --cask chainsaw-cli
```

### Go install

```
go install github.com/chainsaw-dev/chainsaw/cmd/chainsaw@latest
```

### Build from source

```
git clone https://github.com/jessequinn/chainsaw-cli.git
cd chainsaw-cli
make build
```

## Usage

### Scan for vulnerabilities and supply chain issues

```sh
chainsaw scan .                              # auto-detect, table output
chainsaw scan --format json .                # JSON for CI pipelines
chainsaw scan --format sarif .               # SARIF for GitHub/GitLab
chainsaw scan --format markdown .             # Markdown for PR comments
chainsaw scan --tree .                        # dependency tree visualization
chainsaw scan --fail-on high .               # exit 1 on HIGH+ findings
chainsaw scan --ecosystem go,npm,pypi .      # scope to ecosystems
```

### Assess CRA compliance

```sh
chainsaw comply .                            # full CRA assessment
chainsaw comply --format json .              # machine-readable for GRC tools
chainsaw comply --format sarif .             # SARIF output for GitHub
chainsaw comply --format markdown .          # Markdown tables for PR comments
```

### Analyze infrastructure supply chain

```sh
chainsaw supply-chain .                      # multi-layer analysis
chainsaw supply-chain --format json .        # machine-readable output
```

### Run unified compliance check

```sh
chainsaw check .                             # scan + comply + supply-chain in one
chainsaw check --format json .               # machine-readable combined output
chainsaw check --output results.json .       # write to file
```

### Generate SBOM

```sh
chainsaw sbom .                              # CycloneDX 1.5 JSON to stdout
chainsaw sbom --format cyclonedx .           # explicit format
```

### Compare scan results

```sh
chainsaw diff --base main.json --head pr.json        # table output
chainsaw diff --base main.json --head pr.json --format markdown  # for PR comments
chainsaw diff --base main.json --head pr.json --fail-on high     # CI gate
```

### Scaffold security files

```sh
chainsaw init-security .                             # SECURITY.md + security.txt + INCIDENT-RESPONSE.md + .chainsaw.yaml
chainsaw init-security --org "My Company" --email security@example.com .
```

### Generate CI workflow

```sh
chainsaw init-ci .                                   # .github/workflows/chainsaw.yml
chainsaw init-ci --platform gitlab .                 # GitLab CI template
chainsaw init-ci --fail-on critical --go-version 1.22 .
```

### Configure CRA compliance

```sh
chainsaw init-cra .                                  # CRA compliance config wizard
chainsaw init-cra --product "My SaaS" --manufacturer "My Company GmbH" .
chainsaw init-cra --category critical --force .      # category: critical, important, base, default
```

### Generate CRA evidence and documentation

```sh
chainsaw evidence .                                  # ZIP bundle (scan results, CRA assessment, supply chain, SBOM, manifest with SHA-256)
chainsaw generate-docs .                             # Article 10(2) technical documentation skeleton
chainsaw generate-declaration .                      # EU Declaration of Conformity per Article 28
```

### Baseline management

```sh
chainsaw baseline .                                  # save current findings as baseline
chainsaw baseline --update .                         # refresh baseline
chainsaw scan .                                      # baseline automatically used for delta reporting
```

### Watch mode

```sh
chainsaw watch .                                     # polling-based re-scan on lockfile changes
```

### Pre-commit hooks

```sh
chainsaw init-hooks .                                # setup git pre-commit hook (native)
chainsaw init-hooks --framework pre-commit .         # setup pre-commit framework hook
```

### Output JSON schemas

```sh
chainsaw schema --name scan-result                   # print JSON Schema v7 for scan output
chainsaw schema --name compliance-result             # print JSON Schema v7 for comply output
```

### Common flags

| Flag | Short | Description |
|------|-------|-------------|
| `--format` | `-f` | Output format: table, json, sarif, markdown |
| `--output` | `-o` | Write output to file instead of stdout |
| `--quiet` | `-q` | Suppress progress messages |
| `--policy` | | Path to policy file (default: .chainsaw.yaml) |
| `--fail-on` | | Minimum severity to trigger exit code 1 |

## Supported Ecosystems

### Application Dependencies

| Ecosystem | Manifest | Vulnerability Data |
|-----------|----------|-------------------|
| Go | `go.mod` / `go.sum` | OSV (Go) + Go Vuln DB |
| npm | `package-lock.json` | OSV (npm) |
| Python | `requirements.txt`, `Pipfile.lock`, `poetry.lock` | OSV (PyPI) |
| Elixir | `mix.lock` | OSV (Hex) |

### Infrastructure Supply Chain

| Ecosystem | Manifest | Analysis |
|-----------|----------|----------|
| GitHub Actions | `.github/workflows/*.yml` | SHA/tag/branch pin classification, blast radius |
| Dockerfile | `Dockerfile*` | Digest/tag pinning, base image trust |
| Docker Compose | `docker-compose.yml`, `compose.yml` | Service image enumeration, pinning |
| Terraform | `.terraform.lock.hcl`, `*.tf` | Provider pinning, module provenance |
| Ansible | `requirements.yml` | Collection pinning, version enforcement |

### CRA Compliance Checks

| Check | CRA Reference | What It Verifies |
|-------|---------------|-----------------|
| SBOM completeness | Annex I, Part 2(1) | Top-level deps, versions, purls, hashes |
| Transitive SBOM | Annex I, Part 2(1) | Direct vs transitive dep classification |
| Known vulnerabilities | Annex I, Part 1(2)(a) | No known exploitable vulns |
| Disclosure process | Annex I, Part 2(5) | SECURITY.md, security.txt, contact info |
| Update mechanism | Annex I, Part 2(7) | Releases, changelog, semver tags |
| Support period | Annex II(7) | End-date documented |
| Reporting readiness | Article 14 | CSIRT contact, 24h early warning process |
| Product classification | Article 32 | Annex III/IV category, conformity assessment |
| Secure defaults | Annex I, Part 1(3) | Dockerfile USER, GH Actions permissions |
| Deadline countdown | Article 14 | Days remaining, urgency level |
| Deadline timeline | Articles 13-14 | 5 milestones: 2026-09-11, 2027-03-11, 2027-09-11, 2028-09-11, 2030-09-11 |
| Gap remediation plan | Article 14 | Role assignment, effort estimation, priority scoring |

### Track compliance over time

```sh
chainsaw comply --trend .                    # show CRA score progression
```

## Output Formats

| Format | Flag | Use Case |
|--------|------|----------|
| Table | `--format table` (default) | Human-readable terminal output |
| JSON | `--format json` | CI/CD pipelines, programmatic consumption |
| Markdown | `--format markdown` | PR comments, collaboration tools |
| SARIF | `--format sarif` | GitHub Code Scanning, GitLab SAST |

## Policy Configuration

Create `.chainsaw.yaml` in your project root:

```yaml
# Inherit from base policy (local path or HTTP URL, max 3 levels)
extends: ./base-policy.yaml

policy:
  fail-on: high
  ignore:
    - CVE-2024-1234
    - cve: CVE-2024-5678
      reason: "Vendor has patched in their infrastructure"
      expires: "2026-12-31"
  licences:
    deny-list:
      - GPL-3.0-only
      - AGPL-3.0-only

# Per-ecosystem fail-on thresholds
ecosystems:
  go: critical
  npm: high
  pypi: high

cra:
  product-name: "My Product"
  product-version: "2.1.0"
  manufacturer: "My Company GmbH"
  support-end-date: "2031-12-31"
  security-contact: "security@mycompany.eu"
  csirt-contact: "https://www.enisa.europa.eu/csirt-inventory"
  product-category: "default"

supply-chain:
  min-pinning-score: 70
```

Enable licence detection with `--detect-licences` on the `scan` command:

```sh
chainsaw scan --detect-licences .
```

## Exit Codes

| Code | Meaning |
|------|---------|
| 0 | No findings above threshold |
| 1 | Findings above threshold or policy violation |
| 2 | Execution error |

## How Chainsaw Differs

Chainsaw is not another vulnerability scanner. It is a **compliance
engine** that uses vulnerability scanning as one input among several.

| Capability | Trivy | Grype | osv-scanner | **Chainsaw** |
|------------|-------|-------|-------------|-------------|
| Application SCA | 20+ ecosystems | SBOM-driven | OSV-native | Go, npm, Python, Elixir |
| CRA compliance | No | No | No | **Core feature** |
| Infra supply chain | IaC misconfig | No | No | **Pinning + provenance** |
| CI/CD supply chain | No | No | No | **GH Actions analysis** |
| Policy enforcement | No | No | No | **YAML + CRA** |
| Licence detection | No | No | No | **npm + PyPI registries** |
| Scan diffing | No | No | No | **diff command** |
| Evidence export | No | No | No | **ZIP with audit trail** |
| CRA doc generation | No | No | No | **Tech docs + declaration** |
| Watch mode | No | No | No | **Polling re-scan** |
| Baseline tracking | No | No | No | **Delta reporting** |
| SBOM generation | CycloneDX, SPDX | Syft | No | CycloneDX 1.5 |

Chainsaw does not compete on ecosystem breadth. Use Trivy if you need
20 ecosystems. Use chainsaw if you need to answer "are we CRA-ready?"

## Contributing

See `AGENTS.md` for development guidelines.

## Licence

Apache-2.0. See [LICENSE](LICENSE).
