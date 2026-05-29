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
  thresholds, CVE ignore lists, and licence deny lists. Breaks builds
  when policy is violated.

- **Licence detection** -- resolves actual licences from npm and PyPI
  registries with allow/deny policy evaluation.

- **Scan diffing** -- compares scan results between runs to surface
  new/fixed vulnerabilities and component changes for PR workflows.

- **Security scaffolding** -- generates SECURITY.md, security.txt
  (RFC 9116), and CI workflow templates to bootstrap CRA compliance.

- **SBOM generation** -- CycloneDX 1.5 SBOMs covering application and
  infrastructure components.

## Install

```
go install github.com/chainsaw-dev/chainsaw/cmd/chainsaw@latest
```

Or build from source:

```
git clone https://github.com/chainsaw-dev/chainsaw.git
cd chainsaw
make build
```

## Usage

### Scan for vulnerabilities and supply chain issues

```sh
chainsaw scan .                              # auto-detect, table output
chainsaw scan --format json .                # JSON for CI pipelines
chainsaw scan --format sarif .               # SARIF for GitHub/GitLab
chainsaw scan --fail-on high .               # exit 1 on HIGH+ findings
chainsaw scan --ecosystem go,npm,pypi .      # scope to ecosystems
```

### Assess CRA compliance

```sh
chainsaw comply .                            # full CRA assessment
chainsaw comply --format json .              # machine-readable for GRC tools
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
chainsaw init-ci --fail-on critical --go-version 1.22 .
```

### Common flags

| Flag | Short | Description |
|------|-------|-------------|
| `--format` | `-f` | Output format: table, json, sarif |
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

### Track compliance over time

```sh
chainsaw comply --trend .                    # show CRA score progression
```

## Output Formats

| Format | Flag | Use Case |
|--------|------|----------|
| Table | `--format table` (default) | Human-readable terminal output |
| JSON | `--format json` | CI/CD pipelines, programmatic consumption |
| SARIF | `--format sarif` | GitHub Code Scanning, GitLab SAST |

## Policy Configuration

Create `.chainsaw.yaml` in your project root:

```yaml
policy:
  fail-on: high
  ignore:
    - CVE-2024-1234
  licences:
    deny-list:
      - GPL-3.0-only
      - AGPL-3.0-only

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
| SBOM generation | CycloneDX, SPDX | Syft | No | CycloneDX 1.5 |

Chainsaw does not compete on ecosystem breadth. Use Trivy if you need
20 ecosystems. Use chainsaw if you need to answer "are we CRA-ready?"

## Contributing

See `AGENTS.md` for development guidelines.

## Licence

Apache-2.0. See [LICENSE](LICENSE).
