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
  OSV for Go, npm, and Python ecosystems with typosquatting detection
  and lockfile integrity verification.

- **Policy enforcement** -- YAML-based policy engine with severity
  thresholds, CVE ignore lists, and licence deny lists. Breaks builds
  when policy is violated.

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

### Generate SBOM

```sh
chainsaw sbom .                              # CycloneDX 1.5 JSON to stdout
chainsaw sbom --format cyclonedx .           # explicit format
```

## Supported Ecosystems

### Application Dependencies

| Ecosystem | Manifest | Vulnerability Data |
|-----------|----------|-------------------|
| Go | `go.mod` / `go.sum` | OSV (Go) |
| npm | `package-lock.json` | OSV (npm) |
| Python | `requirements.txt`, `Pipfile.lock`, `poetry.lock` | OSV (PyPI) |

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
| Known vulnerabilities | Annex I, Part 1(2)(a) | No known exploitable vulns |
| Disclosure process | Annex I, Part 2(5) | SECURITY.md, security.txt, contact info |
| Update mechanism | Annex I, Part 2(7) | Releases, changelog, semver tags |
| Support period | Annex II(7) | End-date documented |
| Reporting readiness | Article 14 | CI scanning, CSIRT contact, 24h process |

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
  licenses:
    deny:
      - GPL-3.0-only
      - AGPL-3.0-only

cra:
  product-name: "My Product"
  product-version: "2.1.0"
  manufacturer: "My Company GmbH"
  support-end-date: "2031-12-31"
  security-contact: "security@mycompany.eu"
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
| Application SCA | 20+ ecosystems | SBOM-driven | OSV-native | Go, npm, Python |
| CRA compliance | No | No | No | **Core feature** |
| Infra supply chain | IaC misconfig | No | No | **Pinning + provenance** |
| CI/CD supply chain | No | No | No | **GH Actions analysis** |
| Policy enforcement | No | No | No | **YAML + CRA** |
| SBOM generation | CycloneDX, SPDX | Syft | No | CycloneDX 1.5 |

Chainsaw does not compete on ecosystem breadth. Use Trivy if you need
20 ecosystems. Use chainsaw if you need to answer "are we CRA-ready?"

## Contributing

See `AGENTS.md` for development guidelines.

## Licence

TBD
