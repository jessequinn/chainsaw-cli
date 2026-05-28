# Design: v1-core

**Status:** Archived (implemented)

## Architecture

### CLI Interface

```
chainsaw scan [path]                         # auto-detect manifests, table output
chainsaw scan --format json|sarif|table .    # structured output
chainsaw scan --fail-on [critical|high|medium|low] .
chainsaw scan --ecosystem go,npm .           # scope to ecosystems
chainsaw sbom [path]                         # generate SBOM only
chainsaw sbom --format cyclonedx .           # SBOM format selection
chainsaw version                             # print version info
```

Exit codes: 0 = clean, 1 = findings/violations, 2 = execution error.

### Project Structure

```
chainsaw/
├── cmd/chainsaw/main.go          # cobra root + subcommands
├── internal/
│   ├── scanner/                   # Scanner interface + ecosystem parsers
│   │   ├── scanner.go             # interface + registry
│   │   ├── gomod.go               # go.mod/go.sum parser
│   │   └── npm.go                 # package-lock.json parser
│   ├── vuln/                      # vulnerability data
│   │   ├── client.go              # OSV batch API client
│   │   └── matcher.go             # dedup + sort findings
│   ├── sbom/cyclonedx.go          # CycloneDX 1.5 JSON serializer
│   ├── hygiene/                   # supply chain heuristics
│   │   ├── typosquat.go           # Levenshtein-based detection
│   │   └── integrity.go           # missing checksum detection
│   ├── report/                    # output formatters
│   │   ├── table.go               # terminal table
│   │   ├── json.go                # JSON
│   │   └── sarif.go               # SARIF 2.1.0
│   ├── policy/policy.go           # YAML policy engine
│   └── config/config.go           # CLI config struct
├── pkg/models/models.go           # shared types
├── .chainsaw.yaml                 # example policy config
└── Makefile
```

### Core Types

- `Ecosystem` — typed string (`"go"`, `"npm"`)
- `Component` — name, version, ecosystem, hash, licenses, purl
- `Severity` — CRITICAL > HIGH > MEDIUM > LOW > NONE with rank function
- `Finding` — vulnerability or hygiene issue linked to a component
- `ScanResult` — aggregates components, findings, hygiene warnings

### Scanner Interface

Pluggable via `init()` registration pattern:
- `Ecosystem()` — which ecosystem this scanner handles
- `DetectManifests(root)` — walk filesystem for relevant files
- `ParseDependencies(path)` — extract components from a manifest

### Vulnerability Matching

OSV API (`POST /v1/querybatch`) with:
- Batch size cap of 1000 per request
- 30s HTTP timeout
- Ecosystem mapping: `"go"` to `"Go"`, `"npm"` to `"npm"`
- CVSS score to severity: >=9.0 CRITICAL, >=7.0 HIGH, >=4.0 MEDIUM, >0 LOW
- Fixed version extraction from affected ranges

### Policy Engine

Simple YAML (`.chainsaw.yaml`):
- `fail-on` severity threshold
- `ignore` list of CVE/GHSA IDs
- `licenses.deny` list of SPDX identifiers

No OPA in v1. Policy evaluation: filter ignored, check threshold, check licenses, return exit code.

### Dependencies

| Concern | Library |
|---|---|
| CLI | `github.com/spf13/cobra` |
| Go module parsing | `golang.org/x/mod` |
| YAML config | `gopkg.in/yaml.v3` |
| Everything else | stdlib (`net/http`, `encoding/json`, `fmt`) |

Notably absent vs. original SPEC.md: viper (not needed), tablewriter (plain fmt), color (plain text), cyclonedx-go (hand-rolled JSON).
