# Tasks: v1-core

**Status:** Archived (all complete)

## Tasks

- [x] Project scaffold (go.mod, directory structure, Makefile)
- [x] Shared models — `pkg/models/models.go`
- [x] Scanner interface + registry — `internal/scanner/scanner.go`
- [x] Go module scanner — `internal/scanner/gomod.go`
- [x] npm lockfile scanner — `internal/scanner/npm.go`
- [x] OSV API client — `internal/vuln/client.go`
- [x] Vulnerability matcher — `internal/vuln/matcher.go`
- [x] Typosquatting detection — `internal/hygiene/typosquat.go`
- [x] Lockfile integrity checks — `internal/hygiene/integrity.go`
- [x] Policy engine — `internal/policy/policy.go`
- [x] Config struct — `internal/config/config.go`
- [x] Table output — `internal/report/table.go`
- [x] JSON output — `internal/report/json.go`
- [x] SARIF output — `internal/report/sarif.go`
- [x] CycloneDX SBOM — `internal/sbom/cyclonedx.go`
- [x] CLI entry point — `cmd/chainsaw/main.go`
- [x] Example policy file — `.chainsaw.yaml`
- [x] Build verification — `go build ./cmd/chainsaw` passes
- [x] Smoke test — `chainsaw scan .`, `chainsaw sbom .`, `chainsaw version` all work

## Verification

```
$ ./chainsaw version
chainsaw dev

$ ./chainsaw scan .
Chainsaw Scan Results  2026-05-28
3 components scanned, 0 vulnerabilities found, 0 hygiene warnings

$ ./chainsaw scan --format json . | jq .components[0].purl
"pkg:golang/github.com/spf13/cobra@v1.10.2"

$ ./chainsaw sbom . | jq .bomFormat
"CycloneDX"
```
