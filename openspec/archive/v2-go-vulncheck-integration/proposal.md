# Change Proposal: v2-go-vulncheck-integration

**Status:** Proposed
**Date:** 2026-05-28
**Author:** Agent

## Strategic Context

> Go's official vulnerability database (`golang.org/x/vuln`) provides Go-specific coverage that OSV may miss. Integrating both sources improves detection for Go modules while maintaining OSV as the primary source. Priority: MEDIUM — improves Go ecosystem coverage without breaking existing functionality.

## Summary

Integrate Go's official vulnerability database alongside OSV for Go module scanning. Query `golang.org/x/vuln` for Go-specific vulnerabilities and merge results with OSV findings, deduplicating by CVE/GHSA ID.

## Motivation

The Go vulnerability database maintained by the Go security team covers Go-specific advisories with better precision than OSV alone. Many Go vulnerabilities are reported to the Go database first, and some are never published to OSV. Integrating both sources provides comprehensive coverage for Go modules while maintaining OSV as the fallback for other ecosystems.

## Proposed Changes

### Add `source` Field to Finding Model

Extend `pkg/models/Finding` to include a `Source` field (string) indicating the vulnerability source: `"osv"`, `"go-vuln-db"`, or `"both"` (when deduplicated).

### New Go Vuln DB Client

Create `internal/vuln/govuln.go` implementing a Go vulnerability database client:

- Query `golang.org/x/vuln/client` package to fetch vulnerabilities for a given module@version
- Handle the Go vuln DB JSON format (OSV-compatible but Go-specific)
- Implement caching to avoid redundant queries
- Set 30s timeout for all queries (consistent with OSV client)

### Extend Go Module Scanner

Modify `internal/scanner/gomod.go` to:

1. After querying OSV, query the Go vuln DB for the same components
2. Merge results by CVE/GHSA ID, marking duplicates with `Source: "both"`
3. Preserve all unique findings from both sources
4. Add `Source` field to each Finding

### Deduplication Logic

In `internal/vuln/matcher.go`, enhance deduplication to:

- Match by CVE ID first, then GHSA ID
- When a duplicate is found, set `Source: "both"` and keep the finding with higher severity
- Preserve both advisory URLs in a new `AdvisoryURLs` field (slice of strings)

### Update Report Formatters

- **Table formatter:** Add `Source` column showing `OSV`, `Go Vuln DB`, or `Both`
- **JSON formatter:** Include `source` and `advisory_urls` fields
- **SARIF formatter:** Add `source` to rule properties

## Non-goals

- Replacing OSV entirely; OSV remains the primary source for non-Go ecosystems
- Supporting `govulncheck` binary invocation (direct API integration only)
- Call graph analysis or transitive dependency filtering (out of scope)
- Caching Go vuln DB responses to disk (in-memory cache only)

## Risks

- Adds `golang.org/x/vuln` as a new dependency; must be vendored
- Go vuln DB only covers Go ecosystem; no benefit for npm, Python, etc.
- Go vuln DB API may change; requires monitoring upstream
- Deduplication logic must be robust to avoid duplicate findings in output

## Acceptance Criteria

- `chainsaw scan` on Go modules queries both OSV and Go vuln DB
- Findings deduplicated by CVE/GHSA ID
- `Source` field correctly set to `"osv"`, `"go-vuln-db"`, or `"both"`
- Table output shows source column
- JSON output includes `source` and `advisory_urls` fields
- SARIF output includes source in rule properties
- Unit tests with fixture `go.mod` files and recorded Go vuln DB responses
- No regression in scan time for projects with <100 dependencies

## Tasks

- [ ] Add `Source` field to `pkg/models/Finding`
- [ ] Add `AdvisoryURLs` field to `pkg/models/Finding`
- [ ] Implement Go vuln DB client in `internal/vuln/govuln.go`
- [ ] Extend `internal/scanner/gomod.go` to query Go vuln DB
- [ ] Implement deduplication logic in `internal/vuln/matcher.go`
- [ ] Update table formatter to show source column
- [ ] Update JSON formatter to include source and advisory URLs
- [ ] Update SARIF formatter to include source in rule properties
- [ ] Unit tests with fixture `go.mod` and recorded Go vuln DB responses
- [ ] Integration test comparing OSV-only vs. combined results
