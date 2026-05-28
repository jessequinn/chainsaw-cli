# Change Proposal: v2-licence-detection

**Status:** Proposed
**Date:** 2026-05-28
**Author:** Agent

## Strategic Context

> Licence compliance is a core CRA requirement. Current implementation only checks package names against a deny list; actual licence detection via registry APIs enables precise compliance evaluation. Priority: HIGH — directly addresses CRA compliance and differentiates chainsaw from generic vulnerability scanners.

## Summary

Detect actual licences for dependencies by querying package registry APIs (npm, PyPI, Go, Hex). Add `License` field to components and evaluate against policy deny/allow lists using detected licences instead of package names.

## Motivation

The current policy engine only checks package names against a deny list. This is insufficient for CRA compliance, which requires understanding actual licence obligations. By querying registry APIs, we can detect the actual SPDX licence identifier for each dependency and evaluate it against a licence policy. This enables users to enforce licence compliance at the supply chain level.

## Proposed Changes

### Add License Field to Component Model

Extend `pkg/models/Component` to include a `License` field (string) containing the SPDX identifier (e.g., `"MIT"`, `"Apache-2.0"`, `"GPL-3.0-only"`, or `"unknown"` if not detected).

### New Registry Licence Fetcher

Create `internal/hygiene/licence.go` implementing a licence fetcher:

- **npm:** Query `https://registry.npmjs.org/{package}/{version}` — extract `license` field from JSON
- **PyPI:** Query `https://pypi.org/pypi/{package}/{version}/json` — extract `license` from `info` object
- **Go:** Query Go module proxy metadata or `https://pkg.go.dev/{module}@{version}?tab=licenses` — parse licence from response
- **Hex:** Query `https://hex.pm/api/packages/{package}` — extract `license` from meta
- Implement in-memory cache (LRU, max 10k entries) to avoid redundant queries
- Set 10s timeout per query
- Respect registry rate limits: npm 200/min, PyPI 100/min, Hex 100/min
- Implement exponential backoff with jitter on rate limit (429) responses

### Extend Scanners

Modify `internal/scanner/npm.go`, `internal/scanner/gomod.go`, and future Python/Hex scanners to:

1. After parsing dependencies, call the licence fetcher for each component
2. Populate the `License` field on each `Component`
3. On network error or timeout, set `License: "unknown"` and continue (graceful degradation)

### Update Policy Engine

Extend `internal/policy/policy.go` to:

- Add `licence-deny-list` and `licence-allow-list` to policy YAML schema
- Evaluate each component's `License` field against the lists
- Report licence violations with the detected licence and policy rule
- Support SPDX identifier matching (e.g., `GPL-*` matches `GPL-2.0-only`, `GPL-3.0-or-later`)

### Update Report Formatters

- **Table formatter:** Add `License` column
- **JSON formatter:** Include `license` field in component objects
- **SARIF formatter:** Add licence violations as separate rule instances

## Non-goals

- Licence text analysis or classification beyond SPDX identifiers
- Scanning source code for LICENCE files
- Custom licence detection or regex-based matching
- Generating SPDX SBOM output (CycloneDX only in v1)

## Risks

- Network dependency: if registries are unreachable, licence detection fails silently (graceful degradation)
- Rate limits: high-volume scans may hit registry rate limits; requires backoff logic
- Incomplete registry data: not all packages have licence metadata; must handle `"unknown"` gracefully
- SPDX identifier inconsistency: registries may use non-standard identifiers; requires normalization

## Acceptance Criteria

- `chainsaw scan` detects licences for npm, Go, PyPI, and Hex dependencies
- Licences cached in-memory to avoid redundant queries
- Policy engine evaluates `licence-deny-list` and `licence-allow-list`
- Licence violations reported in all output formats
- Graceful degradation: missing licence data does not block scan
- Rate limit backoff implemented and tested
- Unit tests with fixture registry responses (recorded JSON)
- Integration test with real registry queries (optional, gated by flag)

## Tasks

- [ ] Add `License` field to `pkg/models/Component`
- [ ] Implement licence fetcher in `internal/hygiene/licence.go`
- [ ] Add npm licence query logic
- [ ] Add PyPI licence query logic
- [ ] Add Go module proxy licence query logic
- [ ] Add Hex licence query logic
- [ ] Implement LRU cache for licence queries
- [ ] Implement rate limit backoff
- [ ] Extend policy schema with `licence-deny-list` and `licence-allow-list`
- [ ] Update policy evaluator to check licences
- [ ] Update table formatter to show licence column
- [ ] Update JSON formatter to include licence field
- [ ] Update SARIF formatter for licence violations
- [ ] Unit tests with fixture registry responses
- [ ] Integration test with real registry queries
