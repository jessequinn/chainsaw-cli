# Change Proposal: v2-test-suite

**Status:** Proposed
**Date:** 2026-05-28
**Author:** Agent

## Strategic Context

> Zero `_test.go` files exist in the codebase. v1 shipped without any tests — critical technical debt for a security tool. This proposal establishes comprehensive test coverage across all scanners, engines, and reporters. Priority: CRITICAL — must complete before adding new scanners or policy rules.

## Summary

Implement comprehensive test suite for chainsaw covering all 8 scanners, CRA compliance engine, policy engine, vulnerability matching, hygiene checks, report formatters, and supply chain analysis. Use fixture lockfiles, table-driven tests, golden-file tests, and mocked HTTP for external APIs.

## Motivation

A supply-chain security tool must have exemplary test coverage. Current zero-test state creates risk of regressions, makes refactoring unsafe, and violates the Testing Policy mandate (TDD, BDD, ATDD). Fixture-based tests ensure determinism and enable offline development. Golden-file tests catch output format regressions.

## Proposed Changes

### Test Structure

- Test files colocated with source: `internal/scanner/gomod_test.go` beside `gomod.go`
- Fixtures in `testdata/` organized by ecosystem: `testdata/gomod/`, `testdata/npm/`, etc.
- Golden files in `testdata/golden/` for report output
- Mocked HTTP responses in `testdata/fixtures/osv/` (recorded real API responses)
- Table-driven tests throughout; `t.Helper()` in test helpers
- Use `t.TempDir()` for filesystem operations; no real files outside temp

### Scanner Tests (8 packages)

Each scanner gets unit tests covering:
- `DetectManifests()`: finds lockfiles, skips excluded dirs
- `ParseDependencies()`: parses fixture lockfiles, extracts components with correct purls
- Edge cases: empty files, malformed syntax, missing fields
- Typosquatting detection for popular packages

Fixture lockfiles from real projects (anonymised):
- `testdata/gomod/go.mod`, `go.sum` (Go 1.26+)
- `testdata/npm/package-lock.json` (npm v8+)
- `testdata/python/requirements.txt`, `poetry.lock`, `pipfile.lock`
- `testdata/dockerfile/Dockerfile` (multi-stage, base image extraction)
- `testdata/compose/docker-compose.yml` (service image references)
- `testdata/terraform/main.tf` (module sources, provider versions)
- `testdata/ansible/requirements.yml` (role/collection versions)
- `testdata/githubactions/workflow.yml` (action versions)

### CRA Compliance Engine Tests

Unit tests for all 20 checks in `internal/cra/`:
- Manufacturer identification
- Support end-date validation
- Security contact presence
- SBOM generation
- Vulnerability disclosure policy
- Pinning requirements
- Blast radius analysis
- Each check tested with passing and failing scenarios

### Policy Engine Tests

- `LoadPolicy()`: parses `.chainsaw.yaml`, validates schema
- `Evaluate()`: applies severity threshold, CVE ignore list, licence deny list
- Policy inheritance and override
- Malformed YAML handling
- Missing policy file handling

### Vulnerability Matcher & OSV Client Tests

- `Match()`: deduplicates findings, sorts by severity
- `QueryBatch()`: batches up to 1000 packages, handles pagination
- Mocked HTTP responses in `testdata/fixtures/osv/batch-response.json`
- Timeout handling (30s context deadline)
- Partial failures (some packages found, some not)
- Empty results handling

### Hygiene Check Tests

- Typosquatting: Levenshtein distance <= 2 against curated lists
- Integrity: SHA-256 hash verification for npm, Go, Python
- Lockfile tampering detection
- False positive rate on legitimate packages

### Report Formatter Tests

- Table formatter: column alignment, truncation, ANSI colors
- JSON formatter: valid JSON output, schema compliance
- SARIF formatter: SARIF 2.1.0 spec compliance, rule definitions
- Golden-file tests comparing output to `testdata/golden/report-*.txt`

### Supply Chain Analysis Tests

- Pinning score calculation (0-100)
- Blast radius estimation
- Transitive dependency tracking
- Pinning requirement enforcement (SHA vs semver)

### Integration Tests

- CLI command execution via `cmd.Execute()`
- Full scan workflow: detect -> parse -> query -> match -> report
- Exit codes: 0 (clean), 1 (findings), 2 (error)
- Output file generation (SARIF, CycloneDX)

## Non-goals

- Performance benchmarking (separate proposal)
- Mutation testing (future hardening)
- Coverage percentage targets (coverage is a guard rail, not a goal)
- End-to-end tests against real registries (use fixtures)

## Risks

- Large test suite may slow CI. Mitigation: parallelize with `go test -parallel`, cache dependencies
- Fixture maintenance burden. Mitigation: document fixture update process, automate where possible
- Mocking complexity for HTTP. Mitigation: use `httptest.Server`, record real responses once

## Acceptance Criteria

- All scanners have unit tests with >= 80% line coverage
- All policy engine rules tested
- All report formatters tested
- All hygiene checks tested
- No real network calls in tests
- All tests pass with `go test -race -coverprofile=coverage.txt ./...`
- Golden-file tests catch output regressions
- CI enforces coverage baseline

## Tasks

- [ ] Create `testdata/` directory structure and fixture lockfiles (2h)
- [ ] Implement `internal/scanner/gomod_test.go` with table-driven tests (2h)
- [ ] Implement `internal/scanner/npm_test.go` (2h)
- [ ] Implement `internal/scanner/python_test.go` (2h)
- [ ] Implement `internal/scanner/dockerfile_test.go` (2h)
- [ ] Implement `internal/scanner/compose_test.go` (2h)
- [ ] Implement `internal/scanner/terraform_test.go` (2h)
- [ ] Implement `internal/scanner/ansible_test.go` (2h)
- [ ] Implement `internal/scanner/githubactions_test.go` (2h)
- [ ] Implement `internal/vuln/client_test.go` with mocked HTTP (2h)
- [ ] Implement `internal/vuln/matcher_test.go` (2h)
- [ ] Implement `internal/policy/policy_test.go` (2h)
- [ ] Implement `internal/hygiene/integrity_test.go` (2h)
- [ ] Implement `internal/hygiene/typosquat_test.go` (2h)
- [ ] Implement `internal/report/table_test.go` with golden files (2h)
- [ ] Implement `internal/report/json_test.go` (2h)
- [ ] Implement `internal/report/sarif_test.go` (2h)
- [ ] Implement `internal/sbom/cyclonedx_test.go` (2h)
- [ ] Implement `internal/cra/compliance_test.go` (2h)
- [ ] Implement `cmd/chainsaw/scan_test.go` integration tests (2h)
- [ ] Set up CI coverage reporting to Codecov (1h)
