# Change Proposal: v2-context-propagation

**Status:** Proposed
**Date:** 2026-05-28
**Author:** Agent

## Strategic Context

> AGENTS.md mandates `context.Context` as first parameter for all I/O-bound functions per Go conventions. Current codebase does not propagate context, preventing timeout enforcement, cancellation, and graceful degradation. Priority: HIGH — must complete before adding retries or signal handling.

## Summary

Retrofit all I/O-bound functions across the codebase to accept `context.Context` as the first parameter. Update the `Scanner` interface, OSV client, policy loader, report writers, SBOM generator, and CLI entry point to support context-driven cancellation and timeouts.

## Motivation

Context propagation enables:
- Timeout enforcement on registry API calls (30s deadline)
- Graceful cancellation on user interrupt (Ctrl+C)
- Request-scoped values (trace IDs, request metadata)
- Compliance with Go conventions and AGENTS.md mandate
- Foundation for future retry logic and observability

Current code lacks context, making it impossible to enforce timeouts or cancel in-flight requests.

## Proposed Changes

### Scanner Interface Update

Update `internal/scanner/scanner.go`:

```go
type Scanner interface {
    DetectManifests(ctx context.Context, root string) ([]string, error)
    ParseDependencies(ctx context.Context, path string) ([]Component, error)
}
```

All 8 scanner implementations updated to accept and use context.

### OSV Client

Update `internal/vuln/client.go`:

- `NewClient()` stores base context (or accepts it in `QueryBatch`)
- `QueryBatch(ctx context.Context, packages []string) ([]Vulnerability, error)`
- Enforce 30s timeout on HTTP requests via `context.WithTimeout(ctx, 30*time.Second)`
- Propagate context to `http.NewRequestWithContext()`

### Vulnerability Matcher

Update `internal/vuln/matcher.go`:

- `Match(ctx context.Context, components []Component, vulns []Vulnerability) ([]Finding, error)`

### Policy Engine

Update `internal/policy/policy.go`:

- `LoadPolicy(ctx context.Context, path string) (*Policy, error)` — file I/O needs context
- `Evaluate(ctx context.Context, findings []Finding) (Result, error)`

### Report Writers

Update all files in `internal/report/`:

- `WriteTable(ctx context.Context, w io.Writer, findings []Finding) error`
- `WriteJSON(ctx context.Context, w io.Writer, findings []Finding) error`
- `WriteSARIF(ctx context.Context, w io.Writer, findings []Finding) error`

### SBOM Generator

Update `internal/sbom/cyclonedx.go`:

- `GenerateCycloneDX(ctx context.Context, components []Component) ([]byte, error)`

### CRA Compliance Engine

Update `internal/cra/compliance.go`:

- `Assess(ctx context.Context, components []Component) (ComplianceResult, error)`

### Supply Chain Analysis

Update `internal/analysis/` (if it exists):

- All functions that perform I/O accept context

### CLI Entry Point

Update `cmd/chainsaw/main.go`:

- Create root context with signal handling:
  ```go
  ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
  defer cancel()
  ```
- Pass context through command execution chain
- Respect context cancellation in long-running operations

### Scan Command

Update `cmd/chainsaw/scan.go`:

- Accept context from main
- Pass to all scanner, matcher, policy, and report functions
- Propagate to OSV client

### SBOM Command

Update `cmd/chainsaw/sbom.go`:

- Accept context from main
- Pass to SBOM generator

## Non-goals

- Adding retries or exponential backoff (separate proposal)
- Adding timeouts beyond the 30s OSV deadline (separate proposal)
- Observability/tracing integration (future)
- Context-scoped logging (future)

## Risks

- **Breaking change to `Scanner` interface.** All 8 scanners must update. Mitigation: update all scanners in the same commit; add integration tests to catch missing updates
- **Cascading parameter changes.** Many internal functions need updating. Mitigation: systematic refactor, test each package
- **Existing code may not respect context cancellation.** Mitigation: audit all I/O calls, ensure `context.WithTimeout` is used

## Acceptance Criteria

- All I/O-bound functions accept `context.Context` as first parameter
- `Scanner` interface updated; all 8 scanners implement new signature
- OSV client enforces 30s timeout via context
- CLI creates root context with signal handling
- User can interrupt scan with Ctrl+C and context cancels gracefully
- All tests pass with `go test -race ./...`
- No breaking changes to CLI flags or output formats

## Tasks

- [ ] Update `internal/scanner/scanner.go` interface (1h)
- [ ] Update all 8 scanner implementations in `internal/scanner/` (2h)
- [ ] Update `internal/vuln/client.go` with context and timeout (1h)
- [ ] Update `internal/vuln/matcher.go` (30m)
- [ ] Update `internal/policy/policy.go` (30m)
- [ ] Update `internal/report/table.go`, `json.go`, `sarif.go` (1h)
- [ ] Update `internal/sbom/cyclonedx.go` (30m)
- [ ] Update `internal/cra/compliance.go` (30m)
- [ ] Update `cmd/chainsaw/main.go` with signal handling (1h)
- [ ] Update `cmd/chainsaw/scan.go` (1h)
- [ ] Update `cmd/chainsaw/sbom.go` (30m)
- [ ] Add integration tests for context cancellation (1h)
- [ ] Verify no regressions with full test suite (1h)
