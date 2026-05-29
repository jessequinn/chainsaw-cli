# v5-comply-sarif: SARIF Output for Compliance Reports

## Summary

Add SARIF 2.1.0 output to the `comply` command via `--format sarif`. Map each `CRACheck` to a SARIF `result` with: ruleId=check.ID, message=check.Details, level=check.Severity mapped to SARIF levels, helpUri pointing to CRA regulation articles. Reuse `internal/report/sarif.go` patterns.

## Motivation

SARIF integration enables compliance reports to be ingested by GitHub Advanced Security, Sarif Upload API, and other security dashboards. CI/CD pipelines can parse and track compliance violations over time.

## Design

Extend `internal/report/sarif.go`:
- New `WriteCRAResultsAsSARIF()` function
- Map CRA check severity to SARIF levels: CRITICAL->error, HIGH->warning, MEDIUM->note
- Each check becomes a `result` with helpful helpUri (e.g., `https://eur-lex.europa.eu/eli/reg/2024/1847/`)
- Emit CRA-specific rule definitions
- Add `--format sarif` option to `comply` command

## Non-goals

- GitHub Advanced Security API push (separate integration)
- Signed SARIF

## Tasks

1. Add CRA-to-SARIF mapping logic in `sarif.go` -- ~1h
2. Generate helpUri references to CRA articles -- ~30m
3. Add `--format sarif` flag parsing in comply command -- ~30m
4. Implement output writer integration -- ~30m
5. Add test fixtures with real CRA checks -- ~1h
6. Validate against SARIF 2.1.0 schema -- ~30m

## Verification

- SARIF output validates against official schema
- CRA checks appear as results with correct severity
- GitHub can parse and display the SARIF
- helpUri links resolve to CRA regulation text
