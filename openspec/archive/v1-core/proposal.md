# Change Proposal: v1-core

**Status:** Archived (implemented)
**Date:** 2026-05-28
**Author:** Agent

## Summary

Implement the v1 core of chainsaw: a Go CLI for software supply chain
security scanning targeting EU Cyber Resilience Act (CRA) compliance.

## Motivation

Organizations subject to the CRA need to maintain accurate SBOMs,
continuously scan dependencies for known vulnerabilities, enforce license
compliance, and detect supply chain integrity issues. Existing tools
(Grype, Trivy, osv-scanner) solve parts of this but lack an integrated
CRA-oriented workflow with policy enforcement and supply chain hygiene
heuristics in a single binary.

## Proposed Changes

1. Cobra CLI with `scan`, `sbom`, and `version` commands
2. Scanner interface with Go module and npm lockfile parsers
3. OSV API client with batch vulnerability queries
4. CycloneDX 1.5 SBOM generation
5. YAML-based policy engine (severity threshold, CVE ignore list, license deny list)
6. Typosquatting detection via Levenshtein distance
7. Lockfile integrity verification (missing checksums)
8. Table, JSON, and SARIF 2.1.0 output formats

## Non-goals

- Behavioral/dynamic analysis of packages
- Container image scanning
- SAST/DAST
- NVD/CVSS enrichment (deferred to v2)
- OPA-based policy engine (deferred to v2/v3)
- SPDX SBOM format (deferred to v2)
- Python/Rust/Java ecosystem support (deferred to v2+)

## Risks

- OSV API availability and rate limits (mitigated by batch queries, 30s timeout)
- Typosquatting false positives on short package names (mitigated by
  only checking against a curated popular package list)
- Lockfile format changes in future npm versions (mitigated by
  supporting lockfileVersion 2 and 3)

## Acceptance Criteria

- `chainsaw scan .` detects Go and npm dependencies and queries OSV
- `chainsaw scan --format json|sarif .` produces valid structured output
- `chainsaw scan --fail-on high .` exits 1 when HIGH+ findings exist
- `chainsaw sbom .` produces valid CycloneDX 1.5 JSON
- `.chainsaw.yaml` policy file is loaded and evaluated
- Typosquatting and integrity warnings surface in scan results
- Binary compiles and runs with zero external runtime dependencies
