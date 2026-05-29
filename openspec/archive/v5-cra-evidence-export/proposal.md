# v5-cra-evidence-export: Evidence Archive Export for CRA Compliance

## Summary

New `chainsaw evidence [path]` command that produces a ZIP archive containing: scan results (JSON), CRA assessment (JSON), SBOM (CycloneDX), supply chain analysis (JSON), and a `manifest.json` with SHA-256 checksums of each file, assessment date, tool version, and product metadata. CRA Article 10(12) requires 10-year retention of technical documentation.

## Motivation

Organizations need a single, tamper-evident package for audits and regulatory submissions. The manifest with checksums provides integrity verification.

## Design

New command `chainsaw evidence [path]` in `internal/cmd/evidence.go`:
- Runs `scan`, `comply`, `sbom`, and `supply-chain` in sequence
- Collects outputs to temporary files
- Computes SHA-256 checksums of each
- Creates `manifest.json` with: product (from policy), version, date, checksums, tool version
- Creates ZIP: `evidence-<product>-<date>.zip`
- Lives in `internal/cmd/` and `internal/evidence/`

## Non-goals

- GPG signing of manifest
- 7-year retention tracking
- Automatic archive upload to cloud storage

## Tasks

1. Create `evidence.go` command skeleton -- ~30m
2. Implement evidence collection and checksum generation -- ~1h
3. Implement ZIP creation with manifest -- ~1h
4. Add flag parsing (`--path`, `--output`) -- ~15m
5. Add integration tests with fixture projects -- ~1h
6. Update CLI documentation -- ~15m

## Verification

- ZIP archive created with correct structure
- Manifest checksums match file contents
- CycloneDX 1.5 schema validation passes
- Unpacking and verifying integrity works
