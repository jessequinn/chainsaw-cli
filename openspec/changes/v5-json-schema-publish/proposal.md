# v5-json-schema-publish: JSON Schema Generation and Validation

## Summary

Generate JSON schemas for: ScanResult, CRAResult, SupplyChainResult, CheckOutput. Store in `schemas/` directory. Add `--schema` flag to output commands that prints the schema instead of running the scan. Validate output in tests using `jsonschema` package or manual field checks.

## Motivation

JSON schemas enable IDE validation, client code generation, and contract testing. Developers can validate their chainsaw output against the schema before integration.

## Design

New directory `schemas/` at repo root with:
- `scan-result.schema.json`
- `cra-result.schema.json`
- `supply-chain-result.schema.json`
- `check-output.schema.json`

Generate schemas from Go types using reflection or manual definition. Add `--schema` flag to `scan`, `comply`, `supply-chain`, `check` commands. When `--schema` is set, print schema and exit 0.

## Non-goals

- Schema auto-generation from Go tags
- JSON Schema v2020-12 features (stay with v7)
- OpenAPI schema generation

## Tasks

1. Define schemas manually or via code generator -- ~2h
2. Store schemas in `schemas/` directory -- ~30m
3. Add `--schema` flag parsing to commands -- ~1h
4. Implement schema output logic -- ~30m
5. Add schema validation in integration tests -- ~1h
6. Document schema availability -- ~30m

## Verification

- Each schema validates against JSON Schema meta-schema
- Real output validates against schema
- `--schema` flag outputs correctly
- IDE tooling can use schemas for completion
- Test validation catches schema mismatches
