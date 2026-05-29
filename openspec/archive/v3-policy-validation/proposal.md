# Change Proposal: v3-policy-validation

**Status:** Proposed
**Date:** 2026-05-29
**Author:** Agent

## Summary

Add schema validation for `.chainsaw.yaml` policy files. Currently
`LoadPolicy` does raw YAML unmarshal with no validation — invalid field
names are silently ignored and typos like `fail_on: hihg` produce a
zero-value severity that silently passes everything.

## Motivation

A misconfigured policy file should produce a clear error, not silently
pass all checks. This is critical for CI pipelines where policy
enforcement is the primary gate.

## Tasks

1. After unmarshalling, validate known field values:
   - `fail_on` must be a valid severity or empty.
   - `cra.required-score` must be 0-100.
   - `supply-chain.min-pinning-score` must be 0-100.
   - `licences.mode` must be "allow" or "deny" or empty.
2. Warn on unknown top-level YAML keys (use `yaml.Decoder` with
   `KnownFields(true)` or manual check).
3. Return descriptive error messages.
4. Add tests for invalid policy files.

## Non-goals

- JSON Schema generation for the policy format.
