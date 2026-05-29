# v5-policy-ecosystem-overrides: Per-Ecosystem Policy Thresholds

## Summary

Add `ecosystems:` map to policy file under `policy:` section. Keys are ecosystem names, values are `{fail-on: SEVERITY}`. During `Evaluate()`, per-ecosystem threshold takes precedence over global `fail-on`. Example: `ecosystems: {go: {fail-on: HIGH}, github-actions: {fail-on: CRITICAL}}`.

## Motivation

Different ecosystems have different risk profiles. Go dependencies warrant stricter thresholds than GitHub Actions, which are less likely to execute untrusted code. Per-ecosystem overrides enable fine-grained policy.

## Design

In `internal/policy/policy.go`:
- Add `Ecosystems map[string]EcosystemPolicy` to Policy
- `EcosystemPolicy` has `FailOn Severity` field
- During evaluation in matcher, check per-ecosystem threshold first
- Fall back to global `fail-on` if no override
- Support in YAML unmarshalling

## Non-goals

- Per-component policies
- Severity transformations (e.g., downgrade npm findings)

## Tasks

1. Add Ecosystems field to Policy struct -- ~30m
2. Update YAML unmarshalling -- ~30m
3. Implement override logic in matcher -- ~45m
4. Update policy evaluation tests -- ~1h
5. Add integration test with multi-ecosystem project -- ~1h
6. Update `.chainsaw.yaml` example -- ~15m

## Verification

- Ecosystem-specific thresholds applied correctly
- Global fallback works when no override
- Example policies validate and work as expected
- All existing tests still pass
- Mixed projects show correct per-ecosystem behavior
