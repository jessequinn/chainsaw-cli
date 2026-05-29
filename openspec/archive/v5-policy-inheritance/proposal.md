# v5-policy-inheritance: Policy File Composition and Extension

## Summary

Add `extends:` field to `.chainsaw.yaml` pointing to a URL or local path. LoadPolicy fetches and merges the parent policy, with local fields overriding. Support `extends: "https://raw.githubusercontent.com/org/.chainsaw.yaml"` and `extends: "../shared/.chainsaw.yaml"`. Max 3 levels of inheritance.

## Motivation

Organizations need policy templates and shared baselines. Inheritance enables DRY policy configuration and centralized governance.

## Design

In `internal/policy/policy.go`:
- Add `Extends` field to Policy struct
- LoadPolicy recursively fetches parent via HTTP or file path
- Merge parent fields with local fields (local wins)
- Limit depth to 3 to prevent cycles
- Cache fetched policies to avoid redundant downloads
- Validate URL format (HTTPS only)

## Non-goals

- Circular dependency detection (depth limit prevents this)
- Schema validation of extended policies
- Conditional inheritance

## Tasks

1. Add Extends field and parsing -- ~30m
2. Implement recursive load logic -- ~1h
3. Implement merge semantics -- ~45m
4. Add depth limiting and cycle prevention -- ~30m
5. Add HTTP fetch with timeout (reuse OSV client patterns) -- ~30m
6. Add comprehensive tests (local and HTTP) -- ~1.5h

## Verification

- Local extends path resolves correctly
- HTTP extends URL fetches and merges
- Local fields override parent fields
- Depth limit prevents infinite recursion
- Caching reduces redundant fetches
- All existing policy tests still pass
