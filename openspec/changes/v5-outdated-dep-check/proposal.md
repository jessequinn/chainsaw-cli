# v5-outdated-dep-check: Outdated Dependency Detection

## Summary

New hygiene check in `internal/hygiene/outdated.go`. For Go: query proxy.golang.org for latest version. For npm: query registry.npmjs.org. Flag packages where major version is behind by N (configurable in policy, default 2). Add as MEDIUM severity hygiene finding. Output includes suggested upgrade.

## Motivation

Outdated dependencies accumulate technical debt and often contain known vulnerabilities. Proactive detection encourages timely upgrades.

## Design

New `internal/hygiene/outdated.go`:
- `CheckOutdated()` function accepting Context and component list
- Go: query `https://proxy.golang.org/<module>/@latest` for version
- npm: query `https://registry.npmjs.org/<pkg>` for version
- Compare major versions; flag if N versions behind (configurable)
- Return `Finding` with suggested upgrade version
- Add `outdated-threshold` policy field (default 2)

## Non-goals

- Automatic upgrade suggestion (separate feature)
- Beta/RC version handling
- Monorepo version tracking

## Tasks

1. Implement Go version fetcher with caching -- ~1h
2. Implement npm version fetcher with caching -- ~1h
3. Implement version comparison logic -- ~45m
4. Add policy configuration for threshold -- ~30m
5. Add hygiene check integration -- ~45m
6. Add comprehensive tests with mocked registries -- ~1.5h

## Verification

- Detects packages 2+ major versions behind
- Configurable threshold works
- Go and npm queries work correctly
- Suggested upgrade version accurate
- Findings appear in scan output
- Caching reduces redundant requests
