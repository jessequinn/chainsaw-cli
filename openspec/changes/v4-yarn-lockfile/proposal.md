# v4-yarn-lockfile: Yarn Lockfile Support

## Summary

Add Yarn lockfile parsing (`yarn.lock`) to the npm scanner,
covering both Yarn Classic (v1) and Yarn Berry (v2+) formats.

## Motivation

Yarn remains widely used, especially in React and monorepo
ecosystems. Without Yarn support, chainsaw misses these projects
entirely.

## Design

Extend `NpmScanner` to detect and parse `yarn.lock`:

- **Yarn v1**: custom format with `name@version:` blocks containing
  `version` and `resolved` fields. Parse with line-by-line state
  machine.
- **Yarn Berry (v2+)**: YAML format with `__metadata` header. Parse
  with `gopkg.in/yaml.v3`. Packages keyed by `name@npm:version`.

Auto-detect format by checking for `__metadata` key. Extract name,
version, integrity hash. Mark direct deps by cross-referencing
`package.json` if present.

## Non-goals

- Yarn PnP (Plug'n'Play) `.pnp.cjs` resolution.
- Yarn constraints evaluation.
- Yarn Berry patch protocol.

## Tasks

1. Yarn v1 lockfile parser (state machine) -- ~1.5h
2. Yarn Berry YAML parser -- ~1h
3. Direct dependency detection via `package.json` -- ~30m
4. Update `NpmScanner.DetectManifests` -- ~15m
5. Test fixtures (v1 + Berry) and table-driven tests -- ~1h
6. Update README -- ~10m

## Verification

- Parse real `yarn.lock` files from React, Next.js, etc.
- Component counts match `yarn list --json`.
