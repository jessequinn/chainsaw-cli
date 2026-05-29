# v4-pnpm-lockfile: pnpm Lockfile Support

## Summary

Add pnpm lockfile parsing (`pnpm-lock.yaml`) to the npm scanner,
expanding JavaScript ecosystem coverage beyond `package-lock.json`.

## Motivation

pnpm is the second-most popular Node.js package manager. Many
enterprise projects use pnpm for its strict dependency isolation
and performance. Without pnpm support, chainsaw cannot scan a
significant portion of the JavaScript ecosystem.

## Design

Extend `NpmScanner` to detect and parse `pnpm-lock.yaml` (v6 and v9
formats). The YAML structure differs from `package-lock.json`:

- v6: packages keyed by `/<name>@<version>` under `packages:`
- v9: packages keyed by `<name>@<version>` under `packages:`,
  importers section for workspace support

Parse both formats, extract name, version, and integrity hash.
Mark workspace root deps as `Direct: true`. Emit components with
`Ecosystem: npm` and purl scheme `pkg:npm/`.

## Non-goals

- pnpm workspace cross-referencing beyond direct/transitive marking.
- Patched dependency support (`pnpm.patchedDependencies`).

## Tasks

1. Add pnpm lockfile v9 parser (parse `pnpm-lock.yaml`, extract
   packages) -- ~1.5h
2. Add pnpm lockfile v6 backward-compat parser -- ~1h
3. Update `NpmScanner.DetectManifests` to find `pnpm-lock.yaml` -- ~15m
4. Add test fixtures and table-driven tests -- ~1h
5. Update README ecosystem table -- ~10m

## Verification

- Parse real-world `pnpm-lock.yaml` from popular projects.
- Components match `pnpm list --json` output.
- Vulnerability queries return expected results.
