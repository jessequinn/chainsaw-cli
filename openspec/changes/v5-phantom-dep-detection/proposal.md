# v5-phantom-dep-detection: Phantom Dependency Detection

## Summary

New hygiene check in `internal/hygiene/phantom.go`. For npm: scan `.js`/`.ts` files for `require()`/`import` statements, compare against `package.json` `dependencies` keys. Flag imports that resolve only through transitive hoisting. MEDIUM severity. Show the import path and which transitive package provides it.

## Motivation

Phantom dependencies cause silent breakage during upgrades. Proactive detection enables fixing before production impact. This is a common npm footgun.

## Design

New `internal/hygiene/phantom.go`:
- `CheckPhantom()` function for npm projects
- Walk project directory (skip node_modules) collecting `.js`/`.ts` imports
- Parse `require()` and `import` statements (regex-based, not AST)
- Cross-reference against `package.json` `dependencies` (not transitive)
- Flag missing direct dependencies
- Resolve transitive provider from `package-lock.json`
- Return `Finding` with import path and provider info

## Non-goals

- Go module phantom deps (not applicable; Go requires explicit imports)
- Auto-fix via `npm install`
- Deep AST parsing

## Tasks

1. Implement import parser (regex for require/import) -- ~1.5h
2. Implement dependency lookup and hoisting resolution -- ~1.5h
3. Add phantom check integration into hygiene suite -- ~30m
4. Add configuration option (enable/disable) -- ~30m
5. Add comprehensive tests with real npm projects -- ~2h
6. Handle edge cases (dynamic requires, aliases) -- ~1h

## Verification

- Detects phantom dependencies in real projects
- Correctly identifies transitive provider
- No false positives on explicitly declared deps
- Performance acceptable on large projects (>1000 files)
- Works with monorepos (workspace detection)
