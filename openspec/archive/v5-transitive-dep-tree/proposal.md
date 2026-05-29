# v5-transitive-dep-tree: Dependency Tree Visualization

## Summary

Add `DependsOn []string` field to Component. Go scanner: parse go.sum/go.mod graph entries. npm scanner: parse `package-lock.json` `dependencies` nesting. Add `--tree` flag to `scan` command for tree-formatted output showing dependency depth and version constraints.

## Motivation

Understanding transitive dependency chains helps identify attack surface and understand version constraint chains. Tree visualization makes the data actionable.

## Design

In `pkg/models/component.go`:
- Add `DependsOn []string` field (list of dependency names/purls)

In Go scanner (`internal/scanner/gomod.go`):
- Parse `go.sum` entries and `go.mod` require blocks to build graph
- Populate `DependsOn` for each component

In npm scanner (`internal/scanner/npm.go`):
- Parse `package-lock.json` nested `dependencies` structure
- Populate `DependsOn` for each component

In `internal/report/tree.go`:
- New formatter for tree output
- Indent by depth, show component name@version, mark vulnerabilities
- Add `--tree` flag to scan command

## Non-goals

- Interactive tree explorer
- Circular dependency detection
- Version constraint solver

## Tasks

1. Add DependsOn field to Component -- ~30m
2. Implement Go graph parsing in gomod scanner -- ~1.5h
3. Implement npm graph parsing in npm scanner -- ~1h
4. Implement tree formatter -- ~1.5h
5. Add --tree flag to scan command -- ~30m
6. Add integration tests with real projects -- ~1.5h

## Verification

- DependsOn fields populated correctly from lockfiles
- Tree output shows correct hierarchy
- Vulnerabilities highlighted in tree
- Real projects (e.g., kubernetes/kubernetes) render correctly
- Performance acceptable on large trees (>1000 deps)
