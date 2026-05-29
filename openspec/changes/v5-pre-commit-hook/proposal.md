# v5-pre-commit-hook: Git Pre-Commit Hook Integration

## Summary

New `chainsaw init-hooks [path]` command. Generates `.git/hooks/pre-commit` (or `.pre-commit-config.yaml` for pre-commit framework). Hook: on lockfile changes, run `chainsaw scan --quiet --fail-on HIGH`. Only triggers when go.sum, package-lock.json, etc. are staged. Exits non-zero on findings, preventing commit.

## Motivation

Developers should catch vulnerable dependency additions before committing. Pre-commit hooks provide early feedback in the development workflow.

## Design

New command `internal/cmd/init_hooks.go`:
- Generate `.git/hooks/pre-commit` (executable bash script)
- Alternative: generate `.pre-commit-config.yaml` for pre-commit framework
- Hook script: check if lockfiles are staged, run chainsaw scan, exit on findings
- Default fail threshold: HIGH
- Add `--framework` flag (native, pre-commit)
- Ensure hook is executable

## Non-goals

- Post-commit hooks
- Commit message linting
- Pre-push hooks (separate feature)

## Tasks

1. Create hook script template -- ~1h
2. Create pre-commit-config.yaml template -- ~1h
3. Implement init-hooks command -- ~1h
4. Add framework flag parsing -- ~30m
5. Ensure proper permissions on hook file -- ~30m
6. Add integration tests (verify hook can execute) -- ~1.5h

## Verification

- Generated hook is executable
- Hook triggers on lockfile stage
- Hook prevents commit on HIGH findings
- Hook allows commit when clean
- Both framework options generate valid files
- Real project setup and usage works
