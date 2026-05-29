# v5-exit-code-fix: Fix Exit Code Logic in Commands

## Summary

Fix unreachable exit code logic in `checkCmd`, `comply`, and `supply-chain` commands. The `switch` statement in `checkCmd` returns before exit code evaluation. Refactor to store write error, check it, then evaluate exit codes. Fix `comply` and `supply-chain` which return nil instead of exiting non-zero on policy failure.

## Motivation

Currently, exit codes are not properly evaluated on policy failures, making it impossible for CI systems to detect compliance issues and fail builds. This undermines the entire CRA compliance workflow.

## Design

In `internal/cmd/check.go`, `comply.go`, and `supply_chain.go`:
- Store write error instead of returning immediately
- Evaluate exit codes after all writes complete
- Map policy failure to exit code 1
- Return `cmd.ExitFailure` for policy violations

## Non-goals

- Change exit code semantics for other commands.
- Add new policy rule types.

## Tasks

1. Audit all command exit paths in `cmd/chainsaw/*.go` -- ~30m
2. Refactor `checkCmd.Execute()` to defer exit code evaluation -- ~45m
3. Fix `comply` and `supply-chain` command return logic -- ~30m
4. Add integration tests verifying exit codes on policy failure -- ~1h
5. Update `--help` docs to document exit codes -- ~15m

## Verification

- `chainsaw check` with policy failure exits 1
- `chainsaw comply` with failed CRA checks exits 1
- `chainsaw supply-chain` with violations exits 1
- All existing tests still pass
