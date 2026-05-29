# Change Proposal: v3-unified-check

**Status:** Proposed
**Date:** 2026-05-29
**Author:** Agent

## Summary

Add a `chainsaw check` meta-command that runs scan, comply, and
supply-chain analysis in a single invocation with a unified exit code.

## Motivation

CI pipelines currently need three separate commands. A single `check`
command simplifies integration and provides a holistic view.

## Tasks

1. Add `checkCmd()` to `cmd/chainsaw/main.go`.
2. Run scan, comply, and supply-chain internally.
3. Produce unified table/JSON output combining all three.
4. Exit code: 0 if all pass, 1 if any violations.
5. Accept all common flags: `--format`, `--policy`, `--fail-on`.
6. Add tests.

## Non-goals

- Replacing the individual commands.
