# Change Proposal: v3-output-flag

**Status:** Proposed
**Date:** 2026-05-29
**Author:** Agent

## Summary

Add `--output`/`-o` flag to all commands for writing output to a file instead of stdout.

## Motivation

Every command writes to stdout only. SARIF upload, JSON archival, and diff workflows require shell redirection. An --output flag is table stakes for CLI tools.

## Tasks

1. Add --output/-o string flag to scan, comply, supply-chain, check, sbom, diff commands.
2. If set, open file for writing and pass as writer instead of os.Stdout.
3. Still print warnings/status to stderr.
4. Add tests.

## Non-goals

- Multiple output files per invocation.
- Appending mode.
