# Change Proposal: v3-graceful-degradation

**Status:** Proposed
**Date:** 2026-05-29
**Author:** Agent

## Summary

Make scanning resilient to individual scanner or API failures. Currently
a single broken lockfile or OSV timeout kills the entire scan. Per
AGENTS.md: "scan what you can and report which sources were unreachable."

## Motivation

In CI pipelines, a transient OSV API failure or a malformed lockfile
should not prevent scanning all other ecosystems. The scan should
complete with partial results and report which sources failed.

## Tasks

1. Add `Warnings []string` field to `ScanResult` model.
2. In `scanCmd`, `complyCmd`, `supplyChainCmd`: catch scanner errors
   per-ecosystem and accumulate warnings instead of returning immediately.
3. Catch vuln matcher errors and add warning instead of aborting.
4. Print warnings in table/JSON/SARIF output.
5. Add tests for partial scan with simulated failures.

## Non-goals

- Retry logic (handled by v3-osv-retry proposal).
