# Change Proposal: v3-extract-runscan

**Status:** Proposed
**Date:** 2026-05-29
**Author:** Agent

## Summary

Extract duplicated scan logic from main.go into a shared RunScan function.

## Motivation

scanCmd, complyCmd, supplyChainCmd, and checkCmd all duplicate the scanner loop. main.go is now 700+ lines. Extracting reduces duplication and bug surface.

## Tasks

1. Create internal/engine/engine.go with RunScan(ctx, root, opts) returning ScanResult + warnings.
2. Refactor all commands to use it.
3. Move resolveScanners and loadPolicy into the engine package.
4. Add tests for RunScan.

## Non-goals

- Changing command behavior.
- Adding new features.
