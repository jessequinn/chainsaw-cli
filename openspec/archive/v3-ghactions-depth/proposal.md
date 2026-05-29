# Change Proposal: v3-ghactions-depth

**Status:** Proposed
**Date:** 2026-05-29
**Author:** Agent

## Summary

Deepen GitHub Actions analysis beyond action reference detection to
include permissions scope analysis, unpinned action detection, and
workflow_dispatch input validation.

## Motivation

GitHub Actions is the #1 CI supply chain attack vector. The current
scanner detects action references but doesn't analyze permissions
scope or security posture.

## Tasks

1. Add permissions analysis to GitHub Actions scanner or as hygiene
   checks in `internal/hygiene/`.
2. Detect workflows with no `permissions:` block (default is broad).
3. Detect `permissions: write-all` or individual write permissions.
4. Detect unpinned actions (using tags instead of SHA commits).
5. Report as hygiene findings with appropriate severity.
6. Add tests with fixture workflow files.

## Non-goals

- Analyzing workflow logic or step commands.
- Detecting secrets exposure in workflow logs.
