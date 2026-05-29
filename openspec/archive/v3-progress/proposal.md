# Change Proposal: v3-progress

**Status:** Proposed
**Date:** 2026-05-29
**Author:** Agent

## Summary

Add scan progress indication to stderr showing current scanner and API status.

## Motivation

Scanning large projects with multiple ecosystems and OSV queries can take 30+ seconds with no output. Users think it's frozen.

## Tasks

1. Print scanner progress to stderr: "Scanning go (go.mod)...", "Scanning npm (package-lock.json)...", "Querying OSV (X components)...".
2. Only when stderr is a terminal (not redirected).
3. Use --quiet flag to suppress.
4. Add tests.

## Non-goals

- Progress bars.
- Animated spinners.
- Percentage completion.
