# Change Proposal: v3-trend-tracking

**Status:** Proposed
**Date:** 2026-05-29
**Author:** Agent

## Summary

Store CRA compliance assessment results over time and show compliance
trends. Unique competitive feature — no existing tool does this.

## Motivation

Users preparing for the September 2026 CRA deadline need to track
progress. Showing "score improved from 62% to 78% since last
assessment" makes chainsaw sticky and provides audit trail.

## Tasks

1. Create `internal/trend/` package.
2. After `comply` command runs, save result to `.chainsaw/history/`
   as timestamped JSON files.
3. Add `--trend` flag to `comply` command that loads history and
   shows score progression.
4. Table output: show current score, previous score, delta, dates.
5. JSON output: include history array.
6. Add tests.

## Non-goals

- Database storage (JSON files only).
- Web dashboard for trend visualization.
