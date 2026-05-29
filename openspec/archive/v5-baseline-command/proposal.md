# v5-baseline-command: Findings Baseline Tracking

## Summary

New `chainsaw baseline [path]` command. Saves current scan finding IDs + hygiene IDs to `.chainsaw-baseline.json`. When `scan` or `check` runs and a baseline file exists, only report findings NOT in the baseline. Add `--update-baseline` flag to refresh. Show "X new findings (Y baselined)" in output.

## Motivation

Teams need to track new findings separately from legacy issues. Baseline tracking enables focusing on actual deltas and prioritizing newly discovered vulnerabilities.

## Design

New command `internal/cmd/baseline.go`:
- Runs `scan` and collects finding IDs
- Saves to `.chainsaw-baseline.json` with timestamp and finding list
- Load baseline in `scan` command; filter output to show only new
- Add `--update-baseline` flag to rescan and update baseline
- Show summary line: "3 new findings (12 baselined)"
- Add `--baseline` flag to `scan` to disable baseline comparison

## Non-goals

- Automatic baseline generation on first run
- Baseline history tracking
- Comparison UI

## Tasks

1. Define baseline JSON schema -- ~30m
2. Implement baseline save/load logic -- ~1h
3. Implement finding diff in scanner output -- ~1h
4. Add `--update-baseline` flag -- ~30m
5. Integrate into scan command -- ~45m
6. Add integration tests with fixture projects -- ~1.5h

## Verification

- First run creates `.chainsaw-baseline.json`
- Second run shows only new findings
- `--update-baseline` refreshes baseline
- Summary line accurate
- Baseline file format is valid JSON
