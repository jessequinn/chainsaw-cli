# v5-cra-deadline-engine: Multi-Deadline CRA Tracking Engine

## Summary

Replace hardcoded `NextDeadline` with a structured multi-deadline engine in `internal/cra/deadlines.go`. Track: Article 14 reporting (2026-09-11), Article 35 notified bodies (2026-12-11), EN 40000 target (2026-08-30), full application (2027-12-11). Filter by product category and show all relevant deadlines in comply output with countdown and urgency.

## Motivation

Different product categories and articles have different deadlines. A unified engine provides clarity on multiple compliance milestones and enables prioritization.

## Design

New `internal/cra/deadlines.go`:
- `Deadline` struct: `Article string`, `Description string`, `Date time.Time`, `Category string`, `Urgency string`
- `DeadlineEngine` type with `Deadlines()` method returning filtered list
- Filter by category (default/important-class-1/important-class-2/critical)
- Each deadline includes days-until-deadline and urgency (CRITICAL/HIGH/MEDIUM)
- Integrate into `comply` command output

## Non-goals

- Recurring deadlines
- Custom deadline configuration per organization
- Calendar synchronization

## Tasks

1. Define deadline data structure -- ~30m
2. Implement filtering and sorting logic -- ~45m
3. Integrate into `ComplyCommand` output -- ~45m
4. Add countdown display in table format -- ~30m
5. Add unit tests for deadline engine -- ~1h

## Verification

- All 4 deadlines display with correct dates
- Countdown accuracy verified against current date
- Category filtering works correctly
- Table output shows urgency colors (if applicable)
