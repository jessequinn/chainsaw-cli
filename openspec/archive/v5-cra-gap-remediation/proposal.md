# v5-cra-gap-remediation: Structured Remediation Planning

## Summary

Enrich CRA check results with structured remediation: `Role` (engineering/legal/security), `EffortHours` estimate, `Priority` (1-5). Add `RemediationPlan` type and `GeneratePlan()` function that returns sorted list of actions. Output as table or JSON. Lives in `internal/cra/remediation.go`.

## Motivation

Compliance gaps require actionable guidance. Structured remediation enables teams to allocate work across roles and prioritize critical items.

## Design

New `internal/cra/remediation.go`:
- `RemediationAction` struct: `CheckID string`, `Role string`, `Description string`, `EffortHours int`, `Priority int` (1-5, 1=critical)
- `GeneratePlan()` function that maps each failed check to 1-2 actions
- Sort by priority DESC, then effort ASC
- Output formatter in `internal/report/remediation.go` for table and JSON
- Add `--remediation` flag to `comply` command

## Non-goals

- Automated remediation script generation
- Resource cost estimation
- Team assignment automation

## Tasks

1. Define remediation action types -- ~30m
2. Implement plan generation logic with hardcoded mappings -- ~1h
3. Add table formatter -- ~45m
4. Add JSON formatter -- ~30m
5. Integrate into comply command with flag -- ~30m
6. Add tests and fixtures -- ~1h

## Verification

- Each failed check has at least one remediation action
- Actions sorted by priority
- Table and JSON formats consistent
- Real project comply output shows actionable items
