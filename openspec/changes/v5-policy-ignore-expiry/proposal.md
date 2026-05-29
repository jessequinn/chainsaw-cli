# v5-policy-ignore-expiry: Time-Bound Ignore Rules

## Summary

Extend `Policy.Ignore` from `[]string` to `[]IgnoreRule` struct with `ID string`, `Expires string` (YYYY-MM-DD), `Reason string`. Expired ignores are treated as active findings. Ignores without reason trigger a warning. Backward-compatible: bare string `"CVE-..."` still works.

## Motivation

Organizations need to revisit ignored CVEs periodically. Time-bounded ignores prevent indefinite suppression and force re-evaluation of risk.

## Design

In `pkg/models/policy.go`:
- `IgnoreRule` struct with fields: ID, Expires, Reason
- `Policy.Ignore` unmarshals both strings and objects
- `IsExpired()` method on IgnoreRule
- Evaluate checks expiry during policy evaluation
- Warning in logs for missing Reason

## Non-goals

- Automatic CVE re-evaluation suggestions
- Email reminders for expiring ignores

## Tasks

1. Define IgnoreRule struct and YAML unmarshalling -- ~1h
2. Add expiry checking logic in evaluator -- ~45m
3. Update policy loader tests -- ~45m
4. Add warning for missing reason -- ~30m
5. Update `.chainsaw.yaml` example with expiry -- ~15m
6. Integration tests with real-world policies -- ~45m

## Verification

- Expired ignores appear as active findings
- Non-expired ignores still suppressed
- Backward-compatible with bare CVE strings
- Warnings logged for ignored rules without reason
