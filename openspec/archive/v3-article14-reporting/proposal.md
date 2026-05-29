# Change Proposal: v3-article14-reporting

**Status:** Proposed
**Date:** 2026-05-29
**Author:** Agent

## Summary

Enhance the CRA Article 14 reporting check from a placeholder "cannot
be verified automatically" to an actionable check that validates the
presence and content of incident reporting configuration.

## Motivation

Article 14 requires manufacturers to report actively exploited
vulnerabilities to ENISA/CSIRT within 24 hours (deadline: Sept 11,
2026). The current check always fails with a generic message.

## Tasks

1. In `reporting_check.go`, validate that CRAConfig has:
   - `csirt-contact` is non-empty and looks like a valid email/URL.
   - A SECURITY.md or security.txt exists at the project root.
2. Add a new check: "incident response plan documented" — verify
   SECURITY.md contains "incident" or "reporting" keywords.
3. Grade: PASS if all present, WARN if partial, FAIL if none.
4. Add tests with temp directories containing various file combinations.

## Non-goals

- Actually contacting ENISA or CSIRT.
- Generating the incident response plan content.
