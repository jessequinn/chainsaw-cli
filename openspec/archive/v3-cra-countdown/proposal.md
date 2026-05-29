# Change Proposal: v3-cra-countdown

**Status:** Proposed
**Date:** 2026-05-29
**Author:** Agent

## Summary

Add CRA deadline countdown to compliance reports showing days until Article 14 deadline.

## Motivation

Making reports time-aware with "X days until Article 14 deadline" creates urgency and differentiates from static checkers.

## Tasks

1. Add countdown calculation to CRA report output (table and JSON).
2. Show next deadline name, date, and days remaining.
3. Color-code: green (>90 days), yellow (30-90), red (<30).
4. Already have NextDeadline in CRAResult model.
5. Add tests.

## Non-goals

- Multiple deadline tracking.
- Calendar integration.
