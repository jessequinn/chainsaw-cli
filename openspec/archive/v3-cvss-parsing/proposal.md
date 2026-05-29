# Change Proposal: v3-cvss-parsing

**Status:** Proposed
**Date:** 2026-05-29
**Author:** Agent

## Summary

Fix CVSS vector string parsing in the OSV client. The `parseCVSSScore`
function only handles plain numeric scores but OSV frequently returns
CVSS v3.1 vector strings (e.g. `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H`).
When a vector string is encountered, the parser returns 0, mapping the
vulnerability to severity UNKNOWN. This silently downgrades severity
for many real-world vulnerabilities.

## Motivation

Core vulnerability matching is broken for any OSV entry that uses CVSS
vector strings instead of plain numeric scores. This affects severity
classification, policy evaluation, and CRA compliance scoring.

## Tasks

1. Parse CVSS v3.x vector strings to extract the base score using the
   standard formula (or extract from the last metric group).
2. Parse CVSS v2 vector strings as a fallback.
3. Add table-driven tests for both formats.
4. Verify severity mapping is correct for known CVE examples.

## Non-goals

- Full CVSS v3.1 environmental/temporal score calculation.
- Adding a third-party CVSS library dependency.
