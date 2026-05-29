# Change Proposal: v3-csirt-integration

**Status:** Proposed
**Date:** 2026-05-29
**Author:** Agent

## Summary

Extend `init-security` to generate an incident response playbook with
ENISA reporting endpoints, notification template, and timeline
requirements for CRA Article 14 compliance.

## Motivation

Article 14 requires reporting to ENISA within 24h of discovering an
actively exploited vulnerability. Most teams don't know the process.
Generating an actionable playbook is a unique differentiator.

## Tasks

1. Add incident response template to `internal/initcmd/security.go`.
2. Template includes: ENISA Single Reporting Platform URL, required
   notification fields (product ID, description, severity, affected
   versions, mitigation status), timeline (24h early warning, 72h
   update, 14d final report).
3. Generate as `INCIDENT-RESPONSE.md` alongside SECURITY.md.
4. Add CRA checker that validates INCIDENT-RESPONSE.md exists.
5. Add tests.

## Non-goals

- Automated ENISA API integration.
- Actual incident submission.
