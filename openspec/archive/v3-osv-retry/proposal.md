# Change Proposal: v3-osv-retry

**Status:** Proposed
**Date:** 2026-05-29
**Author:** Agent

## Summary

Add exponential backoff with jitter and retry logic to the OSV API
client. Currently there is zero retry logic — a transient 429 or 503
from OSV fails the entire scan.

## Motivation

AGENTS.md mandates "exponential backoff with jitter, max 3 attempts.
Only retry idempotent reads. Honour Retry-After from registries."

## Tasks

1. Add retry wrapper with exponential backoff (base 1s, max 3 attempts).
2. Add jitter (up to 500ms random).
3. Honour `Retry-After` header if present.
4. Only retry on 429, 500, 502, 503, 504, and network errors.
5. Add tests with httptest mock returning transient failures.

## Non-goals

- Retry for non-OSV HTTP calls (Go vuln DB, licence detection).
