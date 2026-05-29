# Change Proposal: v3-licence-unify

**Status:** Proposed
**Date:** 2026-05-29
**Author:** Agent

## Summary

Unify LicensePolicy and LicencePolicy into a single type. Remove the v1 Licenses field.

## Motivation

policy.go has both LicensePolicy (v1, Deny only) and LicencePolicy (v2, mode/allow/deny/per-ecosystem). Evaluate() only checks v1 Licenses.Deny. This dual path is confusing and causes bugs.

## Tasks

1. Remove LicensePolicy struct.
2. Remove Licenses field from Policy.
3. Update Evaluate() to use Licences.DenyList instead of Licenses.Deny.
4. Update all tests.
5. Update policy validation if needed.

## Non-goals

- Adding new licence policy features.
