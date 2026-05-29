# Change Proposal: v3-transitive-sbom

**Status:** Proposed
**Date:** 2026-05-29
**Author:** Agent

## Summary

Add transitive/direct dependency distinction to the Component model.
CRA Annex I Part 2(1) requires identifying all components including
third-party (transitive) dependencies.

## Motivation

The SBOM checker currently counts all components equally. CRA requires
explicit enumeration of transitive dependencies. Knowing direct vs.
transitive also improves blast radius analysis.

## Tasks

1. Add `Direct bool` field to `Component` model.
2. Update Go scanner to mark direct vs. indirect (go.mod `// indirect`).
3. Update npm scanner to mark direct vs. transitive from lockfile.
4. Update SBOM checker to report direct/transitive counts.
5. Update CycloneDX SBOM generator to set dependency scope.
6. Add tests.

## Non-goals

- Full dependency tree/graph resolution.
- Transitive detection for infra scanners (Dockerfile, Terraform, etc.).
