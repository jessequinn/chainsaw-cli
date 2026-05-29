# Change Proposal: v3-product-classification

**Status:** Proposed
**Date:** 2026-05-29
**Author:** Agent

## Summary

Implement CRA product category classification (Annex III/IV). The
`CRAConfig.ProductCategory` field exists but no checker uses it.
Different categories have different conformity assessment requirements.

## Motivation

CRA distinguishes "important" (Class I/II) and "critical" products
with different conformity requirements. Without classification, the
compliance assessment is incomplete.

## Tasks

1. Define product category constants: `default`, `important-class-1`,
   `important-class-2`, `critical`.
2. Add `ClassificationChecker` to `internal/cra/` that:
   - Checks if `product-category` is set in config.
   - Validates it's a known category.
   - Reports category-specific requirements (e.g., Class II requires
     third-party conformity assessment).
3. Wire into `Assess()` checkers list.
4. Add table-driven tests.

## Non-goals

- Automatically determining product category from code analysis.
- Listing all Annex III/IV product types.
