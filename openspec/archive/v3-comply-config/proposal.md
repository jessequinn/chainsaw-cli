# Change Proposal: v3-comply-config

**Status:** Proposed
**Date:** 2026-05-29
**Author:** Agent

## Summary

Fix the `comply` command to populate `CRAConfig` from the loaded policy
file's `CRA` section. Currently line 361 of `main.go` creates an empty
`CRAConfig{}` and never reads the policy's `cra:` YAML fields.

## Motivation

The comply command ignores all user-provided CRA config (manufacturer,
security-contact, support-end-date, csirt-contact, product-name,
product-category). Every CRA check that depends on config fails even
when the config is correctly specified in `.chainsaw.yaml`.

## Tasks

1. Populate `CRAConfig` from `pol.CRA` in the `comply` command.
2. Add test verifying policy CRA fields flow into assessment context.

## Non-goals

- Changing the CRA checker logic itself.
