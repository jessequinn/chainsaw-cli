# Change Proposal: v3-secure-defaults

**Status:** Proposed
**Date:** 2026-05-29
**Author:** Agent

## Summary

Add secure-by-default configuration checks for infrastructure files.
CRA Annex I Part 1(3) requires products to be delivered with a secure
by default configuration.

## Motivation

Dockerfiles running as root, Terraform with overly permissive security
groups, and GitHub Actions with excessive permissions are common supply
chain risks that chainsaw should flag.

## Tasks

1. Add `SecureDefaultsChecker` to `internal/cra/`.
2. Check Dockerfile: flag `USER root` or missing `USER` directive,
   flag `--privileged` in compose files.
3. Check GitHub Actions: flag `permissions: write-all` or missing
   permissions block.
4. Check Terraform: flag `ingress` rules with `0.0.0.0/0` on
   sensitive ports.
5. Wire into CRA `Assess()`.
6. Add tests with fixture files.

## Non-goals

- Full Dockerfile linting (separate proposal v3-dockerfile-lint).
- Runtime configuration analysis.
