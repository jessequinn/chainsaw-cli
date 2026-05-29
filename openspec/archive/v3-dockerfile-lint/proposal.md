# Change Proposal: v3-dockerfile-lint

**Status:** Proposed
**Date:** 2026-05-29
**Author:** Agent

## Summary

Add Dockerfile security linting beyond FROM image extraction.

## Motivation

Current scanner only extracts FROM images. Doesn't check USER root, COPY --chown, exposed ports, or apt-get without pinned versions. These are CRA secure-by-default concerns.

## Tasks

1. Add hygiene checks in internal/hygiene/dockerfile.go.
2. Check for missing USER directive (container runs as root).
3. Check for EXPOSE of sensitive ports (22, 3306, 5432, 6379).
4. Check for unpinned package installs (apt-get install without version pins).
5. Report as hygiene findings with appropriate severity.
6. Add tests with fixture Dockerfiles.

## Non-goals

- Full hadolint replacement.
- Multi-stage build analysis.
- Base image vulnerability scanning.
