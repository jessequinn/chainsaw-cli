# OpenSpec

This directory contains the spec-driven development artefacts for chainsaw.

## Structure

- `specs/` -- canonical specifications (the source of truth for what the system should do).
- `changes/` -- active change proposals (`proposal.md`, `design.md`, `tasks.md`).
- `archive/` -- completed and archived changes.

## Workflow

1. `/opsx-explorer` -- clarify the requirement.
2. `/opsx-propose` -- generate a change proposal under `changes/<change-id>/`.
3. Human reviews. Do not implement until approved.
4. `/opsx-apply` -- implement against the spec.
5. `/opsx-verify` -- verify completion.
6. `/opsx-archive` -- move to `archive/`.

See `AGENTS.md` for full rules.
