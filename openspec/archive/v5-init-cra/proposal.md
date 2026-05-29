# v5-init-cra: Interactive CRA Configuration Wizard

## Summary

New `chainsaw init-cra [path]` command. Interactive wizard (or `--non-interactive` with flags) that asks: product name, manufacturer, product category (default/important-class-1/important-class-2/critical), support end date, security contact, CSIRT contact. Generates `.chainsaw.yaml` with CRA section pre-filled, then runs `chainsaw comply` to show baseline score.

## Motivation

Organizations onboarding to CRA compliance need guided configuration. An interactive wizard reduces errors and ensures all required metadata is captured.

## Design

New command `internal/cmd/init_cra.go`:
- Interactive prompts using `bufio.Reader` or library like survey
- Validate inputs (dates, email formats)
- Generate `.chainsaw.yaml` with CRA metadata section
- Non-interactive mode with flag inputs
- After generation, call `comply` to show baseline
- Output summary of next steps

## Non-goals

- Database integration for organization data
- Pre-population from GitHub API
- Wizard GUI

## Tasks

1. Create init_cra command skeleton and flag parsing -- ~45m
2. Implement interactive prompt flow -- ~1h
3. Validate input and generate YAML -- ~1h
4. Integrate into CLI main and help -- ~30m
5. Add non-interactive mode with flags -- ~45m
6. Add integration tests -- ~1h

## Verification

- Generated `.chainsaw.yaml` is valid YAML
- CRA metadata fields populated correctly
- `comply` runs without error after init
- Baseline score displayed to user
- Non-interactive mode produces identical output
