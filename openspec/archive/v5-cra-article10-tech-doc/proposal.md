# v5-cra-article10-tech-doc: CRA Article 10 Technical Documentation Generator

## Summary

New `chainsaw generate-docs [path]` command. Produces a Markdown document skeleton for CRA Article 10 technical documentation. Sections mapped to Article 10(2) sub-paragraphs, pre-filled with: product description (from .chainsaw.yaml), SBOM reference, vulnerability assessment summary, update mechanism description, support period. Output: `TECHNICAL-DOCUMENTATION.md`.

## Motivation

Article 10 requires detailed technical documentation. A template generator provides a starting point and ensures compliance with EU regulatory requirements.

## Design

New command `internal/cmd/generate_docs.go`:
- Reads product metadata from `.chainsaw.yaml` (product name, version, category, support end date)
- Runs SBOM generator and references output
- Runs scan and summarizes top vulnerabilities
- Creates Markdown with sections for each Article 10(2) sub-paragraph
- Pre-fills changeable sections; leaves guidance comments for manual sections
- Output: `TECHNICAL-DOCUMENTATION.md`

## Non-goals

- Full automation of Article 10 compliance (requires human review)
- Multi-language support
- Word document generation

## Tasks

1. Research CRA Article 10(2) requirements -- ~1h (research agent)
2. Create documentation template -- ~1h
3. Implement `generate_docs` command -- ~1.5h
4. Add SBOM and scan integration -- ~1h
5. Add flag parsing and metadata injection -- ~45m
6. Add integration tests -- ~1h

## Verification

- Generated document contains all Article 10(2) sections
- SBOM file referenced
- Vulnerability summary accurate
- Markdown is valid and renders correctly
- Output filename correct
