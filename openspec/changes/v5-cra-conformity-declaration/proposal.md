# v5-cra-conformity-declaration: EU Declaration of Conformity Generator

## Summary

New `chainsaw generate-declaration [path]` command. Produces a draft EU Declaration of Conformity per Article 28. Fields from .chainsaw.yaml: manufacturer, product name/version, product category. Includes: standards applied (EN 40000 when available), essential requirements addressed, assessment date. Output: `DECLARATION-OF-CONFORMITY.md`.

## Motivation

Article 28 requires a formal Declaration of Conformity. An automated generator ensures consistent formatting and completeness, reducing legal review time.

## Design

New command `internal/cmd/generate_declaration.go`:
- Reads manufacturer, product name/version, category from `.chainsaw.yaml`
- Runs compliance assessment to extract standards met (EN 40000, etc.)
- Generates Markdown with official Declaration structure per Article 28
- Sections: product description, essential requirements, standards applied, manufacturer signature block
- Output: `DECLARATION-OF-CONFORMITY.md`

## Non-goals

- Digital signing
- Multi-manufacturer declarations
- Conformity module integration (separate from declaration)

## Tasks

1. Research Article 28 declaration format requirements -- ~1h
2. Create declaration template -- ~1h
3. Implement command skeleton -- ~45m
4. Add standard discovery from compliance checks -- ~1h
5. Generate final Markdown with all fields -- ~45m
6. Add integration tests -- ~1h

## Verification

- Generated declaration contains all Article 28 required fields
- Manufacturer and product details accurate
- Standards section matches compliance assessment
- Markdown renders correctly
- File output named correctly
