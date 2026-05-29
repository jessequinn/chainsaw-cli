# v5-markdown-report: Markdown Output Formatter

## Summary

Add `--format markdown` support to scan, comply, check, and supply-chain commands. Output Markdown tables suitable for PR comments, wiki pages, or Notion paste. Add `internal/report/markdown.go` with `WriteMarkdown()` function. Include summary section with key metrics.

## Motivation

Markdown output integrates seamlessly with GitHub PR comments, wiki documentation, and collaborative tools like Notion. Teams can embed compliance and scan reports directly in their workflow.

## Design

New `internal/report/markdown.go`:
- `WriteMarkdown()` function for each result type
- ScanResult: table with columns Name, Ecosystem, Version, Severity, CVE
- CRAResult: table with Check ID, Status (✓/✗), Details
- SupplyChainResult: markdown list with findings
- Include summary section: total findings, severity breakdown
- Escape special markdown characters

## Non-goals

- Markdown formatting options (colors, styling)
- Automated PR comment posting
- Embedded images/charts

## Tasks

1. Define markdown table structure for each result type -- ~1h
2. Implement WriteMarkdown for ScanResult -- ~1h
3. Implement WriteMarkdown for CRAResult -- ~45m
4. Implement WriteMarkdown for other result types -- ~1h
5. Add --format markdown flag parsing -- ~30m
6. Add integration tests with snapshot comparisons -- ~1.5h

## Verification

- Generated markdown is valid and renders correctly
- Tables have correct columns and data
- Summary metrics accurate
- Special characters properly escaped
- All result types supported
- Markdown can be copy-pasted into PR comments
