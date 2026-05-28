# Change Proposal: v2-sarif-enrich

**Status:** Proposed
**Date:** 2026-05-28
**Author:** Agent

## Strategic Context

> SARIF 2.1.0 is the standard for CI/CD integration and GitHub Security tab uploads. Enriching SARIF output with CWE, CVSS, remediation guidance, and lockfile locations improves developer experience and enables automated policy enforcement in GitHub. Priority: MEDIUM — improves GitHub integration without breaking existing functionality.

## Summary

Enrich SARIF 2.1.0 output with CWE IDs, CVSS scores, remediation guidance, lockfile locations, and deduplication fingerprints for better GitHub Security tab integration and developer experience.

## Motivation

Current SARIF output is minimal and does not leverage SARIF 2.1.0's rich metadata capabilities. GitHub Security tab can display CWE, CVSS, remediation guidance, and source locations. By enriching SARIF output, we enable:

1. Better vulnerability context in GitHub UI (CWE, CVSS score)
2. Automated remediation guidance (upgrade to fixed version)
3. Precise lockfile locations for developers to fix
4. Result deduplication across multiple scan runs
5. Transitive dependency chain visibility

## Proposed Changes

### Extend SARIF Rule Properties

Modify `internal/report/sarif.go` to populate rule properties with:

- **`cwe`** (array of strings): CWE IDs from OSV advisory (e.g., `["CWE-79", "CWE-89"]`)
- **`cvss_score`** (number): CVSS v3.1 score from OSV (0.0–10.0)
- **`cvss_vector`** (string): CVSS v3.1 vector string (e.g., `"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"`)
- **`helpUri`** (string): URL to OSV advisory (e.g., `https://osv.dev/vulnerability/GHSA-xxxx-yyyy-zzzz`)

### Add Help Text and Markdown

For each result, add:

- **`help.text`** (string): Plain-text remediation guidance (e.g., `"Upgrade to version 1.2.3 or later"`)
- **`help.markdown`** (string): Markdown-formatted remediation with links to advisory and fixed version

### Add Physical Location

Extend result `locations` to include:

- **`physicalLocation`**: Exact lockfile path and line number where the vulnerable dependency is declared
- Example: `package.json:42` or `go.mod:15`

### Add Related Locations

For transitive dependencies, add `relatedLocations` showing the dependency chain:

- Example: `app -> express@4.17.1 -> body-parser@1.19.0 (vulnerable)`

### Add Fingerprints

For result deduplication across runs, add:

- **`fingerprints`**: Stable hash of (package, version, CVE ID) to enable GitHub to deduplicate results across multiple scans

### Update Tool Information

Set tool `informationUri` to point to chainsaw documentation:

- `https://github.com/your-org/chainsaw/docs`

### Graceful Degradation

If OSV does not provide CWE or CVSS data:

- Omit the field rather than setting to null
- Continue with available data

## Non-goals

- SARIF 2.2 support (v2.1.0 is sufficient for GitHub integration)
- Custom SARIF viewers or dashboards
- Generating SARIF for CRA compliance results (separate from vulnerability SARIF)
- SARIF 3-address code flow analysis

## Risks

- OSV may not always provide CWE or CVSS data; must handle gracefully
- Lockfile line numbers may shift between runs; fingerprints must be stable
- Large transitive dependency chains may produce verbose SARIF output
- GitHub Security tab may not display all SARIF properties; test integration

## Acceptance Criteria

- SARIF output includes CWE IDs when available from OSV
- SARIF output includes CVSS score and vector when available
- SARIF output includes `helpUri` pointing to OSV advisory
- SARIF output includes remediation guidance in `help.text` and `help.markdown`
- SARIF output includes `physicalLocation` with lockfile path and line number
- SARIF output includes `relatedLocations` for transitive dependencies
- SARIF output includes stable `fingerprints` for deduplication
- Tool `informationUri` set to chainsaw docs
- Graceful degradation: missing CWE/CVSS does not break SARIF output
- SARIF output validates against official JSON schema
- Unit tests with fixture OSV responses and expected SARIF output
- Integration test uploading SARIF to GitHub and verifying display

## Tasks

- [ ] Extend SARIF rule properties to include CWE, CVSS, helpUri
- [ ] Add help.text and help.markdown to SARIF results
- [ ] Add physicalLocation with lockfile path and line number
- [ ] Add relatedLocations for transitive dependency chains
- [ ] Implement stable fingerprint generation
- [ ] Set tool informationUri
- [ ] Implement graceful degradation for missing CWE/CVSS
- [ ] Validate SARIF output against official schema
- [ ] Unit tests with fixture OSV responses
- [ ] Integration test with GitHub Security tab upload
