# Change Proposal: v2-diff-mode

**Status:** Proposed
**Date:** 2026-05-28
**Author:** Agent

## Strategic Context

> CI/CD integration requires comparing scan results between commits (main vs. PR). A `diff` command enables policy enforcement at the PR level: fail if new vulnerabilities above threshold are introduced. Priority: HIGH — essential for CI/CD workflows and CRA compliance gates.

## Summary

Add a new `chainsaw diff` command comparing scan results between two JSON outputs or git refs. Report new/fixed vulnerabilities, new/removed components, and compliance score deltas. Exit code 1 if new vulnerabilities above threshold are introduced.

## Motivation

Supply chain security gates in CI/CD require comparing scan results between commits. Users need to know:

1. Are new vulnerabilities introduced in this PR?
2. Are any vulnerabilities fixed?
3. Are new components added?
4. Has the compliance score improved or regressed?

A `diff` command enables this workflow: `chainsaw scan --format json > pr.json && chainsaw diff --base main.json --head pr.json`. This is essential for enforcing CRA compliance gates in CI/CD.

## Proposed Changes

### New `diff` Subcommand

Add `chainsaw diff` command with two modes:

#### Mode 1: File-based Diff

```bash
chainsaw diff --base scan-main.json --head scan-pr.json
```

- Load two JSON scan results (from `chainsaw scan --format json`)
- Compare findings, components, and compliance scores
- Output diff in table, JSON, or markdown format

#### Mode 2: Git Ref Diff

```bash
chainsaw diff --base-ref main --head-ref HEAD
```

- Checkout `--base-ref` (e.g., `main`), run `chainsaw scan --format json`, save result
- Checkout `--head-ref` (e.g., `HEAD`), run `chainsaw scan --format json`, save result
- Compare results
- Restore original working directory

### Diff Output Structure

Create `pkg/models/DiffResult` containing:

- **`new_vulnerabilities`**: Findings in head but not in base (sorted by severity)
- **`fixed_vulnerabilities`**: Findings in base but not in head
- **`new_components`**: Components in head but not in base
- **`removed_components`**: Components in base but not in head
- **`compliance_score_delta`**: Change in compliance score (0–100)
- **`pinning_score_delta`**: Change in pinning score (0–100)
- **`scan_time_delta`**: Change in scan duration (ms)

### Deduplication Logic

Findings are considered identical if:

- Same package name, version, and CVE/GHSA ID
- Ecosystem matches

### Output Formats

#### Table Format (default)

```
Diff: main vs. HEAD

New Vulnerabilities (3):
  CRITICAL  pkg:npm/lodash@4.17.20  CVE-2021-23337  Prototype pollution
  HIGH      pkg:npm/express@4.17.1  CVE-2022-24999  Regular expression DoS
  MEDIUM    pkg:npm/qs@6.9.4        CVE-2022-24999  Prototype pollution

Fixed Vulnerabilities (1):
  MEDIUM    pkg:npm/minimist@1.2.5  CVE-2021-44906  Prototype pollution

New Components (2):
  pkg:npm/new-dep@1.0.0
  pkg:npm/another-dep@2.0.0

Removed Components (1):
  pkg:npm/old-dep@1.0.0

Compliance Score: 85 → 78 (Δ -7)
Pinning Score: 92 → 90 (Δ -2)
Scan Time: 2.3s → 2.1s (Δ -0.2s)
```

#### JSON Format

```json
{
  "new_vulnerabilities": [...],
  "fixed_vulnerabilities": [...],
  "new_components": [...],
  "removed_components": [...],
  "compliance_score_delta": -7,
  "pinning_score_delta": -2,
  "scan_time_delta_ms": -200
}
```

#### Markdown Format (for PR comments)

```markdown
## Chainsaw Scan Diff

### New Vulnerabilities (3)
- **CRITICAL**: `pkg:npm/lodash@4.17.20` CVE-2021-23337 — Prototype pollution
- **HIGH**: `pkg:npm/express@4.17.1` CVE-2022-24999 — Regular expression DoS
- **MEDIUM**: `pkg:npm/qs@6.9.4` CVE-2022-24999 — Prototype pollution

### Fixed Vulnerabilities (1)
- **MEDIUM**: `pkg:npm/minimist@1.2.5` CVE-2021-44906 — Prototype pollution

### Compliance Score
85 → 78 (Δ -7)
```

### Exit Codes

- **0**: No new vulnerabilities above threshold
- **1**: New vulnerabilities above threshold introduced
- **2**: Scan or diff error

### Threshold Evaluation

Use policy `fail-on` severity threshold:

- If any new vulnerability has severity >= threshold, exit 1
- Report which vulnerabilities triggered the failure

### Git Ref Mode Implementation

- Create temporary directory for checkout
- Use `git worktree` to avoid modifying working directory
- Run `chainsaw scan` on each ref
- Clean up worktree on completion
- Handle errors gracefully (e.g., ref not found)

## Non-goals

- Diffing SBOM files (CycloneDX diff is a separate tool)
- Three-way merge or conflict resolution
- Storing scan history (user manages JSON files)
- Automatic remediation or PR comments (user integrates via CI script)

## Risks

- JSON output schema becomes a compatibility contract; must be stable
- Git ref mode requires `git worktree` support; may fail on some systems
- Large diffs (1000+ findings) may produce verbose output
- Deduplication logic must be robust to avoid false positives/negatives

## Acceptance Criteria

- `chainsaw diff --base scan-main.json --head scan-pr.json` compares two JSON outputs
- `chainsaw diff --base-ref main --head-ref HEAD` compares git refs
- New vulnerabilities correctly identified and sorted by severity
- Fixed vulnerabilities correctly identified
- New/removed components correctly identified
- Compliance and pinning score deltas calculated correctly
- Exit code 1 if new vulnerabilities above threshold
- Table, JSON, and markdown output formats work correctly
- Graceful error handling for missing files, invalid refs, scan errors
- Unit tests with fixture scan results
- Integration test with real git refs and lockfiles

## Tasks

- [ ] Create `pkg/models/DiffResult` struct
- [ ] Implement deduplication logic for findings
- [ ] Implement file-based diff in `cmd/chainsaw/diff.go`
- [ ] Implement git ref diff mode
- [ ] Implement table formatter for diff output
- [ ] Implement JSON formatter for diff output
- [ ] Implement markdown formatter for diff output
- [ ] Implement exit code logic based on threshold
- [ ] Add `--base`, `--head`, `--base-ref`, `--head-ref` flags
- [ ] Add `--format` flag (table, json, markdown)
- [ ] Add `--threshold` flag to override policy threshold
- [ ] Unit tests with fixture scan results
- [ ] Integration test with real git refs
