# Change Proposal: v2-github-actions

**Status:** Proposed
**Date:** 2026-05-28
**Author:** Agent

## Summary

Add GitHub Actions workflow scanning to chainsaw. Parse workflow YAML
files to enumerate action dependencies and flag unpinned, unverified,
or potentially compromised actions.

## Motivation

GitHub Actions are a critical supply chain surface. Workflows run with
repository secrets, deployment credentials, and write access. A single
compromised action can exfiltrate secrets or inject malicious code into
builds — as demonstrated by the `tj-actions/changed-files` and
`reviewdog` incidents in 2024-2025.

Most actions are pinned to tags (`@v4`) rather than commit SHAs, meaning
a tag force-push silently changes the code that runs. This is the
Terraform "branch ref" problem but worse, because actions run in CI
with elevated permissions.

## Proposed Changes

### New Ecosystem Constant

Add `EcosystemGitHubActions Ecosystem = "github-actions"` to
`pkg/models/models.go`.

### New Scanner: `internal/scanner/githubactions.go`

Implement `GitHubActionsScanner` satisfying the `Scanner` interface.

**DetectManifests** finds:
- `.github/workflows/*.yml`
- `.github/workflows/*.yaml`
- `.github/actions/*/action.yml` (composite actions)

**ParseDependencies** parses workflow YAML:

```yaml
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-go@0aaccfd150d50ccaeb58ebd88eb36e1604f7b7d4
      - uses: docker://alpine:3.18
      - uses: ./.github/actions/custom
```

For each `uses:` directive:
- **Action reference** (`owner/repo@ref`): extract owner, repo, ref
  - If ref is a tag (`v4`, `v1.2.3`): create component, flag as hygiene
    issue (should be pinned to SHA)
  - If ref is a commit SHA (40 hex chars): create component, no warning
  - If ref is a branch (`main`): create component, flag HIGH severity
- **Docker reference** (`docker://image:tag`): extract image and tag,
  create component with ecosystem `docker` (cross-reference with
  docker-compose proposal)
- **Local action** (`./.github/actions/...`): skip

Construct purl: `pkg:githubactions/owner/repo@ref`

### OSV Ecosystem Mapping

No GitHub Actions ecosystem in OSV. However, many actions are
JavaScript/TypeScript packages — if the action has a corresponding npm
package, cross-reference is possible (future enhancement).

Primary value is hygiene checks, not vuln matching.

### Hygiene Checks

GitHub Actions-specific checks (high value — this is the core of the
proposal):

| Check | Severity | Description |
|---|---|---|
| Tag-pinned action | MEDIUM | `uses: actions/checkout@v4` — tag can be force-pushed |
| Branch-pinned action | HIGH | `uses: org/action@main` — mutable reference |
| No pin at all | CRITICAL | `uses: org/action` — latest, completely uncontrolled |
| Third-party action | INFO | Action not from `actions/` org — informational |
| Docker image unpinned | HIGH | `docker://alpine:latest` or `docker://alpine` |
| Excessive permissions | MEDIUM | Workflow-level `permissions: write-all` (parse permissions block) |

### Typosquatting List

Add top 20 popular GitHub Actions:
`actions/checkout`, `actions/setup-node`, `actions/setup-go`,
`actions/setup-python`, `actions/setup-java`, `actions/cache`,
`actions/upload-artifact`, `actions/download-artifact`,
`actions/github-script`, `actions/labeler`,
`docker/build-push-action`, `docker/setup-buildx-action`,
`docker/login-action`, `codecov/codecov-action`,
`softprops/action-gh-release`, `peter-evans/create-pull-request`,
`hashicorp/setup-terraform`, `aws-actions/configure-aws-credentials`,
`google-github-actions/auth`, `azure/login`.

## Non-goals

- Scanning reusable workflow files called via `uses: ./.github/workflows/`
  (future enhancement)
- Analyzing action source code for malicious behavior
- GitHub App / OAuth token scope analysis
- Scanning `.github/dependabot.yml` configuration

## Risks

- YAML parsing of GitHub Actions workflows is well-defined but
  `uses:` can appear in composite actions and reusable workflows with
  different semantics. Mitigation: parse `steps[].uses` only in
  workflow jobs; document limitations.
- False positives on tag-pinned actions: some organizations accept tag
  pinning for first-party actions. Mitigation: allow suppression via
  policy ignore list.

## Acceptance Criteria

- `chainsaw scan --ecosystem github-actions .` detects action
  dependencies
- Parses `.github/workflows/*.yml` `uses:` directives
- Distinguishes SHA-pinned, tag-pinned, and branch-pinned actions
- Flags tag-pinned and branch-pinned actions as hygiene issues
- Components appear in SBOM output with `pkg:githubactions/` purls
- Unit tests with fixture workflow files

## Tasks

- [ ] Add `EcosystemGitHubActions` constant to `pkg/models/models.go`
- [ ] Implement `GitHubActionsScanner` in `internal/scanner/githubactions.go`
- [ ] Parse workflow YAML `uses:` directives
- [ ] Classify pin type (SHA, tag, branch, none)
- [ ] Add GitHub Actions hygiene checks
- [ ] Add popular actions to typosquatting list
- [ ] Unit tests with fixture workflows in `testdata/github-actions/`
