# Change Proposal: v2-ci-integration

**Status:** Proposed
**Date:** 2026-05-28
**Author:** Agent

## Strategic Context

> Chainsaw is a CLI tool designed for CI/CD integration. GitHub Actions is the primary target platform. This proposal adds workflow templates and SARIF integration to enable zero-friction adoption in GitHub. Priority: HIGH — differentiator for GitHub-hosted projects.

## Summary

Add `chainsaw init-ci` command that scaffolds GitHub Actions workflow templates. Workflows run `scan`, `comply`, and `supply-chain` commands, upload SARIF to GitHub Security tab, and post PR comments with compliance score deltas.

## Motivation

GitHub Actions is the dominant CI platform for open-source. Chainsaw should provide:
- Pre-built workflow templates (copy-paste ready)
- SARIF upload for GitHub Security tab integration
- PR comments with compliance score trends
- Configurable thresholds and ecosystems
- Foundation for future marketplace reusable workflow

## Proposed Changes

### New Command: `chainsaw init-ci`

Add `cmd/chainsaw/init_ci.go` implementing a new Cobra command.

### Generated Workflow: `.github/workflows/chainsaw.yml`

Template GitHub Actions workflow:

```yaml
name: Chainsaw Security Scan

on:
  pull_request:
    paths:
      - '**/*.mod'
      - '**/package-lock.json'
      - '**/poetry.lock'
      - 'Dockerfile'
      - 'docker-compose.yml'
      - '*.tf'
      - '.github/workflows/*.yml'
      - '.chainsaw.yaml'
  push:
    branches:
      - main

permissions:
  contents: read
  security-events: write
  pull-requests: write

jobs:
  chainsaw:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Install chainsaw
        run: |
          go install github.com/your-org/chainsaw/cmd/chainsaw@latest

      - name: Run vulnerability scan
        id: scan
        run: |
          chainsaw scan \
            --format sarif \
            --output chainsaw-scan.sarif \
            --policy .chainsaw.yaml \
            .
        continue-on-error: true

      - name: Upload SARIF to GitHub Security
        uses: github/codeql-action/upload-sarif@v2
        if: always()
        with:
          sarif_file: chainsaw-scan.sarif
          category: chainsaw-scan

      - name: Run compliance check
        id: comply
        run: |
          chainsaw comply \
            --format json \
            --output chainsaw-comply.json \
            --policy .chainsaw.yaml \
            .
        continue-on-error: true

      - name: Run supply chain analysis
        id: supply-chain
        run: |
          chainsaw supply-chain \
            --format json \
            --output chainsaw-supply-chain.json \
            .
        continue-on-error: true

      - name: Post PR comment with compliance score
        if: github.event_name == 'pull_request'
        uses: actions/github-script@v7
        with:
          script: |
            const fs = require('fs');
            const comply = JSON.parse(fs.readFileSync('chainsaw-comply.json', 'utf8'));
            const supplyChain = JSON.parse(fs.readFileSync('chainsaw-supply-chain.json', 'utf8'));
            
            const comment = `## Chainsaw Security Report
            
            **Compliance Score:** ${comply.score}%
            **Pinning Score:** ${supplyChain.pinning_score}%
            **Blast Radius:** ${supplyChain.blast_radius}
            
            [View full report](https://github.com/${{ github.repository }}/security/code-scanning)
            `;
            
            github.rest.issues.createComment({
              issue_number: context.issue.number,
              owner: context.repo.owner,
              repo: context.repo.repo,
              body: comment
            });

      - name: Fail if compliance threshold exceeded
        if: failure()
        run: exit 1
```

### Interactive Mode

`chainsaw init-ci` prompts for:
1. Fail threshold (default: 0 findings)
2. Ecosystems to scan (default: all)
3. Policy file path (default: `.chainsaw.yaml`)
4. Upload SARIF (default: yes)
5. Post PR comments (default: yes)

### Non-Interactive Mode

`chainsaw init-ci --non-interactive` uses defaults:
- Fail threshold: 0
- Ecosystems: all
- Policy: `.chainsaw.yaml`
- SARIF upload: enabled
- PR comments: enabled

### Flags

- `--non-interactive`: Use defaults
- `--fail-threshold`: Number of findings to fail on (default: 0)
- `--ecosystems`: Comma-separated list (default: all)
- `--policy-path`: Path to `.chainsaw.yaml` (default: `.chainsaw.yaml`)
- `--enable-sarif`: Upload SARIF (default: true)
- `--enable-pr-comments`: Post PR comments (default: true)
- `--force`: Overwrite existing workflow

### Output

Creates `.github/workflows/chainsaw.yml` with:
- Triggers on PR and push to main
- Runs on ubuntu-latest
- Installs chainsaw via `go install`
- Runs `scan`, `comply`, `supply-chain` commands
- Uploads SARIF to GitHub Security tab
- Posts PR comment with compliance score
- Respects configured thresholds

### SARIF Integration

- `chainsaw scan --format sarif --output chainsaw-scan.sarif`
- Upload via `github/codeql-action/upload-sarif@v2`
- Findings appear in GitHub Security tab
- Developers can review and dismiss findings

### PR Comments

- Extract compliance score from `comply` JSON output
- Extract pinning score from `supply-chain` JSON output
- Post comment on PR with scores and link to full report
- Uses `actions/github-script@v7` for flexibility

## Non-goals

- GitLab CI, Jenkins, Bitbucket Pipelines (separate proposals)
- Reusable workflow marketplace publication (future)
- Slack/Teams notifications (future)
- Automatic remediation or auto-merge (out of scope)
- Custom SARIF rule definitions (use defaults)

## Risks

- Workflow may fail if chainsaw is not in GOPATH. Mitigation: use `go install` with explicit version
- SARIF upload requires GitHub Advanced Security. Mitigation: document requirement, make optional
- PR comments may be noisy on large projects. Mitigation: make configurable, summarize scores

## Acceptance Criteria

- `chainsaw init-ci` creates `.github/workflows/chainsaw.yml`
- Workflow runs on PR and push to main
- Workflow runs `scan`, `comply`, `supply-chain` commands
- SARIF is uploaded to GitHub Security tab
- PR comments include compliance score delta
- Configurable thresholds and ecosystems
- Unit tests with mocked GitHub API

## Tasks

- [ ] Create `cmd/chainsaw/init_ci.go` command (2h)
- [ ] Generate workflow template with all steps (2h)
- [ ] Implement SARIF upload step (1h)
- [ ] Implement PR comment step with score extraction (1h)
- [ ] Add flag support (--fail-threshold, --ecosystems, etc.) (1h)
- [ ] Add unit tests with mocked GitHub API (1h)
- [ ] Document workflow configuration and customization (1h)
- [ ] Test workflow end-to-end in test repository (1h)
