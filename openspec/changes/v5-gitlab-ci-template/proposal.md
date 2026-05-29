# v5-gitlab-ci-template: GitLab CI Integration

## Summary

Extend `init-ci` command with `--platform` flag (default: github, option: gitlab). When gitlab: generate `.gitlab-ci.yml` with stages: build, scan (sarif), comply (json), upload artifacts. Template uses `go build`, `./chainsaw scan`, `./chainsaw check`.

## Motivation

Many organizations use GitLab instead of GitHub. GitLab CI integration enables CRA compliance scanning within GitLab's CI/CD pipeline.

## Design

Extend `internal/cmd/init_ci.go`:
- Add `--platform` flag with values: github, gitlab
- When gitlab: generate `.gitlab-ci.yml` instead of `.github/workflows/`
- Pipeline stages: `build` (compile chainsaw), `scan` (run scan, emit SARIF), `comply` (check CRA compliance)
- Artifacts: `scan-result.sarif`, `comply-result.json`
- Template stored in `internal/templates/gitlab-ci.yml`

## Non-goals

- GitLab Runner configuration
- Integration with GitLab Security Dashboard (separate feature)
- Multi-runner setup

## Tasks

1. Create `.gitlab-ci.yml` template -- ~1h
2. Add --platform flag parsing -- ~30m
3. Implement platform-specific template selection -- ~30m
4. Add template file embedding -- ~45m
5. Add integration test for GitLab output -- ~1h
6. Update init-ci documentation -- ~30m

## Verification

- Generated `.gitlab-ci.yml` is valid GitLab CI syntax
- Stages execute in correct order
- Artifacts collected correctly
- Template renders with correct chainsaw invocations
- GitHub template generation still works (regression test)
