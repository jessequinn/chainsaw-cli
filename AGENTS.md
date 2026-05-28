# Repository Agent Guide

## Core Principle

> Prioritize retrieval-led reasoning over pretrained-knowledge-led reasoning.

Before answering or acting, agents should:

- Use `glob` / `grep` to inspect the actual code structure of this repository.
- Use `webfetch` / websearch / `context7` to verify library and API details.
- Load applicable Skills, OpenSpec docs, and rule files first.
- Treat pretrained knowledge as a hint, not a source of truth.

## Project Overview

- **Purpose:** CLI tool for software supply chain security scanning,
  targeting EU Cyber Resilience Act (CRA) compliance. Scans dependency
  trees and lockfiles to surface vulnerabilities (via OSV), licence
  violations, typosquatting, and lockfile integrity issues.
- **Primary language:** Go 1.26+ (single binary). JS/TS parsers may be
  added later for ecosystem-specific lockfile analysis.
- **Entry points:** `main.go` (not yet created; `scan` and `sbom`
  commands per SPEC.md).
- **Key directories:**
  - `internal/scanner/` -- scanner interface + registry, Go mod parser,
    npm parser.
  - `internal/vuln/` -- OSV API client, vulnerability matcher.
  - `pkg/models/` -- shared types (Component, Finding, ScanResult,
    Severity, Ecosystem).
  - `testdata/` (planned) -- fixture lockfiles, SBOMs, recorded API
    responses.
  - `docs/` (planned) -- design docs and ADRs.
- **Output formats (per SPEC.md):** table, JSON, SARIF.
- **Policy engine (per SPEC.md):** YAML-based `.chainsaw.yaml` with
  `fail-on` severity threshold, CVE ignore list, licence deny list.
- **Exit codes:** 0 = clean, 1 = findings/violations, 2 = execution error.
- **Vulnerability source:** [OSV API](https://osv.dev/) with batch
  queries (max 1000 per request, 30s timeout).
- **Spec:** see `SPEC.md` for the full v1 design.
- **Licence:** TBD (recommend MIT or Apache-2.0).

## Tooling & Environment

- **Go package manager:** Go modules (`go.mod` / `go.sum`).
  Currently depends on `golang.org/x/mod` for `go.mod` parsing.
- **JS package manager:** pnpm (preferred) or npm -- only needed if
  JS/TS parsers are added later. Currently the npm lockfile parser is
  pure Go.
- **Install:** `go mod download`
- **Build:** `go build -o chainsaw .`
- **Test (Go):** `go test -race -coverprofile=coverage.txt -covermode=atomic ./...`
- **Test (JS):** `pnpm test` (vitest recommended).
- **Lint (Go):** `golangci-lint run`
- **Lint (JS):** `eslint .`
- **Format (Go):** `gofmt -s -w .`
- **Format (JS):** `prettier --write .`
- **Security scan:** `govulncheck ./...` / `gosec ./...` / `pnpm audit`

A `.editorconfig` file at the repository root defines whitespace,
indentation, and EOL rules. Agents must respect it when generating or
editing files.

## Git & Branching Hygiene

### Branch naming

- `main` is the only long-lived branch; it is always releasable.
- Feature branches: `feat/<short-kebab-description>` or
  `feat/<issue-id>-<short-kebab>`.
- Bug fix branches: `fix/<short-kebab>` or `fix/<issue-id>-<short-kebab>`.
- Chore / refactor / docs: `chore/`, `refactor/`, `docs/` prefixes.
- One concern per branch. Open a second branch rather than mixing scopes.

### Commit messages

- **Imperative present tense**, subject <= 72 characters, no trailing
  period. (`Add npm lockfile parser`, not `Added` / `Adds`.)
- Subject is a complete short sentence; body explains *why*, wrapped at
  72 columns. Separate subject and body with a blank line.
- Do **not** use Conventional Commit prefixes (`feat:`, `fix:`,
  `chore:`) -- the branch name and PR title already serve that purpose,
  and it conflicts with the imperative-tense changelog policy.
- Reference issues / PRs in the body, not the subject: `Refs #123`,
  `Closes #123`.

### Rebase, merge, and force-push

- Prefer `git rebase` over merge commits while a branch is in development.
- Squash-merge to `main` is the default.
- **Never force-push to `main`.** Use `--force-with-lease` on feature
  branches only.

### Hooks and bypasses

- Pre-commit and pre-push hooks (lint, format, secret scan, tests) are
  mandatory. **Never use `--no-verify`.**

### Worktree and branch cleanup

- Delete branches after merge. Enable "automatically delete head
  branches" on GitHub.
- Remove stale worktrees:

  ```bash
  git worktree remove <path>
  git worktree prune
  git branch --merged main | grep -v '^\* main$'
  git fetch --prune
  ```

## Pull Request & Code Review

### Opening a PR

A PR must include:

1. **What** the change does.
2. **Why** it is needed (issue, OpenSpec change ID, or rationale).
3. **How** it was verified (commands, test output).
4. **Risk / rollback notes** for changes touching scanning logic,
   policy engine, or credential handling.
5. **Breaking changes** prefixed `**Breaking:**`.

Keep PRs < 400 lines of non-generated diff.

### Required checks before merge

- All CI jobs green.
- At least one human reviewer approval (two for security-critical paths:
  policy engine, vulnerability scoring, credential handling).
- No unresolved review threads.
- Branch rebased on `main`.
- Changelog updated if user-visible.

### Merging

- Squash-merge is the default.
- Delete the branch on merge.

## CI/CD Policy

### Required jobs on every PR

| Job | Purpose | Fail condition |
|-----|---------|---------------|
| `test-go` | Go unit + integration tests (race, coverage) | Any failure |
| `test-js` | JS/TS unit tests | Any failure |
| `lint-go` | `golangci-lint` | Any error |
| `lint-js` | `eslint` | Any error |
| `format` | `gofmt` + `prettier` check | Any diff |
| `security` | govulncheck, gosec, gitleaks, `pnpm audit` | Any high or critical |
| `build` | Cross-compile Go binaries | Any failure |

### Rules

- No skipping required checks.
- Deterministic builds from lockfiles + source.
- Cache Go module cache, pnpm store; never cache secrets.

### Release

CLI distributed as pre-built binaries. Release pipeline triggers on
`v*` tags:

1. Cross-compile with ldflags version injection.
2. Generate SHA256 checksums.
3. Attach SBOM (Syft).
4. Create GitHub Release.

## Changelog Policy

This repository maintains a `CHANGELOG.md` following the
[Common Changelog](https://common-changelog.org/) format.

**When to update:**

- In the **same commit** as any user-visible change (new scanner, new
  policy rule, CLI flag change, output format change, bug fix).
- Multi-commit features: entry in the final commit.
- Skip for internal refactors, CI tweaks, test additions.

**Writing rules:**

- **Imperative present tense** (`Add`, `Fix`, `Remove`, `Change`).
- No Conventional Commit prefixes, no emojis.
- Breaking changes prefixed `**Breaking:**`.
- One line per change, focused on impact.

## Semantic Versioning

This repository follows [Semantic Versioning 2.0.0](https://semver.org/).

- `MAJOR` -- incompatible CLI or policy-file schema changes.
- `MINOR` -- new scanners, new output formats, new policy rules.
- `PATCH` -- bug fixes, documentation.
- Pre-1.0.0: breaking changes may occur on `MINOR` bumps.
- Version source of truth: git tag; ldflags inject at build.

## OpenSpec / Spec-Driven Development

This repository uses [OpenSpec](https://github.com/Fission-AI/OpenSpec)
for spec-driven development.

1. `/opsx-explorer` -- clarify the requirement.
2. `/opsx-propose` -- generate proposal under
   `openspec/changes/<change-id>/`.
3. Human reviews. Do not implement until approved.
4. `/opsx-apply` -- implement against the spec.
5. `/opsx-verify` -- verify completion.
6. `/opsx-archive` -- archive.

Rules:

- Never modify `openspec/specs/` directly.
- Proposals under ~1500 words with a "Non-goals" section.
- Task items <= ~2 hours of work.

## oh-my-opencode-slim

This repository works with [oh-my-opencode-slim](https://github.com/alvinunreal/oh-my-opencode-slim) (omo-slim).

### Choosing a top-level agent (the Tab key in OpenCode)

| Top-level agent | Edit tools | Use it for |
|-----------------|-----------|-----------|
| **plan** | Read-only | Exploring, designing, reviewing, OpenSpec `/opsx-explorer` and `/opsx-propose`. Cannot modify the repo. |
| **build** | Full | Small, well-scoped edits where you already know the files to touch. No delegation overhead. |
| **orchestrator** | Full + delegates | Vague or multi-part requests, unfamiliar territory, OpenSpec `/opsx-apply`, hard debugging, adding a new scanner. |

**Heuristic:** one-sentence change with known files -> **build**.
Otherwise -> **orchestrator**. Read-only or design work -> **plan**.

### Specialist subagents (delegated by the orchestrator)

| Agent | Role |
|-------|------|
| **Explorer** | Read-only codebase reconnaissance. |
| **Oracle** | High-reasoning architecture / hard-bug advisor. |
| **Librarian** | External knowledge retrieval (websearch, context7, grep_app). |
| **Designer** | UI / UX implementation (terminal output, SARIF formatting). |
| **Fixer** | Fast, scoped implementation worker. |
| **Council** | (Manual) Multi-model consensus via `@council <task>`. |

### Model selection

| Agent | Default model | Bump to Opus when |
|-------|---------------|------------------|
| **plan** | Opus (pure reasoning, quality dominates) | Already Opus. |
| **build** | Sonnet (best $ / quality for scoped edits) | Irreversible change or Sonnet has already failed. |
| **orchestrator** | Sonnet (routing + planning + execution) | Adding a new scanner from scratch, large refactor. |
| **Explorer / Librarian** | Haiku (high-volume cheap read/search) | Never -- reframe via the orchestrator instead. |
| **Fixer** | Haiku for mechanical edits, Sonnet for non-trivial | Non-trivial edits. |
| **Designer** | Sonnet (output formatting, terminal UX) | N/A. |
| **Oracle** | Opus (always) | Always Opus. |

Never use Haiku as a top-level agent. Never use Opus for high-volume
subagent work.

### Guidance for this repo

- Default to **orchestrator** (Sonnet); it delegates as needed.
- Switch to **plan** when exploring or designing.
- Switch to **build** for small known-scope edits.
- For CVE database schemas, SPDX/CycloneDX specs, npm registry API,
  OSV API, or Go vulnerability database details, prefer `@librarian`
  over pretrained knowledge -- these specs evolve.
- For hard architecture/debug problems, manually invoke `@oracle`.

## Code Style & Conventions

- **Small units.** Functions <= ~50 lines, files <= ~400 lines.
- **Early returns.** Guard-clause first.
- **No dead code.** Delete commented-out code and unused imports.
- **Explicit error types.** Never swallow errors silently.
- **Pure functions by default.** Push side effects to the edges.
- **Dependency injection over globals.**
- **Comments explain *why*, not *what*.**
- **No magic numbers / strings.** Named constants.
- **Boundary types.** Validate external input (lockfiles, SBOMs, API
  responses, CLI flags) at the boundary; pass typed values inward.
- **No `TODO` without an issue link.**
- **One concept per commit / per PR.**
- **No emojis** in code, comments, commit messages, or documentation.

### Go

- Errors are values: `fmt.Errorf("doing X: %w", err)`; check every one.
- No `panic` in library code.
- Accept interfaces, return concrete types.
- `context.Context` as first arg of any I/O-bound function.
- Table-driven tests; `t.Helper()` in helpers.
- Test files beside the code they test.

### TypeScript / JavaScript

- Strict TypeScript (`strict: true`). No `any`.
- `import type { ... }` for type-only imports.
- `const` by default; `let` only when reassigned; never `var`.
- Prefer `??` over `||` for defaults.
- No `// @ts-ignore`; use `// @ts-expect-error <reason>`.
- Always `await` or explicitly `void` promises.
- Named exports only; no default exports.

## Testing Policy

### Development discipline

- **Test-First Development is the default.** Accepted disciplines:
  - **TDD:** Red -> Green -> Refactor at the unit level. Use for
    lockfile parsers, SBOM generators, vulnerability matchers, policy
    evaluators, severity scorers.
  - **BDD:** Given / When / Then at the feature level. Use for CLI
    command behaviour ("when the user scans a project with a known CVE,
    then the output includes the advisory").
  - **ATDD:** Acceptance criteria automated before implementation.
    OpenSpec proposals carry the ATDD criteria.
- **Test-Last Development is prohibited.** Exception: characterisation
  tests on legacy code, clearly labelled.
- **Bug fixes start with a failing test.**

### Test pyramid and structure

- Many unit tests (parsers, matchers, scorers, policy rules), fewer
  integration tests (full scan against fixture projects), very few
  end-to-end tests (CLI invocation with real lockfiles).
- Coverage is a guard rail, not a goal.
- **Mutation testing** (`go-mutesting`, Stryker for JS) for high-stakes
  paths: vulnerability matching, severity scoring, licence
  classification, policy evaluation.
- Test names describe behaviour:
  `TestNpmParser_flags_critical_when_lockfile_has_known_CVE`.
- Table-driven tests (Go); `describe`/`it` (JS).

### Determinism and flake policy

- **No flaky tests.** Quarantine or fix within a week.
- No real network: mock registry APIs, use fixture lockfiles and SBOMs.
  Record real API responses as JSON fixtures in `testdata/`.
- No real filesystem outside `t.TempDir()` (Go) or OS tmpdir (JS).
- Seed all randomness; log the seed on failure.
- Run the full suite locally before opening a PR.

### CLI testing

- Integration tests invoke the compiled binary (or `cmd.Execute()`)
  with fixture projects in `testdata/`, then assert stdout, stderr,
  exit code, and output files (SARIF, CycloneDX, SPDX).
- Golden-file tests for report output: store expected output in
  `testdata/golden/`, compare with `go test -update` flag to refresh.

### Contract and integration testing

- Registry API contracts (npm, PyPI, Go proxy, OSV): record real
  responses as fixtures, replay in tests. Update fixtures when adding
  new registry support.
- SBOM format contracts: validate generated CycloneDX / SPDX output
  against the official JSON schemas.
- Lockfile parsers: test against real-world lockfiles from popular
  open-source projects (anonymised if needed).

### Performance

- Benchmark parser-heavy paths with `go test -bench` when adding new
  lockfile formats or expanding the dependency tree walker.
- Large-project scan time should not regress; track in CI once the
  suite is mature.

### CI integration

Required gates on every PR:

- Go tests (race, coverage), JS tests (vitest), `golangci-lint`,
  `eslint`, govulncheck, gosec, gitleaks, `pnpm audit`, `gofmt` +
  `prettier` check, cross-compile build.
- Coverage uploaded to Codecov.

## Security & Secrets

A supply-chain security tool must itself have exemplary security
practices. Every change is held to a higher standard.

### Secret management

- **Never commit secrets:** API keys, registry tokens, database URLs,
  SSH keys, `.pem` files, service-account JSON.
- Config files with credentials are gitignored. Only `.example` files
  committed.
- **Rotation:** compromised secret -> rotate immediately.
- **Secret scanning:** gitleaks in CI on every PR.
- **No secrets in logs or scan output.** Redact registry tokens, auth
  headers, and private repository URLs.

### Dependencies and supply chain

- **Lockfiles are the source of truth.** Commit `go.sum` and
  `pnpm-lock.yaml`.
- **Audit on every install:** `govulncheck` + `pnpm audit`. CI fails
  on high or critical.
- **No copy-pasting from random sources without review.**
- **Licence allowlist:** MIT, Apache-2.0, BSD-2-Clause, BSD-3-Clause,
  ISC, MPL-2.0.
- **Eat your own dog food:** run `chainsaw` on itself in CI. Any
  finding above the configured threshold fails the build.

### Input handling

- **Validate all parsed input** (lockfiles, SBOMs, manifests, API
  responses) against expected schemas at the boundary. Malformed input
  must produce a clear error, never a panic.
- **Parameterised queries** if any database is used.
- **Path traversal:** resolve user-supplied paths; reject paths outside
  the project root.
- **Deserialisation:** never use unsafe deserialisation (Python pickle,
  YAML `!!python/object`). Prefer JSON or safe YAML.

### Cryptography

- Use Go `crypto/*` and Node `crypto` standard libraries.
- Verify TLS certificates on all outbound connections (registry APIs,
  OSV, advisory databases).
- Hash verification: when checking package integrity, use SHA-256 or
  SHA-512. Never MD5 or SHA-1 for security purposes.

### Operational

- **SBOM** generated on every release (Syft) and attached to the GitHub
  Release.
- Run `govulncheck` and `gosec` in CI.

## Error Handling & Resilience

- **Fail fast on programmer errors** (invalid config, contract
  violations) with a clear message and non-zero exit code.
- **Fail soft on operational errors** (registry API timeouts, rate
  limits, unreachable advisory databases). Report the scan as
  incomplete rather than crashing.
- **Every I/O call has a timeout** via `context.Context`.
- **Retries:** exponential backoff with jitter, max 3 attempts. Only
  retry idempotent reads. Honour `Retry-After` from registries.
- **Graceful degradation:** if one registry is down, scan what you can
  and report which sources were unreachable.
- **Exit codes:** 0 = clean, 1 = findings above threshold, 2 = scan
  error / incomplete. Document in `--help`.
- **Error messages** include the package name, registry, and what was
  expected vs. found. Never leak credentials.

## Observability & Logging

### Logging

- **Structured logs** (JSON when `--json` or in CI, human-readable by
  default).
- **Log levels:** `error`, `warn`, `info`, `debug`. Controlled by
  `--verbose` / `--quiet` flags.
- **Required fields:** timestamp, level, message, scanner name, package
  ecosystem.
- **Never log secrets, registry tokens, or private repository URLs.**
- **No `fmt.Println` / `console.log` in committed code.** Use the
  project logger.

### Metrics and tracing

Not applicable for a CLI tool. If chainsaw is ever wrapped as a
service, add RED metrics and trace propagation at that point.

## Release & Deployment Checklist

### Pre-release

- [ ] All CI checks green on the release commit.
- [ ] Version tag follows SemVer (`vMAJOR.MINOR.PATCH`).
- [ ] `CHANGELOG.md` updated.
- [ ] All open OpenSpec changes archived.
- [ ] `govulncheck` + `pnpm audit` clean.
- [ ] `chainsaw` scanned against itself with no findings above threshold.

### Release

- [ ] Tag: `git tag -s vMAJOR.MINOR.PATCH -m "vMAJOR.MINOR.PATCH"`.
- [ ] Push: `git push origin vMAJOR.MINOR.PATCH`.
- [ ] CI cross-compiles and creates GitHub Release with binaries,
      checksums, and SBOM.
- [ ] Release notes match changelog.

### Post-release

- [ ] Close resolved issues / PRs.
- [ ] If critical bug found: yank, patch, re-release.

## Documentation Policy

### `README.md`

Must answer, in order:

1. **What** -- supply chain scanning CLI.
2. **Why** -- detect vulnerabilities, licence violations, provenance gaps.
3. **Install** -- `go install` or download binary.
4. **Configure** -- policy file format.
5. **Run** -- example scans for each ecosystem.
6. **Output formats** -- text, JSON, SARIF, CycloneDX, SPDX.
7. **Test** -- `go test` + `pnpm test`.
8. **Contributing** -- pointer to AGENTS.md.
9. **Licence.**

### Per-module documentation

- Each `pkg/<module>/` has a `doc.go` or package comment.
- Exported functions and types have Go doc comments.
- JS/TS modules have JSDoc on exported functions.

### Architecture Decision Records

Under `docs/adr/` as [ADRs](https://adr.github.io/).

- Filename: `NNNN-short-kebab-title.md`.
- Sections: Context, Decision, Status, Consequences.
- Immutable; supersede with a new ADR.
- ADR-worthy: choice of vulnerability database, SBOM format support,
  policy engine design, Go/JS boundary strategy.

## Agent Operating Rules

### Read before you write

- Always read a file before editing it.
- Always check actual code with `glob` / `grep` before claiming a
  symbol or file exists.
- When citing code, use `path/to/file.go:line_number`.

### Verify before you claim

- Run `go test -race ./...` and `pnpm test` before reporting done.
- Run `go build .` for any non-trivial change.
- Prefer `webfetch` / `context7` / official docs (OSV, CycloneDX spec,
  SPDX spec, npm registry API) over pretrained knowledge.

### Destructive operations require confirmation

Never run without explicit human confirmation:

- `rm -rf` outside a tempdir.
- `git push --force-with-lease` to a shared branch.
- `git reset --hard` on a branch with unpushed work.
- Mass file rename / move.
- Editing committed history.
- Disabling CI / hooks / branch protection.

### Stay in scope

- Do only what was asked. No side-quest refactors.
- Discovered issues -> write them down, do not fix inline.
- Do not create new files unless required.

### Parallelism and efficiency

- Issue independent tool calls in parallel.
- For broad exploration, prefer a Task subagent.
- For CVE/advisory/spec lookups, prefer `@librarian`.

### Honest reporting

- Partially done -> say so, mark `in_progress`.
- Test failure -> report it.
- Do not know -> say so.

### Long-term memory

Record non-obvious decisions in Long-term Memory Notes below with the
date.

## Non-goals

- This is a scanner, not a remediation tool. Do not add auto-fix or
  auto-upgrade functionality.
- No GUI or web dashboard. Output goes to stdout, files, or CI
  integrations (SARIF upload to GitHub).
- No support for scanning running containers or live infrastructure;
  this operates on source artefacts (lockfiles, SBOMs, manifests).
- No proprietary vulnerability database integration; use open databases
  (OSV, NVD, GitHub Advisory Database).
- CycloneDX and SPDX SBOM generation are future scope (v2+); v1 focuses
  on `scan` and basic `sbom` per SPEC.md.

## Long-term Memory Notes

- _2026-05-28_: Created AGENTS.md, opencode.json, .editorconfig, and .gitignore from canonical template in `agentic-workflows`. Project has initial code: scanner interface + registry (`internal/scanner/`), Go mod parser, npm lockfile parser, OSV API client (`internal/vuln/client.go`), matcher, and shared models (`pkg/models/`). No `main.go` or CLI entry point yet. No tests yet.
- _2026-05-28_: Known issues in existing code: `Finding.FixedIn` vs `FixedVersion` field name mismatch between `pkg/models/models.go` and `internal/vuln/client.go`; `Severity` and `Ecosystem` typed strings may cause type mismatches with plain `string` usage in `client.go` and `matcher.go`. These likely cause compile errors and should be fixed before first build.
