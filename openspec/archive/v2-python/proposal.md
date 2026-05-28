# Change Proposal: v2-python

**Status:** Proposed
**Date:** 2026-05-28
**Author:** Agent

## Strategic Context

> Python is the highest-ROI application ecosystem to add. Large CRA-relevant attack surface (IoT, industrial, automotive sectors run Python). Full OSV coverage. Adds breadth without diluting the CRA/infrastructure positioning. Priority: HIGH — implement alongside CRA engine.

## Summary

Add Python ecosystem scanning to chainsaw. Parse pip, Poetry, and Pipenv
lockfiles to enumerate Python dependencies and query OSV for known
vulnerabilities.

## Motivation

Python is one of the most widely used languages in enterprise software,
data engineering, and ML pipelines. CRA-scoped organizations almost
certainly have Python in their supply chain. The PyPI ecosystem has seen
significant supply chain attacks (typosquatting on `requests`, `urllib3`,
`python-dateutil`, etc.), making it a high-value target for scanning.

## Proposed Changes

### New Ecosystem Constant

Add `EcosystemPyPI Ecosystem = "pypi"` to `pkg/models/models.go`.

### New Scanner: `internal/scanner/python.go`

Implement `PythonScanner` satisfying the `Scanner` interface.

**DetectManifests** finds (in priority order):
1. `poetry.lock` — Poetry lockfile (richest data)
2. `Pipfile.lock` — Pipenv lockfile (JSON, includes hashes)
3. `requirements.txt` — pip freeze output (most common, least metadata)

Skip `venv/`, `.venv/`, `__pycache__/`, `.tox/`, `.eggs/` directories.

**ParseDependencies** by file type:

| File | Format | Version source | Hash source |
|---|---|---|---|
| `poetry.lock` | TOML (`[[package]]` sections) | `version` field | `files` array with sha256 |
| `Pipfile.lock` | JSON | `version` in `default`/`develop` | `hashes` array |
| `requirements.txt` | Line-based `pkg==version` | After `==` | After `--hash=sha256:` if present |

**Package URL format:** `pkg:pypi/package-name@version`

Note: PyPI normalizes package names (underscores to hyphens, lowercase).
The scanner must normalize names before constructing purls:
`my_Package` -> `my-package`.

### OSV Ecosystem Mapping

Map `"pypi"` to `"PyPI"` in `internal/vuln/client.go` `mapEcosystem()`.

### Typosquatting List

Add top 20 popular PyPI packages to `internal/hygiene/typosquat.go`:
`requests`, `boto3`, `urllib3`, `setuptools`, `wheel`, `pip`,
`certifi`, `idna`, `charset-normalizer`, `typing-extensions`,
`numpy`, `pandas`, `pyyaml`, `cryptography`, `flask`, `django`,
`jinja2`, `pillow`, `scipy`, `matplotlib`.

### Dependencies

- `github.com/BurntSushi/toml` for `poetry.lock` parsing (TOML format)
- No new dependencies for `Pipfile.lock` (JSON) or `requirements.txt`
  (line parsing)

## Non-goals

- Parsing `setup.py` or `setup.cfg` (these are build manifests, not
  lockfiles; version ranges not resolvable without pip)
- Parsing `pyproject.toml` dependency declarations (same reason)
- Conda/mamba environments
- Virtual environment introspection

## Risks

- `requirements.txt` has no standard schema — edge cases with extras
  (`pkg[extra]==1.0`), environment markers, `-r` includes, URL-based
  installs. Mitigation: parse `==` pinned lines only, skip everything
  else with a warning.
- `poetry.lock` format is not officially stable. Mitigation: parse the
  well-documented `[[package]]` structure which has been stable since
  Poetry 1.0.

## Acceptance Criteria

- `chainsaw scan --ecosystem pypi .` detects Python dependencies
- Parses `poetry.lock`, `Pipfile.lock`, and `requirements.txt`
- Components have correct purls (`pkg:pypi/...`)
- OSV queries return known Python CVEs
- Typosquatting checks flag near-matches to popular PyPI packages
- Integrity checks flag missing hashes in `requirements.txt`

## Tasks

- [ ] Add `EcosystemPyPI` constant to `pkg/models/models.go`
- [ ] Implement `PythonScanner` in `internal/scanner/python.go`
- [ ] Parse `poetry.lock` (TOML)
- [ ] Parse `Pipfile.lock` (JSON)
- [ ] Parse `requirements.txt` (line-based)
- [ ] Add PyPI name normalization (PEP 503)
- [ ] Add `"pypi"` -> `"PyPI"` mapping in `internal/vuln/client.go`
- [ ] Add popular PyPI packages to typosquatting list
- [ ] Add `toml` dependency to `go.mod`
- [ ] Unit tests with fixture lockfiles in `testdata/python/`
- [ ] Integration test: scan a project with known vulnerable Python deps
