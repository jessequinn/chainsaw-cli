# Change Proposal: v2-dockerfile

**Status:** Proposed
**Date:** 2026-05-28
**Author:** Agent

## Summary

Add Dockerfile base image scanning to chainsaw. Parse `FROM` directives
to enumerate base image dependencies and flag unpinned, unverified, or
risky image references.

## Motivation

Container base images are a foundational supply chain surface. A
compromised or vulnerable base image affects every container built from
it. Common issues:

- `FROM node:latest` — mutable tag, silently changes
- `FROM ubuntu:22.04` — no digest verification
- `FROM some-random-user/custom-image` — untrusted source
- Base images with known CVEs in OS packages

CRA-scoped organizations deploying containers need visibility into their
base image supply chain.

## Proposed Changes

### New Ecosystem Constant

Add `EcosystemDocker Ecosystem = "docker"` to `pkg/models/models.go`.

### New Scanner: `internal/scanner/dockerfile.go`

Implement `DockerfileScanner` satisfying the `Scanner` interface.

**DetectManifests** finds:
- `Dockerfile`
- `Dockerfile.*` (e.g., `Dockerfile.prod`, `Dockerfile.dev`)
- `*.dockerfile`
- `docker/Dockerfile*`
- `build/Dockerfile*`

Skip `.git/`, `vendor/`, `node_modules/` directories.

**ParseDependencies** parses Dockerfile `FROM` directives:

```dockerfile
FROM ubuntu:22.04
FROM node:20-alpine AS builder
FROM golang:1.22@sha256:abc123... AS build
FROM scratch
FROM ${BASE_IMAGE}:${VERSION}
```

For each `FROM` line:
- Skip `FROM scratch` (no dependency)
- Skip `FROM` with unresolved `${...}` ARG variables (warn as hygiene
  issue)
- Extract image name, tag, and digest (if present)
- Handle multi-stage builds: each `FROM` is a separate component
- Distinguish official images (no namespace: `ubuntu`, `node`,
  `golang`) from user images (`myorg/myimage`)

**Component construction:**
- Name: full image reference (`library/ubuntu`, `myorg/myimage`)
- Version: tag or digest
- Purl: `pkg:docker/namespace/name@tag` or
  `pkg:docker/namespace/name@sha256:digest`
- Hash: digest if present, empty otherwise

### OSV Ecosystem Mapping

No direct Docker/OCI ecosystem in OSV. Container image vulnerabilities
live in OS package databases (Debian, Ubuntu, Alpine security trackers).
Skip OSV vuln matching for Docker images — this is a job for Trivy/Grype
which actually inspect image layers.

Chainsaw's value for Dockerfiles is:
1. Dependency enumeration for SBOM
2. Pinning and hygiene enforcement
3. Policy-based image source restrictions

### Hygiene Checks

Dockerfile-specific checks:

| Check | Severity | Description |
|---|---|---|
| `latest` tag | HIGH | `FROM node:latest` — completely mutable |
| No tag at all | HIGH | `FROM ubuntu` — defaults to latest |
| Tag without digest | MEDIUM | `FROM node:20` — tag can be overwritten |
| Digest-pinned | OK | `FROM node@sha256:abc...` — immutable |
| Unresolved ARG | MEDIUM | `FROM ${BASE}` — can't verify |
| Non-official image | INFO | Image from non-`library/` namespace |

### Typosquatting List

Add top 20 popular Docker images:
`ubuntu`, `alpine`, `debian`, `node`, `python`, `golang`, `nginx`,
`redis`, `postgres`, `mysql`, `mongo`, `httpd`, `busybox`,
`amazoncorretto`, `eclipse-temurin`, `mcr.microsoft.com/dotnet/sdk`,
`gcr.io/distroless/static`, `gcr.io/distroless/base`,
`docker`, `registry`.

## Non-goals

- Inspecting image layers for OS package vulnerabilities (Trivy/Grype
  territory — requires pulling the image)
- Scanning `RUN apt-get install` or `RUN apk add` commands for package
  versions (requires package manager resolution)
- Docker BuildKit features (heredocs, mounts) — parse only `FROM`
- OCI image manifest verification (requires registry access)
- Scanning private registry credentials

## Risks

- Multi-stage builds with `FROM ... AS name` and `COPY --from=name`
  create internal references. Mitigation: parse all `FROM` lines, skip
  `COPY --from` references to build stages.
- ARG-based image references (`FROM ${IMAGE}`) are unresolvable at
  static analysis time. Mitigation: flag as hygiene issue, skip
  component creation.
- Some Dockerfiles use `.dockerignore` or BuildKit syntax that changes
  parsing context. Mitigation: parse `FROM` lines only; ignore
  everything else.

## Acceptance Criteria

- `chainsaw scan --ecosystem docker .` detects Dockerfile base images
- Parses `FROM` directives including tags, digests, and multi-stage
- Flags `latest`, missing tags, and missing digests as hygiene issues
- Components appear in SBOM output
- Handles `Dockerfile`, `Dockerfile.*`, `*.dockerfile` patterns
- Unit tests with fixture Dockerfiles

## Tasks

- [ ] Add `EcosystemDocker` constant to `pkg/models/models.go`
- [ ] Implement `DockerfileScanner` in `internal/scanner/dockerfile.go`
- [ ] Parse `FROM` directives (name, tag, digest, AS alias)
- [ ] Handle multi-stage builds
- [ ] Handle ARG variable references (flag, skip)
- [ ] Add Dockerfile hygiene checks (latest, no tag, no digest)
- [ ] Add popular Docker images to typosquatting list
- [ ] Unit tests with fixture Dockerfiles in `testdata/dockerfile/`
