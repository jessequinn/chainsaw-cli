# Change Proposal: v2-docker-compose

**Status:** Proposed
**Date:** 2026-05-28
**Author:** Agent

## Summary

Add Docker Compose service image scanning to chainsaw. Parse
`docker-compose.yml` (and `compose.yml`) to enumerate image dependencies
and flag unpinned or unverified references.

## Motivation

Docker Compose defines multi-service application stacks. Each service
specifies a container image — either pulled from a registry or built
from a Dockerfile. CRA-scoped organizations need visibility into all
image references in their Compose files, especially in production
deployments.

Compose files often reference images that are not covered by Dockerfile
scanning (e.g., sidecar services, databases, monitoring agents), making
this a complementary scanner to the Dockerfile proposal.

## Proposed Changes

### Ecosystem

Reuse `EcosystemDocker Ecosystem = "docker"` from the Dockerfile
proposal. Both scanners produce Docker image components — they share
the same ecosystem and purl namespace.

### New Scanner: `internal/scanner/compose.go`

Implement `ComposeScanner` satisfying the `Scanner` interface.

**DetectManifests** finds:
- `docker-compose.yml`
- `docker-compose.yaml`
- `compose.yml`
- `compose.yaml`
- `docker-compose.*.yml` (e.g., `docker-compose.prod.yml`)

Skip `.git/`, `vendor/`, `node_modules/` directories.

**ParseDependencies** parses Compose YAML:

```yaml
services:
  web:
    image: nginx:1.25-alpine
  api:
    build: ./api
    image: myorg/api:latest
  db:
    image: postgres:16@sha256:abc123...
  cache:
    image: redis:7
  worker:
    build:
      context: ./worker
      dockerfile: Dockerfile.worker
```

For each service:
- If `image:` is present: extract image reference (same parsing as
  Dockerfile `FROM` — name, tag, digest)
- If only `build:` is present and no `image:`: skip (the Dockerfile
  scanner covers this)
- If both `build:` and `image:` are present: the `image:` names the
  built image, which may or may not be a registry pull — flag as
  informational

**Component construction:** same as Dockerfile scanner — reuse the
image reference parsing logic. Extract into a shared helper
`internal/scanner/imageref.go` if both proposals are implemented.

### Deduplication

Since Compose and Dockerfile scanners share the `docker` ecosystem,
the existing `DetectAll` deduplication in `scanner.go` handles cases
where the same image appears in both a Dockerfile and a Compose file.

### Compose-specific Hygiene Checks

| Check | Severity | Description |
|---|---|---|
| `latest` tag | HIGH | `image: nginx:latest` |
| No tag | HIGH | `image: nginx` |
| Tag without digest | MEDIUM | `image: nginx:1.25` |
| Build without image | INFO | Service uses `build:` only — image name unknown |
| Privileged service | MEDIUM | `privileged: true` in service config |
| Host network | MEDIUM | `network_mode: host` |

### Variable Interpolation

Compose files support `${VARIABLE}` interpolation:
```yaml
services:
  web:
    image: ${REGISTRY}/myapp:${VERSION}
```

Same as Dockerfile ARG handling: flag as hygiene issue (MEDIUM), skip
component creation for unresolvable references.

## Non-goals

- Parsing Compose file v1 format (deprecated, `version: "1"` — uses
  top-level service keys without `services:` block)
- Validating Compose file schema beyond image references
- Scanning volumes, networks, secrets configuration
- Docker Swarm stack files (same format, but deployment context differs)
- Pulling images to inspect layers

## Risks

- Compose file format supports includes (`include:` directive in
  Compose v2.20+), which reference other Compose files. Mitigation:
  do not follow includes in v1; document limitation.
- Compose profiles and conditional services may mean not all images
  are actually used. Mitigation: scan all declared images regardless
  of profile; flag profiles as informational.
- Overlap with Dockerfile scanner on the same image. Mitigation:
  existing dedup in `DetectAll` handles this.

## Acceptance Criteria

- `chainsaw scan --ecosystem docker .` detects Compose image references
  (shared ecosystem with Dockerfile scanner)
- Parses `docker-compose.yml`, `compose.yml`, and variants
- Extracts `image:` references from all services
- Flags `latest`, missing tags, missing digests
- Skips build-only services gracefully
- Components deduplicated with Dockerfile scanner output
- Unit tests with fixture Compose files

## Tasks

- [ ] Implement `ComposeScanner` in `internal/scanner/compose.go`
- [ ] Parse Compose YAML `services.*.image` references
- [ ] Reuse or extract shared image reference parser with Dockerfile
      scanner (`internal/scanner/imageref.go`)
- [ ] Add Compose-specific hygiene checks
- [ ] Handle `${VARIABLE}` interpolation (flag, skip)
- [ ] Unit tests with fixture Compose files in `testdata/compose/`

## Dependency on v2-dockerfile

This proposal shares the `docker` ecosystem with v2-dockerfile. If
implemented independently, the image reference parser must be
duplicated or extracted. Recommended: implement v2-dockerfile first,
then extract `imageref.go`, then implement this proposal.
