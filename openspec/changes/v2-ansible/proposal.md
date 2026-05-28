# Change Proposal: v2-ansible

**Status:** Proposed
**Date:** 2026-05-28
**Author:** Agent

## Summary

Add Ansible Galaxy collection and role scanning to chainsaw. Parse
`requirements.yml` to enumerate Ansible dependencies and flag unpinned
or untrusted sources.

## Motivation

Ansible is widely used for configuration management and deployment
automation. Galaxy collections and roles execute arbitrary code on
target systems — a compromised collection can backdoor entire fleets.
CRA-scoped organizations need visibility into their Ansible supply chain.

Ansible Galaxy has no lockfile mechanism, no integrity hashes, and no
built-in vulnerability database. This makes hygiene checks (pinning,
source verification) more valuable than vuln matching.

## Proposed Changes

### New Ecosystem Constant

Add `EcosystemAnsible Ecosystem = "ansible"` to `pkg/models/models.go`.

### New Scanner: `internal/scanner/ansible.go`

Implement `AnsibleScanner` satisfying the `Scanner` interface.

**DetectManifests** finds:
1. `requirements.yml` — Galaxy dependency file (primary)
2. `collections/requirements.yml` — alternate location
3. `roles/requirements.yml` — role-specific requirements

Skip `.ansible/`, `molecule/` directories.

**ParseDependencies** parses YAML:

```yaml
collections:
  - name: community.general
    version: "8.1.0"
  - name: amazon.aws
    version: ">=7.0.0,<8.0.0"
  - name: https://github.com/org/custom-collection.git
    type: git
    version: main

roles:
  - name: geerlingguy.docker
    version: "6.1.0"
  - name: geerlingguy.nginx
```

For each entry:
- Extract `name` and `version`
- If version is a range or missing, flag as hygiene issue (unpinned)
- If source is git with a branch ref, flag as hygiene issue
- Construct purl: `pkg:ansible/namespace.collection@version`
  (no official purl type; use convention)

### OSV Ecosystem Mapping

No Ansible ecosystem in OSV. Skip vuln matching. The value is
dependency enumeration, pinning enforcement, and SBOM generation.

### Hygiene Checks

Ansible-specific hygiene checks:
- **Unpinned collection:** version missing or uses range constraints
  (severity: HIGH — any version could be installed)
- **Unpinned role:** version field missing (severity: HIGH)
- **Git source on branch:** `version: main` or `version: master`
  (severity: MEDIUM)
- **No requirements file:** playbooks exist but no `requirements.yml`
  (informational — may use inline collections)

### Typosquatting List

Add top 15 popular Ansible collections:
`community.general`, `community.aws`, `amazon.aws`,
`ansible.builtin`, `ansible.posix`, `ansible.netcommon`,
`community.docker`, `community.postgresql`, `community.mysql`,
`community.crypto`, `kubernetes.core`, `cloud.common`,
`ansible.windows`, `community.vmware`, `junipernetworks.junos`.

## Non-goals

- Scanning Ansible Vault encrypted files
- Scanning playbook task content for security issues (SAST territory)
- Ansible Tower/AWX project scanning
- Role dependency resolution (roles within roles)

## Risks

- No official purl type for Ansible. Mitigation: use `pkg:ansible/`
  convention.
- No OSV coverage. Mitigation: be transparent; value is enumeration
  and hygiene.
- `requirements.yml` format varies (some projects use `dependencies`
  key in `galaxy.yml` instead). Mitigation: support both; document
  what is scanned.

## Acceptance Criteria

- `chainsaw scan --ecosystem ansible .` detects Ansible dependencies
- Parses `requirements.yml` collections and roles
- Flags unpinned versions and branch-based git sources
- Components appear in SBOM output
- Unit tests with fixture YAML files

## Tasks

- [ ] Add `EcosystemAnsible` constant to `pkg/models/models.go`
- [ ] Implement `AnsibleScanner` in `internal/scanner/ansible.go`
- [ ] Parse `requirements.yml` collections and roles
- [ ] Add Ansible-specific hygiene checks (unpinned, branch refs)
- [ ] Add popular Ansible collections to typosquatting list
- [ ] Unit tests with fixture files in `testdata/ansible/`
