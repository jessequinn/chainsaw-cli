# Change Proposal: v2-security-policy-generator

**Status:** Proposed
**Date:** 2026-05-28
**Author:** Agent

## Strategic Context

> CRA compliance requires documented security policies and coordinated vulnerability disclosure. Chainsaw should scaffold these artefacts to reduce friction for new users. Priority: MEDIUM — improves user onboarding and CRA compliance posture.

## Summary

Add `chainsaw init-security` command that scaffolds security policy files: `SECURITY.md` (coordinated disclosure template), `.well-known/security.txt` (RFC 9116), and `.chainsaw.yaml` CRA section with manufacturer and security contact placeholders.

## Motivation

CRA mandates:
- Coordinated vulnerability disclosure process
- Security contact information
- Manufacturer identification
- Support end-date tracking

Users starting new projects need templates to bootstrap these. Interactive scaffolding reduces friction and ensures compliance from day one.

## Proposed Changes

### New Command: `chainsaw init-security`

Add `cmd/chainsaw/init_security.go` implementing a new Cobra command.

### Generated Files

#### 1. `SECURITY.md`

Template for coordinated vulnerability disclosure:

```markdown
# Security Policy

## Reporting a Vulnerability

We take security seriously. If you discover a vulnerability, please email
[SECURITY_EMAIL] instead of using the issue tracker.

### Reporting Process

1. Email [SECURITY_EMAIL] with:
   - Description of the vulnerability
   - Steps to reproduce
   - Potential impact
   - Your name and affiliation (optional)

2. We will acknowledge receipt within 48 hours

3. We will investigate and provide an estimated timeline for a fix

4. We will notify you when a patch is released

### Supported Versions

| Version | Supported |
|---------|-----------|
| [VERSION] | Yes |
| < [VERSION] | No |

### Security Contact

- Email: [SECURITY_EMAIL]
- PGP Key: [OPTIONAL_PGP_URL]

### Disclosure Timeline

- Day 0: Vulnerability reported
- Day 1-7: Initial assessment and reproduction
- Day 8-30: Fix development and testing
- Day 31: Coordinated public disclosure
```

#### 2. `.well-known/security.txt`

RFC 9116 compliant security metadata:

```
Contact: mailto:[SECURITY_EMAIL]
Expires: [EXPIRY_DATE]
Preferred-Languages: en
Canonical: https://[REPO_URL]/SECURITY.md
Policy: https://[REPO_URL]/SECURITY.md
```

#### 3. `.chainsaw.yaml` CRA Section

Extend existing policy file with CRA metadata:

```yaml
cra:
  manufacturer: "[ORG_NAME]"
  support-end-date: "[YYYY-MM-DD]"
  security-contact: "[SECURITY_EMAIL]"
  csirt-contact: "[CSIRT_EMAIL]"
  vulnerability-disclosure-policy: "https://[REPO_URL]/SECURITY.md"
```

### Interactive Mode (Default)

Prompt user for:
1. Organization name (default: git config `user.name`)
2. Security email (default: git config `user.email`)
3. Support end-date (default: today + 2 years)
4. CSIRT contact (optional, default: same as security email)
5. Repository URL (default: git remote `origin`)

### Non-Interactive Mode

`chainsaw init-security --non-interactive` uses sensible defaults:
- Org name: git config or "Organization"
- Security email: git config or "security@example.com"
- Support end-date: today + 2 years
- CSIRT contact: same as security email
- Repo URL: git remote origin or "https://github.com/org/repo"

### Output

All generated files are templates with `[TODO]` markers for human review:
- `[SECURITY_EMAIL]` → user-provided email
- `[ORG_NAME]` → user-provided org
- `[YYYY-MM-DD]` → calculated date
- `[REPO_URL]` → git remote or user input

Files are created with sensible permissions:
- `SECURITY.md`: 0644 (world-readable)
- `.well-known/security.txt`: 0644
- `.chainsaw.yaml`: 0644 (no secrets in template)

### Flags

- `--non-interactive`: Use defaults, no prompts
- `--org-name`: Override org name
- `--security-email`: Override security email
- `--support-end-date`: Override support end-date (YYYY-MM-DD)
- `--csirt-contact`: Override CSIRT contact
- `--repo-url`: Override repository URL
- `--force`: Overwrite existing files

## Non-goals

- Generating actual security policies (legal/business concern)
- Auto-filling from GitHub API (future enhancement)
- Validating email addresses or dates
- Encrypting security contact information
- Integrating with external secret management

## Risks

- Generated files may be incomplete or incorrect. Mitigation: all files are templates with TODO markers; users must review before committing
- Users may commit security contact info unintentionally. Mitigation: document in generated files that review is required
- `.well-known/security.txt` requires web server configuration. Mitigation: document in SECURITY.md

## Acceptance Criteria

- `chainsaw init-security` creates `SECURITY.md`, `.well-known/security.txt`, updates `.chainsaw.yaml`
- Interactive mode prompts for org, email, dates
- Non-interactive mode uses defaults
- All files contain TODO markers for human review
- Flags override defaults
- `--force` overwrites existing files
- Generated files are valid Markdown, YAML, and RFC 9116 compliant
- Unit tests with mocked user input

## Tasks

- [ ] Create `cmd/chainsaw/init_security.go` command (2h)
- [ ] Implement interactive prompts with defaults (1h)
- [ ] Generate `SECURITY.md` template (1h)
- [ ] Generate `.well-known/security.txt` template (1h)
- [ ] Update `.chainsaw.yaml` with CRA section (1h)
- [ ] Add flag support (--non-interactive, --org-name, etc.) (1h)
- [ ] Add unit tests with mocked input (1h)
- [ ] Update CLI help and documentation (1h)
