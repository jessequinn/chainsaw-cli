# Change Proposal: v2-strategic-positioning

**Status:** Proposed
**Date:** 2026-05-28
**Author:** Agent

## Summary

Reposition chainsaw from "another vulnerability scanner" to "CRA
compliance engine with infrastructure supply chain depth." This is a
strategic framing document, not a code change.

## Problem

Chainsaw v1 is a simplified osv-scanner + CycloneDX generator with
typosquatting checks. The competitive landscape makes this untenable:

| Tool | What it does better than chainsaw |
|---|---|
| Trivy | 20+ ecosystems, container scanning, IaC, 32k stars |
| Grype + Syft | SBOM-driven SCA, EPSS scoring |
| OSV-Scanner | Google-maintained, guided remediation |
| supply-chain-guard | 170+ malware patterns, attack-chain correlation, trust scoring, SLSA verification, prompt injection detection |
| Snyk / Checkmarx | Reachability analysis, fix prioritization, enterprise workflows |

Chainsaw cannot win on breadth (Trivy), detection depth
(supply-chain-guard), or enterprise features (Snyk). It needs a
different axis.

## Positioning

**Chainsaw is a CRA compliance engine that scans software and
infrastructure supply chains.**

Two differentiation axes:

### Axis 1: CRA Compliance (no existing tool owns this)

The EU Cyber Resilience Act (Regulation 2024/2847) creates mandatory
obligations for manufacturers of products with digital elements:

- **Reporting obligations apply September 11, 2026** (3.5 months away)
- Full requirements apply December 11, 2027
- Requires: SBOM maintenance, vulnerability handling processes,
  coordinated vulnerability disclosure, security updates, conformity
  assessment documentation

No existing open-source tool provides:
- CRA-specific compliance gap analysis
- Annex I requirements verification
- Vulnerability disclosure process assessment
- Article 14 reporting readiness checks
- Technical documentation completeness scoring
- CE marking readiness reporting

Chainsaw fills this gap.

### Axis 2: Infrastructure Supply Chain Depth

Traditional SCA tools scan application dependencies (npm, pip, Maven).
The infrastructure layer — Terraform providers, Ansible collections,
GitHub Actions, Dockerfiles, Compose files — is poorly covered:

- Trivy does IaC misconfiguration scanning, not supply chain analysis
- supply-chain-guard has regex-based IaC scanning but no semantic depth
- No tool treats infrastructure dependencies as first-class supply
  chain components with the same rigor as application dependencies

Chainsaw treats every dependency — application, infrastructure, and
CI/CD — as part of the same supply chain graph, subject to the same
policy enforcement and CRA compliance requirements.

## New Tagline

> Chainsaw: CRA-ready supply chain compliance for software and
> infrastructure.

## What This Means for v2 Proposals

### Ecosystem proposals (Python, Elixir) become secondary

These add breadth but not differentiation. Trivy already has 20+
ecosystems. Implement Python (large attack surface, CRA-relevant),
defer Elixir until demand exists.

### Infrastructure proposals (Terraform, Ansible, GH Actions, Docker) become primary

These deliver the infrastructure supply chain depth axis. Reframe them
around supply chain analysis, not just "parse another file format."

### New proposals needed

- **CRA compliance engine** — the core differentiator
- **Infrastructure supply chain graph** — unified dependency model
  across application and infrastructure layers

## Competitive Positioning Matrix (post-v2)

| Capability | Trivy | Grype | OSV-Scanner | supply-chain-guard | **Chainsaw** |
|---|---|---|---|---|---|
| Application SCA | Strong | Strong | Strong | Good | Good |
| Container scanning | Strong | Strong | No | No | No |
| IaC misconfiguration | Strong | No | No | Regex | No |
| Infrastructure supply chain | No | No | No | Regex | **Deep** |
| CI/CD supply chain | No | No | No | Good | **Deep** |
| CRA compliance | No | No | No | No | **Core** |
| SBOM generation | Strong | Strong (Syft) | No | Good | Good |
| Malware detection | No | No | No | Strong | No |
| Policy enforcement | No | No | No | Good | **CRA-aligned** |

## Non-goals

- Competing with Trivy on ecosystem breadth
- Competing with supply-chain-guard on malware pattern detection
- Container image layer scanning
- SAST / DAST
- Runtime security
