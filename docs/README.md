# Documentation

Documentation for Chanakya AI, an AI-assisted security investigation tool for
authorized, defensive use. Start with the [project README](../README.md) for
an overview, installation and usage.

## Case Studies

Real investigations run with Chanakya AI v1.1.0.

- **[Local Host Security Investigation](case-studies/LOCAL-HOST-SECURITY-INVESTIGATION.md)**:
  a read-only investigation of a Windows host covering platform discovery,
  listening services, evidence-cited findings, deterministic risk assessment
  and a verified audit trail. *Sanitized portfolio report; raw host data is
  intentionally excluded.*
- **[Local Juice Shop Web Security Assessment](case-studies/LOCAL-WEB-SECURITY-ASSESSMENT-JUICE-SHOP.md)**:
  benign HTTP probing of a local OWASP Juice Shop instance, a wildcard CORS
  configuration observation, a manually performed remediation, and the
  documented verification boundary.

## Architecture & Design

- [Architecture specification](../ARCHITECTURE.md), including "Implementation
  status at v1.1.0"
- [Threat model](THREAT-MODEL.md) and the consolidated threat register
- [Agent Runtime](AGENT-RUNTIME.md): Runtime design and invariants
- [Data contracts](CONTRACTS.md)
- [Policy Gateway](POLICY-GATEWAY.md)
- [Security Tool Registry](TOOL-REGISTRY.md)
- [Capability and permission model](CAPABILITY-PERMISSION-MODEL.md)
- [Target Manager](TARGET-MANAGER.md)
- [Target-aware agent context](TARGET-AWARE-AGENT-CONTEXT.md)
- [Phase 2 implementation](PHASE-2-IMPLEMENTATION.md) and
  [Phase 10 readiness](PHASE-10-READINESS.md) (historical design notes)

## Release & Validation

- [v1.0.0 Release Validation](releases/FINAL-RELEASE-VALIDATION-REPORT.md):
  end-to-end validation against the real Anthropic API
- [v1.0.0 Security Audit](releases/FINAL-SECURITY-AUDIT-REPORT.md)
- [v1.0.0 Release Report](releases/FINAL-V1.0.0-RELEASE-REPORT.md)
- [v1.1.0 Release Readiness](releases/RELEASE-READINESS-v1.1.0-REPORT.md)
- [v1.1.0 Release Preparation](releases/RELEASE-PREP-V1.1.0-REPORT.md)
- Historical Release Preparation Reports (v1.0.0):
  - [RP1–RP4](releases/RELEASE-PREP-RP1-RP4-REPORT.md)
  - [RP5–RP9](releases/RELEASE-PREP-RP5-RP9-REPORT.md)

## Engineering Reports

- [Phase 21 Anthropic Multi-Tool Investigation](engineering/PHASE-21-ANTHROPIC-MULTI-TOOL-INVESTIGATION.md):
  diagnosis of the multiple-tool-use-block failure and the recommended fix
- [Phase 21 Architecture Readiness](engineering/PHASE-21-ARCHITECTURE-READINESS-REPORT.md)
- [Local Pentest PoC Readiness](engineering/CHANAKYA-LOCAL-PENTEST-POC-READINESS.md):
  inspection that identified the minimum capability for a controlled local
  web exercise (one localhost-only, human-approved HTTP probe)
- [Local Pentest PoC Implementation Report](engineering/CHANAKYA-LOCAL-PENTEST-POC-IMPLEMENTATION-REPORT.md)

## Labs

- [Local XSS Training Lab](labs/LOCAL-XSS-LAB-REPORT.md): a small,
  deliberately vulnerable (reflected XSS), loopback-only training target (source in [`labs/local-xss/`](../labs/local-xss/))

## Investigation data

Raw investigation data (audit, evidence, findings and risk records) is never
stored in this repository. Keep it in a private workdir outside Git, such as
`D:\Chanakya-Data`. See
[Public vs private investigation data](../README.md#public-vs-private-investigation-data).
