# Chanakya AI

## AI-Assisted Security Agent

Chanakya AI is an AI-assisted security agent designed for authorized security investigations, evidence-driven analysis, and human-approved defensive operations.

## Vision

The project aims to combine:

- AI-assisted security investigation
- Agent Runtime
- Security tool orchestration
- MCP-based tool integration
- Target and environment intelligence
- Evidence collection
- Risk assessment
- Human approval
- Security audit logging

The system will initially support local security analysis and will be designed to expand to authorized labs, cloud environments, web applications, APIs, source-code repositories, and other authorized targets.

> This project is developed for authorized security testing, research, and defensive purposes.

## Implementation status

- **Phase 0 — Design** (`ARCHITECTURE.md`, `docs/CONTRACTS.md`,
  `docs/THREAT-MODEL.md`): complete.
- **Phase 2 — Security Control Plane** (`docs/POLICY-GATEWAY.md`,
  `docs/TOOL-REGISTRY.md`, `docs/CAPABILITY-PERMISSION-MODEL.md`):
  implemented under `chanakya/` — the Policy Gateway, the Security Tool
  Registry, and the capability/permission model. See
  `docs/PHASE-2-IMPLEMENTATION.md` for what was built, how it enforces the
  design docs, and its known limitations.
- **Phases 3–19** (`ARCHITECTURE.md` status notes, `docs/AGENT-RUNTIME.md`):
  the Agent Runtime and a minimal CLI (`python -m chanakya.cli
  "<objective>"`, with `--review <investigation_id>` for read-only
  reconstruction); the Anthropic provider; two read-only local-host
  capabilities; durable, hash-chained Evidence, Findings, RiskAssessments
  and Audit Log; human approval; deterministic, versioned risk rules;
  durable agent-turn records (Phase 14); tool-output credential
  screening with Registry-declared model egress (Phase 15); and
  Runtime-owned failure text, so handler errors never reach the audit log
  or the model (Phase 16); Runtime-owned error and terminal records,
  durable before the state changes (Phase 17); and a provider transport
  isolated from the process environment, verified and recorded (Phase 18),
  with SDK debug logging checked across the whole logger hierarchy
  (Phase 19).
- **Not yet implemented**: MCP integration, remote targets,
  state-changing capabilities, recommendations, identity/authentication,
  persistence/resume, and any Web UI or API.

Run the test suite with:
```
python -m pytest -v
```