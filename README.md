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
- **Not yet implemented**: the Agent Runtime, the AI Agent, the LLM
  Abstraction, MCP integration, real security tools, and any UI (CLI or
  Web).

Run the test suite with:
```
python -m pytest -v
```