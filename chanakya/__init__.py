"""Chanakya AI — Phase 2 Security Control Plane.

Implements, per docs/ARCHITECTURE.md and docs/CAPABILITY-PERMISSION-MODEL.md:

- ``chanakya.contracts``  — the ToolRequest / PolicyDecision / Target data
  contracts from docs/CONTRACTS.md, implemented exactly as specified there.
- ``chanakya.registry``   — the Security Tool Registry (docs/TOOL-REGISTRY.md).
- ``chanakya.capability`` — the capability/permission model: action types,
  permission levels, and the invariants connecting them to classification
  (docs/CAPABILITY-PERMISSION-MODEL.md).
- ``chanakya.policy``     — the Policy & Security Gateway
  (docs/POLICY-GATEWAY.md) — the sole allow/deny/require_approval authority.
- ``chanakya.targets``    — a minimal, descriptive-only target registry the
  Gateway needs for scope checks. This is NOT the future Target Manager /
  Target Adapters from docs/ARCHITECTURE.md §6-7 — see the Phase 2
  implementation notes for what remains for the Agent Runtime phase.

Deliberately NOT implemented in this phase: the Agent Runtime, the AI Agent,
the LLM Abstraction, the MCP/Tool Layer, any real security tool, and any
shell/process execution path. Nothing in this package executes a security
tool or a shell command against any target.
"""

__version__ = "1.0.0"
