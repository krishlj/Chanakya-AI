"""Chanakya AI — policy-gated, read-only, audited security investigation.

The model proposes; it never executes. Every proposed action passes, in
order, through Runtime turn validation (at most one tool call per turn),
ToolRequest intake, the Policy Gateway (the sole allow/deny/require_approval
authority), the Security Tool Registry and capability envelope, human
approval when required, the Tool Layer, tool-output screening, Evidence,
evidence-grounded Findings, the deterministic Risk Engine and the durable,
hash-chained Audit Log. ``--review`` verifies a past investigation
read-only. See ARCHITECTURE.md ("Implementation status at v1.0.0").

Packages: ``cli`` (entry point and composition root), ``runtime``,
``providers`` (Anthropic), ``contracts``, ``policy``, ``registry``,
``capability``, ``targets``, ``tools``, ``approval``, ``evidence``,
``findings``, ``risk``, ``audit``, ``review``.

Scope: the local host only. Three read-only capabilities — two passive
observers (``observe_local_host_environment``, ``list_listening_ports``) and
one active, human-approved loopback web-security probe (``http_probe_local``),
which sends a single bounded HTTP GET to ``127.0.0.1`` and never anywhere
else. There is no shell or arbitrary command execution, no state-changing
capability, no remote target and no MCP integration.
"""

__version__ = "1.0.0"
