"""ToolRequest Intake — docs/AGENT-RUNTIME.md §4.

The first point the Agent's untrusted output is treated as a candidate
``ToolRequest`` at all. Performs exactly the structural (contract-level)
validation ``ToolRequest.from_dict`` already implements — nothing more:
it does not consult the Security Tool Registry, does not validate
``parameters`` against a capability's schema, and does not evaluate
policy. All of that remains the Policy Gateway's job
(docs/POLICY-GATEWAY.md §10).

A validation failure here never reaches the Policy Gateway at all, and
is never repaired or "helped along" on the Agent's behalf (RT-INV-5) —
it is re-raised for the Agent Loop Controller to surface as information.
"""
from __future__ import annotations

from typing import Any, Mapping

from chanakya.contracts.tool_request import MalformedRequestError, ToolRequest


class ToolRequestIntake:
    """Stateless by design — there is nothing to configure or inject
    here; the whole point is that every raw payload gets exactly the
    same, unconditional structural check (RT-INV-5, TB-3)."""

    @staticmethod
    def intake(raw_tool_request: Mapping[str, Any]) -> ToolRequest:
        """Raises ``chanakya.contracts.tool_request.MalformedRequestError``
        for anything that fails contract-level validation. Callers must
        not catch this and construct a "corrected" ``ToolRequest``
        themselves — the only valid recovery is surfacing the error and
        letting the Agent propose something new on its own initiative."""
        return ToolRequest.from_dict(raw_tool_request)


__all__ = ["ToolRequestIntake", "MalformedRequestError", "ToolRequest"]
