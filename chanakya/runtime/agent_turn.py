"""AgentTurnOutput — docs/AGENT-RUNTIME.md "Additional contracts".

The schema-validated envelope for one Agent turn's output. Produced by
the provider mapping (``chanakya.providers.mapping``) from the raw model
reply, and consumed only by the Agent Loop Controller, after the Runtime has
checked the reply carries at most one ``tool_use`` block (CT-INV-3). Never
seen by the Policy Gateway, Security Tool Registry, or the Tool Layer.

Like ``ToolRequest.from_dict`` (docs/CONTRACTS.md §3), ``from_dict`` here
is the one place a raw, untrusted dict becomes a typed object — and
still just a *proposal*: turning ``next_action == propose_tool_request``
into an actual `ToolRequest` still requires the separate, independent
validation in ``chanakya.runtime.tool_request_intake`` (RT-INV-5: the
Runtime never repairs or upgrades untrusted Agent output; it only ever
validates it as-is).
"""
from __future__ import annotations

import copy
from dataclasses import dataclass
from enum import Enum
from typing import Any, Mapping, Optional, Tuple

from chanakya.contracts.enums import SUPPORTED_CONTRACT_VERSIONS

from .exceptions import MalformedAgentTurnOutputError


class NextAction(str, Enum):
    """docs/AGENT-RUNTIME.md — AgentTurnOutput.next_action. Exactly these
    two values; there is no third "do nothing" option — an Agent that has
    nothing further to propose must explicitly conclude."""

    PROPOSE_TOOL_REQUEST = "propose_tool_request"
    CONCLUDE = "conclude"


_REQUIRED_FIELDS = ("turn_id", "contract_version", "investigation_id", "next_action", "produced_at")

#: Phase 9 — the most findings one turn may carry. More is malformed.
MAX_FINDINGS_PER_TURN = 20


@dataclass(frozen=True)
class AgentTurnOutput:
    turn_id: str
    contract_version: str
    investigation_id: str
    next_action: NextAction
    produced_at: str
    tool_request: Optional[Mapping[str, Any]] = None
    explanation: Optional[str] = None
    #: Phase 9 (docs/AGENT-RUNTIME.md "Additional contracts"): raw,
    #: model-proposed findings, allowed only with ``conclude``. Structural
    #: check only; the Agent Loop Controller validates each one and
    #: resolves its evidence references before anything is stored.
    findings: Tuple[Mapping[str, Any], ...] = ()

    @staticmethod
    def from_dict(data: Mapping[str, Any]) -> "AgentTurnOutput":
        """Structural validation only. Does NOT validate ``tool_request``
        as a real ``ToolRequest`` — that is
        ``chanakya.runtime.tool_request_intake.ToolRequestIntake``'s job,
        performed as a deliberately separate step (docs/AGENT-RUNTIME.md
        §4)."""
        if not isinstance(data, Mapping):
            raise MalformedAgentTurnOutputError("AgentTurnOutput payload must be a mapping/object")

        missing = [f for f in _REQUIRED_FIELDS if f not in data]
        if missing:
            raise MalformedAgentTurnOutputError(f"missing required field(s): {', '.join(missing)}")

        contract_version = data["contract_version"]
        if contract_version not in SUPPORTED_CONTRACT_VERSIONS:
            raise MalformedAgentTurnOutputError(f"unsupported contract_version: {contract_version!r}")

        try:
            next_action = NextAction(data["next_action"])
        except ValueError as exc:
            raise MalformedAgentTurnOutputError(f"invalid 'next_action': {data['next_action']!r}") from exc

        tool_request = data.get("tool_request")
        if next_action == NextAction.PROPOSE_TOOL_REQUEST:
            if tool_request is None or not isinstance(tool_request, Mapping):
                raise MalformedAgentTurnOutputError(
                    "'tool_request' is required and must be an object when next_action == propose_tool_request"
                )
        else:
            if tool_request is not None:
                raise MalformedAgentTurnOutputError(
                    "'tool_request' must be absent when next_action == conclude"
                )

        for field_name in ("turn_id", "investigation_id", "produced_at"):
            value = data[field_name]
            if not isinstance(value, str) or not value:
                raise MalformedAgentTurnOutputError(f"field '{field_name}' must be a non-empty string")

        explanation = data.get("explanation")
        if explanation is not None and not isinstance(explanation, str):
            raise MalformedAgentTurnOutputError("field 'explanation' must be a string if present")

        findings = data.get("findings")
        if findings is None:
            findings = []
        if not isinstance(findings, list):
            raise MalformedAgentTurnOutputError("field 'findings' must be a list if present")
        if findings and next_action != NextAction.CONCLUDE:
            raise MalformedAgentTurnOutputError("'findings' are only allowed when next_action == conclude")
        if len(findings) > MAX_FINDINGS_PER_TURN:
            raise MalformedAgentTurnOutputError(f"more than {MAX_FINDINGS_PER_TURN} findings in one turn")
        if not all(isinstance(item, Mapping) for item in findings):
            raise MalformedAgentTurnOutputError("each entry of 'findings' must be an object")

        return AgentTurnOutput(
            turn_id=data["turn_id"],
            contract_version=contract_version,
            investigation_id=data["investigation_id"],
            next_action=next_action,
            produced_at=data["produced_at"],
            tool_request=dict(tool_request) if tool_request is not None else None,
            explanation=explanation,
            findings=tuple(copy.deepcopy(dict(item)) for item in findings),
        )
