"""ToolRequest contract — docs/CONTRACTS.md §3.

This is the only artifact the Agent is allowed to produce that expresses an
intent to act. Nothing in this module executes anything; ``from_dict`` only
performs the structural validation the Policy Gateway's evaluation flow
requires as its first step (docs/POLICY-GATEWAY.md §10, step 1).

Security note: ``rationale`` and ``expected_output_description`` are parsed
and stored (they are legitimate optional contract fields, used for
display/audit) but their *content* is never inspected here beyond a basic
type check, and — critically — nothing downstream in ``chanakya.policy``
ever reads their content when making an enforcement decision
(docs/POLICY-GATEWAY.md §15).
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Mapping, Optional

from .enums import SUPPORTED_CONTRACT_VERSIONS


class MalformedRequestError(ValueError):
    """Raised when a raw ToolRequest payload fails contract validation.

    The Policy Gateway catches this specifically and converts it into a
    ``deny`` / ``matched_rule: "malformed-request"`` PolicyDecision — this
    exception must never propagate past the Gateway boundary.
    """


_REQUIRED_FIELDS = (
    "tool_request_id",
    "contract_version",
    "investigation_id",
    "step_id",
    "capability",
    "target_ref",
    "parameters",
    "proposed_by",
    "proposed_at",
)

_REQUIRED_STRING_FIELDS = (
    "tool_request_id",
    "investigation_id",
    "step_id",
    "capability",
    "target_ref",
    "proposed_at",
)


@dataclass(frozen=True)
class ToolRequest:
    tool_request_id: str
    contract_version: str
    investigation_id: str
    step_id: str
    capability: str
    target_ref: str
    parameters: Mapping[str, Any]
    proposed_by: str
    proposed_at: str
    rationale: Optional[str] = None
    expected_output_description: Optional[str] = None

    @staticmethod
    def from_dict(data: Mapping[str, Any]) -> "ToolRequest":
        """Structural (contract-level) validation only.

        Raises ``MalformedRequestError`` for: a non-mapping payload, any
        missing required field, an unsupported/unrecognized
        ``contract_version``, a ``proposed_by`` value other than the fixed
        literal ``"agent"``, a non-string required string field, or a
        non-mapping ``parameters`` value. It does NOT validate
        ``parameters`` against a capability's schema — that is the Policy
        Gateway's separate, Registry-driven step
        (docs/POLICY-GATEWAY.md §10, step 3).
        """
        if not isinstance(data, Mapping):
            raise MalformedRequestError("ToolRequest payload must be a mapping/object")

        missing = [f for f in _REQUIRED_FIELDS if f not in data]
        if missing:
            raise MalformedRequestError(f"missing required field(s): {', '.join(missing)}")

        contract_version = data["contract_version"]
        if contract_version not in SUPPORTED_CONTRACT_VERSIONS:
            raise MalformedRequestError(f"unsupported contract_version: {contract_version!r}")

        if data["proposed_by"] != "agent":
            raise MalformedRequestError("field 'proposed_by' must be exactly 'agent'")

        for field_name in _REQUIRED_STRING_FIELDS:
            value = data[field_name]
            if not isinstance(value, str) or not value:
                raise MalformedRequestError(f"field '{field_name}' must be a non-empty string")

        if not isinstance(data["parameters"], Mapping):
            raise MalformedRequestError("field 'parameters' must be an object")

        rationale = data.get("rationale")
        if rationale is not None and not isinstance(rationale, str):
            raise MalformedRequestError("field 'rationale' must be a string if present")

        expected_output_description = data.get("expected_output_description")
        if expected_output_description is not None and not isinstance(expected_output_description, str):
            raise MalformedRequestError("field 'expected_output_description' must be a string if present")

        return ToolRequest(
            tool_request_id=data["tool_request_id"],
            contract_version=contract_version,
            investigation_id=data["investigation_id"],
            step_id=data["step_id"],
            capability=data["capability"],
            target_ref=data["target_ref"],
            parameters=dict(data["parameters"]),
            proposed_by=data["proposed_by"],
            proposed_at=data["proposed_at"],
            rationale=rationale,
            expected_output_description=expected_output_description,
        )
