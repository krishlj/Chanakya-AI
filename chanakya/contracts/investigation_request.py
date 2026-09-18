"""InvestigationRequest contract — docs/CONTRACTS.md §1.

The only contract that originates directly from a human, outside the
agent loop. ``from_dict`` performs the structural validation
``docs/CONTRACTS.md`` §1 requires before an ``InvestigationManager`` may
turn this into an ``InvestigationContext`` (docs/AGENT-RUNTIME.md §1).
"""
from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Mapping, Optional, Sequence

from .enums import SUPPORTED_CONTRACT_VERSIONS

#: docs/CONTRACTS.md §1 validation requirements: "submitted_by must
#: identify a human account, never a system/agent id."
_RESERVED_IDENTITIES = frozenset({"agent", "system"})


class Priority(str, Enum):
    """docs/CONTRACTS.md §1 — InvestigationRequest.priority."""

    LOW = "low"
    NORMAL = "normal"
    HIGH = "high"


class MalformedInvestigationRequestError(ValueError):
    """Raised when a raw InvestigationRequest payload fails contract
    validation. Must never propagate into a created InvestigationContext —
    a request that fails validation never produces one
    (docs/AGENT-RUNTIME.md §1)."""


_REQUIRED_FIELDS = (
    "investigation_request_id",
    "contract_version",
    "objective",
    "requested_targets",
    "submitted_by",
    "submitted_at",
)


@dataclass(frozen=True)
class InvestigationRequest:
    investigation_request_id: str
    contract_version: str
    objective: str
    requested_targets: Sequence[str]
    submitted_by: str
    submitted_at: str
    constraints: Sequence[str] = field(default_factory=tuple)
    scope_notes: Optional[str] = None
    priority: Optional[Priority] = None
    tags: Sequence[str] = field(default_factory=tuple)

    @staticmethod
    def from_dict(data: Mapping[str, Any]) -> "InvestigationRequest":
        """Structural (contract-level) validation only — does not check
        that ``requested_targets`` actually resolve against the Target
        Manager's registry; that cross-check is the InvestigationManager's
        job (docs/AGENT-RUNTIME.md §1), since it requires a registry
        dependency this contract module deliberately does not import.
        """
        if not isinstance(data, Mapping):
            raise MalformedInvestigationRequestError("InvestigationRequest payload must be a mapping/object")

        missing = [f for f in _REQUIRED_FIELDS if f not in data]
        if missing:
            raise MalformedInvestigationRequestError(f"missing required field(s): {', '.join(missing)}")

        contract_version = data["contract_version"]
        if contract_version not in SUPPORTED_CONTRACT_VERSIONS:
            raise MalformedInvestigationRequestError(f"unsupported contract_version: {contract_version!r}")

        objective = data["objective"]
        if not isinstance(objective, str) or not objective.strip():
            raise MalformedInvestigationRequestError("field 'objective' must be a non-empty string")

        requested_targets = data["requested_targets"]
        if not isinstance(requested_targets, Sequence) or isinstance(requested_targets, (str, bytes)):
            raise MalformedInvestigationRequestError("field 'requested_targets' must be a list of strings")
        if not requested_targets:
            raise MalformedInvestigationRequestError("field 'requested_targets' must be non-empty")
        if not all(isinstance(t, str) and t for t in requested_targets):
            raise MalformedInvestigationRequestError("field 'requested_targets' must contain only non-empty strings")

        submitted_by = data["submitted_by"]
        if not isinstance(submitted_by, str) or not submitted_by:
            raise MalformedInvestigationRequestError("field 'submitted_by' must be a non-empty string")
        if submitted_by in _RESERVED_IDENTITIES:
            raise MalformedInvestigationRequestError(
                f"field 'submitted_by' must identify a human, not the reserved identity {submitted_by!r}"
            )

        submitted_at = data["submitted_at"]
        if not isinstance(submitted_at, str) or not submitted_at:
            raise MalformedInvestigationRequestError("field 'submitted_at' must be a non-empty string")

        priority_raw = data.get("priority")
        priority: Optional[Priority] = None
        if priority_raw is not None:
            try:
                priority = Priority(priority_raw)
            except ValueError as exc:
                raise MalformedInvestigationRequestError(f"invalid 'priority': {priority_raw!r}") from exc

        constraints = data.get("constraints", ())
        tags = data.get("tags", ())
        scope_notes = data.get("scope_notes")

        return InvestigationRequest(
            investigation_request_id=data["investigation_request_id"],
            contract_version=contract_version,
            objective=objective,
            requested_targets=tuple(requested_targets),
            submitted_by=submitted_by,
            submitted_at=submitted_at,
            constraints=tuple(constraints),
            scope_notes=scope_notes,
            priority=priority,
            tags=tuple(tags),
        )
