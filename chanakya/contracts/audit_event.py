"""AuditEvent contract — docs/CONTRACTS.md §13.

The append-only record of every security-relevant operation or state
transition in the system, independent of whether any tool actually ran.
The Agent Runtime is the sole producer (docs/ARCHITECTURE.md §14,
docs/POLICY-GATEWAY.md §12, docs/AGENT-RUNTIME.md §14) — this module only
defines the data shape; ``chanakya.runtime.audit`` is the emission
boundary that constructs and forwards these to an injected sink.

Per docs/CONTRACTS.md §13: ``event_type`` is "extensible only via a
contract_version bump, never by inventing ad hoc strings" — the enum
below is exactly the closed set the design document defines, no more, no
less.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Mapping, Optional


class AuditEventType(str, Enum):
    """docs/CONTRACTS.md §13 — the closed event_type enum."""

    INVESTIGATION_STARTED = "investigation_started"
    REQUEST_PROPOSED = "request_proposed"
    POLICY_EVALUATED = "policy_evaluated"
    APPROVAL_REQUESTED = "approval_requested"
    APPROVAL_DECIDED = "approval_decided"
    DISPATCH_STARTED = "dispatch_started"
    DISPATCH_COMPLETED = "dispatch_completed"
    DISPATCH_FAILED = "dispatch_failed"
    EVIDENCE_RECORDED = "evidence_recorded"
    FINDING_CREATED = "finding_created"
    RISK_ASSESSED = "risk_assessed"
    RECOMMENDATION_CREATED = "recommendation_created"
    INVESTIGATION_COMPLETED = "investigation_completed"
    INVESTIGATION_HALTED = "investigation_halted"
    ERROR = "error"
    #: Phase 14 (contract_version 1.1.0): forensic model-turn records.
    AGENT_TURN_REQUESTED = "agent_turn_requested"
    AGENT_TURN_RECEIVED = "agent_turn_received"
    AGENT_TURN_REJECTED = "agent_turn_rejected"


#: The version the Runtime emits. 1.0.0 streams (Phases 6-13) and 1.1.0
#: streams (Phase 14) stay readable; the turn event types exist only from
#: 1.1.0. 1.2.0 (Phase 15) adds ``model_egress`` to the policy_evaluated
#: envelope summary and ``capability``/``model_egress`` to each manifest
#: context entry, and means every Evidence record carries screening
#: provenance. 1.3.0 (Phase 16) means every ``dispatch_failed``
#: ``error_message`` and every ``tool_result_error`` context entry is a
#: Runtime-owned failure message (``chanakya.contracts.tool_failure``);
#: earlier streams may hold free-form failure text. 1.4.0 (Phase 17) means
#: every ``error`` and ``investigation_halted`` event carries exactly a
#: closed-shape Runtime record (``chanakya.contracts.runtime_failure``) and
#: a provider-failure turn outcome records only ``PROVIDER_FAILURE`` as its
#: ``error_type``; earlier streams may hold exception text there.
AUDIT_EVENT_CONTRACT_VERSION = "1.4.0"
SUPPORTED_AUDIT_EVENT_VERSIONS = frozenset({"1.0.0", "1.1.0", "1.2.0", "1.3.0", AUDIT_EVENT_CONTRACT_VERSION})


def version_tuple(version: str) -> tuple:
    """``"1.2.0"`` -> ``(1, 2, 0)``, for ordering supported versions."""
    return tuple(int(part) for part in version.split("."))
AGENT_TURN_EVENT_TYPES = frozenset(
    {AuditEventType.AGENT_TURN_REQUESTED, AuditEventType.AGENT_TURN_RECEIVED, AuditEventType.AGENT_TURN_REJECTED}
)


class AuditSeverity(str, Enum):
    """docs/CONTRACTS.md §13 — AuditEvent.severity (optional)."""

    INFO = "info"
    WARNING = "warning"
    ERROR = "error"


@dataclass(frozen=True)
class AuditEvent:
    audit_event_id: str
    contract_version: str
    event_type: AuditEventType
    occurred_at: str
    actor: str
    related_ids: Mapping[str, str] = field(default_factory=dict)
    investigation_id: Optional[str] = None
    details: Optional[Mapping[str, Any]] = None
    severity: Optional[AuditSeverity] = None

    def __post_init__(self) -> None:
        if not self.actor:
            raise ValueError("AuditEvent.actor must be non-empty")
        if self.contract_version not in SUPPORTED_AUDIT_EVENT_VERSIONS:
            raise ValueError(f"unsupported AuditEvent.contract_version: {self.contract_version!r}")
        # docs/CONTRACTS.md §13: new event types only through a version bump.
        if self.event_type in AGENT_TURN_EVENT_TYPES and self.contract_version == "1.0.0":
            raise ValueError("agent turn event types require AuditEvent contract_version 1.1.0")
