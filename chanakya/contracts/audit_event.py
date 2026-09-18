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
