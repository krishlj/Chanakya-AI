"""Read-only investigation review projection — Phase 12.

``InvestigationReview`` is what ``chanakya.review.reconstruct_investigation``
returns: a frozen, non-executable summary of one investigation rebuilt from
its durable artifacts. It is not a contract, carries no authority and is
never passed to the Runtime, the Policy Gateway, a provider or a tool.

Strings that came from the model or the target (objective, finding titles,
policy reasons) are included as data for display; a presenter must escape
them. Anomalies carry a fixed ``code`` and, at most, an identifier.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Optional, Tuple


class ReviewStatus(str, Enum):
    """How the durable record says the investigation ended."""

    COMPLETED = "completed"          # investigation_completed recorded
    HALTED = "halted"                # investigation_halted recorded
    FAILED = "failed"                # terminal `error` (investigation_status=failed) recorded
    INCOMPLETE = "incomplete"        # no terminal event: crashed, killed, or still running
    UNVERIFIABLE = "unverifiable"    # the audit chain failed verification
    NOT_FOUND = "not_found"          # no audit stream for this id


@dataclass(frozen=True)
class Anomaly:
    """A reconstruction or consistency problem. ``code`` is fixed; ``subject``
    is an identifier (never free text) or ``None``."""

    code: str
    subject: Optional[str] = None


@dataclass(frozen=True)
class Origin:
    investigation_request_id: str
    submitted_by: str
    submitted_at: str
    target_refs: Tuple[str, ...]
    objective: str


@dataclass(frozen=True)
class PolicyRecord:
    verdict: str
    matched_rule: str
    reason: str
    classification: Optional[str]
    risk_category: Optional[str]
    envelope_timeout_seconds: Optional[int]
    envelope_max_output_bytes: Optional[int]
    envelope_output_schema_hash: Optional[str]
    #: Phase 15: the Registry-declared egress in the envelope summary
    #: (AuditEvent 1.2.0+); None for older streams or a deny.
    envelope_model_egress: Optional[str] = None


@dataclass(frozen=True)
class ApprovalRecord:
    approval_request_id: str
    capability: str
    target_ref: str
    parameters_canonical: str
    expires_at: Optional[str]
    outcome: Optional[str] = None       # "accept" / "deny" / "expired" ..., None if never decided
    decided_by: Optional[str] = None


@dataclass(frozen=True)
class DispatchRecord:
    resolved_timeout_seconds: int
    max_output_bytes: int
    status: Optional[str] = None        # ToolResult status, None if no completion was recorded
    tool_result_id: Optional[str] = None
    error_message: Optional[str] = None


@dataclass(frozen=True)
class RequestRecord:
    """One proposed ToolRequest and everything recorded about it."""

    tool_request_id: str
    capability: str
    target_ref: str
    step_id: str
    attempt_number: int
    parameters_canonical: str
    parameters_hash: str
    policy: Optional[PolicyRecord] = None
    approval: Optional[ApprovalRecord] = None
    dispatch: Optional[DispatchRecord] = None
    evidence_id: Optional[str] = None


@dataclass(frozen=True)
class EvidenceRecord:
    evidence_id: str
    tool_result_id: str
    tool_request_id: str
    capability: str
    target_id: str
    verified: bool
    #: Phase 15: the screening policy version this record carries, or None.
    #: For a pre-1.2.0 stream, None means "predates Phase 15", never
    #: "screened and clean".
    screening_version: Optional[str] = None
    screening_required: bool = False


@dataclass(frozen=True)
class FindingRecord:
    finding_id: str
    title: str
    category: Optional[str]
    confidence: Optional[str]
    evidence_refs: Tuple[str, ...]


@dataclass(frozen=True)
class RiskRecord:
    risk_assessment_id: str
    finding_id: str
    severity: str
    confidence: str
    scoring_method: str


@dataclass(frozen=True)
class TurnRecord:
    """Phase 14: one model turn as recorded (manifest + outcome). Forensic
    data only; it carries no authority."""

    turn_id: str
    turn_sequence: int
    provider: str
    model: Optional[str]
    endpoint: Optional[str]
    config_version: Optional[str]
    declared: bool
    provider_request_hash: str
    instructions_hash: str
    context_sources: Tuple[str, ...]
    outcome: Optional[str] = None           # None if no outcome was recorded
    accepted: Optional[bool] = None
    stop_reason: Optional[str] = None
    proposed_capability: Optional[str] = None
    explanation_status: Optional[str] = None
    explanation: Optional[str] = None       # model-authored, screened; escape on display
    raw_output_hash: Optional[str] = None


@dataclass(frozen=True)
class InvestigationReview:
    investigation_id: str
    status: ReviewStatus
    terminal_reason: Optional[str] = None
    audit_verified: bool = False
    audit_record_count: int = 0
    origin: Optional[Origin] = None
    requests: Tuple[RequestRecord, ...] = ()
    evidence: Tuple[EvidenceRecord, ...] = ()
    findings: Tuple[FindingRecord, ...] = ()
    risk_assessments: Tuple[RiskRecord, ...] = ()
    #: Phase 14: model turns, in order (empty for pre-1.1.0 streams).
    turns: Tuple[TurnRecord, ...] = ()
    anomalies: Tuple[Anomaly, ...] = field(default_factory=tuple)

    @property
    def consistent(self) -> bool:
        """True only for a verified audit chain with no anomalies."""
        return self.audit_verified and not self.anomalies


__all__ = [
    "Anomaly",
    "ApprovalRecord",
    "DispatchRecord",
    "EvidenceRecord",
    "FindingRecord",
    "InvestigationReview",
    "Origin",
    "PolicyRecord",
    "RequestRecord",
    "ReviewStatus",
    "RiskRecord",
    "TurnRecord",
]
