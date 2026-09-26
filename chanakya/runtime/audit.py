"""Runtime audit emission boundary — docs/AGENT-RUNTIME.md §14.

The Agent Runtime is the sole producer of ``AuditEvent``s
(docs/ARCHITECTURE.md §14, docs/POLICY-GATEWAY.md §12) — the Policy
Gateway, the Approval mechanism, and a future Tool Layer never write to
the Audit Log directly; they only hand the Runtime what it needs. This
module is that emission point.

This is deliberately **not** the persistent, tamper-evident Audit Log
described in ``ARCHITECTURE.md`` §14/§10 (append-only storage with
content hashing) — that store does not exist yet (per
docs/PHASE-2-IMPLEMENTATION.md's "no Audit Log yet" limitation, carried
forward; Step 3.5's own scope explicitly excludes building one). Events
are handed to an injected ``AuditSink`` — ``NullAuditSink`` by default
(no side effects, safe for any caller that doesn't care about audit
output), or ``InMemoryAuditSink`` for tests/inspection.

Where this step's required event categories ("retry", "timeout") have no
dedicated ``event_type`` in ``docs/CONTRACTS.md`` §13's closed enum, they
are represented via ``details`` on the closest matching type
(``dispatch_failed``), per that contract's own explicit rule against
inventing ad hoc ``event_type`` strings — the same pattern already
flagged as an open item in docs/AGENT-RUNTIME.md.
"""
from __future__ import annotations

import uuid
from typing import Any, List, Mapping, Optional, Protocol

from chanakya.contracts.approval import ApprovalRequest
from chanakya.contracts.audit_event import AuditEvent, AuditEventType, AuditSeverity
from chanakya.contracts.policy_decision import PolicyDecision
from chanakya.contracts.risk_assessment import RiskAssessment
from chanakya.contracts.tool_result import ToolResult

from .clock import utcnow_iso
from .exceptions import AuditSinkError

_CONTRACT_VERSION = "1.0.0"


class AuditSink(Protocol):
    def emit(self, event: AuditEvent) -> None:
        ...


class NullAuditSink:
    """The default. Emits nothing; has no side effects."""

    def emit(self, event: AuditEvent) -> None:
        return None


class InMemoryAuditSink:
    """A test/inspection double — NOT the real Audit Log: no
    persistence, no append-only storage guarantee beyond this Python
    object's lifetime, no tamper-evidence."""

    def __init__(self) -> None:
        self.events: List[AuditEvent] = []

    def emit(self, event: AuditEvent) -> None:
        self.events.append(event)


class AuditEmitter:
    """Constructs well-formed ``AuditEvent`` records and forwards them to
    the injected sink. Each method corresponds to exactly one
    docs/CONTRACTS.md §13 ``event_type`` — see docs/AGENT-RUNTIME.md
    §14's trigger table."""

    def __init__(self, sink: Optional[AuditSink] = None, *, clock=utcnow_iso) -> None:
        self._sink = sink if sink is not None else NullAuditSink()
        self._clock = clock

    def _emit(
        self,
        event_type: AuditEventType,
        *,
        actor: str,
        investigation_id: Optional[str] = None,
        related_ids: Optional[Mapping[str, str]] = None,
        details: Optional[Mapping[str, Any]] = None,
        severity: Optional[AuditSeverity] = None,
    ) -> AuditEvent:
        event = AuditEvent(
            audit_event_id=str(uuid.uuid4()),
            contract_version=_CONTRACT_VERSION,
            event_type=event_type,
            occurred_at=self._clock(),
            actor=actor,
            investigation_id=investigation_id,
            related_ids=dict(related_ids) if related_ids else {},
            details=dict(details) if details else None,
            severity=severity,
        )
        try:
            self._sink.emit(event)
        except Exception as exc:
            # docs/AGENT-RUNTIME.md §11: an Audit Log write failure is
            # treated with the same severity as an Evidence write
            # failure — the caller (Agent Loop Controller) must halt
            # rather than let an unaudited action proceed. Wrapping the
            # sink's own exception in AuditSinkError is what lets the
            # caller distinguish "the audit sink itself is broken" from
            # any other unexpected Runtime error.
            raise AuditSinkError(f"AuditSink.emit failed: {exc}") from exc
        return event

    # -- investigation lifecycle (also usable by InvestigationManager) --

    def investigation_started(self, investigation_id: str, *, actor: str = "system") -> AuditEvent:
        return self._emit(
            AuditEventType.INVESTIGATION_STARTED,
            actor=actor,
            investigation_id=investigation_id,
            related_ids={"investigation_id": investigation_id},
        )

    def investigation_completed(self, investigation_id: str, *, actor: str = "system") -> AuditEvent:
        return self._emit(
            AuditEventType.INVESTIGATION_COMPLETED,
            actor=actor,
            investigation_id=investigation_id,
            related_ids={"investigation_id": investigation_id},
        )

    def investigation_halted(
        self, investigation_id: str, *, reason: str, details: Optional[Mapping[str, Any]] = None, actor: str = "system"
    ) -> AuditEvent:
        merged = {"reason": reason, **(dict(details) if details else {})}
        return self._emit(
            AuditEventType.INVESTIGATION_HALTED,
            actor=actor,
            investigation_id=investigation_id,
            related_ids={"investigation_id": investigation_id},
            details=merged,
            severity=AuditSeverity.WARNING,
        )

    def error(
        self,
        investigation_id: Optional[str],
        *,
        reason: str,
        details: Optional[Mapping[str, Any]] = None,
        actor: str = "system",
    ) -> AuditEvent:
        merged = {"reason": reason, **(dict(details) if details else {})}
        related_ids = {"investigation_id": investigation_id} if investigation_id else {}
        return self._emit(
            AuditEventType.ERROR,
            actor=actor,
            investigation_id=investigation_id,
            related_ids=related_ids,
            details=merged,
            severity=AuditSeverity.ERROR,
        )

    # -- per-step pipeline (Agent Loop Controller) ------------------------

    def request_proposed(self, investigation_id: str, tool_request_id: str, *, actor: str = "agent") -> AuditEvent:
        return self._emit(
            AuditEventType.REQUEST_PROPOSED,
            actor=actor,
            investigation_id=investigation_id,
            related_ids={"tool_request_id": tool_request_id},
        )

    def policy_evaluated(
        self, investigation_id: str, tool_request_id: str, decision: PolicyDecision, *, actor: str = "system"
    ) -> AuditEvent:
        return self._emit(
            AuditEventType.POLICY_EVALUATED,
            actor=actor,
            investigation_id=investigation_id,
            related_ids={"tool_request_id": tool_request_id, "policy_decision_id": decision.policy_decision_id},
            details={"verdict": decision.verdict.value, "matched_rule": decision.matched_rule, "reason": decision.reason},
            severity=AuditSeverity.INFO,
        )

    def approval_requested(self, approval_request: ApprovalRequest, *, actor: str = "system") -> AuditEvent:
        return self._emit(
            AuditEventType.APPROVAL_REQUESTED,
            actor=actor,
            investigation_id=approval_request.investigation_id,
            related_ids={
                "tool_request_id": approval_request.tool_request_id,
                "policy_decision_id": approval_request.policy_decision_id,
                "approval_request_id": approval_request.approval_request_id,
            },
        )

    def approval_decided(
        self,
        investigation_id: str,
        approval_request_id: str,
        *,
        outcome: str,
        actor: str,
        decided_by: Optional[str] = None,
        justification: Optional[str] = None,
    ) -> AuditEvent:
        details: dict = {"outcome": outcome}
        if decided_by is not None:
            details["decided_by"] = decided_by
        if justification is not None:
            details["justification"] = justification
        return self._emit(
            AuditEventType.APPROVAL_DECIDED,
            actor=actor,
            investigation_id=investigation_id,
            related_ids={"approval_request_id": approval_request_id},
            details=details,
        )

    def dispatch_started(self, investigation_id: str, tool_request_id: str, *, actor: str = "system") -> AuditEvent:
        return self._emit(
            AuditEventType.DISPATCH_STARTED,
            actor=actor,
            investigation_id=investigation_id,
            related_ids={"tool_request_id": tool_request_id},
        )

    def dispatch_completed(self, investigation_id: str, tool_result: ToolResult, *, actor: str = "system") -> AuditEvent:
        return self._emit(
            AuditEventType.DISPATCH_COMPLETED,
            actor=actor,
            investigation_id=investigation_id,
            related_ids={"tool_request_id": tool_result.tool_request_id, "tool_result_id": tool_result.tool_result_id},
            details={"status": tool_result.status.value},
        )

    def dispatch_failed(
        self,
        investigation_id: str,
        tool_result: ToolResult,
        *,
        retry_scheduled: bool,
        next_attempt_number: Optional[int] = None,
        reason: Optional[str] = None,
        actor: str = "system",
    ) -> AuditEvent:
        details: dict = {"status": tool_result.status.value, "retry_scheduled": retry_scheduled}
        if tool_result.error_message:
            details["error_message"] = tool_result.error_message
        if reason is not None:
            details["reason"] = reason
        if next_attempt_number is not None:
            details["next_attempt_number"] = next_attempt_number
        return self._emit(
            AuditEventType.DISPATCH_FAILED,
            actor=actor,
            investigation_id=investigation_id,
            related_ids={"tool_request_id": tool_result.tool_request_id, "tool_result_id": tool_result.tool_result_id},
            details=details,
            severity=AuditSeverity.WARNING,
        )

    def evidence_recorded(
        self, investigation_id: str, evidence_id: str, tool_result_id: str, *, actor: str = "system"
    ) -> AuditEvent:
        return self._emit(
            AuditEventType.EVIDENCE_RECORDED,
            actor=actor,
            investigation_id=investigation_id,
            related_ids={"evidence_id": evidence_id, "tool_result_id": tool_result_id},
        )

    def finding_created(
        self, investigation_id: str, finding_id: str, evidence_refs, *, actor: str = "agent"
    ) -> AuditEvent:
        """Phase 9. Records that a Finding was stored. Carries ids only,
        never the Finding's text (docs/CONTRACTS.md §13: reference, don't
        duplicate)."""
        return self._emit(
            AuditEventType.FINDING_CREATED,
            actor=actor,
            investigation_id=investigation_id,
            related_ids={"finding_id": finding_id},
            details={"evidence_refs": list(evidence_refs)},
        )

    def risk_assessed(self, investigation_id: str, risk_assessment: RiskAssessment, *, actor: str = "system") -> AuditEvent:
        """Phase 10. Records that a RiskAssessment was stored. The actor is
        ``system``: the rating comes from the deterministic Risk Engine, not
        the agent. Ids and enum values only; the rationale is never copied."""
        return self._emit(
            AuditEventType.RISK_ASSESSED,
            actor=actor,
            investigation_id=investigation_id,
            related_ids={
                "risk_assessment_id": risk_assessment.risk_assessment_id,
                "finding_id": risk_assessment.finding_id,
            },
            details={
                "evidence_refs": list(risk_assessment.evidence_refs),
                "severity": risk_assessment.severity.value,
                "confidence": risk_assessment.confidence,
                "scoring_method": risk_assessment.scoring_method,
                "rule_ids": list(risk_assessment.rule_ids),
            },
        )
