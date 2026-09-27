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
from chanakya.contracts.audit_details import (
    AuditFactError,
    envelope_summary,
    request_details,
    risk_context_details,
    text_fact,
)
from chanakya.contracts.agent_turn import ContextManifest, TurnOutcomeRecord
from chanakya.contracts.audit_event import AUDIT_EVENT_CONTRACT_VERSION, AuditEvent, AuditEventType, AuditSeverity
from chanakya.contracts.policy_decision import PolicyDecision
from chanakya.contracts.risk_assessment import RiskAssessment
from chanakya.contracts.tool_request import ToolRequest
from chanakya.contracts.tool_result import ToolResult

from .clock import utcnow_iso
from .dispatch import DispatchInstruction
from .exceptions import AuditSinkError

#: Phase 14: every event is emitted under AuditEvent contract 1.1.0, the
#: version that introduced the agent turn event types (docs/CONTRACTS.md §13).
_CONTRACT_VERSION = AUDIT_EVENT_CONTRACT_VERSION


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


def _facts(build):
    """Builds Phase 12 durable facts. A fact that cannot be recorded safely
    (credential-shaped, too large, not serializable) is an audit write
    failure: ``AuditSinkError`` with a fixed code, so the existing Runtime
    backstop halts before the action proceeds (RT-INV-6)."""
    try:
        return build()
    except AuditFactError as exc:
        raise AuditSinkError(f"audit fact rejected: {exc.code} ({exc.field})") from None
    except (KeyError, TypeError, AttributeError):
        raise AuditSinkError("audit fact rejected: FACT_INVALID") from None


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

    def investigation_started(
        self, investigation_id: str, *, origin: Optional[Mapping[str, Any]] = None, actor: str = "system"
    ) -> AuditEvent:
        """Phase 12: ``origin`` is the ``investigation_started`` details built
        by ``chanakya.contracts.audit_details.origin_details`` (request id,
        requester, submission time, target scope, bounded objective)."""
        return self._emit(
            AuditEventType.INVESTIGATION_STARTED,
            actor=actor,
            investigation_id=investigation_id,
            related_ids={"investigation_id": investigation_id},
            details=dict(origin) if origin is not None else None,
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

    def request_proposed(
        self,
        investigation_id: str,
        tool_request_id: str,
        *,
        tool_request: Optional[ToolRequest] = None,
        step_id: Optional[str] = None,
        attempt_number: Optional[int] = None,
        actor: str = "agent",
    ) -> AuditEvent:
        """Phase 12: with ``tool_request``, records what was proposed:
        capability, target, the Runtime step and attempt, and the
        parameters as canonical JSON plus integrity hash (D-2)."""
        details = None
        if tool_request is not None:
            details = _facts(
                lambda: request_details(
                    capability=tool_request.capability,
                    target_ref=tool_request.target_ref,
                    step_id=step_id,
                    attempt_number=attempt_number,
                    parameters=tool_request.parameters,
                )
            )
        return self._emit(
            AuditEventType.REQUEST_PROPOSED,
            actor=actor,
            investigation_id=investigation_id,
            related_ids={"tool_request_id": tool_request_id},
            details=details,
        )

    def policy_evaluated(
        self,
        investigation_id: str,
        tool_request_id: str,
        decision: PolicyDecision,
        *,
        tool_request: Optional[ToolRequest] = None,
        actor: str = "system",
    ) -> AuditEvent:
        """Phase 12: with ``tool_request``, also records the capability and
        target the decision covers, the Registry classification and risk
        category snapshots, and a summary of the authorized envelope
        (limits plus output-schema hash). Facts only; this record never
        authorizes anything."""
        details: dict = {"verdict": decision.verdict.value, "matched_rule": decision.matched_rule, "reason": decision.reason}
        if tool_request is not None:
            details.update(
                _facts(
                    lambda: {
                        "capability": text_fact("capability", tool_request.capability),
                        "target_ref": text_fact("target_ref", tool_request.target_ref),
                        "classification": decision.classification.value if decision.classification else None,
                        "risk_category": decision.risk_category.value if decision.risk_category else None,
                        "envelope": envelope_summary(decision.capability_envelope),
                    }
                )
            )
        return self._emit(
            AuditEventType.POLICY_EVALUATED,
            actor=actor,
            investigation_id=investigation_id,
            related_ids={"tool_request_id": tool_request_id, "policy_decision_id": decision.policy_decision_id},
            details=details,
            severity=AuditSeverity.INFO,
        )

    def approval_requested(
        self, approval_request: ApprovalRequest, *, step_id: Optional[str] = None, actor: str = "system"
    ) -> AuditEvent:
        """Phase 12: with ``step_id``, records what the approver was asked
        to approve: the ``risk_context`` facts (capability, target,
        canonical parameters and hash) and ``expires_at``."""
        details = None
        if step_id is not None:
            details = _facts(
                lambda: {
                    "step_id": text_fact("step_id", step_id),
                    "expires_at": text_fact("expires_at", approval_request.expires_at, optional=True),
                    "risk_context": risk_context_details(approval_request.risk_context),
                }
            )
        return self._emit(
            AuditEventType.APPROVAL_REQUESTED,
            actor=actor,
            investigation_id=approval_request.investigation_id,
            related_ids={
                "tool_request_id": approval_request.tool_request_id,
                "policy_decision_id": approval_request.policy_decision_id,
                "approval_request_id": approval_request.approval_request_id,
            },
            details=details,
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

    def dispatch_started(
        self,
        investigation_id: str,
        tool_request_id: str,
        *,
        instruction: Optional[DispatchInstruction] = None,
        step_id: Optional[str] = None,
        actor: str = "system",
    ) -> AuditEvent:
        """Phase 12: with ``instruction``, records what is about to run,
        taken from the ``DispatchInstruction`` itself so the record cannot
        claim a different envelope: capability, target, step, attempt,
        resolved timeout and output limit, and the authorizing decision."""
        details = None
        if instruction is not None:
            details = _facts(
                lambda: {
                    "capability": text_fact("capability", instruction.capability),
                    "target_ref": text_fact("target_ref", instruction.target_ref),
                    "step_id": text_fact("step_id", step_id),
                    "attempt_number": instruction.attempt_number,
                    "resolved_timeout_seconds": instruction.resolved_timeout_seconds,
                    "max_output_bytes": instruction.resolved_resource_limits["max_output_bytes"],
                    "policy_decision_id": text_fact("policy_decision_id", instruction.policy_decision_id),
                }
            )
        return self._emit(
            AuditEventType.DISPATCH_STARTED,
            actor=actor,
            investigation_id=investigation_id,
            related_ids={"tool_request_id": tool_request_id},
            details=details,
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

    # -- Phase 14: forensic model-turn records (docs/CONTRACTS.md §14) ------

    def agent_turn_requested(self, investigation_id: str, manifest: ContextManifest, *, actor: str = "system") -> AuditEvent:
        """The context manifest, durable BEFORE the provider is called
        (CT-INV-1). A fact that cannot be recorded safely is an audit write
        failure, so the provider is never called."""
        details = _facts(manifest.to_details)
        return self._emit(
            AuditEventType.AGENT_TURN_REQUESTED,
            actor=actor,
            investigation_id=investigation_id,
            related_ids={"agent_turn_id": details["turn_id"]},
            details=details,
        )

    def agent_turn_outcome(self, investigation_id: str, record: TurnOutcomeRecord, *, actor: str = "agent") -> AuditEvent:
        """Exactly one per requested turn: ``agent_turn_received`` when the
        Runtime accepted the output, ``agent_turn_rejected`` otherwise
        (including provider failure). Durable BEFORE any accepted output is
        used (CT-INV-1). Forensic only; it authorizes nothing (CT-INV-5)."""
        details = _facts(record.to_details)
        return self._emit(
            AuditEventType.AGENT_TURN_RECEIVED if record.accepted else AuditEventType.AGENT_TURN_REJECTED,
            actor=actor,
            investigation_id=investigation_id,
            related_ids={"agent_turn_id": details["turn_id"]},
            details=details,
            severity=None if record.accepted else AuditSeverity.WARNING,
        )
