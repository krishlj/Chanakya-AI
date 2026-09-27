"""Investigation reconstruction and verification — Phase 12.

``reconstruct_investigation`` rebuilds one investigation from durable
artifacts only, and reports what does not add up. It is strictly read-only:
it calls only read APIs (``list_by_investigation``, ``exists``,
``verify_in_investigation``) and the pure ``risk_engine.assess``. It never
writes, repairs, executes, authorizes, approves, calls a model or resumes
anything, and its result is never fed back into the Runtime.

What it checks:

1. **Audit chain.** ``audit_log.list_by_investigation`` re-verifies every
   record hash, every ``previous_record_hash`` link, contiguous sequence
   numbers, record and event shape, and stream ownership. Any failure makes
   the review ``UNVERIFIABLE``, and nothing else is reported as fact.
2. **Authorization history.** Events are replayed in order. Phase 12
   ``details`` are validated against ``chanakya.contracts.audit_details``
   (closed key sets; parameters re-hashed). A decision, approval or
   dispatch that does not follow from the recorded history is an anomaly,
   for example a dispatch with no allow or accepted approval, or an
   approval with no ``require_approval`` decision.
3. **Cross-store consistency.** Audit ↔ Evidence ↔ Findings ↔
   RiskAssessments, each store read with its own verification. Covers
   orphans in both directions, cross-investigation references, and risk
   recomputation with the deterministic engine.
4. **Terminal state.** ``COMPLETED``/``HALTED``/``FAILED`` only when the
   matching terminal event is recorded; otherwise ``INCOMPLETE``. A missing
   terminal event is never reported as a completion.
5. **Model influence (Phase 14, CT-INV-6).** For streams written under
   AuditEvent contract 1.1.0, every model turn must be a manifest
   (``agent_turn_requested``) followed by exactly one outcome
   (``agent_turn_received``/``agent_turn_rejected``), with contiguous
   sequences and deterministic ids. Review recomputes the instruction and
   objective hashes from the recorded origin, checks the provider identity
   and endpoint never change, resolves every context entry to a tool result
   this investigation recorded *earlier* (and, for Evidence, re-hashes the
   verified payload), and requires every proposed request, finding and
   completion to follow an accepted turn that produced it. Turn records are
   forensic; Review never treats them as authority.
6. **Sensitive-data screening and egress (Phase 15, NX-INV-3/4).** For
   streams written under AuditEvent 1.2.0, every Evidence record must carry
   the screening marker (``screening_version``, ``redactions_applied=False``)
   and its payload must still pass the same screen; every model context
   entry must name the capability that produced it and an ``allowed``
   egress that matches the ``policy_evaluated`` envelope summary. Older
   streams are reported as predating the control, never as screened.
7. **Versions.** The Runtime writes one ``contract_version`` per stream. A
   stream with several is flagged (``mixed_contract_versions``) and judged
   by the strictest (highest) version it contains, so downgrading the first
   event cannot relax any check.

Anomalies are fixed codes plus, at most, an identifier.
"""
from __future__ import annotations

from typing import Any, Dict, List, Optional

from chanakya.audit.log import CorruptAuditLogError, InvalidAuditIdentifierError
from chanakya.contracts.agent_turn import (
    INSTRUCTIONS_TEMPLATE_VERSION,
    SOURCE_KIND_EVIDENCE,
    derive_agent_turn_id,
    hash_json_normalized,
    hash_value,
    provider_identity_from_details,
    render_instructions,
    validate_turn_details,
)
from chanakya.contracts.audit_details import validate_details
from chanakya.contracts.audit_event import version_tuple
from chanakya.contracts.tool_output_screening import (
    is_supported_screening_version,
    screen_tool_output,
)
from chanakya.evidence.store import EvidenceStoreError
from chanakya.findings.store import FindingStoreError

from .models import (
    Anomaly,
    ApprovalRecord,
    DispatchRecord,
    EvidenceRecord,
    FindingRecord,
    InvestigationReview,
    Origin,
    PolicyRecord,
    RequestRecord,
    ReviewStatus,
    RiskRecord,
    TurnRecord,
)

_REVIEW_ASSESSED_AT = "review"
_RISK_COMPARED = (
    "risk_assessment_id", "investigation_id", "finding_refs", "evidence_refs", "severity", "confidence",
    "scoring_method", "rule_ids", "assessed_by", "rationale",
)


class _Builder:
    def __init__(self, investigation_id: str) -> None:
        self.investigation_id = investigation_id
        self.anomalies: List[Anomaly] = []
        self.origin: Optional[Origin] = None
        self.requests: Dict[str, Dict[str, Any]] = {}
        self.approvals: Dict[str, str] = {}
        self.results: Dict[str, str] = {}
        self.evidence_events: Dict[str, str] = {}
        self.finding_events: Dict[str, Any] = {}
        self.risk_events: Dict[str, Optional[str]] = {}
        self.risk_methods: Dict[str, Optional[str]] = {}
        self.terminal: Optional[ReviewStatus] = None
        self.terminal_reason: Optional[str] = None
        # Phase 14: model-turn replay state.
        self.turn_era = False
        self.egress_era = False
        self.turns: Dict[str, Dict[str, Any]] = {}
        self.pending_turn: Optional[str] = None
        self.last_turn_sequence = 0
        self.turn_identity: Any = None
        self.expect_capability: Optional[str] = None
        self.expect_findings = 0
        self.accepted_conclusion = False
        self.context_evidence: List[Any] = []

    def flag(self, code: str, subject: Optional[str] = None) -> None:
        self.anomalies.append(Anomaly(code, subject if isinstance(subject, str) else None))

    # -- event replay ---------------------------------------------------

    def set_versions(self, records) -> None:
        """Phase 15: one version per stream. Mixed versions are an anomaly,
        and the strictest (highest) version present decides which records
        are required: turn records from 1.1.0, egress and screening
        provenance from 1.2.0."""
        versions = set()
        for record in records:
            try:
                versions.add(version_tuple(record.event.contract_version))
            except (TypeError, ValueError, AttributeError):
                self.flag("contract_version_invalid")
        if len(versions) > 1:
            self.flag("mixed_contract_versions")
        strictest = max(versions) if versions else (1, 0, 0)
        self.turn_era = strictest >= (1, 1, 0)
        self.egress_era = strictest >= (1, 2, 0)

    def replay(self, records) -> None:
        for index, record in enumerate(records):
            event = record.event
            kind = event.event_type.value
            ids = event.related_ids if isinstance(event.related_ids, dict) else {}
            details = event.details
            if self.terminal is not None:
                self.flag("event_after_terminal", event.audit_event_id)
            if index == 0 and kind != "investigation_started":
                self.flag("stream_missing_investigation_started")
            handler = getattr(self, f"_on_{kind}", None)
            if handler is not None:
                handler(index, ids, details)

    def _details_ok(self, kind: str, details: Any, subject: Optional[str]) -> bool:
        problems = validate_details(kind, details, egress_recorded=self.egress_era)
        for code in problems:
            self.flag(code, subject)
        return not problems

    def _on_investigation_started(self, index, ids, details) -> None:
        if index != 0:
            self.flag("duplicate_investigation_started")
            return
        if self._details_ok("investigation_started", details, self.investigation_id):
            self.origin = Origin(
                investigation_request_id=details["investigation_request_id"],
                submitted_by=details["submitted_by"],
                submitted_at=details["submitted_at"],
                target_refs=tuple(details["target_refs"]),
                objective=details["objective"],
            )

    def _on_request_proposed(self, index, ids, details) -> None:
        tid = ids.get("tool_request_id")
        if self.turn_era:
            capability = details.get("capability") if isinstance(details, dict) else None
            if self.pending_turn is not None:
                self.flag("turn_order_invalid", tid)
            elif self.expect_capability is None:
                self.flag("request_without_accepted_turn", tid)
            elif capability != self.expect_capability:
                self.flag("turn_request_mismatch", tid)
        if not self._details_ok("request_proposed", details, tid):
            return
        if tid in self.requests:
            self.flag("duplicate_request", tid)
            return
        self.requests[tid] = dict(
            tool_request_id=tid,
            capability=details["capability"],
            target_ref=details["target_ref"],
            step_id=details["step_id"],
            attempt_number=details["attempt_number"],
            parameters_canonical=details["parameters_canonical"],
            parameters_hash=details["parameters_hash"],
            policy=None, policy_decision_id=None, approval=None, dispatch=None, evidence_id=None,
        )

    def _on_policy_evaluated(self, index, ids, details) -> None:
        tid = ids.get("tool_request_id")
        request = self.requests.get(tid)
        if request is None:
            self.flag("policy_without_request", tid)
            return
        if not self._details_ok("policy_evaluated", details, tid):
            return
        if request["policy"] is not None:
            self.flag("duplicate_policy_decision", tid)
            return
        if details["capability"] != request["capability"] or details["target_ref"] != request["target_ref"]:
            self.flag("policy_request_mismatch", tid)
        envelope = details["envelope"]
        if details["verdict"] != "deny" and envelope is None:
            self.flag("authorization_without_envelope", tid)
        if envelope is not None and envelope["capability"] != request["capability"]:
            self.flag("envelope_capability_mismatch", tid)
        request["policy"] = PolicyRecord(
            verdict=details["verdict"],
            matched_rule=details["matched_rule"],
            reason=details["reason"] if isinstance(details["reason"], str) else "",
            classification=details["classification"],
            risk_category=details["risk_category"],
            envelope_timeout_seconds=envelope["timeout_seconds"] if envelope else None,
            envelope_max_output_bytes=envelope["max_output_bytes"] if envelope else None,
            envelope_output_schema_hash=envelope["output_schema_hash"] if envelope else None,
            envelope_model_egress=envelope.get("model_egress") if envelope else None,
        )
        request["policy_decision_id"] = ids.get("policy_decision_id")

    def _on_approval_requested(self, index, ids, details) -> None:
        tid, arid = ids.get("tool_request_id"), ids.get("approval_request_id")
        request = self.requests.get(tid)
        if request is None or request["policy"] is None or request["policy"].verdict != "require_approval":
            self.flag("approval_without_require_approval", arid or tid)
            return
        if ids.get("policy_decision_id") != request["policy_decision_id"]:
            self.flag("approval_policy_mismatch", arid)
        if not self._details_ok("approval_requested", details, arid):
            return
        context = details["risk_context"]
        if (
            context["capability"] != request["capability"]
            or context["target_ref"] != request["target_ref"]
            or context["parameters_hash"] != request["parameters_hash"]
        ):
            self.flag("approval_context_mismatch", arid)
        request["approval"] = dict(
            approval_request_id=arid, capability=context["capability"], target_ref=context["target_ref"],
            parameters_canonical=context["parameters_canonical"], expires_at=details["expires_at"],
            outcome=None, decided_by=None,
        )
        self.approvals[arid] = tid

    def _on_approval_decided(self, index, ids, details) -> None:
        arid = ids.get("approval_request_id")
        tid = self.approvals.get(arid)
        if tid is None:
            self.flag("approval_decision_without_request", arid)
            return
        approval = self.requests[tid]["approval"]
        if approval["outcome"] is not None:
            self.flag("duplicate_approval_decision", arid)
            return
        details = details if isinstance(details, dict) else {}
        approval["outcome"] = details.get("outcome") if isinstance(details.get("outcome"), str) else "unknown"
        approval["decided_by"] = details.get("decided_by") if isinstance(details.get("decided_by"), str) else None

    def _on_dispatch_started(self, index, ids, details) -> None:
        tid = ids.get("tool_request_id")
        request = self.requests.get(tid)
        if request is None:
            self.flag("dispatch_without_request", tid)
            return
        if not self._details_ok("dispatch_started", details, tid):
            return
        policy, approval = request["policy"], request["approval"]
        authorized = policy is not None and (
            policy.verdict == "allow"
            or (policy.verdict == "require_approval" and approval is not None and approval["outcome"] == "accept")
        )
        if not authorized:
            self.flag("dispatch_without_authorization", tid)
        if (
            details["capability"] != request["capability"]
            or details["target_ref"] != request["target_ref"]
            or details["step_id"] != request["step_id"]
            or details["policy_decision_id"] != request["policy_decision_id"]
        ):
            self.flag("dispatch_request_mismatch", tid)
        if policy is not None and policy.envelope_timeout_seconds is not None and (
            details["resolved_timeout_seconds"] > policy.envelope_timeout_seconds
            or details["max_output_bytes"] != policy.envelope_max_output_bytes
        ):
            self.flag("dispatch_envelope_mismatch", tid)
        if request["dispatch"] is not None:
            self.flag("duplicate_dispatch", tid)
            return
        request["dispatch"] = dict(
            resolved_timeout_seconds=details["resolved_timeout_seconds"],
            max_output_bytes=details["max_output_bytes"], status=None, tool_result_id=None, error_message=None,
        )

    def _on_dispatch_result(self, ids, details, failed: bool) -> None:
        tid = ids.get("tool_request_id")
        request = self.requests.get(tid)
        if request is None or request["dispatch"] is None:
            self.flag("dispatch_result_without_dispatch", tid)
            return
        details = details if isinstance(details, dict) else {}
        dispatch = request["dispatch"]
        trid = ids.get("tool_result_id")
        dispatch["tool_result_id"] = trid
        dispatch["status"] = details.get("status") if isinstance(details.get("status"), str) else None
        if failed and isinstance(details.get("error_message"), str):
            dispatch["error_message"] = details["error_message"]
        if isinstance(trid, str):
            self.results[trid] = tid

    def _on_dispatch_completed(self, index, ids, details) -> None:
        self._on_dispatch_result(ids, details, failed=False)

    def _on_dispatch_failed(self, index, ids, details) -> None:
        self._on_dispatch_result(ids, details, failed=True)

    def _on_evidence_recorded(self, index, ids, details) -> None:
        evid, trid = ids.get("evidence_id"), ids.get("tool_result_id")
        tid = self.results.get(trid)
        if tid is None:
            self.flag("evidence_without_dispatch", evid)
        else:
            self.requests[tid]["evidence_id"] = evid
        if isinstance(evid, str):
            self.evidence_events[evid] = trid

    def _on_finding_created(self, index, ids, details) -> None:
        fid = ids.get("finding_id")
        if self.turn_era:
            if self.pending_turn is not None or not self.accepted_conclusion or self.expect_findings <= 0:
                self.flag("finding_without_accepted_turn", fid)
            else:
                self.expect_findings -= 1
        if isinstance(fid, str):
            refs = details.get("evidence_refs") if isinstance(details, dict) else None
            self.finding_events[fid] = tuple(refs) if isinstance(refs, list) else None

    def _on_risk_assessed(self, index, ids, details) -> None:
        raid = ids.get("risk_assessment_id")
        if isinstance(raid, str):
            self.risk_events[raid] = ids.get("finding_id")
            method = details.get("scoring_method") if isinstance(details, dict) else None
            self.risk_methods[raid] = method if isinstance(method, str) else None

    def _on_investigation_completed(self, index, ids, details) -> None:
        if self.turn_era and (self.pending_turn is not None or not self.accepted_conclusion):
            self.flag("completion_without_accepted_turn")
        self._set_terminal(ReviewStatus.COMPLETED, None)

    # -- Phase 14: model turns ---------------------------------------------

    def _turn_details_ok(self, kind: str, details: Any, subject: Optional[str]) -> bool:
        if not self.turn_era:
            self.flag("turn_event_unsupported_version", subject)
            return False
        problems = validate_turn_details(kind, details, egress_recorded=self.egress_era)
        for code in problems:
            self.flag(code, subject)
        return not problems

    def _on_agent_turn_requested(self, index, ids, details) -> None:
        subject = ids.get("agent_turn_id")
        if not self._turn_details_ok("agent_turn_requested", details, subject):
            return
        turn_id, sequence = details["turn_id"], details["turn_sequence"]
        if subject != turn_id or derive_agent_turn_id(self.investigation_id, sequence) != turn_id:
            self.flag("turn_id_mismatch", turn_id)
        if self.pending_turn is not None:
            self.flag("turn_outcome_missing", self.pending_turn)
            self.pending_turn = None
        if turn_id in self.turns or sequence <= self.last_turn_sequence:
            self.flag("duplicate_turn_record", turn_id)
            return
        if sequence != self.last_turn_sequence + 1:
            self.flag("turn_sequence_gap", turn_id)
        self.last_turn_sequence = sequence
        identity = provider_identity_from_details(details)
        if self.turn_identity is None:
            self.turn_identity = identity
        else:
            first = self.turn_identity
            if identity.endpoint != first.endpoint:
                self.flag("turn_endpoint_mismatch", turn_id)
            if (identity.provider, identity.model, identity.config_version, identity.declared,
                    identity.timeout_seconds, identity.max_tokens) != (
                    first.provider, first.model, first.config_version, first.declared,
                    first.timeout_seconds, first.max_tokens):
                self.flag("turn_provider_mismatch", turn_id)
        if details["template_version"] != INSTRUCTIONS_TEMPLATE_VERSION:
            self.flag("turn_template_unknown", turn_id)
        elif self.origin is not None:
            instructions = render_instructions(self.origin.objective, self.investigation_id)
            if hash_value(instructions) != details["instructions_hash"]:
                self.flag("turn_instructions_mismatch", turn_id)
            if hash_value(self.origin.objective) != details["objective_hash"]:
                self.flag("turn_objective_mismatch", turn_id)
        self._check_turn_context(turn_id, details["context_entries"])
        self.turns[turn_id] = dict(
            turn_id=turn_id, turn_sequence=sequence, provider=identity.provider, model=identity.model,
            endpoint=identity.endpoint, config_version=identity.config_version, declared=identity.declared,
            provider_request_hash=details["provider_request_hash"], instructions_hash=details["instructions_hash"],
            context_sources=tuple(entry["source"] for entry in details["context_entries"]),
            outcome=None, accepted=None, stop_reason=None, proposed_capability=None,
            explanation_status=None, explanation=None, raw_output_hash=None,
        )
        self.pending_turn = turn_id
        self.expect_capability, self.expect_findings, self.accepted_conclusion = None, 0, False

    def _check_turn_context(self, turn_id: str, entries) -> None:
        """Every entry must name a tool result this investigation recorded
        before this turn, from the same step, with the same content."""
        seen = set()
        for entry in entries:
            result_id = entry["tool_result_id"]
            if result_id in seen:
                self.flag("turn_context_duplicate_source", turn_id)
            seen.add(result_id)
            request = self.requests.get(self.results.get(result_id, ""))
            if request is None:
                self.flag("turn_context_foreign_source", turn_id)
                continue
            if entry["step_id"] != request["step_id"]:
                self.flag("turn_context_step_mismatch", turn_id)
            if self.egress_era:
                # Phase 15 (NX-INV-3): the data came from this capability,
                # which the Registry (as recorded in the authorizing
                # decision's envelope) declared egress-allowed.
                policy = request["policy"]
                declared = policy.envelope_model_egress if policy is not None else None
                if entry["capability"] != request["capability"]:
                    self.flag("turn_context_capability_mismatch", turn_id)
                if entry["model_egress"] != "allowed":
                    self.flag("turn_context_egress_not_allowed", turn_id)
                if declared != entry["model_egress"]:
                    self.flag("turn_context_egress_mismatch", turn_id)
            dispatch = request["dispatch"] or {}
            if entry["source_kind"] == SOURCE_KIND_EVIDENCE:
                if request["evidence_id"] != entry["evidence_id"]:
                    self.flag("turn_context_evidence_mismatch", turn_id)
                else:
                    self.context_evidence.append((turn_id, entry["evidence_id"], entry["content_hash"]))
            elif dispatch.get("status") in (None, "success") or not isinstance(dispatch.get("error_message"), str):
                self.flag("turn_context_source_mismatch", turn_id)
            elif hash_json_normalized(dispatch["error_message"]) != entry["content_hash"]:
                self.flag("turn_context_hash_mismatch", turn_id)

    def _on_turn_outcome(self, kind: str, ids, details) -> None:
        subject = ids.get("agent_turn_id")
        if not self._turn_details_ok(kind, details, subject):
            if subject is not None and subject == self.pending_turn:
                self.pending_turn = None
            return
        turn_id = details["turn_id"]
        turn = self.turns.get(turn_id)
        if turn is None or subject != turn_id:
            self.flag("turn_outcome_without_manifest", turn_id)
            return
        if turn["outcome"] is not None:
            self.flag("duplicate_turn_record", turn_id)
            return
        if self.pending_turn != turn_id:
            self.flag("turn_order_invalid", turn_id)
        if details["turn_sequence"] != turn["turn_sequence"]:
            self.flag("turn_id_mismatch", turn_id)
        if details["provider_request_hash"] != turn["provider_request_hash"]:
            self.flag("turn_request_hash_mismatch", turn_id)
        turn.update(
            outcome=details["outcome"], accepted=details["accepted"], stop_reason=details["stop_reason"],
            proposed_capability=details["proposed_capability"], explanation_status=details["explanation_status"],
            explanation=details["explanation"], raw_output_hash=details["raw_output_hash"],
        )
        self.pending_turn = None
        if details["outcome"] == "tool_request":
            self.expect_capability = details["proposed_capability"]
        elif details["outcome"] == "findings":
            self.expect_findings, self.accepted_conclusion = details["findings_count"], True
        elif details["outcome"] == "conclusion":
            self.accepted_conclusion = True

    def _on_agent_turn_received(self, index, ids, details) -> None:
        self._on_turn_outcome("agent_turn_received", ids, details)

    def _on_agent_turn_rejected(self, index, ids, details) -> None:
        self._on_turn_outcome("agent_turn_rejected", ids, details)

    def _on_investigation_halted(self, index, ids, details) -> None:
        reason = details.get("reason") if isinstance(details, dict) else None
        self._set_terminal(ReviewStatus.HALTED, reason if isinstance(reason, str) else None)

    def _on_error(self, index, ids, details) -> None:
        # Only InvestigationManager.fail marks its `error` as terminal; the
        # fail-closed backstop's `error` events are not a terminal state.
        if isinstance(details, dict) and details.get("investigation_status") == "failed":
            reason = details.get("reason")
            self._set_terminal(ReviewStatus.FAILED, reason if isinstance(reason, str) else None)

    def _set_terminal(self, status: ReviewStatus, reason: Optional[str]) -> None:
        if self.terminal is not None:
            self.flag("duplicate_terminal_event")
            return
        self.terminal, self.terminal_reason = status, reason


def reconstruct_investigation(
    investigation_id: str,
    *,
    audit_log: Any,
    evidence_store: Any,
    finding_store: Any,
    risk_store: Any,
    risk_engine: Any,
) -> InvestigationReview:
    """Read-only reconstruction of one investigation; see module docstring."""
    try:
        records = audit_log.list_by_investigation(investigation_id)
    except InvalidAuditIdentifierError:
        return InvestigationReview(
            investigation_id=str(investigation_id)[:128], status=ReviewStatus.UNVERIFIABLE,
            anomalies=(Anomaly("invalid_investigation_id"),),
        )
    except CorruptAuditLogError:
        # Fail closed: nothing from an unverifiable chain is reported as fact.
        return InvestigationReview(
            investigation_id=investigation_id, status=ReviewStatus.UNVERIFIABLE,
            anomalies=(Anomaly("audit_chain_invalid"),),
        )

    builder = _Builder(investigation_id)
    builder.set_versions(records)
    builder.replay(records)
    if builder.pending_turn is not None:
        builder.flag("turn_outcome_missing", builder.pending_turn)
    if not records:
        status = ReviewStatus.NOT_FOUND
        builder.flag("no_audit_history")
    elif builder.terminal is None:
        status = ReviewStatus.INCOMPLETE
        builder.flag("no_terminal_event")
        for request in builder.requests.values():
            if request["dispatch"] is not None and request["dispatch"]["status"] is None:
                builder.flag("dispatch_without_result", request["tool_request_id"])
    else:
        status = builder.terminal

    evidence = _check_evidence(builder, evidence_store)
    findings, stored_findings = _check_findings(
        builder, finding_store, evidence_store, {e.evidence_id for e in evidence}
    )
    risks = _check_risk(builder, risk_store, risk_engine, stored_findings)
    _check_turn_evidence(builder, evidence_store)

    return InvestigationReview(
        investigation_id=investigation_id,
        status=status,
        terminal_reason=builder.terminal_reason,
        audit_verified=True,
        audit_record_count=len(records),
        origin=builder.origin,
        requests=tuple(_freeze_request(r) for r in builder.requests.values()),
        evidence=evidence,
        findings=findings,
        risk_assessments=risks,
        turns=tuple(TurnRecord(**turn) for turn in builder.turns.values()),
        anomalies=tuple(builder.anomalies),
    )


def _check_turn_evidence(builder: _Builder, evidence_store: Any) -> None:
    """Phase 14 (CT-INV-6): an Evidence-backed context entry must hash to the
    verified payload output of that Evidence in this investigation."""
    for turn_id, evidence_id, content_hash in builder.context_evidence:
        try:
            evidence_store.verify_in_investigation(builder.investigation_id, evidence_id)
            payload = evidence_store.get_payload(evidence_id)
        except EvidenceStoreError:
            builder.flag("turn_context_evidence_missing", turn_id)
            continue
        if not isinstance(payload, dict) or hash_json_normalized(payload.get("output")) != content_hash:
            builder.flag("turn_context_hash_mismatch", turn_id)


def _freeze_request(request: Dict[str, Any]) -> RequestRecord:
    approval, dispatch = request["approval"], request["dispatch"]
    return RequestRecord(
        tool_request_id=request["tool_request_id"],
        capability=request["capability"],
        target_ref=request["target_ref"],
        step_id=request["step_id"],
        attempt_number=request["attempt_number"],
        parameters_canonical=request["parameters_canonical"],
        parameters_hash=request["parameters_hash"],
        policy=request["policy"],
        approval=ApprovalRecord(**approval) if approval is not None else None,
        dispatch=DispatchRecord(**dispatch) if dispatch is not None else None,
        evidence_id=request["evidence_id"],
    )


def _exists_elsewhere(evidence_store: Any, evidence_id: str) -> bool:
    try:
        return bool(evidence_store.exists(evidence_id))
    except EvidenceStoreError:
        return False


def _check_evidence(builder: _Builder, evidence_store: Any):
    try:
        stored = evidence_store.list_by_investigation(builder.investigation_id)
    except EvidenceStoreError:
        builder.flag("evidence_store_unverifiable")
        return ()
    by_id = {e.evidence_id: e for e in stored}
    verified_ids = set()
    for evidence_id, tool_result_id in builder.evidence_events.items():
        record = by_id.get(evidence_id)
        if record is None:
            code = "evidence_foreign_investigation" if _exists_elsewhere(evidence_store, evidence_id) else "evidence_missing"
            builder.flag(code, evidence_id)
            continue
        if record.tool_result_id != tool_result_id:
            builder.flag("evidence_result_mismatch", evidence_id)
        request = builder.requests.get(builder.results.get(tool_result_id, ""))
        if request is not None and (
            record.tool_request_id != request["tool_request_id"]
            or record.capability != request["capability"]
            or record.target_id != request["target_ref"]
        ):
            builder.flag("evidence_request_mismatch", evidence_id)
        try:
            evidence_store.verify_in_investigation(builder.investigation_id, evidence_id)
            verified_ids.add(evidence_id)
        except EvidenceStoreError:
            builder.flag("evidence_unverifiable", evidence_id)
            continue
        if builder.egress_era:
            _check_screening(builder, evidence_store, record)
    for evidence_id in by_id:
        if evidence_id not in builder.evidence_events:
            builder.flag("orphan_evidence", evidence_id)
    return tuple(
        EvidenceRecord(
            evidence_id=e.evidence_id, tool_result_id=e.tool_result_id, tool_request_id=e.tool_request_id,
            capability=e.capability, target_id=e.target_id, verified=e.evidence_id in verified_ids,
            screening_version=e.screening_version, screening_required=builder.egress_era,
        )
        for e in stored
    )


def _check_screening(builder: _Builder, evidence_store: Any, record: Any) -> None:
    """Phase 15 (NX-INV-4): 1.2.0-era Evidence must carry the screening
    marker, must not claim redaction, and its payload must still pass the
    same screen (a forged marker on unscreened content is caught here).
    Reports fixed codes only; never repairs."""
    evidence_id = record.evidence_id
    if record.screening_version is None:
        builder.flag("evidence_screening_missing", evidence_id)
        return
    if not is_supported_screening_version(record.screening_version) or record.redactions_applied is not False:
        builder.flag("evidence_screening_invalid", evidence_id)
        return
    try:
        payload = evidence_store.get_payload(evidence_id)
    except EvidenceStoreError:
        builder.flag("evidence_unverifiable", evidence_id)
        return
    if screen_tool_output(payload if payload is not None else {}) is not None:
        builder.flag("evidence_screening_inconsistent", evidence_id)


def _check_findings(builder: _Builder, finding_store: Any, evidence_store: Any, scoped_evidence: set):
    try:
        stored = finding_store.list_by_investigation(builder.investigation_id)
    except FindingStoreError:
        builder.flag("finding_store_unverifiable")
        return (), None
    for finding in stored:
        fid = finding.finding_id
        if fid not in builder.finding_events:
            builder.flag("orphan_finding", fid)
        elif builder.finding_events[fid] != tuple(finding.evidence_refs):
            builder.flag("finding_audit_mismatch", fid)
        for ref in finding.evidence_refs:
            if ref not in scoped_evidence:
                code = "finding_evidence_foreign_investigation" if _exists_elsewhere(evidence_store, ref) else "finding_evidence_missing"
                builder.flag(code, fid)
            elif ref not in builder.evidence_events:
                builder.flag("finding_evidence_unrecorded", fid)
    stored_ids = {f.finding_id for f in stored}
    for fid in builder.finding_events:
        if fid not in stored_ids:
            builder.flag("finding_missing", fid)
    records = tuple(
        FindingRecord(
            finding_id=f.finding_id, title=f.title, category=f.category, confidence=f.confidence,
            evidence_refs=tuple(f.evidence_refs),
        )
        for f in stored
    )
    return records, stored


def _check_risk(builder: _Builder, risk_store: Any, risk_engine: Any, stored_findings):
    try:
        stored = risk_store.list_by_investigation(builder.investigation_id)
    except Exception:  # the risk store's own error types live in chanakya.risk, which Review does not import
        builder.flag("risk_store_unverifiable")
        return ()
    findings = {f.finding_id: f for f in (stored_findings or ())}
    for assessment in stored:
        raid, fid = assessment.risk_assessment_id, assessment.finding_id
        finding = findings.get(fid)
        if finding is None:
            builder.flag("risk_missing_finding", raid)
        elif tuple(assessment.evidence_refs) != tuple(finding.evidence_refs):
            builder.flag("risk_evidence_mismatch", raid)
        if raid not in builder.risk_events:
            builder.flag("orphan_risk_assessment", raid)
        elif builder.risk_events[raid] != fid or builder.risk_methods.get(raid) != assessment.scoring_method:
            builder.flag("risk_audit_mismatch", raid)
    stored_ids = {a.risk_assessment_id for a in stored}
    for raid in builder.risk_events:
        if raid not in stored_ids:
            builder.flag("risk_assessment_missing", raid)
    if stored_findings is not None and (stored or findings):
        _recompute_risk(builder, risk_engine, stored_findings, stored)
    return tuple(
        RiskRecord(
            risk_assessment_id=a.risk_assessment_id, finding_id=a.finding_id, severity=a.severity.value,
            confidence=a.confidence, scoring_method=a.scoring_method,
        )
        for a in stored
    )


def _recompute_risk(builder: _Builder, risk_engine: Any, stored_findings, stored) -> None:
    """Phase 13 (RV-INV-2): each stored assessment is recomputed under the
    rule set it records, resolved through the trusted registry by
    ``risk_engine.for_scoring_method``. The active rule set is never
    substituted, and an unknown rule set is an anomaly, never a fallback.

    Coverage (a rateable finding with no stored assessment) is checked only
    under the rule set this investigation's own records name. With none
    recorded, the rule set cannot be known from durable history, so no
    coverage claim is made."""
    findings_by_id = {f.finding_id: f for f in stored_findings}
    by_method: Dict[str, list] = {}
    for assessment in stored:
        by_method.setdefault(assessment.scoring_method, []).append(assessment)
    for method, assessments in by_method.items():
        engine = _engine_for(builder, risk_engine, method, [a.risk_assessment_id for a in assessments])
        if engine is None:
            continue
        subset = tuple(findings_by_id[a.finding_id] for a in assessments if a.finding_id in findings_by_id)
        try:
            result = engine.assess(builder.investigation_id, subset, assessed_at=_REVIEW_ASSESSED_AT)
        except Exception:  # an engine or evidence integrity failure is reported, never raised
            builder.flag("risk_recomputation_failed")
            continue
        expected = {a.finding_id: a for a in result.assessments}
        for assessment in assessments:
            exp = expected.get(assessment.finding_id)
            if exp is None:
                builder.flag("risk_unexpected_assessment", assessment.risk_assessment_id)
            elif any(getattr(assessment, name) != getattr(exp, name) for name in _RISK_COMPARED):
                builder.flag("risk_recomputation_mismatch", assessment.risk_assessment_id)

    recorded = set(by_method) | {m for m in builder.risk_methods.values() if m is not None}
    if len(recorded) > 1:
        builder.flag("risk_mixed_scoring_methods")
        return
    if not recorded:
        return
    (method,) = recorded
    engine = _engine_for(builder, risk_engine, method, [])
    if engine is None:
        return
    try:
        result = engine.assess(builder.investigation_id, tuple(stored_findings), assessed_at=_REVIEW_ASSESSED_AT)
    except Exception:
        builder.flag("risk_recomputation_failed")
        return
    stored_findings_ids = {a.finding_id for a in stored}
    for assessment in result.assessments:
        if assessment.finding_id not in stored_findings_ids:
            builder.flag("risk_assessment_not_recorded", assessment.finding_id)


def _engine_for(builder: _Builder, risk_engine: Any, method: str, subjects):
    try:
        return risk_engine.for_scoring_method(method)
    except Exception:  # unknown or unavailable rule set: fail closed, never substitute
        for subject in subjects or [None]:
            builder.flag("risk_unknown_scoring_method", subject)
        return None


__all__ = ["reconstruct_investigation"]
