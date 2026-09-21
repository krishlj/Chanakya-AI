"""Agent Loop Controller — docs/AGENT-RUNTIME.md §3, orchestration
skeleton (Phase 3 Step 3.4) now wired to the Runtime Execution Controls
(Phase 3 Step 3.5): Timeout Supervisor, Retry Controller, approval
expiry, and audit emission.

Represents the full pipeline:

    Agent turn -> ToolRequest -> Runtime intake -> Policy evaluation
    boundary -> (approval) -> Execution boundary -> ToolResult ->
    Context/evidence handoff -> Next agent turn

with a bounded, independently-re-evaluated retry loop inserted between
"ToolResult" and "Next agent turn" for transient failures only
(docs/AGENT-RUNTIME.md §12):

    failed/timed-out execution -> Retry Controller -> new ToolRequest /
    new execution attempt -> Policy Gateway -> new PolicyDecision ->
    controlled execution

Every dependency is injected as an explicit interface (``Protocol``)
rather than imported concretely, per this phase's boundaries: no LLM
provider, no real Tool Layer, no bypass of the Policy Gateway.
"""
from __future__ import annotations

import json
import time
import uuid
from dataclasses import dataclass
from enum import Enum
from typing import Any, Callable, Mapping, Optional, Protocol, Sequence

from chanakya.contracts.approval import (
    ApprovalDecision,
    ApprovalDecisionValue,
    ApprovalRequest,
    ApprovalStatus,
)
from chanakya.contracts.enums import Verdict
from chanakya.contracts.evidence import Evidence
from chanakya.contracts.investigation_context import InvestigationContext, InvestigationStatus
from chanakya.contracts.policy_decision import PolicyDecision
from chanakya.contracts.tool_request import MalformedRequestError, ToolRequest
from chanakya.contracts.tool_result import ToolResult, ToolResultStatus
from chanakya.policy.gateway import EvaluationContext

from .agent_turn import AgentTurnOutput, NextAction
from .audit import AuditEmitter
from .clock import add_seconds, utcnow_iso
from .context_assembler import AssembledContext, ContextAssembler
from .dispatch import DispatchInstruction, ToolExecutor, dispatch
from .evidence import EvidenceRecorder, StubEvidenceRecorder
from .exceptions import (
    AuditSinkError,
    DispatchPreconditionError,
    InvestigationTerminatedError,
    MalformedAgentTurnOutputError,
    ResourceLimitExceededError,
)
from .investigation_manager import InvestigationManager
from .limits import ApprovalExpiryAction
from .resource_governor import ResourceGovernor
from .retry_controller import RetryController
from .step_record import StepRecord, StepStatus
from .timeout_supervisor import TimeoutSupervisor
from .tool_request_intake import ToolRequestIntake

_CONTRACT_VERSION = "1.0.0"

#: Phase 5.2.3: content_hash/storage_ref are Store-owned (Phase 5.2.2) —
#: this Runtime never computes a hash or assigns a storage location.
#: These are only the contract-required non-empty placeholders a real
#: EvidenceRecorder (chanakya.runtime.evidence.FilesystemEvidenceRecorder)
#: unconditionally overwrites with its Store's authoritative values before
#: anything is persisted; a caller must never treat either value as final.
_PENDING_STORE_ASSIGNMENT = "pending-store-assignment"

#: Investigation states from which a step is still meaningfully "in
#: progress" — anything else observed mid-pipeline means something else
#: (an operator cancellation, a resource-limit halt) already ended the
#: investigation concurrently with this step.
_IN_PROGRESS_STATUSES = (InvestigationStatus.RUNNING, InvestigationStatus.AWAITING_APPROVAL)

#: Phase 5.5 (RG-INV-3): returned by ``_estimate_size_bytes`` when a
#: value cannot be safely serialized/measured at all (non-JSON-safe
#: content, a pathologically deep or circular structure). Deliberately
#: larger than any realistic ``RuntimeExecutionLimits`` ceiling, so an
#: unmeasurable value always fails the corresponding size check — never
#: silently treated as within bounds.
_UNMEASURABLE_SIZE_BYTES = 2**63


def _estimate_size_bytes(value: Any) -> int:
    """Deterministic, provider-agnostic size estimate for Resource
    Governance (Phase 5.5): the canonical UTF-8 JSON byte length of
    ``value`` — never a token count (no LLM tokenizer or SDK dependency,
    per the approved design), and never anything the value itself could
    claim about its own size (RG-INV-4 — no provider-supplied size hint
    is ever consulted; this function always measures the actual
    serialized bytes). ``default=str`` lets an unusual-but-benign
    non-JSON-native value (e.g. some object a provider returned) still
    be measured via its string form rather than aborting outright; a
    value that STILL cannot be serialized this way (a circular
    reference, pathological nesting that exhausts the recursion limit,
    or any other structural failure) returns ``_UNMEASURABLE_SIZE_BYTES``
    — fail closed, per RG-INV-3, never assumed to be within any limit.
    """
    try:
        return len(
            json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True, default=str).encode("utf-8")
        )
    except (TypeError, ValueError, RecursionError):
        return _UNMEASURABLE_SIZE_BYTES


class AgentProvider(Protocol):
    """Not implemented in this phase (no LLM provider)."""

    def next_turn(self, assembled_context: AssembledContext) -> Mapping[str, Any]:
        ...


class PolicyEvaluator(Protocol):
    """Matches ``chanakya.policy.gateway.PolicyGateway.evaluate`` exactly
    — the real Policy Gateway satisfies this Protocol without adaptation.
    The controller never evaluates policy itself (RT-INV-1); a policy
    evaluator that raises is treated as an internal Runtime error and
    fails closed (Phase 3 Step 3.5: "policy errors must not become
    ALLOW"), never interpreted as any particular verdict."""

    def evaluate(self, raw_request: Mapping[str, Any], context: EvaluationContext) -> PolicyDecision:
        ...


class ApprovalProvider(Protocol):
    """Not implemented in this phase (no UI layer here). If ``None`` is
    injected, a ``require_approval`` verdict simply blocks — it never
    resolves to an implicit accept (RT-INV-3). A provider that raises is
    treated as an internal Runtime error and fails closed (Phase 3 Step
    3.5: "approval-provider errors must not become approval"), never
    interpreted as ACCEPT."""

    def request_approval(self, approval_request: ApprovalRequest) -> ApprovalDecision:
        ...


class TurnOutcome(str, Enum):
    CONCLUDED = "concluded"
    STEP_COMPLETED = "step_completed"
    STEP_DENIED = "step_denied"
    STEP_FAILED = "step_failed"
    STEP_TIMED_OUT = "step_timed_out"
    AWAITING_APPROVAL = "awaiting_approval"
    APPROVAL_EXPIRED = "approval_expired"
    CANCELLED = "cancelled"
    MALFORMED_TURN = "malformed_turn"
    MALFORMED_REQUEST = "malformed_request"
    HALTED = "halted"
    FAILED = "failed"


#: Outcomes eligible for a bounded retry (docs/AGENT-RUNTIME.md §12).
#: Every other outcome — denials, malformed input, pending/expired
#: approval, cancellation, resource-limit halts — is excluded here, by
#: construction, from ever reaching the Retry Controller at all.
_RETRYABLE_OUTCOMES = (TurnOutcome.STEP_FAILED, TurnOutcome.STEP_TIMED_OUT)


@dataclass(frozen=True)
class TurnResult:
    outcome: TurnOutcome
    step_record: Optional[StepRecord] = None
    tool_result: Optional[ToolResult] = None
    detail: Optional[str] = None


class AgentLoopController:
    """Orchestration only — see module docstring. Every collaborator is
    injected; this class holds no global state and makes no policy,
    approval, or retry-eligibility decision of its own beyond routing to
    the component whose job that is."""

    def __init__(
        self,
        investigation_manager: InvestigationManager,
        resource_governor: ResourceGovernor,
        policy_evaluator: PolicyEvaluator,
        executor: ToolExecutor,
        *,
        context_assembler: Optional[ContextAssembler] = None,
        approval_provider: Optional[ApprovalProvider] = None,
        evidence_recorder: Optional[EvidenceRecorder] = None,
        retry_controller: Optional[RetryController] = None,
        timeout_supervisor: Optional[TimeoutSupervisor] = None,
        audit: Optional[AuditEmitter] = None,
        clock=utcnow_iso,
        sleep: Callable[[float], None] = time.sleep,
    ) -> None:
        self._investigations = investigation_manager
        self._governor = resource_governor
        self._policy_evaluator = policy_evaluator
        self._executor = executor
        self._context_assembler = context_assembler or ContextAssembler()
        self._approval_provider = approval_provider
        self._evidence_recorder = evidence_recorder or StubEvidenceRecorder()
        self._retry_controller = retry_controller or RetryController(resource_governor.limits)
        self._timeout_supervisor = timeout_supervisor or TimeoutSupervisor(resource_governor, clock=clock)
        self._audit = audit if audit is not None else AuditEmitter(clock=clock)
        self._clock = clock
        self._sleep = sleep

    # -- public entry point ----------------------------------------------

    def run_turn(
        self,
        investigation_id: str,
        agent: AgentProvider,
        *,
        capability_catalog: Sequence[Mapping[str, Any]] = (),
        recent_tool_results: Sequence[ToolResult] = (),
    ) -> TurnResult:
        context = self._investigations.get(investigation_id)
        if context.is_terminal:
            raise InvestigationTerminatedError(
                f"cannot run a turn for investigation {investigation_id!r}: "
                f"already terminal (status={context.status.value!r})"
            )
        if context.status == InvestigationStatus.AWAITING_APPROVAL:
            # RT-INV-10 (at most one step in flight): a prior turn is
            # still blocked on a pending approval decision (there is no
            # ApprovalProvider configured to ever resolve it, or one that
            # simply hasn't answered yet). The Agent must not be
            # consulted for a *new* action while one is still pending —
            # found during Phase 3 Step 3.6 adversarial testing, where
            # repeated proposals against such a step previously reached
            # StepAlreadyInFlightError and were converted to a confusing
            # FAILED via the generic fail-closed backstop.
            return TurnResult(
                outcome=TurnOutcome.AWAITING_APPROVAL,
                detail="investigation is already awaiting a pending approval decision",
            )

        try:
            return self._run_turn_body(investigation_id, context, agent, capability_catalog, recent_tool_results)
        except Exception as exc:  # Runtime fail-closed backstop — §11/§7.H.
            # Any unexpected internal error (a buggy PolicyEvaluator or
            # ApprovalProvider that raises instead of returning, a
            # programming defect, a broken AuditSink, ...) must never be
            # silently swallowed, never retried automatically, and never
            # leave the investigation in an ambiguous non-terminal state.
            return self._fail_closed_on_unexpected_error(investigation_id, exc)

    def _fail_closed_on_unexpected_error(self, investigation_id: str, exc: Exception) -> TurnResult:
        # docs/AGENT-RUNTIME.md §11 treats an Audit Log write failure
        # with the same severity as an Evidence write failure: halt
        # rather than let an unaudited action proceed. Everything else
        # unexpected resolves to the generic `failed` terminal state.
        is_audit_failure = isinstance(exc, AuditSinkError)
        reason = "audit_sink_failure" if is_audit_failure else "unhandled_runtime_exception"

        try:
            self._audit.error(investigation_id, reason=reason, details={"detail": str(exc), "type": exc.__class__.__name__})
        except Exception:
            pass  # the audit sink is already known (or newly suspected)
            # broken — reporting the failure must never itself crash the
            # loop or mask the original error.

        try:
            current = self._investigations.get(investigation_id)
            if not current.is_terminal:
                if current.status == InvestigationStatus.AWAITING_APPROVAL:
                    # FAILED/HALTED are only reachable from RUNNING in
                    # this phase's state machine (docs/AGENT-RUNTIME.md
                    # §15) — resolve the pending approval state via its
                    # one existing, already-valid exit (-> RUNNING)
                    # first, rather than adding a new transition edge
                    # for this error path alone.
                    self._investigations.resume_running(investigation_id)
                if is_audit_failure:
                    self._investigations.halt(investigation_id, reason=reason, details={"detail": str(exc)})
                    return TurnResult(outcome=TurnOutcome.HALTED, detail=str(exc))
                self._investigations.fail(investigation_id, reason=reason, details={"detail": str(exc)})
        except Exception:
            pass  # already terminal, or otherwise un-transitionable — nothing further to do safely
        return TurnResult(outcome=TurnOutcome.FAILED, detail=str(exc))

    def _run_turn_body(
        self,
        investigation_id: str,
        context: InvestigationContext,
        agent: AgentProvider,
        capability_catalog: Sequence[Mapping[str, Any]],
        recent_tool_results: Sequence[ToolResult],
    ) -> TurnResult:
        try:
            self._timeout_supervisor.check_investigation_timeout(investigation_id)
        except ResourceLimitExceededError as exc:
            self._investigations.halt(
                investigation_id, reason="max_investigation_duration_seconds_exceeded", details={"detail": str(exc)}
            )
            return TurnResult(outcome=TurnOutcome.HALTED, detail=str(exc))

        assembled = self._context_assembler.assemble(
            context, capability_catalog=capability_catalog, recent_tool_results=recent_tool_results
        )

        # Phase 5.5 (RG-INV-1): reject an oversized assembled context
        # BEFORE it is ever handed to the provider — ContextAssembler
        # itself stays stateless and unaware of any Resource Governance
        # concern (unmodified); measuring and enforcing is the Runtime's
        # own job, exactly like every other limit checked in this method.
        context_size = _estimate_size_bytes(
            {
                "instructions": assembled.instructions,
                "capability_catalog": list(assembled.capability_catalog),
                "data": [{"source": entry.source, "content": entry.content} for entry in assembled.data],
            }
        )
        try:
            self._governor.check_context_size(context_size)
        except ResourceLimitExceededError as exc:
            self._investigations.halt(
                investigation_id, reason="max_context_bytes_exceeded", details={"detail": str(exc)}
            )
            return TurnResult(outcome=TurnOutcome.HALTED, detail=str(exc))

        raw_turn = agent.next_turn(assembled)

        # Phase 5.5 (RG-INV-2): reject an oversized raw provider return
        # value BEFORE it is parsed into AgentTurnOutput — never
        # truncated, repaired, or partially interpreted first (RT-INV-5).
        output_size = _estimate_size_bytes(raw_turn)
        try:
            self._governor.check_provider_output_size(output_size)
        except ResourceLimitExceededError as exc:
            self._investigations.halt(
                investigation_id, reason="max_provider_output_bytes_exceeded", details={"detail": str(exc)}
            )
            return TurnResult(outcome=TurnOutcome.HALTED, detail=str(exc))

        try:
            turn_output = AgentTurnOutput.from_dict(raw_turn)
        except MalformedAgentTurnOutputError as exc:
            return TurnResult(outcome=TurnOutcome.MALFORMED_TURN, detail=str(exc))

        if turn_output.next_action == NextAction.CONCLUDE:
            self._investigations.complete(investigation_id)
            return TurnResult(outcome=TurnOutcome.CONCLUDED)

        return self._handle_tool_request_turn(investigation_id, context, turn_output)

    # -- ToolRequest -> intake -> policy -> (approval) -> dispatch, with bounded retry --

    def _handle_tool_request_turn(
        self, investigation_id: str, context: InvestigationContext, turn_output: AgentTurnOutput
    ) -> TurnResult:
        try:
            self._governor.record_step_proposed(investigation_id)
        except ResourceLimitExceededError as exc:
            self._investigations.halt(
                investigation_id, reason="max_steps_per_investigation_exceeded", details={"detail": str(exc)}
            )
            return TurnResult(outcome=TurnOutcome.HALTED, detail=str(exc))

        raw_tool_request = dict(turn_output.tool_request or {})
        return self._run_attempt_with_retries(investigation_id, context, raw_tool_request)

    def _run_attempt_with_retries(
        self, investigation_id: str, context: InvestigationContext, raw_tool_request: Mapping[str, Any]
    ) -> TurnResult:
        current_request = dict(raw_tool_request)
        attempt_number = 1
        result = self._attempt(investigation_id, context, current_request, attempt_number)

        while result.outcome in _RETRYABLE_OUTCOMES:
            step = result.step_record
            tool_result = result.tool_result
            assert step is not None and tool_result is not None  # guaranteed by _execute_once

            investigation_status = self._investigations.get(investigation_id).status
            if investigation_status != InvestigationStatus.RUNNING:
                # The investigation ended (cancelled, or independently
                # halted) while this attempt was executing — never retry
                # a cancelled/halted investigation.
                self._audit.dispatch_failed(investigation_id, tool_result, retry_scheduled=False, reason="investigation no longer running")
                return result

            if not self._retry_controller.should_retry(step):
                self._audit.dispatch_failed(investigation_id, tool_result, retry_scheduled=False, reason="retry budget exhausted")
                return result

            next_attempt_number = step.attempt_number + 1
            self._audit.dispatch_failed(
                investigation_id, tool_result, retry_scheduled=True, next_attempt_number=next_attempt_number
            )
            self._governor.record_retry(investigation_id)
            self._sleep(self._retry_controller.backoff_seconds)

            # Re-check: cancellation (or any other halt) may have
            # occurred during the backoff wait itself — this is a
            # distinct race window from the pre-sleep check above, and
            # was found missing during Phase 3 Step 3.6 integration
            # testing. Without it, a cancellation delivered entirely
            # inside the backoff period would be silently ignored and
            # the next attempt would launch anyway.
            if self._investigations.get(investigation_id).status != InvestigationStatus.RUNNING:
                return result

            current_request = dict(current_request)
            current_request["tool_request_id"] = str(uuid.uuid4())
            current_request["proposed_at"] = self._clock()
            result = self._attempt(investigation_id, context, current_request, next_attempt_number)

        return result

    def _attempt(
        self, investigation_id: str, context: InvestigationContext, raw_tool_request: Mapping[str, Any], attempt_number: int
    ) -> TurnResult:
        provisional_id = raw_tool_request.get("tool_request_id")
        step = StepRecord(
            step_id=str(uuid.uuid4()),
            tool_request_id=provisional_id if isinstance(provisional_id, str) and provisional_id else str(uuid.uuid4()),
            attempt_number=attempt_number,
            started_at=self._clock(),
            clock=self._clock,
        )
        context.begin_step(step)
        step.transition(StepStatus.VALIDATING)

        try:
            tool_request = ToolRequestIntake.intake(raw_tool_request)
        except MalformedRequestError as exc:
            # Never retried (invalid request) — RT-INV-5.
            step.transition(StepStatus.STEP_FAILED)
            context.end_current_step()
            return TurnResult(outcome=TurnOutcome.MALFORMED_REQUEST, step_record=step, detail=str(exc))

        self._audit.request_proposed(investigation_id, tool_request.tool_request_id)

        step.transition(StepStatus.POLICY_EVALUATING)
        evaluation_context = EvaluationContext(
            authorized_target_refs=frozenset(context.target_refs),
            call_counts=self._governor.capability_call_counts(investigation_id),
        )
        policy_decision = self._policy_evaluator.evaluate(dict(raw_tool_request), evaluation_context)
        step.set_policy_decision_id(policy_decision.policy_decision_id)
        self._audit.policy_evaluated(investigation_id, tool_request.tool_request_id, policy_decision)

        if policy_decision.verdict == Verdict.DENY:
            # Never retried (denied request) — docs/AGENT-RUNTIME.md §12.
            step.transition(StepStatus.STEP_DENIED)
            context.end_current_step()
            return TurnResult(outcome=TurnOutcome.STEP_DENIED, step_record=step)

        if policy_decision.verdict == Verdict.REQUIRE_APPROVAL:
            return self._handle_require_approval(investigation_id, context, step, tool_request, policy_decision)

        step.transition(StepStatus.DISPATCHING)
        return self._execute_once(investigation_id, context, step, tool_request, policy_decision)

    def _handle_require_approval(
        self,
        investigation_id: str,
        context: InvestigationContext,
        step: StepRecord,
        tool_request: ToolRequest,
        policy_decision: PolicyDecision,
    ) -> TurnResult:
        step.transition(StepStatus.AWAITING_STEP_APPROVAL)
        # Idempotent: if no ApprovalProvider is configured, a prior turn
        # may already have left the investigation AWAITING_APPROVAL (it
        # never resolved, since nothing exists yet to answer it) —
        # AWAITING_APPROVAL -> AWAITING_APPROVAL is not itself a valid
        # transition (docs/AGENT-RUNTIME.md §15), so this is only invoked
        # when a real transition is actually needed. Found during Phase
        # 3 Step 3.6 adversarial testing (repeated proposals against a
        # step with no approval mechanism wired up).
        if context.status != InvestigationStatus.AWAITING_APPROVAL:
            self._investigations.enter_awaiting_approval(investigation_id)

        requested_at = self._clock()
        expiry_seconds = self._governor.limits.approval_expiry_seconds_default
        expires_at = add_seconds(requested_at, expiry_seconds) if expiry_seconds is not None else None

        approval_request = ApprovalRequest(
            approval_request_id=str(uuid.uuid4()),
            contract_version=_CONTRACT_VERSION,
            investigation_id=investigation_id,
            tool_request_id=tool_request.tool_request_id,
            policy_decision_id=policy_decision.policy_decision_id,
            risk_context={
                "capability": tool_request.capability,
                "target_ref": tool_request.target_ref,
                "parameters": dict(tool_request.parameters),
            },
            status=ApprovalStatus.PENDING,
            requested_at=requested_at,
            expires_at=expires_at,
        )
        step.set_approval_request_id(approval_request.approval_request_id)
        self._audit.approval_requested(approval_request)

        if self._approval_provider is None:
            # RT-INV-3: no implicit/timeout-default approval. With no
            # approval mechanism wired up at all, the step stays
            # pending — it must never be treated as accepted.
            return TurnResult(
                outcome=TurnOutcome.AWAITING_APPROVAL,
                step_record=step,
                detail="no ApprovalProvider configured; dispatch blocked pending human approval",
            )

        approval_decision = self._approval_provider.request_approval(approval_request)
        decided_check_time = self._clock()
        step.set_approval_decision_id(approval_decision.approval_decision_id)

        # Cancellation race-guard: the investigation may have ended
        # (operator cancellation, an independent halt) while we were
        # waiting on a human decision.
        current_status = self._investigations.get(investigation_id).status
        if current_status not in _IN_PROGRESS_STATUSES:
            # The step-level machine only allows STEP_DENIED (not
            # STEP_FAILED) from AWAITING_STEP_APPROVAL — a cancelled wait
            # is denial-shaped ("dispatch will never happen for this
            # step"), the same as an expired or rejected approval.
            step.transition(StepStatus.STEP_DENIED)
            context.end_current_step()
            return TurnResult(
                outcome=TurnOutcome.CANCELLED, step_record=step, detail="investigation ended while awaiting approval"
            )

        # Expiry: fail closed regardless of what the decision says — an
        # ACCEPT that arrives after the deadline is never honored.
        if approval_request.expires_at is not None and decided_check_time > approval_request.expires_at:
            self._audit.approval_decided(
                investigation_id, approval_request.approval_request_id, outcome="expired", actor="system"
            )
            step.transition(StepStatus.STEP_DENIED)
            context.end_current_step()
            is_p4 = policy_decision.notes == "justification_required"
            if is_p4 and self._governor.limits.p4_approval_expiry_action == ApprovalExpiryAction.HALT_INVESTIGATION:
                self._investigations.halt(investigation_id, reason="p4_approval_expired")
                return TurnResult(
                    outcome=TurnOutcome.APPROVAL_EXPIRED,
                    step_record=step,
                    detail="P4 approval expired; investigation halted per p4_approval_expiry_action",
                )
            self._investigations.resume_running(investigation_id)
            return TurnResult(
                outcome=TurnOutcome.APPROVAL_EXPIRED,
                step_record=step,
                detail="approval expired before a decision was recorded in time",
            )

        self._audit.approval_decided(
            investigation_id,
            approval_request.approval_request_id,
            outcome=approval_decision.decision.value,
            decided_by=approval_decision.decided_by,
            justification=approval_decision.justification,
            actor=approval_decision.decided_by,
        )
        self._investigations.resume_running(investigation_id)

        if approval_decision.decision != ApprovalDecisionValue.ACCEPT:
            # Never retried (denied by a human) — docs/AGENT-RUNTIME.md §12.
            step.transition(StepStatus.STEP_DENIED)
            context.end_current_step()
            return TurnResult(outcome=TurnOutcome.STEP_DENIED, step_record=step)

        step.transition(StepStatus.DISPATCHING)
        return self._execute_once(
            investigation_id,
            context,
            step,
            tool_request,
            policy_decision,
            approval_request=approval_request,
            approval_decision=approval_decision,
        )

    def _execute_once(
        self,
        investigation_id: str,
        context: InvestigationContext,
        step: StepRecord,
        tool_request: ToolRequest,
        policy_decision: PolicyDecision,
        *,
        approval_request: Optional[ApprovalRequest] = None,
        approval_decision: Optional[ApprovalDecision] = None,
    ) -> TurnResult:
        try:
            self._governor.record_tool_call(investigation_id, tool_request.capability)
        except ResourceLimitExceededError as exc:
            # step is DISPATCHING here (set by the caller just before this
            # method runs); the step-level machine only allows STEP_FAILED
            # from EXECUTING, so dispatch is recorded as having begun (it
            # was attempted) before being marked failed.
            step.transition(StepStatus.EXECUTING)
            step.transition(StepStatus.STEP_FAILED)
            context.end_current_step()
            self._investigations.halt(
                investigation_id, reason="max_tool_calls_per_investigation_exceeded", details={"detail": str(exc)}
            )
            return TurnResult(outcome=TurnOutcome.HALTED, step_record=step, detail=str(exc))

        timeout_seconds = self._governor.limits.default_step_timeout_seconds
        instruction = DispatchInstruction(
            investigation_id=investigation_id,
            tool_request_id=tool_request.tool_request_id,
            capability=tool_request.capability,
            target_ref=tool_request.target_ref,
            parameters=tool_request.parameters,
            resolved_timeout_seconds=timeout_seconds,
            resolved_resource_limits={},
            policy_decision_id=policy_decision.policy_decision_id,
            approval_decision_id=approval_decision.approval_decision_id if approval_decision else None,
            attempt_number=step.attempt_number,
        )
        step.transition(StepStatus.EXECUTING)
        self._audit.dispatch_started(investigation_id, tool_request.tool_request_id)

        timeout_bound_executor = self._timeout_supervisor.bind(self._executor, timeout_seconds=timeout_seconds)

        try:
            tool_result = dispatch(
                instruction,
                policy_decision,
                timeout_bound_executor,
                approval_request=approval_request,
                approval_decision=approval_decision,
            )
        except DispatchPreconditionError as exc:
            # Should be unreachable given correct wiring above — treated
            # as a fatal Runtime condition, never silently swallowed.
            step.transition(StepStatus.STEP_FAILED)
            context.end_current_step()
            self._investigations.fail(
                investigation_id, reason="dispatch_precondition_violation", details={"detail": str(exc)}
            )
            return TurnResult(outcome=TurnOutcome.FAILED, step_record=step, detail=str(exc))

        step.set_tool_result_id(tool_result.tool_result_id)

        # Cancellation race-guard: the investigation may have been ended
        # by another caller while this (synchronous) dispatch was in
        # flight. A late-arriving result is never treated as
        # authoritative once that has happened (RT-INV-9).
        current_status = self._investigations.get(investigation_id).status
        if current_status != InvestigationStatus.RUNNING:
            step.transition(StepStatus.STEP_FAILED)
            context.end_current_step()
            return TurnResult(
                outcome=TurnOutcome.CANCELLED,
                step_record=step,
                tool_result=tool_result,
                detail="investigation ended during execution; result discarded",
            )

        if tool_result.status == ToolResultStatus.SUCCESS:
            step.transition(StepStatus.STEP_COMPLETED)
            self._audit.dispatch_completed(investigation_id, tool_result)

            try:
                # Phase 5.2.3: assemble the complete Evidence record from
                # context already in scope — exactly the same identifiers
                # already used to build DispatchInstruction/audit calls
                # above, plus the classification snapshot the Policy
                # Gateway already attached to this exact policy_decision
                # (chanakya/policy/gateway.py's PolicyGateway._decide —
                # no second Registry lookup, no re-authorization). Kept
                # inside this try block deliberately: if Evidence's own
                # contract validation rejects anything here (e.g. an
                # unexpectedly absent classification), that failure is an
                # evidence-recording failure like any other and is handled
                # identically by the except block below.
                evidence = Evidence(
                    evidence_id=str(uuid.uuid4()),
                    contract_version=_CONTRACT_VERSION,
                    investigation_id=investigation_id,
                    step_id=step.step_id,
                    tool_request_id=tool_result.tool_request_id,
                    tool_result_id=tool_result.tool_result_id,
                    target_id=tool_request.target_ref,
                    capability=tool_result.capability,
                    recorded_at=self._clock(),
                    content_hash=_PENDING_STORE_ASSIGNMENT,
                    storage_ref=_PENDING_STORE_ASSIGNMENT,
                    classification=policy_decision.classification,
                )
                # Phase 5.3: the actual tool-output content — kept OUT of
                # the Evidence object itself (docs/CONTRACTS.md §7, still
                # unmodified) and instead handed alongside it as a plain,
                # JSON-serializable mapping. Untrusted, tool/target-
                # originated data, exactly like every other use of
                # tool_result.* elsewhere in this file (RT-INV-7) — this
                # is pure data assembly, not hashing or storage; both of
                # those remain EvidenceStore's exclusive responsibility
                # (chanakya/evidence/store.py).
                evidence_payload = {
                    "output": tool_result.output,
                    "error_message": tool_result.error_message,
                    "raw_output": tool_result.raw_output,
                    "warnings": list(tool_result.warnings),
                }
                evidence_id = self._evidence_recorder.record(evidence, evidence_payload)
            except Exception as exc:
                # docs/AGENT-RUNTIME.md §9: "the corresponding action is
                # treated as not having durably happened... the
                # investigation halts rather than continuing without
                # provenance." The tool execution itself genuinely
                # succeeded (STEP_COMPLETED is not retracted), but that
                # fact is never surfaced as usable evidence, never added
                # to evidence_refs, and the investigation is halted
                # rather than silently continuing as if nothing failed.
                step.transition(StepStatus.EVIDENCE_FAILED)
                context.end_current_step()
                self._investigations.halt(
                    investigation_id, reason="evidence_recording_failed", details={"detail": str(exc)}
                )
                return TurnResult(
                    outcome=TurnOutcome.HALTED, step_record=step, tool_result=tool_result, detail=str(exc)
                )

            step.set_evidence_id(evidence_id)
            context.add_evidence_ref(evidence_id)
            step.transition(StepStatus.EVIDENCE_RECORDED)
            self._audit.evidence_recorded(investigation_id, evidence_id, tool_result.tool_result_id)
            context.end_current_step()
            return TurnResult(outcome=TurnOutcome.STEP_COMPLETED, step_record=step, tool_result=tool_result)

        if tool_result.status == ToolResultStatus.TIMEOUT:
            step.transition(StepStatus.STEP_TIMED_OUT)
            context.end_current_step()
            return TurnResult(outcome=TurnOutcome.STEP_TIMED_OUT, step_record=step, tool_result=tool_result)

        step.transition(StepStatus.STEP_FAILED)
        context.end_current_step()
        return TurnResult(outcome=TurnOutcome.STEP_FAILED, step_record=step, tool_result=tool_result)
