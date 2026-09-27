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

import copy
import json
import time
import uuid
from dataclasses import dataclass
from enum import Enum
from types import MappingProxyType
from typing import Any, Callable, Dict, List, Mapping, Optional, Protocol, Sequence, Tuple

from chanakya.capability.envelope import is_envelope_violation
from chanakya.contracts.agent_turn import (
    ACCEPTED_OUTCOMES,
    ACCEPTED_STOP_REASONS,
    MAX_CONTEXT_ENTRIES,
    SOURCE_KIND_EVIDENCE,
    SOURCE_KIND_TOOL_RESULT_ERROR,
    UNDECLARED_PROVIDER,
    AgentTurnOutcome,
    ContextEntry,
    ContextManifest,
    PreparedProviderRequest,
    ProviderIdentity,
    ProviderResponse,
    TurnOutcomeRecord,
    derive_agent_turn_id,
    hash_json_normalized,
    hash_value,
)
from chanakya.contracts.approval import (
    ApprovalDecision,
    ApprovalDecisionValue,
    ApprovalRequest,
    ApprovalStatus,
)
from chanakya.contracts.enums import Verdict
from chanakya.contracts.evidence import Evidence
from chanakya.contracts.investigation_context import InvestigationContext, InvestigationStatus
from chanakya.contracts.finding import Finding, FindingValidationError
from chanakya.contracts.policy_decision import PolicyDecision
from chanakya.contracts.risk_assessment import (
    MAX_RISK_ASSESSMENTS_PER_INVESTIGATION,
    NOT_ASSESSED_CATEGORY_UNRATED,
    NotAssessedFinding,
    RiskAssessment,
    RiskAssessmentValidationError,
    RiskEngineResult,
    derive_risk_assessment_id,
    severity_rank,
)
from chanakya.contracts.risk_taxonomy import RiskRuleSet, RiskRuleSetError, resolve_rule_set
from chanakya.contracts.tool_request import MalformedRequestError, ToolRequest
from chanakya.contracts.tool_result import ToolResult, ToolResultStatus
from chanakya.policy.gateway import EvaluationContext
from chanakya.targets.context import TargetContextProjectionError
from chanakya.targets.environment_source import EnvironmentContextUnavailableError
from chanakya.targets.environment_view import EnvironmentContextProjectionError, EnvironmentContextView
from chanakya.targets.exceptions import UnregisteredTargetError

from .agent_turn import AgentTurnOutput, NextAction
from .audit import AuditEmitter
from .clock import add_seconds, utcnow_iso
from .context_assembler import (
    AssembledContext,
    ContextAssembler,
    EnvironmentContextSource,
    TargetContextSource,
    validate_environment_context_scope,
    validate_target_context_scope,
)
from .dispatch import DispatchInstruction, ToolExecutor, dispatch
from .evidence import EvidenceRecorder, StubEvidenceRecorder
from .exceptions import (
    AuditSinkError,
    ContextSourceError,
    ProviderContractError,
    DispatchPreconditionError,
    EnvironmentContextScopeError,
    InvestigationTerminatedError,
    MalformedAgentTurnOutputError,
    ResourceLimitExceededError,
    TargetContextScopeError,
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


def _verify_environment_context_binding(
    context: InvestigationContext, environment_context: Sequence[Any]
) -> None:
    """Phase 5.7.6 defense in depth (EC-INV-2/7): whatever assembler
    produced ``environment_context`` — including an injected one when no
    source is configured — every entry must be an ``EnvironmentContextView``
    bound to one of this investigation's own targets."""
    in_scope = frozenset(context.target_refs)
    for entry in environment_context:
        if not isinstance(entry, EnvironmentContextView):
            raise EnvironmentContextScopeError(
                f"assembled environment context entries must be EnvironmentContextView, got {type(entry).__name__}"
            )
        if entry.target_id not in in_scope:
            raise EnvironmentContextScopeError(
                f"assembled environment context references a target outside investigation "
                f"{context.investigation_id!r} target_refs"
            )


class _ProviderTurn:
    """Phase 14: one provider call in flight (Runtime-internal)."""

    def __init__(self, *, turn_id: str, sequence: int, request_hash: str) -> None:
        self.turn_id = turn_id
        self.sequence = sequence
        self.request_hash = request_hash
        self.received = False
        self.raw_turn: Any = None
        self.stop_reason: Optional[str] = None
        self.tool_use_blocks: Optional[int] = None


def _verify_context_data(assembled: AssembledContext, sources: Sequence["_ContextSource"]) -> None:
    """Phase 14 (CT-INV-2): the assembled untrusted data must be exactly the
    Runtime-owned sources, in order: nothing added, dropped or altered."""
    expected = tuple((f"tool_result:{s.tool_result.tool_result_id}", s.content) for s in sources)
    actual = tuple((entry.source, entry.content) for entry in assembled.data)
    if actual != expected:
        raise ContextSourceError("assembled context data differs from the Runtime-owned context sources")


class AgentProvider(Protocol):
    """The model boundary. ``next_turn`` is the minimal shape (in-process
    doubles). Phase 14: a *declared* provider (``AnthropicProvider``) also
    implements ``provider_identity() -> ProviderIdentity``,
    ``prepare_turn(assembled) -> PreparedProviderRequest`` and
    ``send_turn(prepared) -> ProviderResponse``; the Runtime then records
    the exact request hash and identity before anything is sent. A provider
    without them is recorded as ``UNDECLARED_PROVIDER`` with the hash of
    the assembled context it was handed."""

    def next_turn(self, assembled_context: AssembledContext) -> Mapping[str, Any]:
        ...


@dataclass(frozen=True)
class _ContextSource:
    """Phase 14: one tool result this Runtime produced for an investigation
    and may place in that investigation's model context (CT-INV-2)."""

    tool_result: ToolResult
    step_id: str
    evidence_id: Optional[str]
    source_kind: str
    content: Any
    content_hash: str


def _is_declared_provider(agent: Any) -> bool:
    return all(callable(getattr(agent, name, None)) for name in ("provider_identity", "prepare_turn", "send_turn"))


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


class FindingRecorder(Protocol):
    """Phase 9. Durable, append-only Finding storage
    (``chanakya.findings.FindingStore`` satisfies this)."""

    def append(self, finding: Finding) -> None:
        ...


class RiskAssessor(Protocol):
    """Phase 10. The deterministic Risk Engine (``chanakya.risk.RiskEngine``
    satisfies this). Rates the Findings stored in one conclude turn; the
    Runtime never computes a rating itself (docs/AGENT-RUNTIME.md SR-18)."""

    def assess(self, investigation_id: str, findings: Sequence[Finding], *, assessed_at: str) -> RiskEngineResult:
        ...


class RiskAssessmentRecorder(Protocol):
    """Phase 10. Durable, append-only RiskAssessment storage
    (``chanakya.risk.RiskAssessmentStore`` satisfies this)."""

    def append(self, risk_assessment: RiskAssessment) -> None:
        ...


def _validate_risk_result(
    investigation_id: str,
    context: InvestigationContext,
    findings: Tuple[Finding, ...],
    result: Any,
    rule_set: RiskRuleSet,
) -> Tuple[RiskAssessment, ...]:
    """Phase 10. Checks a Risk Engine result against the Findings stored in
    this conclude turn before anything is stored. Raises
    ``RiskAssessmentValidationError``; never repairs.

    Every assessment is rebuilt from its dict, so an object altered after
    construction is re-validated against the contract (rule-set shape,
    deterministic id, severity ceiling).

    Phase 13 (RV-INV-4/6): the batch, every assessment and every
    not-assessed entry must name exactly the Runtime's one active rule set.
    A result produced under any other rule set, older or newer, is rejected;
    nothing is ever re-labelled or downgraded."""
    if not isinstance(result, RiskEngineResult):
        raise RiskAssessmentValidationError("risk assessor returned an unexpected type")
    try:
        assessments = tuple(RiskAssessment.from_dict(ra.to_dict()) for ra in result.assessments)
        not_assessed = tuple(
            NotAssessedFinding(n.finding_id, n.reason, n.scoring_method) for n in result.not_assessed
        )
        methods = {result.scoring_method} | {a.scoring_method for a in assessments} | {
            n.scoring_method for n in not_assessed
        }
    except RiskAssessmentValidationError:
        raise
    except Exception:
        raise RiskAssessmentValidationError("risk assessor returned a malformed assessment") from None
    if methods != {rule_set.scoring_method}:
        raise RiskAssessmentValidationError("risk result was not produced under the active rule set")
    if len(assessments) + len(not_assessed) > MAX_RISK_ASSESSMENTS_PER_INVESTIGATION:
        raise RiskAssessmentValidationError("risk assessor returned too many results")
    by_id = {finding.finding_id: finding for finding in findings}
    covered = [ra.finding_id for ra in assessments] + [item.finding_id for item in not_assessed]
    if len(set(covered)) != len(covered) or set(covered) != set(by_id):
        raise RiskAssessmentValidationError(
            "risk assessor must cover every finding stored in this turn exactly once, and nothing else"
        )
    recorded = set(context.evidence_refs)
    for ra in assessments:
        finding = by_id[ra.finding_id]
        if ra.investigation_id != investigation_id or finding.investigation_id != investigation_id:
            raise RiskAssessmentValidationError("risk assessment belongs to another investigation")
        if ra.evidence_refs != finding.evidence_refs or not set(ra.evidence_refs) <= recorded:
            raise RiskAssessmentValidationError("risk assessment evidence differs from its finding's evidence")
        if ra.risk_assessment_id != derive_risk_assessment_id(investigation_id, ra.finding_id, ra.scoring_method):
            raise RiskAssessmentValidationError("risk assessment id is not the deterministic id")
        if ra.rule_ids[1] != f"category.{finding.category}":
            raise RiskAssessmentValidationError("risk assessment does not rate its finding's category")
        if severity_rank(ra.severity.value) > severity_rank(rule_set.max_severity):
            raise RiskAssessmentValidationError("risk assessment severity exceeds the rule-set ceiling")
    for item in not_assessed:
        rated = by_id[item.finding_id].category in rule_set.taxonomy
        if (item.reason == NOT_ASSESSED_CATEGORY_UNRATED) == rated:
            raise RiskAssessmentValidationError("not-assessed reason does not match the finding's category")
    return assessments


#: Phase 9: the most findings one investigation may record.
MAX_FINDINGS_PER_INVESTIGATION = 20

_FINDING_FIELDS = frozenset({"title", "description", "evidence_refs", "category", "confidence"})
_FINDING_REQUIRED = frozenset({"title", "description", "evidence_refs"})


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
        target_context_source: Optional[TargetContextSource] = None,
        environment_context_source: Optional[EnvironmentContextSource] = None,
        finding_recorder: Optional[FindingRecorder] = None,
        risk_assessor: Optional[RiskAssessor] = None,
        risk_recorder: Optional[RiskAssessmentRecorder] = None,
        risk_rule_set: Optional[RiskRuleSet] = None,
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
        # Phase 5.7.3 (docs/TARGET-AWARE-AGENT-CONTEXT.md §10): optional,
        # narrow, descriptive-only. None -> empty target context (the
        # pre-5.7.3 behavior). Never passed to the Policy Gateway.
        self._target_context_source = target_context_source
        # Phase 5.7.6 (docs/TARGET-AWARE-AGENT-CONTEXT.md §13a): optional,
        # opt-in, observational-only. None -> no environment context. Called
        # once per turn (fresh, never cached). Never passed to the Policy
        # Gateway, never used to fill a target_ref.
        self._environment_context_source = environment_context_source
        # Phase 9: optional. With None, a conclude turn that carries
        # findings fails the investigation instead of dropping them.
        self._finding_recorder = finding_recorder
        # Phase 10: both or neither. With neither, conclude behaves exactly
        # as in Phase 9. A rating that could not be stored, or a store with
        # nothing to rate, is a composition error.
        if (risk_assessor is None) != (risk_recorder is None):
            raise ValueError("risk_assessor and risk_recorder must be configured together")
        # Phase 13: exactly one active rule set, supplied by trusted
        # composition code and required when risk assessment is configured.
        # It must be the registered definition; nothing defaults to v1.
        if risk_assessor is not None or risk_rule_set is not None:
            if risk_assessor is None or not isinstance(risk_rule_set, RiskRuleSet):
                raise ValueError("risk assessment requires exactly one active RiskRuleSet")
            try:
                registered = resolve_rule_set(risk_rule_set.scoring_method)
            except RiskRuleSetError:
                raise ValueError("the active risk rule set is not registered") from None
            if registered != risk_rule_set:
                raise ValueError("the active risk rule set differs from its registered definition")
        self._risk_assessor = risk_assessor
        self._risk_recorder = risk_recorder
        self._risk_rule_set = risk_rule_set
        self._clock = clock
        self._sleep = sleep
        # Phase 14 (CT-INV-2): the Runtime-owned record of the tool results
        # each investigation produced, the only source of model-context data,
        # and each investigation's turn counter. In memory, like the rest of
        # live Runtime state; never conversation memory (no model output is
        # kept or replayed).
        self._context_sources: Dict[str, List[_ContextSource]] = {}
        self._turn_sequences: Dict[str, int] = {}

    # -- public entry point ----------------------------------------------

    def run_turn(
        self,
        investigation_id: str,
        agent: AgentProvider,
        *,
        capability_catalog: Sequence[Mapping[str, Any]] = (),
        recent_tool_results: Sequence[ToolResult] = (),
    ) -> TurnResult:
        """Phase 14: the Runtime composes model context itself from the tool
        results this investigation produced (the last
        ``MAX_CONTEXT_ENTRIES``). ``recent_tool_results`` is kept only for
        compatibility and selects nothing: every entry must be one of those
        Runtime-owned results, unaltered and not duplicated, or the
        investigation fails closed (``context_source_rejected``) before the
        provider is called."""
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
            result = self._run_turn_body(investigation_id, context, agent, capability_catalog, recent_tool_results)
            self._remember_context_source(investigation_id, result)
            return result
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

        # Phase 14 (CT-INV-2): model-context data comes only from the tool
        # results this Runtime produced for this investigation. A caller may
        # not add, alter, repeat or resurrect one; any attempt fails the
        # investigation before the provider is reached.
        sources = self._context_window(investigation_id)
        try:
            self._check_caller_results(sources, recent_tool_results)
        except ContextSourceError as exc:
            return self._reject_context_sources(investigation_id, exc)

        # Phase 5.7.3 (TC-INV-3): target context is derived ONLY from this
        # investigation's own target_refs, freshly each turn (no cache), and
        # the assembler re-verifies scope. Any failure to build it — an
        # unregistered target, a target whose allowlisted values fail
        # projection, or a scope mismatch — fails the investigation closed
        # BEFORE the provider (or anything downstream) is ever reached;
        # target context is never omitted, partial, or invented.
        #
        # Phase 5.7.6 (EC-INV-2/7/11): environment context follows the same
        # pattern — collected freshly each turn for this investigation's own
        # target_refs, bound + projected by the loop itself, then confirmed
        # to be exactly what the assembler carried. Any collection, binding,
        # or projection failure fails the investigation closed before the
        # provider is reached; nothing is dropped, re-bound, or truncated.
        #
        # Without a configured source, the assembler is called exactly as
        # before (no new keyword), so any existing injected ContextAssembler
        # stays compatible. With a source, the loop checks scope itself and
        # then confirms the assembler carried exactly those views — it does
        # not rely on an injected assembler to validate.
        try:
            assemble_kwargs = {}
            target_contexts = None
            if self._target_context_source is not None:
                target_contexts = validate_target_context_scope(
                    context, self._target_context_source.describe_targets(context.target_refs), required=True
                )
                assemble_kwargs["target_contexts"] = target_contexts
            expected_environment = None
            if self._environment_context_source is not None:
                environment_contexts = tuple(
                    self._environment_context_source.collect_environment_contexts(context.target_refs)
                )
                expected_environment = validate_environment_context_scope(context, environment_contexts)
                # Phase 5.7.7: a configured source must cover every target of
                # this investigation. A source that silently drops one gives
                # the model partial observations; fail closed instead, the
                # same rule required-mode target context applies.
                uncovered = set(context.target_refs) - {view.target_id for view in expected_environment}
                if uncovered:
                    raise EnvironmentContextScopeError(
                        f"environment context is missing for {len(uncovered)} of investigation "
                        f"{context.investigation_id!r} target_refs"
                    )
                assemble_kwargs["environment_contexts"] = environment_contexts
            assembled = self._context_assembler.assemble(
                context,
                capability_catalog=capability_catalog,
                recent_tool_results=tuple(source.tool_result for source in sources),
                **assemble_kwargs,
            )
            if target_contexts is not None and tuple(assembled.target_context) != target_contexts:
                raise TargetContextScopeError(
                    "assembled target context differs from the investigation-scoped target context"
                )
            if expected_environment is not None and tuple(assembled.environment_context) != expected_environment:
                raise EnvironmentContextScopeError(
                    "assembled environment context differs from the investigation-scoped environment context"
                )
            _verify_environment_context_binding(context, assembled.environment_context)
            # Phase 14: whatever assembler ran, the data it carries must be
            # exactly the Runtime-owned sources, in order.
            _verify_context_data(assembled, sources)
        except ContextSourceError as exc:
            return self._reject_context_sources(investigation_id, exc)
        except (UnregisteredTargetError, TargetContextProjectionError, TargetContextScopeError) as exc:
            self._investigations.fail(
                investigation_id,
                reason="target_context_unavailable",
                details={"detail": str(exc), "type": exc.__class__.__name__},
            )
            return TurnResult(outcome=TurnOutcome.FAILED, detail=str(exc))
        except (
            EnvironmentContextUnavailableError,
            EnvironmentContextProjectionError,
            EnvironmentContextScopeError,
        ) as exc:
            self._investigations.fail(
                investigation_id,
                reason="environment_context_unavailable",
                details={"detail": str(exc), "type": exc.__class__.__name__},
            )
            return TurnResult(outcome=TurnOutcome.FAILED, detail=str(exc))

        # Phase 5.5 (RG-INV-1): reject an oversized assembled context
        # BEFORE it is ever handed to the provider — ContextAssembler
        # itself stays stateless and unaware of any Resource Governance
        # concern (unmodified); measuring and enforcing is the Runtime's
        # own job, exactly like every other limit checked in this method.
        measured = {
            "instructions": assembled.instructions,
            "capability_catalog": list(assembled.capability_catalog),
            "data": [{"source": entry.source, "content": entry.content} for entry in assembled.data],
            # Phase 5.7.3 (TC-INV-11): measured through the same canonical
            # serialization providers will use, inside this one check —
            # never measured separately, never added after the check.
            "target_context": [view.as_model_mapping() for view in assembled.target_context],
        }
        if assembled.environment_context:
            # Phase 5.7.6 (EC-INV-8): same rule for environment context. Added
            # only when present, so measurement without it is byte-identical
            # to pre-5.7.6.
            measured["environment_context"] = [view.as_model_mapping() for view in assembled.environment_context]
        context_size = _estimate_size_bytes(measured)
        try:
            self._governor.check_context_size(context_size)
        except ResourceLimitExceededError as exc:
            self._investigations.halt(
                investigation_id, reason="max_context_bytes_exceeded", details={"detail": str(exc)}
            )
            return TurnResult(outcome=TurnOutcome.HALTED, detail=str(exc))

        # Phase 14 (CT-INV-1): the manifest is durable before the provider is
        # called, and exactly one outcome is durable before any output is
        # used. A failed write raises AuditSinkError and the backstop halts.
        turn = self._call_provider(investigation_id, context, agent, assembled, sources, measured)
        raw_turn = turn.raw_turn

        # Phase 5.5 (RG-INV-2): reject an oversized raw provider return
        # value BEFORE it is parsed into AgentTurnOutput — never
        # truncated, repaired, or partially interpreted first (RT-INV-5).
        output_size = _estimate_size_bytes(raw_turn)
        try:
            self._governor.check_provider_output_size(output_size)
        except ResourceLimitExceededError as exc:
            self._record_outcome(investigation_id, turn, AgentTurnOutcome.PROVIDER_OUTPUT_TOO_LARGE)
            self._investigations.halt(
                investigation_id, reason="max_provider_output_bytes_exceeded", details={"detail": str(exc)}
            )
            return TurnResult(outcome=TurnOutcome.HALTED, detail=str(exc))

        outcome, turn_output, built_findings, capability, detail = self._classify_turn(investigation_id, context, turn)
        self._record_outcome(
            investigation_id,
            turn,
            outcome,
            proposed_capability=capability,
            tool_request_hash=(
                hash_json_normalized(turn_output.tool_request)
                if turn_output is not None and turn_output.tool_request is not None
                else None
            ),
            findings_count=len(turn_output.findings) if turn_output is not None else 0,
        )

        if outcome == AgentTurnOutcome.MALFORMED_TOOL_REQUEST:
            # Recorded as rejected. The existing path consumes a step and
            # fails it as MALFORMED_REQUEST without reaching the Gateway.
            return self._handle_tool_request_turn(investigation_id, context, turn_output)
        if outcome not in ACCEPTED_OUTCOMES:
            return self._rejected_turn(investigation_id, detail)

        if turn_output.next_action == NextAction.CONCLUDE:
            if turn_output.findings:
                ended, stored = self._record_findings(
                    investigation_id, context, turn_output.findings, built=built_findings
                )
                if ended is not None:
                    return ended
                if self._risk_assessor is not None:
                    ended = self._assess_risk(investigation_id, context, stored)
                    if ended is not None:
                        return ended
            self._investigations.complete(investigation_id)
            return TurnResult(outcome=TurnOutcome.CONCLUDED)

        return self._handle_tool_request_turn(investigation_id, context, turn_output)

    # -- Phase 14: Runtime-owned context and forensic turn records ----------

    def _context_window(self, investigation_id: str) -> Tuple[_ContextSource, ...]:
        return tuple(self._context_sources.get(investigation_id, ())[-MAX_CONTEXT_ENTRIES:])

    def _remember_context_source(self, investigation_id: str, result: TurnResult) -> None:
        """Keeps the final tool result of a step this Runtime ran (the result
        the CLI used to pass back) as a future context source. Only a SUCCESS
        with recorded Evidence, or a failed/timed-out result (audited as
        ``dispatch_failed``), qualifies."""
        tool_result, step = result.tool_result, result.step_record
        if tool_result is None or step is None:
            return
        if result.outcome == TurnOutcome.STEP_COMPLETED and step.evidence_id:
            kind, evidence_id, content = SOURCE_KIND_EVIDENCE, step.evidence_id, tool_result.output
        elif result.outcome in (TurnOutcome.STEP_FAILED, TurnOutcome.STEP_TIMED_OUT):
            kind, evidence_id, content = SOURCE_KIND_TOOL_RESULT_ERROR, None, tool_result.error_message
        else:
            return
        content_hash = hash_json_normalized(content)
        if content_hash is None:
            return  # unserializable content never becomes model context
        self._context_sources.setdefault(investigation_id, []).append(
            _ContextSource(tool_result, step.step_id, evidence_id, kind, content, content_hash)
        )

    @staticmethod
    def _check_caller_results(sources: Tuple[_ContextSource, ...], supplied: Sequence[Any]) -> None:
        by_id = {source.tool_result.tool_result_id: source for source in sources}
        seen = set()
        for result in supplied:
            if not isinstance(result, ToolResult):
                raise ContextSourceError("a supplied context result is not a ToolResult")
            source = by_id.get(result.tool_result_id)
            if source is None:
                raise ContextSourceError(
                    "a supplied tool result was not produced by this investigation's recent steps "
                    "(foreign, unknown or stale)"
                )
            if result.tool_result_id in seen:
                raise ContextSourceError("a supplied tool result is duplicated")
            if result != source.tool_result:
                raise ContextSourceError("a supplied tool result differs from the one this investigation recorded")
            seen.add(result.tool_result_id)

    def _reject_context_sources(self, investigation_id: str, exc: ContextSourceError) -> TurnResult:
        self._investigations.fail(investigation_id, reason="context_source_rejected", details={"detail": str(exc)})
        return TurnResult(outcome=TurnOutcome.FAILED, detail=str(exc))

    def _call_provider(
        self,
        investigation_id: str,
        context: InvestigationContext,
        agent: AgentProvider,
        assembled: AssembledContext,
        sources: Tuple[_ContextSource, ...],
        measured: Mapping[str, Any],
    ) -> _ProviderTurn:
        sequence = self._turn_sequences.get(investigation_id, 0) + 1
        turn_id = derive_agent_turn_id(investigation_id, sequence)
        declared = _is_declared_provider(agent)
        prepared = None
        if declared:
            identity = agent.provider_identity()
            if not isinstance(identity, ProviderIdentity) or not identity.declared:
                raise ProviderContractError("a declared provider must return a declared ProviderIdentity")
            prepared = agent.prepare_turn(assembled)
            if not isinstance(prepared, PreparedProviderRequest) or prepared.investigation_id != investigation_id:
                raise ProviderContractError("provider prepared a request of the wrong shape or investigation")
            request_hash = prepared.request_hash
        else:
            # An in-process provider is handed the assembled context itself;
            # that is the request, so that is what is hashed.
            identity = UNDECLARED_PROVIDER
            request_hash = hash_json_normalized({"investigation_id": investigation_id, **measured})
            if request_hash is None:
                raise AuditSinkError("audit fact rejected: FACT_NOT_SERIALIZABLE (provider_request_hash)")
        manifest = ContextManifest(
            turn_id=turn_id,
            turn_sequence=sequence,
            instructions_hash=hash_value(assembled.instructions),
            objective_hash=hash_value(context.objective),
            capability_catalog_hash=hash_json_normalized(list(assembled.capability_catalog)) or "",
            target_context_hash=(
                hash_json_normalized([view.as_model_mapping() for view in assembled.target_context])
                if assembled.target_context
                else None
            ),
            environment_context_hash=(
                hash_json_normalized([view.as_model_mapping() for view in assembled.environment_context])
                if assembled.environment_context
                else None
            ),
            entries=tuple(
                ContextEntry(
                    position=position,
                    source=f"tool_result:{source.tool_result.tool_result_id}",
                    source_kind=source.source_kind,
                    tool_result_id=source.tool_result.tool_result_id,
                    step_id=source.step_id,
                    evidence_id=source.evidence_id,
                    content_hash=source.content_hash,
                )
                for position, source in enumerate(sources)
            ),
            provider=identity,
            provider_request_hash=request_hash,
        )
        self._audit.agent_turn_requested(investigation_id, manifest)
        self._turn_sequences[investigation_id] = sequence
        turn = _ProviderTurn(turn_id=turn_id, sequence=sequence, request_hash=request_hash)
        try:
            if declared:
                response = agent.send_turn(prepared)
                if not isinstance(response, ProviderResponse):
                    raise ProviderContractError("provider returned a response of the wrong shape")
                turn.raw_turn = response.turn
                turn.stop_reason = response.stop_reason
                turn.tool_use_blocks = response.tool_use_blocks
            else:
                turn.raw_turn = agent.next_turn(assembled)
        except Exception as exc:
            # The provider produced nothing usable: record that, then let the
            # existing backstop fail the investigation (LLM-INV-9).
            self._record_outcome(
                investigation_id, turn, AgentTurnOutcome.PROVIDER_FAILURE, error_type=type(exc).__name__
            )
            raise
        turn.received = True
        return turn

    def _classify_turn(self, investigation_id: str, context: InvestigationContext, turn: _ProviderTurn):
        """Decides, before anything is used, whether the Runtime accepts this
        output. Returns ``(outcome, turn_output, built_findings,
        proposed_capability, detail)``. Stores nothing."""
        if turn.tool_use_blocks is not None and turn.tool_use_blocks > 1:
            return AgentTurnOutcome.MULTIPLE_TOOL_USE_BLOCKS, None, None, None, (
                f"provider returned {turn.tool_use_blocks} tool_use blocks; exactly one action per turn is accepted"
            )
        if turn.stop_reason is not None and turn.stop_reason not in ACCEPTED_STOP_REASONS:
            return AgentTurnOutcome.UNSUPPORTED_STOP_REASON, None, None, None, (
                "provider output stopped for an unsupported reason; nothing from it is used"
            )
        try:
            turn_output = AgentTurnOutput.from_dict(turn.raw_turn)
        except MalformedAgentTurnOutputError as exc:
            raw_action = turn.raw_turn.get("next_action") if isinstance(turn.raw_turn, Mapping) else None
            outcome = (
                AgentTurnOutcome.RESERVED_CHANNEL_MISUSE
                if raw_action == "invalid_reserved_tool_use"
                else AgentTurnOutcome.MALFORMED_TURN
            )
            return outcome, None, None, None, str(exc)
        if turn_output.next_action == NextAction.CONCLUDE:
            if not turn_output.findings:
                return AgentTurnOutcome.CONCLUSION, turn_output, None, None, None
            if self._finding_recorder is None:
                # Accepted as reported; storage then fails closed
                # (finding_store_unavailable), exactly as before Phase 14.
                return AgentTurnOutcome.FINDINGS, turn_output, None, None, None
            try:
                built = self._build_findings(investigation_id, context, turn_output.findings)
            except FindingValidationError as exc:
                return AgentTurnOutcome.INVALID_FINDINGS, turn_output, None, None, str(exc)
            return AgentTurnOutcome.FINDINGS, turn_output, built, None, None
        try:
            request = ToolRequestIntake.intake(dict(turn_output.tool_request or {}))
        except MalformedRequestError as exc:
            return AgentTurnOutcome.MALFORMED_TOOL_REQUEST, turn_output, None, None, str(exc)
        return AgentTurnOutcome.TOOL_REQUEST, turn_output, None, request.capability, None

    def _record_outcome(
        self,
        investigation_id: str,
        turn: _ProviderTurn,
        outcome: AgentTurnOutcome,
        *,
        proposed_capability: Optional[str] = None,
        tool_request_hash: Optional[str] = None,
        findings_count: int = 0,
        error_type: Optional[str] = None,
    ) -> None:
        raw = turn.raw_turn
        self._audit.agent_turn_outcome(
            investigation_id,
            TurnOutcomeRecord(
                turn_id=turn.turn_id,
                turn_sequence=turn.sequence,
                outcome=outcome,
                provider_request_hash=turn.request_hash,
                raw_output_hash=hash_json_normalized(raw) if turn.received else None,
                stop_reason=turn.stop_reason,
                tool_use_blocks=turn.tool_use_blocks,
                proposed_capability=proposed_capability,
                tool_request_hash=tool_request_hash,
                findings_count=findings_count,
                explanation=raw.get("explanation") if isinstance(raw, Mapping) else None,
                error_type=error_type,
            ),
        )

    def _rejected_turn(self, investigation_id: str, detail: Optional[str]) -> TurnResult:
        """A rejected model turn consumes a step of the investigation's
        budget, so a flood of malformed output halts instead of looping."""
        try:
            self._governor.record_step_proposed(investigation_id)
        except ResourceLimitExceededError as exc:
            self._investigations.halt(
                investigation_id, reason="max_steps_per_investigation_exceeded", details={"detail": str(exc)}
            )
            return TurnResult(outcome=TurnOutcome.HALTED, detail=str(exc))
        return TurnResult(outcome=TurnOutcome.MALFORMED_TURN, detail=detail)

    # -- Phase 9: evidence-grounded findings (conclude turns only) ---------

    def _record_findings(
        self,
        investigation_id: str,
        context: InvestigationContext,
        raw_findings: Sequence[Mapping[str, Any]],
        *,
        built: Optional[Tuple[Finding, ...]] = None,
    ) -> Tuple[Optional[TurnResult], Tuple[Finding, ...]]:
        """Validates every proposed finding and resolves its evidence
        references before storing any of them. Returns ``(None, stored)``
        when all were stored (the caller then assesses risk, if configured,
        and completes the investigation), or ``(TurnResult, ())`` when this
        turn ends instead.

        Findings never reach Intake, the Policy Gateway, approval or
        dispatch; nothing here can authorize or trigger an action."""
        if self._finding_recorder is None:
            # Never silently drop findings the Agent reported.
            self._investigations.fail(
                investigation_id, reason="finding_store_unavailable", details={"finding_count": len(raw_findings)}
            )
            return (
                TurnResult(outcome=TurnOutcome.FAILED, detail="findings reported but no finding store is configured"),
                (),
            )
        # Phase 14: the batch was validated (a rejection is recorded durably)
        # before the turn was accepted; ``built`` is that validated batch.
        findings = built if built is not None else self._build_findings(investigation_id, context, raw_findings)

        for finding in findings:
            try:
                self._finding_recorder.append(finding)
            except Exception as exc:
                # Same posture as an Evidence write failure: halt rather
                # than complete with an unrecorded conclusion.
                self._investigations.halt(
                    investigation_id,
                    reason="finding_recording_failed",
                    details={"detail": str(exc), "type": exc.__class__.__name__},
                )
                return TurnResult(outcome=TurnOutcome.HALTED, detail=str(exc)), ()
            context.add_finding_ref(finding.finding_id)
            self._audit.finding_created(investigation_id, finding.finding_id, finding.evidence_refs)
        return None, findings

    # -- Phase 10: deterministic risk assessment (conclude turns only) -----

    def _assess_risk(
        self, investigation_id: str, context: InvestigationContext, findings: Tuple[Finding, ...]
    ) -> Optional[TurnResult]:
        """Rates the Findings just stored, through the injected Risk Engine,
        validates the whole result, then stores and audits each assessment.
        Returns ``None`` so the caller completes the investigation, or the
        ``TurnResult`` that ends this turn instead.

        Stored Findings are never altered or removed here. Any engine,
        integrity, validation or storage failure halts the investigation
        (``risk_assessment_failed``); an audit failure reaches the
        fail-closed backstop (``audit_sink_failure``). Not-assessed
        Findings are not a failure. Risk assessments never reach Intake,
        the Policy Gateway, approval or dispatch."""
        try:
            result = self._risk_assessor.assess(investigation_id, findings, assessed_at=self._clock())
            assessments = _validate_risk_result(investigation_id, context, findings, result, self._risk_rule_set)
        except Exception as exc:
            return self._halt_risk_assessment(investigation_id, exc)
        for risk_assessment in assessments:
            try:
                self._risk_recorder.append(risk_assessment)
            except Exception as exc:
                return self._halt_risk_assessment(investigation_id, exc)
            context.add_risk_assessment_ref(risk_assessment.risk_assessment_id)
            self._audit.risk_assessed(investigation_id, risk_assessment)
        return None

    def _halt_risk_assessment(self, investigation_id: str, exc: Exception) -> TurnResult:
        self._investigations.halt(
            investigation_id,
            reason="risk_assessment_failed",
            details={"detail": str(exc), "type": exc.__class__.__name__},
        )
        return TurnResult(outcome=TurnOutcome.HALTED, detail=str(exc))

    def _build_findings(
        self, investigation_id: str, context: InvestigationContext, raw_findings: Sequence[Mapping[str, Any]]
    ) -> Tuple[Finding, ...]:
        """Evidence references are the ``tool_result_id`` values the model
        was shown. Each must resolve, through this investigation's own step
        history, to Evidence recorded for this investigation. An unknown,
        foreign or unrecorded reference fails the whole batch."""
        if len(context.finding_refs) + len(raw_findings) > MAX_FINDINGS_PER_INVESTIGATION:
            raise FindingValidationError(f"more than {MAX_FINDINGS_PER_INVESTIGATION} findings for one investigation")
        recorded = set(context.evidence_refs)
        evidence_by_result = {
            step.tool_result_id: step.evidence_id
            for step in context.step_history
            if step.tool_result_id and step.evidence_id and step.evidence_id in recorded
        }
        findings = []
        for index, raw in enumerate(raw_findings, start=1):
            keys = set(raw)
            if not keys <= _FINDING_FIELDS or not _FINDING_REQUIRED <= keys:
                raise FindingValidationError(
                    f"finding {index} must have title, description and evidence_refs, and only {sorted(_FINDING_FIELDS)}"
                )
            refs = raw["evidence_refs"]
            if not isinstance(refs, list) or not refs or not all(isinstance(r, str) and r for r in refs):
                raise FindingValidationError(f"finding {index}: evidence_refs must be a non-empty list of strings")
            evidence_refs = []
            for ref in refs:
                evidence_id = evidence_by_result.get(ref)
                if evidence_id is None:
                    raise FindingValidationError(
                        f"finding {index} cites a tool result with no recorded evidence in this investigation"
                    )
                evidence_refs.append(evidence_id)
            try:
                findings.append(
                    Finding(
                        finding_id=str(uuid.uuid4()),
                        contract_version=_CONTRACT_VERSION,
                        investigation_id=investigation_id,
                        title=raw["title"],
                        description=raw["description"],
                        evidence_refs=tuple(evidence_refs),
                        created_at=self._clock(),
                        created_by="agent",
                        category=raw.get("category"),
                        confidence=raw.get("confidence"),
                    )
                )
            except FindingValidationError as exc:
                raise FindingValidationError(f"finding {index}: {exc}") from None
        return tuple(findings)

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

            if tool_result.status == ToolResultStatus.ERROR and is_envelope_violation(tool_result.error_message):
                # Phase 11: an envelope violation is deterministic (same
                # handler, same envelope); retrying would only repeat it.
                self._audit.dispatch_failed(
                    investigation_id, tool_result, retry_scheduled=False, reason="capability_envelope_violation"
                )
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

        # Phase 12: what was proposed, durable before the Gateway sees it.
        self._audit.request_proposed(
            investigation_id,
            tool_request.tool_request_id,
            tool_request=tool_request,
            step_id=step.step_id,
            attempt_number=attempt_number,
        )

        step.transition(StepStatus.POLICY_EVALUATING)
        evaluation_context = EvaluationContext(
            authorized_target_refs=frozenset(context.target_refs),
            call_counts=self._governor.capability_call_counts(investigation_id),
        )
        policy_decision = self._policy_evaluator.evaluate(dict(raw_tool_request), evaluation_context)
        step.set_policy_decision_id(policy_decision.policy_decision_id)
        self._audit.policy_evaluated(
            investigation_id, tool_request.tool_request_id, policy_decision, tool_request=tool_request
        )

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
                # Phase 7 (N1): deep copy, so nothing holding the
                # ApprovalRequest can mutate nested values of the
                # ToolRequest that the Gateway validated and will dispatch.
                "parameters": copy.deepcopy(dict(tool_request.parameters)),
            },
            status=ApprovalStatus.PENDING,
            requested_at=requested_at,
            expires_at=expires_at,
        )
        step.set_approval_request_id(approval_request.approval_request_id)
        self._audit.approval_requested(approval_request, step_id=step.step_id)

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

        # Phase 11 (D-1): execution is constrained by the envelope the Gateway
        # attached to this decision, i.e. the Registry state it authorized.
        # The Runtime never invents limits: without an envelope for exactly
        # this capability, nothing is dispatched.
        envelope = policy_decision.capability_envelope
        if envelope is None or envelope.capability != tool_request.capability:
            step.transition(StepStatus.EXECUTING)
            step.transition(StepStatus.STEP_FAILED)
            context.end_current_step()
            detail = "authorized PolicyDecision carries no capability envelope for this capability"
            self._investigations.fail(
                investigation_id, reason="dispatch_precondition_violation", details={"detail": detail}
            )
            return TurnResult(outcome=TurnOutcome.FAILED, step_record=step, detail=detail)
        # The Runtime ceiling can only tighten the Registry timeout (CE-INV-3).
        timeout_seconds = min(envelope.timeout_seconds, self._governor.limits.default_step_timeout_seconds)
        instruction = DispatchInstruction(
            investigation_id=investigation_id,
            tool_request_id=tool_request.tool_request_id,
            capability=tool_request.capability,
            target_ref=tool_request.target_ref,
            parameters=tool_request.parameters,
            resolved_timeout_seconds=timeout_seconds,
            resolved_resource_limits=MappingProxyType({"max_output_bytes": envelope.max_output_bytes}),
            policy_decision_id=policy_decision.policy_decision_id,
            approval_decision_id=approval_decision.approval_decision_id if approval_decision else None,
            attempt_number=step.attempt_number,
            capability_envelope=envelope,
        )
        step.transition(StepStatus.EXECUTING)
        self._audit.dispatch_started(
            investigation_id, tool_request.tool_request_id, instruction=instruction, step_id=step.step_id
        )

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
