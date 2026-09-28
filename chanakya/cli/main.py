"""Minimal CLI and composition root — Phase 7 (ARCHITECTURE.md §1).

The one reviewed place where the production Runtime is assembled:

    build_runtime()      constructs every component and wires them together
    run_investigation()  drives AgentLoopController.run_turn() to a terminal state
    main()               parses arguments, reads the API key once, runs

Authority stays where it already is. The CLI never evaluates policy,
approves, dispatches, executes, or writes Evidence/AuditEvents: it only
constructs components and calls ``InvestigationManager.create_investigation``
/``start``/``cancel`` and ``AgentLoopController.run_turn``. The Policy
Gateway decides, the Runtime executes through ``dispatch()``, and the
``TerminalApprovalProvider`` only answers the ``ApprovalRequest``s the
Runtime issues.

Credentials: ``main()`` is the only code that reads the provider API key
(``ProviderConfig.api_key_env_var``) from the environment. It reads it
once and passes it straight to ``AnthropicProvider``; nothing prints,
logs, or stores it.

Terminal output: everything that could carry model- or target-originated
text (outcome details) is rendered with ``json.dumps(..., ensure_ascii=True)``.

Phase 10: ``build_runtime`` also wires the deterministic Risk Engine and
the append-only ``RiskAssessmentStore`` (``<workdir>/risk``) into the
controller. Rule-based ratings are displayed only after
``verify_risk_provenance`` recomputes every stored assessment; they are
labeled as rule-based, shown apart from the agent's own confidence, and a
finding the rules cannot rate is shown as "not assessed". The rule set is
not configurable here.

Phase 12: ``--review <investigation_id>`` (``review_investigation``)
rebuilds a past investigation from the durable stores through
``chanakya.review``. It is read-only: it reads no credential, builds no
Runtime, provider, Gateway or executor, and creates no files.

Phase 14: the Runtime composes model context itself (``run_investigation``
passes no tool results), the provider endpoint is explicit (the CLI refuses
to start while an SDK redirect variable is set), and ``--review`` shows each
model turn's forensic record, including a screened explanation.

Known gaps (deferred): the Agent's explanation text is not shown live
(``TurnResult`` does not carry it); live investigation state is in memory
only (Evidence, Findings, RiskAssessments and the Audit Log are durable, and
reviewable with ``--review``); no justification is collected with an
approval.
"""
from __future__ import annotations

import argparse
import getpass
import json
import os
import sys
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Mapping, Optional, Sequence, TextIO, Tuple, Union

from chanakya.approval import TerminalApprovalProvider
from chanakya.audit import FilesystemAuditLog
from chanakya.contracts.audit_details import AuditFactError
from chanakya.contracts.enums import Verdict
from chanakya.contracts.investigation_context import InvestigationContext
from chanakya.contracts.risk_taxonomy import active_rule_set
from chanakya.contracts.investigation_request import InvestigationRequest
from chanakya.contracts.target import Target, TargetStatus
from chanakya.evidence import EvidenceStore
from chanakya.findings import FindingStore
from chanakya.policy import PolicyGateway, PolicyRule, PolicySet, RuleMatch
from chanakya.providers.anthropic_provider import FORBIDDEN_SDK_ENVIRONMENT, AnthropicProvider
from chanakya.providers.config import ProviderConfig
from chanakya.registry.bootstrap import production_registry_entries
from chanakya.registry.registry import SecurityToolRegistry
from chanakya.risk import RiskAssessmentStore, RiskEngine, StoreEvidenceFactsReader, verify_risk_provenance
from chanakya.review import reconstruct_investigation
from chanakya.runtime.agent_loop import AgentLoopController, AgentProvider, TurnOutcome, TurnResult
from chanakya.runtime.audit import AuditEmitter
from chanakya.runtime.clock import utcnow_iso
from chanakya.runtime.evidence import FilesystemEvidenceRecorder
from chanakya.runtime.investigation_manager import InvestigationManager
from chanakya.runtime.limits import RuntimeExecutionLimits
from chanakya.runtime.resource_governor import ResourceGovernor
from chanakya.targets.manager import TargetManager
from chanakya.targets.registry import TargetRegistry
from chanakya.tools.bootstrap import build_tool_executor

DEFAULT_MODEL = "claude-opus-5-5"
API_KEY_ENV_VAR = "ANTHROPIC_API_KEY"
DEFAULT_MAX_TURNS = 8
LOCAL_TARGET_ID = "local-host"
_MAX_DETAIL_CHARS = 300

EXIT_COMPLETED = 0
EXIT_NOT_COMPLETED = 1
EXIT_CONFIG_ERROR = 2
EXIT_INTERRUPTED = 130


def _safe_full(value: Any) -> str:
    """Like ``_safe`` but never shortened (finding descriptions are bounded
    at 4000 characters by the Finding contract)."""
    return json.dumps(value, ensure_ascii=True, default=repr)


def _safe(value: Any) -> str:
    """Terminal-safe rendering of a value that may carry untrusted text."""
    text = json.dumps(value, ensure_ascii=True, default=repr)
    return text if len(text) <= _MAX_DETAIL_CHARS else text[:_MAX_DETAIL_CHARS] + "...(truncated for display)"


@dataclass(frozen=True)
class CliRuntime:
    """Everything ``run_investigation`` needs; built only by ``build_runtime``."""

    registry: SecurityToolRegistry
    target_registry: TargetRegistry
    manager: InvestigationManager
    controller: AgentLoopController
    audit: AuditEmitter
    audit_log: FilesystemAuditLog
    evidence_store: EvidenceStore
    finding_store: FindingStore
    risk_store: RiskAssessmentStore
    risk_engine: RiskEngine
    approval_provider: TerminalApprovalProvider
    target_id: str
    approver: str


def _local_host_target(now: str) -> Target:
    return Target(
        target_id=LOCAL_TARGET_ID,
        contract_version="1.0.0",
        target_type="local_host",
        display_name="Local host",
        authorized_scope="This machine only; read-only observation capabilities",
        registered_at=now,
        status=TargetStatus.AUTHORIZED,
    )


def _policy_set(require_approval: bool, now: str) -> PolicySet:
    if not require_approval:
        return PolicySet(policy_set_version="1.0.0", rules=())
    rule = PolicyRule(
        rule_id="cli-require-approval",
        contract_version="1.0.0",
        policy_set_version="1.0.0",
        description="Operator flag --require-approval: every capability needs human approval.",
        enabled=True,
        priority=100,
        match=RuleMatch(),
        effect=Verdict.REQUIRE_APPROVAL,
        reason_template="operator requires human approval for every capability (--require-approval)",
        created_at=now,
        updated_at=now,
        owner="operator",
    )
    return PolicySet(policy_set_version="1.0.0", rules=(rule,))


def _limits() -> RuntimeExecutionLimits:
    return RuntimeExecutionLimits(
        config_version="1.0.0",
        max_steps_per_investigation=10,
        max_tool_calls_per_investigation=10,
        max_investigation_duration_seconds=900,
        default_step_timeout_seconds=60,
        max_retries_per_step=1,
        retry_backoff_seconds=1,
        max_concurrent_investigations=1,
    )


def build_runtime(
    workdir: Union[str, Path],
    *,
    approver: str,
    require_approval: bool = False,
    input_fn: Callable[[str], str] = input,
    output: Optional[TextIO] = None,
) -> CliRuntime:
    """Constructs the production Runtime. Evidence and the Audit Log live
    under ``workdir``. One ``AuditEmitter`` (backed by the durable log) is
    shared by the InvestigationManager and the AgentLoopController."""
    workdir = Path(workdir)
    now = utcnow_iso()

    registry = SecurityToolRegistry(production_registry_entries(now=now))
    target_registry = TargetRegistry([_local_host_target(now)])
    target_manager = TargetManager(target_registry)
    gateway = PolicyGateway(registry, target_registry, _policy_set(require_approval, now))
    executor = build_tool_executor(target_registry, capability_registry=registry)

    evidence_store = EvidenceStore(workdir / "evidence")
    finding_store = FindingStore(workdir / "findings")
    risk_store = RiskAssessmentStore(workdir / "risk")
    # Phase 13: the one active rule set comes from trusted code, never from
    # arguments, environment, configuration or the model.
    rule_set = active_rule_set()
    risk_engine = RiskEngine(StoreEvidenceFactsReader(evidence_store), rule_set=rule_set)
    audit_log = FilesystemAuditLog(workdir / "audit")
    audit = AuditEmitter(audit_log)

    governor = ResourceGovernor(_limits(), clock=lambda: datetime.now(timezone.utc))
    manager = InvestigationManager(target_registry, governor, audit=audit)
    approval_provider = TerminalApprovalProvider(approver, input_fn=input_fn, output=output)
    controller = AgentLoopController(
        manager,
        governor,
        gateway,
        executor,
        approval_provider=approval_provider,
        evidence_recorder=FilesystemEvidenceRecorder(evidence_store),
        audit=audit,
        target_context_source=target_manager,
        finding_recorder=finding_store,
        risk_assessor=risk_engine,
        risk_recorder=risk_store,
        risk_rule_set=rule_set,
    )
    return CliRuntime(
        registry=registry,
        target_registry=target_registry,
        manager=manager,
        controller=controller,
        audit=audit,
        audit_log=audit_log,
        evidence_store=evidence_store,
        finding_store=finding_store,
        risk_store=risk_store,
        risk_engine=risk_engine,
        approval_provider=approval_provider,
        target_id=LOCAL_TARGET_ID,
        approver=approval_provider.approver,
    )


def _report(output: TextIO, turn: int, result: TurnResult) -> None:
    line = f"turn {turn}: {result.outcome.value}"
    if result.tool_result is not None:
        line += f" (tool result: {result.tool_result.status.value})"
    if result.detail:
        line += f" detail={_safe(result.detail)}"
    output.write(line + "\n")
    output.flush()


def run_investigation(
    runtime: CliRuntime,
    agent: AgentProvider,
    objective: str,
    *,
    max_turns: int = DEFAULT_MAX_TURNS,
    output: Optional[TextIO] = None,
) -> Tuple[InvestigationContext, bool]:
    """Creates, starts, and drives one investigation until it is terminal.
    Returns ``(context, interrupted)``. At the turn cap, or on Ctrl+C
    outside an approval prompt, the investigation is cancelled through
    ``InvestigationManager.cancel`` (it ends HALTED, audited)."""
    output = output if output is not None else sys.stdout
    if isinstance(max_turns, bool) or not isinstance(max_turns, int) or max_turns < 1:
        raise ValueError("max_turns must be a positive integer")

    request = InvestigationRequest.from_dict(
        {
            "investigation_request_id": f"cli-{uuid.uuid4()}",
            "contract_version": "1.0.0",
            "objective": objective,
            "requested_targets": [runtime.target_id],
            "submitted_by": runtime.approver,
            "submitted_at": utcnow_iso(),
        }
    )
    context = runtime.manager.create_investigation(request)
    runtime.manager.start(context.investigation_id)
    output.write(f"investigation: {context.investigation_id}\n")
    output.flush()

    interrupted = False
    try:
        for turn in range(1, max_turns + 1):
            # Phase 14 (CT-INV-2): the Runtime composes the model context from
            # this investigation's own results; the CLI selects nothing.
            result = runtime.controller.run_turn(
                context.investigation_id,
                agent,
                capability_catalog=runtime.registry.catalog_view(),
            )
            _report(output, turn, result)
            if context.is_terminal or result.outcome == TurnOutcome.AWAITING_APPROVAL:
                break
        if not context.is_terminal:
            output.write(f"turn limit ({max_turns}) reached or no progress possible; cancelling\n")
            runtime.manager.cancel(context.investigation_id, cancelled_by=runtime.approver)
    except KeyboardInterrupt:
        interrupted = True
        output.write("\ninterrupted; cancelling the investigation\n")
        if not context.is_terminal:
            runtime.manager.cancel(context.investigation_id, cancelled_by=runtime.approver)

    reason = (context.error_state or {}).get("reason")
    output.write(
        f"final status: {context.status.value}"
        + (f" (reason: {_safe(reason)})" if reason else "")
        + f"\nevidence records: {len(context.evidence_refs)}\n"
    )
    _report_findings(output, runtime, context.investigation_id)
    output.flush()
    return context, interrupted


_RISK_HEADER = (
    "risk ratings are computed by fixed rules from the agent's category and evidence provenance; "
    "they are not independently verified and do not establish the absence of risk\n"
)


def _report_findings(output: TextIO, runtime: CliRuntime, investigation_id: str) -> None:
    """Shows the stored, verified findings and, under each, its Phase 10
    rule-based risk assessment. All finding text is model-authored and
    untrusted, so every value is rendered escaped. Ratings are shown only
    after ``verify_risk_provenance`` has recomputed and matched every stored
    assessment; otherwise none is shown. The agent's own confidence and the
    rule-based rating are shown separately, never blended."""
    findings = runtime.finding_store.list_by_investigation(investigation_id)
    output.write(f"findings: {len(findings)} (agent opinions grounded in evidence; not verified facts)\n")
    report = verify_risk_provenance(
        investigation_id,
        risk_store=runtime.risk_store,
        finding_store=runtime.finding_store,
        engine=runtime.risk_engine,
    )
    if findings or not report.verified:
        output.write(_RISK_HEADER)
    if not report.verified:
        output.write("risk assessments: failed verification; not shown\n")
    for number, finding in enumerate(findings, start=1):
        output.write(
            f"  [{number}] {_safe(finding.title)}\n"
            f"      agent-reported confidence: {_safe(finding.confidence)}  category: {_safe(finding.category)}\n"
            + _risk_lines(report, finding.finding_id)
            + f"      evidence: {_safe(list(finding.evidence_refs))}\n"
            f"      {_safe_full(finding.description)}\n"
        )


def _risk_lines(report: Any, finding_id: str) -> str:
    if not report.verified:
        return "      rule-based risk: not shown (failed verification)\n"
    assessment = report.assessments.get(finding_id)
    if assessment is None:
        reason = report.not_assessed.get(finding_id, "unavailable")
        return f"      rule-based risk: not assessed ({_safe(reason)})\n"
    return (
        f"      rule-based risk ({_safe(assessment.scoring_method)}):\n"
        f"          severity: {_safe(assessment.severity.value)}\n"
        f"          basis confidence: {_safe(assessment.confidence)}\n"
        f"          rules: {_safe_full(list(assessment.rule_ids))}\n"
    )


def review_investigation(workdir: Union[str, Path], investigation_id: str, *, output: Optional[TextIO] = None) -> int:
    """Phase 12, ``--review``: read-only reconstruction of a past
    investigation from the durable stores under ``workdir``. No credential
    is read and no provider, Runtime, Gateway or executor is built. The
    stores are opened only if their directories already exist, so nothing
    is created. Every value is rendered escaped. Exit 0 only for a verified,
    consistent record."""
    output = output if output is not None else sys.stdout
    workdir = Path(workdir)
    roots = {name: workdir / name for name in ("audit", "evidence", "findings", "risk")}
    if not roots["audit"].is_dir():
        output.write(f"review: {_safe(investigation_id)}\nstatus: \"not_found\" (no audit log under this workdir)\n")
        return EXIT_NOT_COMPLETED
    audit_log = FilesystemAuditLog(roots["audit"])
    evidence_store = _ReadOnlyEvidence(roots["evidence"])
    review = reconstruct_investigation(
        investigation_id,
        audit_log=audit_log,
        evidence_store=evidence_store,
        finding_store=FindingStore(roots["findings"]),
        risk_store=RiskAssessmentStore(roots["risk"]),
        # Recomputation resolves each assessment's recorded rule set from here.
        risk_engine=RiskEngine(StoreEvidenceFactsReader(evidence_store), rule_set=active_rule_set()),
    )
    _render_review(output, review)
    output.flush()
    return EXIT_COMPLETED if review.consistent else EXIT_NOT_COMPLETED


class _ReadOnlyEvidence(EvidenceStore):
    """``EvidenceStore`` for review: never creates its root (the base
    constructor would), and exposes no ``append``."""

    def __init__(self, root: Path) -> None:  # noqa: D401 — deliberately does not call super().__init__
        self._root = Path(root).resolve()

    def append(self, *args: Any, **kwargs: Any):  # pragma: no cover - never called by review
        raise PermissionError("review is read-only")


def _render_review(output: TextIO, review: Any) -> None:
    write = output.write
    write(f"review: {_safe(review.investigation_id)}\n")
    write(f"status: {_safe(review.status.value)}")
    write(f" (reason: {_safe(review.terminal_reason)})\n" if review.terminal_reason else "\n")
    write(f"audit chain: {'verified' if review.audit_verified else 'NOT VERIFIED'} ({review.audit_record_count} records)\n")
    write(f"consistency: {'consistent' if review.consistent else f'{len(review.anomalies)} anomalies'}\n")
    if review.origin is not None:
        origin = review.origin
        write(f"objective: {_safe_full(origin.objective)}\n")
        write(f"submitted by: {_safe(origin.submitted_by)} at {_safe(origin.submitted_at)}\n")
        write(f"request: {_safe(origin.investigation_request_id)}  targets: {_safe(list(origin.target_refs))}\n")
    write(f"requests: {len(review.requests)}\n")
    for number, request in enumerate(review.requests, start=1):
        write(
            f"  [{number}] {_safe(request.capability)} on {_safe(request.target_ref)}"
            f" (step {_safe(request.step_id)}, attempt {request.attempt_number})\n"
            f"      parameters: {_safe(request.parameters_canonical)} {_safe(request.parameters_hash)}\n"
        )
        policy = request.policy
        if policy is None:
            write("      policy: none recorded\n")
        else:
            write(
                f"      policy: {_safe(policy.verdict)} by rule {_safe(policy.matched_rule)}"
                f"; classification {_safe(policy.classification)}; risk category {_safe(policy.risk_category)}\n"
                f"      reason: {_safe(policy.reason)}\n"
            )
            if policy.envelope_timeout_seconds is not None:
                write(
                    f"      envelope: timeout {policy.envelope_timeout_seconds}s, max output "
                    f"{policy.envelope_max_output_bytes} bytes, schema {_safe(policy.envelope_output_schema_hash)}"
                    + (f", model egress {_safe(policy.envelope_model_egress)}" if policy.envelope_model_egress else "")
                    + "\n"
                )
        if request.approval is not None:
            approval = request.approval
            write(
                f"      approval: requested for {_safe(approval.capability)} on {_safe(approval.target_ref)}"
                f" with {_safe(approval.parameters_canonical)}; expires {_safe(approval.expires_at)};"
                f" outcome {_safe(approval.outcome)} by {_safe(approval.decided_by)}\n"
            )
        if request.dispatch is not None:
            dispatch = request.dispatch
            write(
                f"      dispatch: timeout {dispatch.resolved_timeout_seconds}s, max output {dispatch.max_output_bytes}"
                f" bytes; result {_safe(dispatch.status)}"
                + (f"; error {_safe(dispatch.error_message)}" if dispatch.error_message else "")
                + ("; error text withheld (not Runtime-owned or unsafe)" if dispatch.error_message_withheld else "")
                + "\n"
            )
        if request.evidence_id is not None:
            write(f"      evidence: {_safe(request.evidence_id)}\n")
    # Phase 14: model turns (forensic records; no authority). Every value is
    # escaped; explanations appear only if they were recorded (screened).
    write(f"model turns: {len(review.turns)} (forensic records of model influence; they authorize nothing)\n")
    for turn in review.turns:
        status = "no outcome recorded" if turn.outcome is None else ("accepted" if turn.accepted else "rejected")
        write(
            f"  [{turn.turn_sequence}] {_safe(turn.outcome)} ({status}); stop reason {_safe(turn.stop_reason)}"
            + (f"; proposed {_safe(turn.proposed_capability)}" if turn.proposed_capability else "")
            + "\n"
            f"      provider {_safe(turn.provider)} model {_safe(turn.model)} endpoint {_safe(turn.endpoint)}"
            f" config {_safe(turn.config_version)}\n"
            f"      request {_safe(turn.provider_request_hash)}; context {_safe(list(turn.context_sources))}\n"
            f"      explanation: {_safe(turn.explanation_status)}"
            + (f" {_safe(turn.explanation)}" if turn.explanation is not None else "")
            + "\n"
        )
    write(f"evidence records: {len(review.evidence)}\n")
    for evidence in review.evidence:
        # Phase 15: screening provenance. Absence in an older stream means
        # the record predates the control, never "screened and clean".
        if evidence.screening_version is not None:
            screening = f"screened {_safe(evidence.screening_version)}"
        elif evidence.screening_required:
            screening = "NOT SCREENED"
        else:
            screening = "not assessed (predates Phase 15)"
        write(
            f"  {_safe(evidence.evidence_id)} {_safe(evidence.capability)} on {_safe(evidence.target_id)}"
            f" ({'verified' if evidence.verified else 'NOT VERIFIED'}; {screening})\n"
        )
    write(f"findings: {len(review.findings)} (agent opinions grounded in evidence; not verified facts)\n")
    for finding in review.findings:
        write(
            f"  {_safe(finding.finding_id)} {_safe(finding.title)}\n"
            f"      category {_safe(finding.category)}; agent-reported confidence {_safe(finding.confidence)};"
            f" evidence {_safe(list(finding.evidence_refs))}\n"
        )
    write(f"risk assessments: {len(review.risk_assessments)} (rule-based; not independently verified)\n")
    for risk in review.risk_assessments:
        write(
            f"  {_safe(risk.finding_id)}: severity {_safe(risk.severity)}, basis confidence {_safe(risk.confidence)}"
            f" ({_safe(risk.scoring_method)})\n"
        )
    write(f"anomalies: {len(review.anomalies)}\n")
    for anomaly in review.anomalies:
        write(f"  - {_safe(anomaly.code)}" + (f" ({_safe(anomaly.subject)})" if anomaly.subject else "") + "\n")


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="chanakya", description="Run one Chanakya AI investigation of this host.")
    parser.add_argument("objective", nargs="?", default=None, help="what to investigate")
    parser.add_argument(
        "--review",
        metavar="INVESTIGATION_ID",
        default=None,
        help="read-only: reconstruct and verify a past investigation from --workdir (no model, no execution)",
    )
    parser.add_argument("--model", default=DEFAULT_MODEL, help=f"model id (default: {DEFAULT_MODEL})")
    parser.add_argument("--workdir", default=".chanakya", help="where evidence and the audit log are stored")
    parser.add_argument("--approver", default=None, help="your name, recorded on approval decisions (default: OS user)")
    parser.add_argument("--require-approval", action="store_true", help="require human approval for every capability")
    parser.add_argument("--max-turns", type=int, default=DEFAULT_MAX_TURNS, help=f"turn cap (default: {DEFAULT_MAX_TURNS})")
    return parser


def main(
    argv: Optional[Sequence[str]] = None,
    *,
    environ: Optional[Mapping[str, str]] = None,
    input_fn: Callable[[str], str] = input,
    output: Optional[TextIO] = None,
) -> int:
    output = output if output is not None else sys.stdout
    args = _parser().parse_args(argv)
    environ = os.environ if environ is None else environ

    # Phase 12: review mode is fully separate. It reads no credential,
    # builds no Runtime, provider, Gateway or executor, and writes nothing.
    if args.review is not None:
        if args.objective is not None:
            output.write("error: give either an objective or --review, not both\n")
            return EXIT_CONFIG_ERROR
        return review_investigation(args.workdir, args.review, output=output)
    if args.objective is None:
        output.write("error: an objective is required (or --review INVESTIGATION_ID)\n")
        return EXIT_CONFIG_ERROR

    if args.max_turns < 1:
        output.write("error: --max-turns must be at least 1\n")
        return EXIT_CONFIG_ERROR
    approver = args.approver
    if approver is None:
        try:
            approver = getpass.getuser()
        except Exception:
            approver = ""

    config = ProviderConfig(
        provider="anthropic",
        model=args.model,
        api_key_env_var=API_KEY_ENV_VAR,
        timeout_seconds=60.0,
        findings_channel=True,
    )
    # Phase 14 (T-59): the provider destination and headers come only from
    # ProviderConfig. An environment that would redirect them is refused;
    # only variable names are checked, never their values.
    redirecting = [name for name in FORBIDDEN_SDK_ENVIRONMENT if name in environ]
    if redirecting:
        output.write(f"error: unset {', '.join(redirecting)}; the provider endpoint is fixed by configuration\n")
        return EXIT_CONFIG_ERROR
    api_key = environ.get(config.api_key_env_var)  # the only read of the credential
    if not api_key:
        output.write(f"error: environment variable {config.api_key_env_var} is not set\n")
        return EXIT_CONFIG_ERROR

    try:
        runtime = build_runtime(
            args.workdir, approver=approver, require_approval=args.require_approval, input_fn=input_fn, output=output
        )
        agent = AnthropicProvider(config, api_key)
    except ValueError as exc:
        output.write(f"error: {_safe(str(exc))}\n")
        return EXIT_CONFIG_ERROR
    del api_key

    try:
        context, interrupted = run_investigation(
            runtime, agent, args.objective, max_turns=args.max_turns, output=output
        )
    except AuditFactError as exc:
        # Phase 12 (D-1): the objective or origin facts could not be recorded
        # safely, so no investigation was created. The value is not echoed.
        output.write(f"error: investigation request rejected ({exc.code}: {exc.field})\n")
        return EXIT_CONFIG_ERROR
    if interrupted:
        return EXIT_INTERRUPTED
    return EXIT_COMPLETED if context.status.value == "completed" else EXIT_NOT_COMPLETED


__all__ = ["CliRuntime", "build_runtime", "main", "review_investigation", "run_investigation"]
