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

Known gaps (deferred): the Agent's explanation text is not shown
(``TurnResult`` does not carry it); investigation state is in memory only
(Evidence and the Audit Log are durable); no justification is collected
with an approval.
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
from chanakya.contracts.enums import Verdict
from chanakya.contracts.investigation_context import InvestigationContext
from chanakya.contracts.investigation_request import InvestigationRequest
from chanakya.contracts.target import Target, TargetStatus
from chanakya.evidence import EvidenceStore
from chanakya.policy import PolicyGateway, PolicyRule, PolicySet, RuleMatch
from chanakya.providers.anthropic_provider import AnthropicProvider
from chanakya.providers.config import ProviderConfig
from chanakya.registry.bootstrap import make_observe_local_host_environment_entry
from chanakya.registry.registry import SecurityToolRegistry
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
_RECENT_RESULTS = 5
_MAX_DETAIL_CHARS = 300

EXIT_COMPLETED = 0
EXIT_NOT_COMPLETED = 1
EXIT_CONFIG_ERROR = 2
EXIT_INTERRUPTED = 130


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

    registry = SecurityToolRegistry([make_observe_local_host_environment_entry(now=now)])
    target_registry = TargetRegistry([_local_host_target(now)])
    target_manager = TargetManager(target_registry)
    gateway = PolicyGateway(registry, target_registry, _policy_set(require_approval, now))
    executor = build_tool_executor(target_registry)

    evidence_store = EvidenceStore(workdir / "evidence")
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
    )
    return CliRuntime(
        registry=registry,
        target_registry=target_registry,
        manager=manager,
        controller=controller,
        audit=audit,
        audit_log=audit_log,
        evidence_store=evidence_store,
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

    recent: Tuple[Any, ...] = ()
    interrupted = False
    try:
        for turn in range(1, max_turns + 1):
            result = runtime.controller.run_turn(
                context.investigation_id,
                agent,
                capability_catalog=runtime.registry.catalog_view(),
                recent_tool_results=recent,
            )
            _report(output, turn, result)
            if result.tool_result is not None:
                recent = (recent + (result.tool_result,))[-_RECENT_RESULTS:]
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
    output.flush()
    return context, interrupted


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="chanakya", description="Run one Chanakya AI investigation of this host.")
    parser.add_argument("objective", help="what to investigate")
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

    if args.max_turns < 1:
        output.write("error: --max-turns must be at least 1\n")
        return EXIT_CONFIG_ERROR
    approver = args.approver
    if approver is None:
        try:
            approver = getpass.getuser()
        except Exception:
            approver = ""

    config = ProviderConfig(provider="anthropic", model=args.model, api_key_env_var=API_KEY_ENV_VAR, timeout_seconds=60.0)
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

    context, interrupted = run_investigation(runtime, agent, args.objective, max_turns=args.max_turns, output=output)
    if interrupted:
        return EXIT_INTERRUPTED
    return EXIT_COMPLETED if context.status.value == "completed" else EXIT_NOT_COMPLETED


__all__ = ["CliRuntime", "build_runtime", "main", "run_investigation"]
