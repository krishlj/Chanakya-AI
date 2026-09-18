"""Phase 3 Step 3.6 §§8-9 — Resource-limit integration across a complete
investigation, and failure injection for every major Runtime dependency
(Agent provider, Policy Gateway, Approval provider, Tool executor,
Evidence recorder, Audit sink, Resource Governor).

Critical rule under test throughout: an exception must never become
ALLOW, ACCEPT, successful tool execution, or successful investigation
completion.
"""
from __future__ import annotations

import datetime as _dt

import pytest

from chanakya.contracts.investigation_context import InvestigationStatus
from chanakya.contracts.tool_result import ToolResultStatus
from chanakya.runtime.agent_loop import AgentLoopController, TurnOutcome
from chanakya.runtime.audit import AuditEmitter, InMemoryAuditSink
from chanakya.runtime.limits import RuntimeExecutionLimits
from chanakya.runtime.resource_governor import ResourceGovernor

from runtime_factories import (
    FakeToolExecutor,
    RaisingApprovalProvider,
    RaisingAuditSink,
    RaisingEvidenceRecorder,
    RaisingPolicyEvaluator,
    RaisingToolExecutor,
    ScriptedAgentProvider,
    make_agent_turn_propose,
)


def no_sleep(_seconds: float) -> None:
    return None


@pytest.fixture
def started_investigation(investigation_manager, investigation_request):
    context = investigation_manager.create_investigation(investigation_request)
    investigation_manager.start(context.investigation_id)
    return context


def _limits(**overrides) -> RuntimeExecutionLimits:
    base = dict(
        config_version="1.0.0", max_steps_per_investigation=2, max_tool_calls_per_investigation=2,
        max_investigation_duration_seconds=600, default_step_timeout_seconds=15, max_retries_per_step=1,
        retry_backoff_seconds=0, max_concurrent_investigations=5,
    )
    base.update(overrides)
    return RuntimeExecutionLimits(**base)


# --------------------------------------------------------------------------
# §8 — resource limit integration
# --------------------------------------------------------------------------


def test_max_steps_checked_before_execution(investigation_manager, gateway, started_investigation):
    governor = ResourceGovernor(_limits(max_steps_per_investigation=1), clock=_dt.datetime.now)
    governor.register_investigation(started_investigation.investigation_id)
    executor = FakeToolExecutor()
    controller = AgentLoopController(investigation_manager, governor, gateway, executor, sleep=no_sleep)

    controller.run_turn(
        started_investigation.investigation_id,
        ScriptedAgentProvider([make_agent_turn_propose(started_investigation.investigation_id, "list_listening_ports", "target-local-host-01")]),
    )
    result = controller.run_turn(
        started_investigation.investigation_id,
        ScriptedAgentProvider([make_agent_turn_propose(started_investigation.investigation_id, "list_listening_ports", "target-local-host-01")]),
    )
    assert result.outcome == TurnOutcome.HALTED
    assert executor.call_count == 1  # the second proposal never dispatched -- checked before execution
    assert started_investigation.status == InvestigationStatus.HALTED


def test_max_tool_calls_checked_before_execution(investigation_manager, gateway, started_investigation):
    governor = ResourceGovernor(_limits(max_tool_calls_per_investigation=1, max_steps_per_investigation=5), clock=_dt.datetime.now)
    governor.register_investigation(started_investigation.investigation_id)
    governor.record_tool_call(started_investigation.investigation_id, "list_listening_ports")  # pre-exhaust the budget
    executor = FakeToolExecutor()
    controller = AgentLoopController(investigation_manager, governor, gateway, executor, sleep=no_sleep)
    result = controller.run_turn(
        started_investigation.investigation_id,
        ScriptedAgentProvider([make_agent_turn_propose(started_investigation.investigation_id, "list_listening_ports", "target-local-host-01")]),
    )
    assert result.outcome == TurnOutcome.HALTED
    assert executor.call_count == 0  # never even attempted -- checked before execution


def test_max_investigation_duration_halts_before_the_agent_is_even_consulted(
    investigation_manager, gateway, started_investigation
):
    limits = _limits(max_investigation_duration_seconds=10)
    ticks = [_dt.datetime(2026, 1, 1, tzinfo=_dt.timezone.utc)]
    governor = ResourceGovernor(limits, clock=lambda: ticks[0])
    governor.register_investigation(started_investigation.investigation_id)
    ticks[0] = ticks[0] + _dt.timedelta(seconds=11)  # already over budget before the turn starts

    executor = FakeToolExecutor()
    controller = AgentLoopController(investigation_manager, governor, gateway, executor, sleep=no_sleep)

    class NeverCalledAgent:
        def next_turn(self, assembled_context):
            raise AssertionError("the Agent must never be consulted once the investigation timeout has expired")

    result = controller.run_turn(started_investigation.investigation_id, NeverCalledAgent())
    assert result.outcome == TurnOutcome.HALTED
    assert executor.call_count == 0


def test_max_concurrent_investigations_enforced(target_registry, resource_governor, investigation_manager):
    from chanakya.contracts.investigation_request import InvestigationRequest
    from chanakya.runtime.exceptions import ResourceLimitExceededError

    limit = resource_governor.limits.max_concurrent_investigations
    for i in range(limit):
        req = InvestigationRequest.from_dict(
            {
                "investigation_request_id": f"conc-{i}", "contract_version": "1.0.0", "objective": "x",
                "requested_targets": ["target-local-host-01"], "submitted_by": "human", "submitted_at": "2026-01-01T00:00:00Z",
            }
        )
        investigation_manager.create_investigation(req)

    overflow_req = InvestigationRequest.from_dict(
        {
            "investigation_request_id": "conc-overflow", "contract_version": "1.0.0", "objective": "x",
            "requested_targets": ["target-local-host-01"], "submitted_by": "human", "submitted_at": "2026-01-01T00:00:00Z",
        }
    )
    with pytest.raises(ResourceLimitExceededError):
        investigation_manager.create_investigation(overflow_req)


def test_max_retries_per_step_enforced_across_investigation(investigation_manager, gateway, started_investigation):
    governor = ResourceGovernor(_limits(max_retries_per_step=1, max_tool_calls_per_investigation=10), clock=_dt.datetime.now)
    governor.register_investigation(started_investigation.investigation_id)
    executor = RaisingToolExecutor(RuntimeError("permanent tool failure"))
    controller = AgentLoopController(investigation_manager, governor, gateway, executor, sleep=no_sleep)
    result = controller.run_turn(
        started_investigation.investigation_id,
        ScriptedAgentProvider([make_agent_turn_propose(started_investigation.investigation_id, "list_listening_ports", "target-local-host-01")]),
    )
    # A raw exception (not a ToolResult) from the executor is an
    # unexpected error, not a retryable ToolResult outcome -- fails
    # closed immediately rather than retrying blindly.
    assert result.outcome == TurnOutcome.FAILED
    assert executor.call_count == 1


def test_resource_limit_failure_never_creates_an_invalid_state_transition(investigation_manager, gateway, started_investigation):
    """A resource-limit halt during dispatch must land on a valid
    terminal step-state (regression coverage for the Step 3.5
    DISPATCHING -> STEP_FAILED bug, fixed via an intermediate EXECUTING
    transition)."""
    governor = ResourceGovernor(_limits(max_tool_calls_per_investigation=1), clock=_dt.datetime.now)
    governor.register_investigation(started_investigation.investigation_id)
    governor.record_tool_call(started_investigation.investigation_id, "list_listening_ports")  # pre-exhaust the budget
    executor = FakeToolExecutor()
    controller = AgentLoopController(investigation_manager, governor, gateway, executor, sleep=no_sleep)
    result = controller.run_turn(
        started_investigation.investigation_id,
        ScriptedAgentProvider([make_agent_turn_propose(started_investigation.investigation_id, "list_listening_ports", "target-local-host-01")]),
    )
    assert result.outcome == TurnOutcome.HALTED
    assert result.step_record.is_terminal
    assert result.step_record.status.value == "step_failed"


# --------------------------------------------------------------------------
# §9 — error integration for every major dependency
# --------------------------------------------------------------------------


def test_agent_provider_failure_fails_closed(investigation_manager, resource_governor, gateway, started_investigation):
    class RaisingAgent:
        def next_turn(self, assembled_context):
            raise RuntimeError("agent/LLM provider unreachable")

    executor = FakeToolExecutor()
    controller = AgentLoopController(investigation_manager, resource_governor, gateway, executor, sleep=no_sleep)
    result = controller.run_turn(started_investigation.investigation_id, RaisingAgent())
    assert result.outcome == TurnOutcome.FAILED
    assert executor.call_count == 0
    assert started_investigation.status == InvestigationStatus.FAILED


def test_policy_gateway_failure_fails_closed_never_allow(investigation_manager, resource_governor, started_investigation):
    executor = FakeToolExecutor()
    controller = AgentLoopController(
        investigation_manager, resource_governor, RaisingPolicyEvaluator(RuntimeError("gateway down")), executor, sleep=no_sleep
    )
    result = controller.run_turn(
        started_investigation.investigation_id,
        ScriptedAgentProvider([make_agent_turn_propose(started_investigation.investigation_id, "list_listening_ports", "target-local-host-01")]),
    )
    assert result.outcome == TurnOutcome.FAILED
    assert executor.call_count == 0


def test_approval_provider_failure_fails_closed_never_accept(investigation_manager, resource_governor, gateway, started_investigation):
    executor = FakeToolExecutor()
    controller = AgentLoopController(
        investigation_manager, resource_governor, gateway, executor,
        approval_provider=RaisingApprovalProvider(RuntimeError("approval backend down")), sleep=no_sleep,
    )
    result = controller.run_turn(
        started_investigation.investigation_id,
        ScriptedAgentProvider([make_agent_turn_propose(started_investigation.investigation_id, "terminate_process", "target-local-host-01", {"pid": 1})]),
    )
    assert result.outcome == TurnOutcome.FAILED
    assert executor.call_count == 0
    assert started_investigation.status == InvestigationStatus.FAILED


def test_tool_executor_failure_fails_closed_never_success(investigation_manager, resource_governor, gateway, started_investigation):
    executor = RaisingToolExecutor(RuntimeError("tool crashed"))
    controller = AgentLoopController(investigation_manager, resource_governor, gateway, executor, sleep=no_sleep)
    result = controller.run_turn(
        started_investigation.investigation_id,
        ScriptedAgentProvider([make_agent_turn_propose(started_investigation.investigation_id, "list_listening_ports", "target-local-host-01")]),
    )
    assert result.outcome == TurnOutcome.FAILED
    assert started_investigation.evidence_refs == ()


def test_evidence_recorder_failure_halts_never_silently_completes(
    target_registry, resource_governor, gateway, investigation_request
):
    """Regression test for the Step 3.6 hardening fix: EVIDENCE_FAILED
    step status + investigation halt (docs/AGENT-RUNTIME.md §9)."""
    from chanakya.runtime.investigation_manager import InvestigationManager

    sink = InMemoryAuditSink()
    audit = AuditEmitter(sink)
    manager = InvestigationManager(target_registry, resource_governor, audit=audit)
    context = manager.create_investigation(investigation_request)
    manager.start(context.investigation_id)

    executor = FakeToolExecutor()  # tool genuinely succeeds
    recorder = RaisingEvidenceRecorder(RuntimeError("evidence store unavailable"))
    controller = AgentLoopController(
        manager, resource_governor, gateway, executor, evidence_recorder=recorder, audit=audit, sleep=no_sleep
    )
    result = controller.run_turn(
        context.investigation_id,
        ScriptedAgentProvider([make_agent_turn_propose(context.investigation_id, "list_listening_ports", "target-local-host-01")]),
    )
    assert result.outcome == TurnOutcome.HALTED
    assert result.step_record.status.value == "evidence_failed"
    assert context.evidence_refs == ()  # never added despite the tool succeeding
    assert context.status == InvestigationStatus.HALTED
    assert recorder.calls  # the recorder really was invoked
    assert any(e.event_type.value == "investigation_halted" for e in sink.events)


def test_audit_sink_failure_halts_never_bypasses_policy(investigation_manager, target_registry, resource_governor, gateway, investigation_request):
    """Critical rule: audit infrastructure itself must not become a
    security bypass. A broken sink must never let dispatch proceed
    silently -- it fails closed (halts), matching docs/AGENT-RUNTIME.md
    §11's treatment of an Audit Log write failure."""
    from chanakya.runtime.investigation_manager import InvestigationManager

    audit = AuditEmitter(RaisingAuditSink())
    manager = InvestigationManager(target_registry, resource_governor, audit=AuditEmitter())  # manager's own audit stays healthy
    context = manager.create_investigation(investigation_request)
    manager.start(context.investigation_id)

    executor = FakeToolExecutor()
    controller = AgentLoopController(manager, resource_governor, gateway, executor, audit=audit, sleep=no_sleep)
    result = controller.run_turn(
        context.investigation_id,
        ScriptedAgentProvider([make_agent_turn_propose(context.investigation_id, "list_listening_ports", "target-local-host-01")]),
    )
    # The broken audit sink aborts the pipeline (fails closed) -- the
    # tool must never actually be dispatched as a side effect of an
    # audit failure being ignored.
    assert result.outcome in (TurnOutcome.HALTED, TurnOutcome.FAILED)
    assert context.status in (InvestigationStatus.HALTED, InvestigationStatus.FAILED)
    assert context.evidence_refs == ()


def test_resource_governor_unexpected_failure_fails_closed(investigation_manager, gateway, started_investigation):
    class BrokenGovernor:
        limits = _limits()

        def check_duration(self, investigation_id):
            raise RuntimeError("governor internal bug")

    executor = FakeToolExecutor()
    controller = AgentLoopController(investigation_manager, BrokenGovernor(), gateway, executor, sleep=no_sleep)
    result = controller.run_turn(
        started_investigation.investigation_id,
        ScriptedAgentProvider([make_agent_turn_propose(started_investigation.investigation_id, "list_listening_ports", "target-local-host-01")]),
    )
    assert result.outcome == TurnOutcome.FAILED
    assert executor.call_count == 0
    assert started_investigation.status == InvestigationStatus.FAILED
