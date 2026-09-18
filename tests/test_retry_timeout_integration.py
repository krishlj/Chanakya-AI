"""Phase 3 Step 3.6 §§5-6 — Retry and Timeout integration across the
full Agent Loop, wired to the real PolicyGateway.
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
from chanakya.runtime.timeout_supervisor import ToolExecutionTimedOut

from runtime_factories import (
    FakeToolExecutor,
    RaisingToolExecutor,
    ScriptedAgentProvider,
    SequenceClock,
    SpyPolicyEvaluator,
    iso,
    make_agent_turn_propose,
    make_tool_result,
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
        config_version="1.0.0", max_steps_per_investigation=5, max_tool_calls_per_investigation=10,
        max_investigation_duration_seconds=600, default_step_timeout_seconds=5, max_retries_per_step=2,
        retry_backoff_seconds=0, max_concurrent_investigations=5,
    )
    base.update(overrides)
    return RuntimeExecutionLimits(**base)


# --------------------------------------------------------------------------
# §5 — retry integration
# --------------------------------------------------------------------------


def test_retry_full_pipeline_new_policy_decision_each_attempt(
    investigation_manager, gateway, started_investigation
):
    governor = ResourceGovernor(_limits(), clock=_dt.datetime.now)
    governor.register_investigation(started_investigation.investigation_id)
    spy = SpyPolicyEvaluator(gateway)
    n = {"c": 0}

    def flaky(instruction):
        n["c"] += 1
        status = ToolResultStatus.FAILURE if n["c"] < 3 else ToolResultStatus.SUCCESS
        return make_tool_result(instruction.tool_request_id, instruction.capability, status=status)

    executor = FakeToolExecutor(result_factory=flaky)
    controller = AgentLoopController(investigation_manager, governor, spy, executor, sleep=no_sleep)
    agent = ScriptedAgentProvider(
        [make_agent_turn_propose(started_investigation.investigation_id, "list_listening_ports", "target-local-host-01")]
    )

    result = controller.run_turn(started_investigation.investigation_id, agent)

    assert result.outcome == TurnOutcome.STEP_COMPLETED
    assert executor.call_count == 3
    assert spy.call_count == 3  # every attempt independently policy-evaluated
    # Each call used a distinct tool_request_id (never the same request twice).
    seen_ids = {call[0]["tool_request_id"] for call in spy.calls}
    assert len(seen_ids) == 3
    assert result.step_record.attempt_number == 3
    assert len(started_investigation.evidence_refs) == 1  # only the successful attempt produced evidence


def test_successful_retry_terminates_retry_processing(investigation_manager, resource_governor, gateway, started_investigation):
    n = {"c": 0}

    def flaky(instruction):
        n["c"] += 1
        status = ToolResultStatus.FAILURE if n["c"] == 1 else ToolResultStatus.SUCCESS
        return make_tool_result(instruction.tool_request_id, instruction.capability, status=status)

    executor = FakeToolExecutor(result_factory=flaky)
    controller = AgentLoopController(investigation_manager, resource_governor, gateway, executor, sleep=no_sleep)
    agent = ScriptedAgentProvider(
        [make_agent_turn_propose(started_investigation.investigation_id, "list_listening_ports", "target-local-host-01")]
    )
    result = controller.run_turn(started_investigation.investigation_id, agent)
    assert executor.call_count == 2  # stopped immediately on success, no 3rd attempt
    assert result.outcome == TurnOutcome.STEP_COMPLETED


def test_failed_retries_eventually_reach_a_valid_failure_state(investigation_manager, gateway, started_investigation):
    governor = ResourceGovernor(_limits(max_retries_per_step=2), clock=_dt.datetime.now)
    governor.register_investigation(started_investigation.investigation_id)
    executor = FakeToolExecutor(
        result_factory=lambda i: make_tool_result(i.tool_request_id, i.capability, status=ToolResultStatus.FAILURE)
    )
    controller = AgentLoopController(investigation_manager, governor, gateway, executor, sleep=no_sleep)
    agent = ScriptedAgentProvider(
        [make_agent_turn_propose(started_investigation.investigation_id, "list_listening_ports", "target-local-host-01")]
    )
    result = controller.run_turn(started_investigation.investigation_id, agent)
    assert result.outcome == TurnOutcome.STEP_FAILED
    assert result.step_record.is_terminal
    assert executor.call_count == 3  # bounded: 1 + 2 retries, never more
    assert started_investigation.status == InvestigationStatus.RUNNING  # a valid, non-crashed state


def test_retry_respects_tool_call_resource_limit(investigation_manager, gateway, started_investigation):
    governor = ResourceGovernor(_limits(max_tool_calls_per_investigation=2, max_retries_per_step=10), clock=_dt.datetime.now)
    governor.register_investigation(started_investigation.investigation_id)
    executor = FakeToolExecutor(
        result_factory=lambda i: make_tool_result(i.tool_request_id, i.capability, status=ToolResultStatus.FAILURE)
    )
    controller = AgentLoopController(investigation_manager, governor, gateway, executor, sleep=no_sleep)
    agent = ScriptedAgentProvider(
        [make_agent_turn_propose(started_investigation.investigation_id, "list_listening_ports", "target-local-host-01")]
    )
    result = controller.run_turn(started_investigation.investigation_id, agent)
    assert result.outcome == TurnOutcome.HALTED  # the tool-call budget stopped it, not the (much larger) retry budget
    assert executor.call_count == 2
    assert started_investigation.status == InvestigationStatus.HALTED


def test_no_infinite_retry_is_possible_by_construction(investigation_manager, gateway, started_investigation):
    """However large max_retries_per_step is configured, the loop always
    terminates because RetryController.should_retry is a strict, bounded
    comparison against attempt_number -- there is no code path that
    re-arms an exhausted budget."""
    governor = ResourceGovernor(_limits(max_retries_per_step=50, max_tool_calls_per_investigation=1000), clock=_dt.datetime.now)
    governor.register_investigation(started_investigation.investigation_id)
    executor = FakeToolExecutor(
        result_factory=lambda i: make_tool_result(i.tool_request_id, i.capability, status=ToolResultStatus.FAILURE)
    )
    controller = AgentLoopController(investigation_manager, governor, gateway, executor, sleep=no_sleep)
    agent = ScriptedAgentProvider(
        [make_agent_turn_propose(started_investigation.investigation_id, "list_listening_ports", "target-local-host-01")]
    )
    result = controller.run_turn(started_investigation.investigation_id, agent)
    assert executor.call_count == 51  # 1 + 50, exactly -- terminates, does not hang
    assert result.outcome == TurnOutcome.STEP_FAILED


# --------------------------------------------------------------------------
# §6 — timeout integration
# --------------------------------------------------------------------------


def test_executor_signaled_timeout_across_full_loop_produces_correct_step_and_audit(
    investigation_manager, resource_governor, gateway, started_investigation
):
    sink = InMemoryAuditSink()
    audit = AuditEmitter(sink)
    executor = RaisingToolExecutor(ToolExecutionTimedOut("executor's own timeout fired"))
    controller = AgentLoopController(investigation_manager, resource_governor, gateway, executor, audit=audit, sleep=no_sleep)
    agent = ScriptedAgentProvider(
        [make_agent_turn_propose(started_investigation.investigation_id, "list_listening_ports", "target-local-host-01")]
    )

    result = controller.run_turn(started_investigation.investigation_id, agent)

    assert result.outcome == TurnOutcome.STEP_TIMED_OUT
    assert result.tool_result.status == ToolResultStatus.TIMEOUT
    assert started_investigation.evidence_refs == ()  # a timed-out result is never trusted as evidence
    dispatch_failed = [e for e in sink.events if e.event_type.value == "dispatch_failed"]
    assert dispatch_failed and dispatch_failed[-1].details["status"] == "timeout"


class _EverIncreasingClock:
    """Returns a strictly increasing ISO timestamp, stepping forward by
    a large amount every call. Unlike a fixed ``SequenceClock``, this
    needs no assumption about exactly how many clock reads happen before
    the pair ``TimeoutSupervisor.execute_with_timeout`` cares about —
    ANY two consecutive reads it takes will show a large elapsed time,
    guaranteed to exceed a small configured budget."""

    def __init__(self, step_seconds: int = 100) -> None:
        self._step = step_seconds
        self._calls = 0

    def __call__(self) -> str:
        value = iso(self._calls * self._step)
        self._calls += 1
        return value


def test_wall_clock_backstop_overrides_a_late_but_technically_successful_result(
    investigation_manager, gateway, started_investigation
):
    """The executor itself does not signal a timeout and returns SUCCESS
    -- but wall-clock time shows it overran its budget. That result must
    never be trusted merely because it eventually arrived."""
    limits = _limits(default_step_timeout_seconds=5)
    governor = ResourceGovernor(limits, clock=_dt.datetime.now)
    governor.register_investigation(started_investigation.investigation_id)
    executor = FakeToolExecutor()  # returns SUCCESS
    controller = AgentLoopController(
        investigation_manager, governor, gateway, executor, sleep=no_sleep,
        clock=_EverIncreasingClock(step_seconds=100),
    )
    agent = ScriptedAgentProvider(
        [make_agent_turn_propose(started_investigation.investigation_id, "list_listening_ports", "target-local-host-01")]
    )
    result = controller.run_turn(started_investigation.investigation_id, agent)
    assert result.outcome in (TurnOutcome.STEP_TIMED_OUT, TurnOutcome.STEP_FAILED, TurnOutcome.HALTED)
    assert result.outcome != TurnOutcome.STEP_COMPLETED
    assert started_investigation.evidence_refs == ()


def test_timed_out_step_follows_retry_controller_rules(investigation_manager, gateway, started_investigation):
    governor = ResourceGovernor(_limits(max_retries_per_step=1), clock=_dt.datetime.now)
    governor.register_investigation(started_investigation.investigation_id)
    executor = RaisingToolExecutor(ToolExecutionTimedOut("always times out"))
    controller = AgentLoopController(investigation_manager, governor, gateway, executor, sleep=no_sleep)
    agent = ScriptedAgentProvider(
        [make_agent_turn_propose(started_investigation.investigation_id, "list_listening_ports", "target-local-host-01")]
    )
    result = controller.run_turn(started_investigation.investigation_id, agent)
    assert executor.call_count == 2  # 1 initial + 1 retry (max_retries_per_step=1), then bounded stop
    assert result.outcome == TurnOutcome.STEP_TIMED_OUT


def test_investigation_cannot_silently_report_success_from_a_timed_out_result(
    investigation_manager, resource_governor, gateway, started_investigation
):
    executor = RaisingToolExecutor(ToolExecutionTimedOut("x"))
    controller = AgentLoopController(investigation_manager, resource_governor, gateway, executor, sleep=no_sleep)
    agent = ScriptedAgentProvider(
        [make_agent_turn_propose(started_investigation.investigation_id, "list_listening_ports", "target-local-host-01")]
    )
    result = controller.run_turn(started_investigation.investigation_id, agent)
    assert result.outcome != TurnOutcome.STEP_COMPLETED
    assert result.outcome != TurnOutcome.CONCLUDED
    assert started_investigation.evidence_refs == ()
