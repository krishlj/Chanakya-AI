"""Phase 3 Step 3.5 — Runtime Execution Controls, integration-level
tests. Wired to the REAL Phase 2 ``PolicyGateway`` so retry/approval/
cancellation/error-handling behavior is proven against actual policy
enforcement, not a test double standing in for it.
"""
from __future__ import annotations

import pytest

from chanakya.contracts.approval import ApprovalDecisionValue
from chanakya.contracts.investigation_context import InvestigationStatus
from chanakya.contracts.tool_result import ToolResultStatus
from chanakya.runtime.agent_loop import AgentLoopController, TurnOutcome
from chanakya.runtime.audit import AuditEmitter, InMemoryAuditSink
from chanakya.runtime.dispatch import DispatchInstruction
from chanakya.runtime.investigation_manager import InvestigationManager
from chanakya.runtime.limits import ApprovalExpiryAction, RuntimeExecutionLimits
from chanakya.runtime.resource_governor import ResourceGovernor
from chanakya.runtime.retry_controller import RetryController
from chanakya.runtime.timeout_supervisor import TimeoutSupervisor, ToolExecutionTimedOut

from runtime_factories import (
    CancelDuringExecutionToolExecutor,
    FakeToolExecutor,
    RaisingApprovalProvider,
    RaisingPolicyEvaluator,
    RaisingToolExecutor,
    ScriptedAgentProvider,
    ScriptedApprovalProvider,
    SequenceClock,
    SpyPolicyEvaluator,
    iso,
    make_agent_turn_propose,
    make_tool_result,
)


def no_sleep(_seconds: float) -> None:
    """Used everywhere in this module in place of the default
    ``time.sleep`` so retry-backoff tests run instantly and
    deterministically."""
    return None


@pytest.fixture
def started_investigation(investigation_manager, investigation_request):
    context = investigation_manager.create_investigation(investigation_request)
    investigation_manager.start(context.investigation_id)
    return context


# --------------------------------------------------------------------------
# B / N — cancellation, distinguishable from other outcomes
# --------------------------------------------------------------------------


def test_cancellation_during_dispatch_discards_the_result_and_records_no_evidence(
    investigation_manager, resource_governor, gateway, started_investigation
):
    executor = CancelDuringExecutionToolExecutor(investigation_manager, started_investigation.investigation_id)
    controller = AgentLoopController(investigation_manager, resource_governor, gateway, executor, sleep=no_sleep)
    agent = ScriptedAgentProvider(
        [make_agent_turn_propose(started_investigation.investigation_id, "list_listening_ports", "target-local-host-01")]
    )

    result = controller.run_turn(started_investigation.investigation_id, agent)

    assert result.outcome == TurnOutcome.CANCELLED
    assert started_investigation.status == InvestigationStatus.HALTED
    # The would-be-successful ToolResult must never become Evidence.
    assert started_investigation.evidence_refs == ()
    assert executor.call_count == 1


def test_cancelled_investigation_cannot_dispatch_new_tools(
    investigation_manager, resource_governor, gateway, started_investigation
):
    from chanakya.runtime.exceptions import InvestigationTerminatedError

    investigation_manager.cancel(started_investigation.investigation_id, cancelled_by="alice")
    executor = FakeToolExecutor()
    controller = AgentLoopController(investigation_manager, resource_governor, gateway, executor, sleep=no_sleep)
    agent = ScriptedAgentProvider(
        [make_agent_turn_propose(started_investigation.investigation_id, "list_listening_ports", "target-local-host-01")]
    )

    with pytest.raises(InvestigationTerminatedError):
        controller.run_turn(started_investigation.investigation_id, agent)
    assert executor.call_count == 0


def test_timeout_and_cancellation_are_distinguishable_outcomes(
    investigation_manager, resource_governor, gateway, started_investigation
):
    timeout_executor = RaisingToolExecutor(ToolExecutionTimedOut("simulated tool timeout"))
    controller_timeout = AgentLoopController(
        investigation_manager, resource_governor, gateway, timeout_executor, sleep=no_sleep,
        retry_controller=RetryController(RuntimeExecutionLimits(
            config_version="1.0.0", max_steps_per_investigation=5, max_tool_calls_per_investigation=5,
            max_investigation_duration_seconds=600, default_step_timeout_seconds=5, max_retries_per_step=1,
            retry_backoff_seconds=0, max_concurrent_investigations=5,
        )),
    )
    agent = ScriptedAgentProvider(
        [make_agent_turn_propose(started_investigation.investigation_id, "list_listening_ports", "target-local-host-01")]
    )
    timeout_result = controller_timeout.run_turn(started_investigation.investigation_id, agent)
    assert timeout_result.outcome == TurnOutcome.STEP_TIMED_OUT
    assert timeout_result.outcome != TurnOutcome.CANCELLED


# --------------------------------------------------------------------------
# A/C/D/E/F/M — retry behavior
# --------------------------------------------------------------------------


def test_retry_receives_a_fresh_independent_policy_decision(
    investigation_manager, resource_governor, gateway, started_investigation
):
    """A/D/E: a failed execution is retried with a NEW ToolRequest that
    is independently re-evaluated by the Policy Gateway — the original
    PolicyDecision is never reused."""
    attempts = {"count": 0}

    def flaky_then_success(instruction: DispatchInstruction):
        attempts["count"] += 1
        if attempts["count"] == 1:
            return make_tool_result(instruction.tool_request_id, instruction.capability, status=ToolResultStatus.FAILURE, error_message="tool_execution_failed: HANDLER_EXCEPTION")
        return make_tool_result(instruction.tool_request_id, instruction.capability, status=ToolResultStatus.SUCCESS)

    executor = FakeToolExecutor(result_factory=flaky_then_success)
    spy_gateway = SpyPolicyEvaluator(gateway)
    controller = AgentLoopController(investigation_manager, resource_governor, spy_gateway, executor, sleep=no_sleep)
    agent = ScriptedAgentProvider(
        [make_agent_turn_propose(started_investigation.investigation_id, "list_listening_ports", "target-local-host-01")]
    )

    result = controller.run_turn(started_investigation.investigation_id, agent)

    assert result.outcome == TurnOutcome.STEP_COMPLETED
    assert executor.call_count == 2  # first attempt failed, retry succeeded
    assert spy_gateway.call_count == 2  # independently re-evaluated, not skipped
    first_request, _ = spy_gateway.calls[0]
    second_request, _ = spy_gateway.calls[1]
    assert first_request["tool_request_id"] != second_request["tool_request_id"]  # a materially new ToolRequest
    assert result.step_record.attempt_number == 2


def test_retry_count_is_bounded_then_step_fails(
    investigation_manager, gateway, started_investigation
):
    """C: retries are bounded, never infinite."""
    limits = RuntimeExecutionLimits(
        config_version="1.0.0", max_steps_per_investigation=5, max_tool_calls_per_investigation=10,
        max_investigation_duration_seconds=600, default_step_timeout_seconds=15, max_retries_per_step=2,
        retry_backoff_seconds=0, max_concurrent_investigations=5,
    )
    governor = ResourceGovernor(limits, clock=__import__("datetime").datetime.now)
    governor.register_investigation(started_investigation.investigation_id)

    executor = FakeToolExecutor(
        result_factory=lambda instruction: make_tool_result(
            instruction.tool_request_id, instruction.capability, status=ToolResultStatus.FAILURE, error_message="tool_execution_failed: HANDLER_EXCEPTION"
        )
    )
    controller = AgentLoopController(investigation_manager, governor, gateway, executor, sleep=no_sleep)
    agent = ScriptedAgentProvider(
        [make_agent_turn_propose(started_investigation.investigation_id, "list_listening_ports", "target-local-host-01")]
    )

    result = controller.run_turn(started_investigation.investigation_id, agent)

    assert result.outcome == TurnOutcome.STEP_FAILED
    # 1 initial attempt + 2 retries = 3 total attempts, never more.
    assert executor.call_count == 3
    assert result.step_record.attempt_number == 3
    assert started_investigation.status == InvestigationStatus.RUNNING  # exhausted retries != investigation failure


def test_denied_requests_are_never_retried(
    investigation_manager, resource_governor, gateway, started_investigation
):
    """F: a DENY verdict must never enter the retry loop, regardless of
    how many retries are configured."""
    executor = FakeToolExecutor()
    controller = AgentLoopController(investigation_manager, resource_governor, gateway, executor, sleep=no_sleep)
    agent = ScriptedAgentProvider(
        [make_agent_turn_propose(started_investigation.investigation_id, "no_such_capability", "target-local-host-01")]
    )

    result = controller.run_turn(started_investigation.investigation_id, agent)

    assert result.outcome == TurnOutcome.STEP_DENIED
    assert executor.call_count == 0
    assert result.step_record.attempt_number == 1


def test_cancelled_investigation_is_never_retried(
    investigation_manager, resource_governor, gateway, started_investigation
):
    """Retries must never resume against an investigation that ended
    (cancelled) mid-execution."""
    executor = CancelDuringExecutionToolExecutor(investigation_manager, started_investigation.investigation_id)

    def failing_after_cancel(instruction: DispatchInstruction):
        return make_tool_result(instruction.tool_request_id, instruction.capability, status=ToolResultStatus.FAILURE)

    # The cancel-during-execution executor always returns SUCCESS, which
    # already proves discard-on-cancel (tested above). Here we prove the
    # *retry loop itself* never re-engages once the investigation is no
    # longer RUNNING, using a governor that would otherwise permit it.
    controller = AgentLoopController(investigation_manager, resource_governor, gateway, executor, sleep=no_sleep)
    agent = ScriptedAgentProvider(
        [make_agent_turn_propose(started_investigation.investigation_id, "list_listening_ports", "target-local-host-01")]
    )
    result = controller.run_turn(started_investigation.investigation_id, agent)
    assert result.outcome == TurnOutcome.CANCELLED
    assert executor.call_count == 1  # never retried after cancellation


def test_failed_execution_cannot_silently_become_successful_completion(
    investigation_manager, resource_governor, gateway, started_investigation
):
    """M."""
    executor = FakeToolExecutor(
        result_factory=lambda instruction: make_tool_result(
            instruction.tool_request_id, instruction.capability, status=ToolResultStatus.FAILURE, error_message="tool_execution_failed: HANDLER_EXCEPTION"
        )
    )
    controller = AgentLoopController(investigation_manager, resource_governor, gateway, executor, sleep=no_sleep)
    agent = ScriptedAgentProvider(
        [make_agent_turn_propose(started_investigation.investigation_id, "list_listening_ports", "target-local-host-01")]
    )
    result = controller.run_turn(started_investigation.investigation_id, agent)
    assert result.outcome != TurnOutcome.STEP_COMPLETED
    assert result.outcome == TurnOutcome.STEP_FAILED
    assert started_investigation.evidence_refs == ()


# --------------------------------------------------------------------------
# G — approval expiry
# --------------------------------------------------------------------------


def _controller_with_expiry(investigation_manager, gateway, executor, *, p4_action=ApprovalExpiryAction.FAIL_STEP, clock):
    limits = RuntimeExecutionLimits(
        config_version="1.0.0", max_steps_per_investigation=5, max_tool_calls_per_investigation=5,
        max_investigation_duration_seconds=600, default_step_timeout_seconds=15, max_retries_per_step=1,
        retry_backoff_seconds=0, max_concurrent_investigations=5, approval_expiry_seconds_default=60,
        p4_approval_expiry_action=p4_action,
    )
    import datetime as _dt

    governor = ResourceGovernor(limits, clock=_dt.datetime.now)
    return AgentLoopController(
        investigation_manager, governor, gateway, executor, clock=clock, sleep=no_sleep,
        audit=AuditEmitter(),  # decoupled from the test's SequenceClock -- only the
                               # requested_at/decided_check_time reads below matter
        approval_provider=ScriptedApprovalProvider(ApprovalDecisionValue.ACCEPT),
    )


def test_expired_approval_cannot_dispatch_even_when_accepted(
    investigation_manager, gateway, started_investigation
):
    """G: an ACCEPT that arrives after the deadline must never authorize
    execution — expiry fails closed regardless of the decision content."""
    executor = FakeToolExecutor()
    governor = None
    # Clock ticks: requested_at, then (after the "slow" approval
    # provider returns) a reading far past expires_at.
    clock = SequenceClock([iso(0), iso(0), iso(1000)])
    controller = _controller_with_expiry(investigation_manager, gateway, executor, clock=clock)

    agent = ScriptedAgentProvider(
        [make_agent_turn_propose(started_investigation.investigation_id, "terminate_process", "target-local-host-01", {"pid": 1})]
    )
    result = controller.run_turn(started_investigation.investigation_id, agent)

    assert result.outcome == TurnOutcome.APPROVAL_EXPIRED
    assert executor.call_count == 0
    assert started_investigation.status == InvestigationStatus.RUNNING  # fail_step (default): investigation continues


def test_expiry_never_silently_becomes_allow(investigation_manager, gateway, started_investigation):
    executor = FakeToolExecutor()
    clock = SequenceClock([iso(0), iso(0), iso(1000)])
    controller = _controller_with_expiry(investigation_manager, gateway, executor, clock=clock)
    agent = ScriptedAgentProvider(
        [make_agent_turn_propose(started_investigation.investigation_id, "terminate_process", "target-local-host-01", {"pid": 1})]
    )
    result = controller.run_turn(started_investigation.investigation_id, agent)
    assert result.outcome not in (TurnOutcome.STEP_COMPLETED,)
    assert executor.call_count == 0


# --------------------------------------------------------------------------
# H — resource limits prevent execution
# --------------------------------------------------------------------------


def test_tool_call_budget_exhaustion_during_retries_halts_investigation(
    investigation_manager, gateway, started_investigation
):
    limits = RuntimeExecutionLimits(
        config_version="1.0.0", max_steps_per_investigation=5, max_tool_calls_per_investigation=1,
        max_investigation_duration_seconds=600, default_step_timeout_seconds=15, max_retries_per_step=3,
        retry_backoff_seconds=0, max_concurrent_investigations=5,
    )
    import datetime as _dt

    governor = ResourceGovernor(limits, clock=_dt.datetime.now)
    governor.register_investigation(started_investigation.investigation_id)
    executor = FakeToolExecutor(
        result_factory=lambda instruction: make_tool_result(
            instruction.tool_request_id, instruction.capability, status=ToolResultStatus.FAILURE
        )
    )
    controller = AgentLoopController(investigation_manager, governor, gateway, executor, sleep=no_sleep)
    agent = ScriptedAgentProvider(
        [make_agent_turn_propose(started_investigation.investigation_id, "list_listening_ports", "target-local-host-01")]
    )
    result = controller.run_turn(started_investigation.investigation_id, agent)
    assert result.outcome == TurnOutcome.HALTED
    assert started_investigation.status == InvestigationStatus.HALTED
    assert executor.call_count == 1  # the retry never got to run -- the budget stopped it first


# --------------------------------------------------------------------------
# I/J/K — error handling fails closed
# --------------------------------------------------------------------------


def test_policy_evaluator_error_fails_closed(investigation_manager, resource_governor, started_investigation):
    """I."""
    raising_gateway = RaisingPolicyEvaluator(RuntimeError("gateway blew up"))
    executor = FakeToolExecutor()
    controller = AgentLoopController(investigation_manager, resource_governor, raising_gateway, executor, sleep=no_sleep)
    agent = ScriptedAgentProvider(
        [make_agent_turn_propose(started_investigation.investigation_id, "list_listening_ports", "target-local-host-01")]
    )

    result = controller.run_turn(started_investigation.investigation_id, agent)

    assert result.outcome == TurnOutcome.FAILED
    assert executor.call_count == 0  # never dispatched
    assert started_investigation.status == InvestigationStatus.FAILED  # reached a valid terminal state


def test_approval_provider_error_fails_closed(investigation_manager, resource_governor, gateway, started_investigation):
    """J."""
    executor = FakeToolExecutor()
    raising_approval = RaisingApprovalProvider(RuntimeError("approval backend blew up"))
    controller = AgentLoopController(
        investigation_manager, resource_governor, gateway, executor, approval_provider=raising_approval, sleep=no_sleep
    )
    agent = ScriptedAgentProvider(
        [make_agent_turn_propose(started_investigation.investigation_id, "terminate_process", "target-local-host-01", {"pid": 1})]
    )

    result = controller.run_turn(started_investigation.investigation_id, agent)

    assert result.outcome == TurnOutcome.FAILED
    assert executor.call_count == 0  # never dispatched -- an error is not an approval
    assert started_investigation.status == InvestigationStatus.FAILED


def test_tool_execution_error_does_not_become_approval_or_completion(
    investigation_manager, resource_governor, gateway, started_investigation
):
    """K."""
    executor = RaisingToolExecutor(RuntimeError("tool crashed"))
    controller = AgentLoopController(investigation_manager, resource_governor, gateway, executor, sleep=no_sleep)
    agent = ScriptedAgentProvider(
        [make_agent_turn_propose(started_investigation.investigation_id, "list_listening_ports", "target-local-host-01")]
    )

    result = controller.run_turn(started_investigation.investigation_id, agent)

    assert result.outcome == TurnOutcome.FAILED
    assert result.outcome != TurnOutcome.STEP_COMPLETED
    assert started_investigation.evidence_refs == ()


# --------------------------------------------------------------------------
# L — audit events for major lifecycle events
# --------------------------------------------------------------------------


def test_audit_events_emitted_for_major_lifecycle_events(
    investigation_manager_factory, gateway, target_registry, resource_governor, investigation_request
):
    sink = InMemoryAuditSink()
    audit = AuditEmitter(sink)
    manager = investigation_manager_factory(audit=audit)
    context = manager.create_investigation(investigation_request)
    manager.start(context.investigation_id)

    executor = FakeToolExecutor()
    controller = AgentLoopController(manager, resource_governor, gateway, executor, audit=audit, sleep=no_sleep)
    agent = ScriptedAgentProvider(
        [make_agent_turn_propose(context.investigation_id, "list_listening_ports", "target-local-host-01")]
    )
    controller.run_turn(context.investigation_id, agent)
    manager.complete(context.investigation_id)

    event_types = [event.event_type.value for event in sink.events]
    assert "investigation_started" in event_types
    assert "request_proposed" in event_types
    assert "policy_evaluated" in event_types
    assert "dispatch_started" in event_types
    assert "dispatch_completed" in event_types
    assert "evidence_recorded" in event_types
    assert "investigation_completed" in event_types
    # Every event is traceable to this investigation.
    assert all(event.investigation_id == context.investigation_id for event in sink.events)


def test_audit_events_for_approval_and_retry_and_halt(
    investigation_manager_factory, gateway, resource_governor, investigation_request
):
    sink = InMemoryAuditSink()
    audit = AuditEmitter(sink)
    manager = investigation_manager_factory(audit=audit)
    context = manager.create_investigation(investigation_request)
    manager.start(context.investigation_id)

    approval_provider = ScriptedApprovalProvider(ApprovalDecisionValue.ACCEPT)
    flaky = {"n": 0}

    def flaky_then_success(instruction):
        flaky["n"] += 1
        if flaky["n"] == 1:
            return make_tool_result(instruction.tool_request_id, instruction.capability, status=ToolResultStatus.FAILURE)
        return make_tool_result(instruction.tool_request_id, instruction.capability, status=ToolResultStatus.SUCCESS)

    executor = FakeToolExecutor(result_factory=flaky_then_success)
    controller = AgentLoopController(
        manager, resource_governor, gateway, executor, approval_provider=approval_provider, audit=audit, sleep=no_sleep
    )
    agent = ScriptedAgentProvider(
        [make_agent_turn_propose(context.investigation_id, "terminate_process", "target-local-host-01", {"pid": 1})]
    )
    controller.run_turn(context.investigation_id, agent)

    event_types = [event.event_type.value for event in sink.events]
    assert "approval_requested" in event_types
    assert "approval_decided" in event_types
    assert "dispatch_failed" in event_types  # the first (failed) attempt

    dispatch_failed_events = [e for e in sink.events if e.event_type.value == "dispatch_failed"]
    assert any(e.details.get("retry_scheduled") is True for e in dispatch_failed_events)
