"""Phase 3 Step 3.6 §15 — Property/boundary matrix tests, using plain
``pytest.mark.parametrize`` (no new test dependency) across:
PolicyDecision verdict, ApprovalDecision outcome, investigation status,
and tool execution outcome.
"""
from __future__ import annotations

import datetime as _dt

import pytest

from chanakya.contracts.approval import ApprovalDecisionValue
from chanakya.contracts.investigation_context import InvestigationStatus
from chanakya.contracts.tool_result import ToolResultStatus
from chanakya.runtime.agent_loop import AgentLoopController, TurnOutcome
from chanakya.runtime.exceptions import InvestigationTerminatedError
from chanakya.runtime.limits import RuntimeExecutionLimits
from chanakya.runtime.resource_governor import ResourceGovernor
from chanakya.runtime.timeout_supervisor import ToolExecutionTimedOut

from runtime_factories import (
    FakeToolExecutor,
    RaisingPolicyEvaluator,
    RaisingToolExecutor,
    ScriptedAgentProvider,
    ScriptedApprovalProvider,
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


# -- axis: PolicyDecision verdict (ALLOW/DENY/REQUIRE_APPROVAL/error) x expected outcome --

@pytest.mark.parametrize(
    "capability, use_broken_gateway, expected_outcome, dispatch_expected",
    [
        ("list_listening_ports", False, TurnOutcome.STEP_COMPLETED, True),   # ALLOW
        ("no_such_capability", False, TurnOutcome.STEP_DENIED, False),        # DENY
        ("terminate_process", False, TurnOutcome.AWAITING_APPROVAL, False),   # REQUIRE_APPROVAL
        ("list_listening_ports", True, TurnOutcome.FAILED, False),           # policy evaluator error
    ],
)
def test_policy_decision_axis(
    investigation_manager, resource_governor, gateway, started_investigation,
    capability, use_broken_gateway, expected_outcome, dispatch_expected,
):
    executor = FakeToolExecutor()
    evaluator = RaisingPolicyEvaluator(RuntimeError("boom")) if use_broken_gateway else gateway
    controller = AgentLoopController(investigation_manager, resource_governor, evaluator, executor, sleep=no_sleep)
    params = {"pid": 1} if capability == "terminate_process" else None
    turn = make_agent_turn_propose(started_investigation.investigation_id, capability, "target-local-host-01", params)
    result = controller.run_turn(started_investigation.investigation_id, ScriptedAgentProvider([turn]))
    assert result.outcome == expected_outcome
    assert (executor.call_count == 1) is dispatch_expected


# -- axis: ApprovalDecision outcome (accept/reject/expired/mismatched) x expected outcome --

@pytest.mark.parametrize(
    "approval_mode, expected_outcome, dispatch_expected",
    [
        ("accept", TurnOutcome.STEP_COMPLETED, True),
        ("reject", TurnOutcome.STEP_DENIED, False),
        ("expired", TurnOutcome.APPROVAL_EXPIRED, False),
    ],
)
def test_approval_decision_axis(investigation_manager, gateway, started_investigation, approval_mode, expected_outcome, dispatch_expected):
    from runtime_factories import SequenceClock, iso
    from chanakya.runtime.audit import AuditEmitter

    limits_kwargs = dict(
        config_version="1.0.0", max_steps_per_investigation=5, max_tool_calls_per_investigation=5,
        max_investigation_duration_seconds=600, default_step_timeout_seconds=15, max_retries_per_step=1,
        retry_backoff_seconds=0, max_concurrent_investigations=5,
    )
    if approval_mode == "expired":
        limits_kwargs["approval_expiry_seconds_default"] = 30
    limits = RuntimeExecutionLimits(**limits_kwargs)
    governor = ResourceGovernor(limits, clock=_dt.datetime.now)
    executor = FakeToolExecutor()

    if approval_mode == "accept":
        provider = ScriptedApprovalProvider(ApprovalDecisionValue.ACCEPT)
        clock_kwargs = {}
    elif approval_mode == "reject":
        provider = ScriptedApprovalProvider(ApprovalDecisionValue.DENY)
        clock_kwargs = {}
    else:  # expired
        provider = ScriptedApprovalProvider(ApprovalDecisionValue.ACCEPT)
        clock_kwargs = {"clock": SequenceClock([iso(0), iso(0), iso(999)]), "audit": AuditEmitter()}

    controller = AgentLoopController(
        investigation_manager, governor, gateway, executor, approval_provider=provider, sleep=no_sleep, **clock_kwargs
    )
    turn = make_agent_turn_propose(started_investigation.investigation_id, "terminate_process", "target-local-host-01", {"pid": 1})
    result = controller.run_turn(started_investigation.investigation_id, ScriptedAgentProvider([turn]))
    assert result.outcome == expected_outcome
    assert (executor.call_count == 1) is dispatch_expected


def test_approval_decision_axis_mismatched_never_dispatches():
    from chanakya.contracts.enums import Verdict
    from chanakya.contracts.policy_decision import PolicyDecision
    from chanakya.runtime.dispatch import DispatchInstruction, dispatch
    from chanakya.runtime.exceptions import DispatchPreconditionError
    from runtime_factories import make_approval_decision, make_approval_request

    instruction = DispatchInstruction(
        investigation_id="inv-1", tool_request_id="tr-1", capability="terminate_process",
        target_ref="target-local-host-01", parameters={"pid": 1}, resolved_timeout_seconds=15,
        resolved_resource_limits={}, policy_decision_id="pd-1", attempt_number=1,
    )
    decision = PolicyDecision(
        policy_decision_id="pd-1", contract_version="1.0.0", tool_request_id="tr-1",
        verdict=Verdict.REQUIRE_APPROVAL, matched_rule="x", reason="x", evaluated_at="2026-01-01T00:00:00Z",
    )
    approval_request = make_approval_request("inv-1", "tr-1", "pd-1")
    mismatched_decision = make_approval_decision("some-other-approval-request-id", ApprovalDecisionValue.ACCEPT)
    executor = FakeToolExecutor()
    with pytest.raises(DispatchPreconditionError):
        dispatch(instruction, decision, executor, approval_request=approval_request, approval_decision=mismatched_decision)
    assert executor.call_count == 0


# -- axis: investigation status x run_turn behavior --

@pytest.mark.parametrize(
    "setup, expect_raises, expected_outcome",
    [
        ("running", False, TurnOutcome.STEP_COMPLETED),
        ("awaiting_approval", False, TurnOutcome.AWAITING_APPROVAL),
        ("completed", True, None),
        ("failed", True, None),
        ("halted", True, None),
    ],
)
def test_investigation_status_axis(investigation_manager, resource_governor, gateway, started_investigation, setup, expect_raises, expected_outcome):
    executor = FakeToolExecutor()
    controller = AgentLoopController(investigation_manager, resource_governor, gateway, executor, sleep=no_sleep)

    if setup == "awaiting_approval":
        controller.run_turn(
            started_investigation.investigation_id,
            ScriptedAgentProvider([make_agent_turn_propose(started_investigation.investigation_id, "terminate_process", "target-local-host-01", {"pid": 1})]),
        )
    elif setup == "completed":
        from runtime_factories import make_agent_turn_conclude

        controller.run_turn(started_investigation.investigation_id, ScriptedAgentProvider([make_agent_turn_conclude(started_investigation.investigation_id)]))
    elif setup == "failed":
        investigation_manager.fail(started_investigation.investigation_id, reason="test")
    elif setup == "halted":
        investigation_manager.cancel(started_investigation.investigation_id, cancelled_by="alice")

    turn = make_agent_turn_propose(started_investigation.investigation_id, "list_listening_ports", "target-local-host-01")
    if expect_raises:
        with pytest.raises(InvestigationTerminatedError):
            controller.run_turn(started_investigation.investigation_id, ScriptedAgentProvider([turn]))
    else:
        result = controller.run_turn(started_investigation.investigation_id, ScriptedAgentProvider([turn]))
        assert result.outcome == expected_outcome


# -- axis: tool execution outcome (success/failure/timeout/exception) x expected outcome --

@pytest.mark.parametrize(
    "mode, expected_outcome",
    [
        ("success", TurnOutcome.STEP_COMPLETED),
        ("failure", TurnOutcome.STEP_FAILED),
        ("timeout", TurnOutcome.STEP_TIMED_OUT),
        ("exception", TurnOutcome.FAILED),
    ],
)
def test_tool_execution_outcome_axis(investigation_manager, gateway, started_investigation, mode, expected_outcome):
    limits = RuntimeExecutionLimits(
        config_version="1.0.0", max_steps_per_investigation=5, max_tool_calls_per_investigation=5,
        max_investigation_duration_seconds=600, default_step_timeout_seconds=15, max_retries_per_step=1,
        retry_backoff_seconds=0, max_concurrent_investigations=5,
    )
    governor = ResourceGovernor(limits, clock=_dt.datetime.now)
    governor.register_investigation(started_investigation.investigation_id)

    if mode == "success":
        executor = FakeToolExecutor()
    elif mode == "failure":
        executor = FakeToolExecutor(result_factory=lambda i: make_tool_result(i.tool_request_id, i.capability, status=ToolResultStatus.FAILURE))
    elif mode == "timeout":
        executor = RaisingToolExecutor(ToolExecutionTimedOut("x"))
    else:
        executor = RaisingToolExecutor(RuntimeError("unexpected crash"))

    controller = AgentLoopController(investigation_manager, governor, gateway, executor, sleep=no_sleep)
    turn = make_agent_turn_propose(started_investigation.investigation_id, "list_listening_ports", "target-local-host-01")
    result = controller.run_turn(started_investigation.investigation_id, ScriptedAgentProvider([turn]))
    assert result.outcome == expected_outcome
