"""Phase 3 Step 3.6 §10 — State machine integration: proving that no
complete Runtime flow (not just the unit-level transition tables tested
in test_investigation_context.py / test_step_record.py) can ever produce
an invalid investigation-level or step-level transition.
"""
from __future__ import annotations

import datetime as _dt

import pytest

from chanakya.contracts.investigation_context import (
    InvalidInvestigationTransitionError,
    InvestigationStatus,
)
from chanakya.contracts.tool_result import ToolResultStatus
from chanakya.runtime.agent_loop import AgentLoopController, TurnOutcome
from chanakya.runtime.limits import RuntimeExecutionLimits
from chanakya.runtime.resource_governor import ResourceGovernor
from chanakya.runtime.step_record import ALLOWED_STEP_TRANSITIONS, StepStatus

from runtime_factories import (
    FakeToolExecutor,
    RaisingToolExecutor,
    ScriptedAgentProvider,
    make_agent_turn_conclude,
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


# -- investigation-level: forbidden transitions can never be reached via any integration path --


def test_running_to_completed_requires_explicit_conclude(investigation_manager, resource_governor, gateway, started_investigation):
    """RUNNING -> COMPLETED must never happen as a side effect of a
    successful dispatch alone -- only an explicit `conclude` turn."""
    executor = FakeToolExecutor()
    controller = AgentLoopController(investigation_manager, resource_governor, gateway, executor, sleep=no_sleep)
    controller.run_turn(
        started_investigation.investigation_id,
        ScriptedAgentProvider([make_agent_turn_propose(started_investigation.investigation_id, "list_listening_ports", "target-local-host-01")]),
    )
    assert started_investigation.status == InvestigationStatus.RUNNING  # not auto-completed
    controller.run_turn(
        started_investigation.investigation_id,
        ScriptedAgentProvider([make_agent_turn_conclude(started_investigation.investigation_id)]),
    )
    assert started_investigation.status == InvestigationStatus.COMPLETED


@pytest.mark.parametrize(
    "terminal_setup",
    ["completed", "halted", "failed"],
)
def test_no_integration_path_can_leave_a_terminal_state(
    investigation_manager, resource_governor, gateway, started_investigation, terminal_setup
):
    executor = FakeToolExecutor()
    controller = AgentLoopController(investigation_manager, resource_governor, gateway, executor, sleep=no_sleep)

    if terminal_setup == "completed":
        controller.run_turn(started_investigation.investigation_id, ScriptedAgentProvider([make_agent_turn_conclude(started_investigation.investigation_id)]))
    elif terminal_setup == "halted":
        investigation_manager.cancel(started_investigation.investigation_id, cancelled_by="alice")
    else:
        investigation_manager.fail(started_investigation.investigation_id, reason="test")

    assert started_investigation.status == InvestigationStatus(terminal_setup)

    from chanakya.runtime.exceptions import InvestigationTerminatedError

    with pytest.raises(InvestigationTerminatedError):
        controller.run_turn(
            started_investigation.investigation_id,
            ScriptedAgentProvider([make_agent_turn_propose(started_investigation.investigation_id, "list_listening_ports", "target-local-host-01")]),
        )
    # Confirm the state machine itself independently rejects a direct
    # attempt to leave any of these terminal states.
    for candidate in InvestigationStatus:
        with pytest.raises(InvalidInvestigationTransitionError):
            started_investigation.transition_status(candidate)


def test_awaiting_approval_to_failed_is_never_direct_even_under_error(
    investigation_manager, resource_governor, gateway, started_investigation
):
    """The Step 3.6 fail-closed helper resolves AWAITING_APPROVAL -> FAILED
    via the one existing valid exit (-> RUNNING) rather than a new,
    undocumented transition edge; verify the investigation never gets
    stuck and never silently stays AWAITING_APPROVAL forever."""
    from runtime_factories import RaisingApprovalProvider

    executor = FakeToolExecutor()
    controller = AgentLoopController(
        investigation_manager, resource_governor, gateway, executor,
        approval_provider=RaisingApprovalProvider(RuntimeError("boom")), sleep=no_sleep,
    )
    controller.run_turn(
        started_investigation.investigation_id,
        ScriptedAgentProvider([make_agent_turn_propose(started_investigation.investigation_id, "terminate_process", "target-local-host-01", {"pid": 1})]),
    )
    assert started_investigation.status == InvestigationStatus.FAILED  # reached, not stuck at awaiting_approval


# -- step-level: forbidden transitions can never be reached via any integration path --


def test_dispatching_to_step_failed_never_direct_goes_through_executing(
    investigation_manager, gateway, started_investigation
):
    """Regression coverage for the Step 3.5 bug where a resource-limit
    failure tried DISPATCHING -> STEP_FAILED directly (invalid); the
    fix routes through EXECUTING first, which is the only valid path."""
    governor = ResourceGovernor(
        RuntimeExecutionLimits(
            config_version="1.0.0", max_steps_per_investigation=5, max_tool_calls_per_investigation=1,
            max_investigation_duration_seconds=600, default_step_timeout_seconds=15, max_retries_per_step=1,
            retry_backoff_seconds=0, max_concurrent_investigations=5,
        ),
        clock=_dt.datetime.now,
    )
    governor.register_investigation(started_investigation.investigation_id)
    governor.record_tool_call(started_investigation.investigation_id, "list_listening_ports")
    executor = FakeToolExecutor()
    controller = AgentLoopController(investigation_manager, governor, gateway, executor, sleep=no_sleep)
    result = controller.run_turn(
        started_investigation.investigation_id,
        ScriptedAgentProvider([make_agent_turn_propose(started_investigation.investigation_id, "list_listening_ports", "target-local-host-01")]),
    )
    assert result.step_record.status == StepStatus.STEP_FAILED
    assert result.step_record.is_terminal
    # Directly assert the state machine's own rule: DISPATCHING has no
    # direct edge to STEP_FAILED.
    assert StepStatus.STEP_FAILED not in ALLOWED_STEP_TRANSITIONS[StepStatus.DISPATCHING]
    assert StepStatus.EXECUTING in ALLOWED_STEP_TRANSITIONS[StepStatus.DISPATCHING]
    assert StepStatus.STEP_FAILED in ALLOWED_STEP_TRANSITIONS[StepStatus.EXECUTING]


def test_awaiting_step_approval_never_transitions_directly_to_step_failed(
    investigation_manager, resource_governor, gateway, started_investigation
):
    """Regression coverage for the Step 3.6 bug where the
    cancellation-during-approval-wait guard tried
    AWAITING_STEP_APPROVAL -> STEP_FAILED directly (invalid); the fix
    uses STEP_DENIED, the only terminal-shaped exit that state allows."""
    from chanakya.contracts.approval import ApprovalDecision, ApprovalDecisionValue, ApprovalRequest
    from runtime_factories import make_approval_decision

    class CancellingApprovalProvider:
        def request_approval(self, approval_request: ApprovalRequest) -> ApprovalDecision:
            investigation_manager.cancel(started_investigation.investigation_id, cancelled_by="alice")
            return make_approval_decision(approval_request.approval_request_id, ApprovalDecisionValue.ACCEPT)

    executor = FakeToolExecutor()
    controller = AgentLoopController(
        investigation_manager, resource_governor, gateway, executor,
        approval_provider=CancellingApprovalProvider(), sleep=no_sleep,
    )
    result = controller.run_turn(
        started_investigation.investigation_id,
        ScriptedAgentProvider([make_agent_turn_propose(started_investigation.investigation_id, "terminate_process", "target-local-host-01", {"pid": 1})]),
    )
    assert result.step_record.status == StepStatus.STEP_DENIED
    assert StepStatus.STEP_FAILED not in ALLOWED_STEP_TRANSITIONS[StepStatus.AWAITING_STEP_APPROVAL]
    assert StepStatus.STEP_DENIED in ALLOWED_STEP_TRANSITIONS[StepStatus.AWAITING_STEP_APPROVAL]


def test_step_completed_to_evidence_failed_is_the_only_failure_exit(investigation_manager, resource_governor, gateway, started_investigation):
    from runtime_factories import RaisingEvidenceRecorder

    executor = FakeToolExecutor()
    controller = AgentLoopController(
        investigation_manager, resource_governor, gateway, executor,
        evidence_recorder=RaisingEvidenceRecorder(RuntimeError("boom")), sleep=no_sleep,
    )
    result = controller.run_turn(
        started_investigation.investigation_id,
        ScriptedAgentProvider([make_agent_turn_propose(started_investigation.investigation_id, "list_listening_ports", "target-local-host-01")]),
    )
    assert result.step_record.status == StepStatus.EVIDENCE_FAILED
    assert StepStatus.EVIDENCE_FAILED in ALLOWED_STEP_TRANSITIONS[StepStatus.STEP_COMPLETED]


@pytest.mark.parametrize("terminal", [StepStatus.STEP_DENIED, StepStatus.STEP_FAILED, StepStatus.STEP_TIMED_OUT, StepStatus.EVIDENCE_RECORDED, StepStatus.EVIDENCE_FAILED])
def test_terminal_step_states_have_no_outbound_edge_anywhere_in_the_integrated_machine(terminal):
    assert ALLOWED_STEP_TRANSITIONS[terminal] == frozenset()
