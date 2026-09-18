"""Agent Loop Controller — end-to-end orchestration skeleton tests.

Wired to the REAL Phase 2 ``PolicyGateway`` (not a fake) so these tests
prove genuine integration: "Runtime cannot dispatch without a
PolicyDecision" and "REQUIRE_APPROVAL cannot become execution without an
accepted ApprovalDecision" are demonstrated against the actual policy
enforcement code, not a test double standing in for it.
"""
from __future__ import annotations

import pytest

from chanakya.contracts.approval import ApprovalDecisionValue
from chanakya.contracts.investigation_context import InvestigationStatus
from chanakya.contracts.tool_result import ToolResultStatus
from chanakya.runtime.agent_loop import AgentLoopController, TurnOutcome
from chanakya.runtime.exceptions import InvestigationTerminatedError

from runtime_factories import (
    FakeToolExecutor,
    ScriptedAgentProvider,
    ScriptedApprovalProvider,
    SpyPolicyEvaluator,
    make_agent_turn_conclude,
    make_agent_turn_propose,
)


@pytest.fixture
def started_investigation(investigation_manager, investigation_request):
    context = investigation_manager.create_investigation(investigation_request)
    investigation_manager.start(context.investigation_id)
    return context


def make_controller(investigation_manager, resource_governor, gateway, executor, *, approval_provider=None):
    return AgentLoopController(
        investigation_manager,
        resource_governor,
        gateway,
        executor,
        approval_provider=approval_provider,
    )


def test_conclude_turn_completes_investigation_without_dispatch(
    investigation_manager, resource_governor, gateway, started_investigation
):
    executor = FakeToolExecutor()
    controller = make_controller(investigation_manager, resource_governor, gateway, executor)
    agent = ScriptedAgentProvider([make_agent_turn_conclude(started_investigation.investigation_id)])

    result = controller.run_turn(started_investigation.investigation_id, agent)

    assert result.outcome == TurnOutcome.CONCLUDED
    assert started_investigation.status == InvestigationStatus.COMPLETED
    assert executor.call_count == 0


def test_allowed_readonly_capability_dispatches_and_records_evidence(
    investigation_manager, resource_governor, gateway, started_investigation
):
    executor = FakeToolExecutor()
    controller = make_controller(investigation_manager, resource_governor, gateway, executor)
    agent = ScriptedAgentProvider(
        [make_agent_turn_propose(started_investigation.investigation_id, "list_listening_ports", "target-local-host-01")]
    )

    result = controller.run_turn(started_investigation.investigation_id, agent)

    assert result.outcome == TurnOutcome.STEP_COMPLETED
    assert executor.call_count == 1
    assert result.tool_result.status == ToolResultStatus.SUCCESS
    assert len(started_investigation.evidence_refs) == 1
    assert started_investigation.status == InvestigationStatus.RUNNING
    assert started_investigation.current_step_id is None  # step concluded


def test_unknown_capability_is_denied_without_dispatch(
    investigation_manager, resource_governor, gateway, started_investigation
):
    executor = FakeToolExecutor()
    controller = make_controller(investigation_manager, resource_governor, gateway, executor)
    agent = ScriptedAgentProvider(
        [make_agent_turn_propose(started_investigation.investigation_id, "no_such_capability", "target-local-host-01")]
    )

    result = controller.run_turn(started_investigation.investigation_id, agent)

    assert result.outcome == TurnOutcome.STEP_DENIED
    assert executor.call_count == 0
    assert started_investigation.status == InvestigationStatus.RUNNING


def test_state_changing_capability_without_approval_provider_blocks_pending(
    investigation_manager, resource_governor, gateway, started_investigation
):
    """Invariant #5/#6: with no human approval mechanism wired up, a
    require_approval verdict must never resolve to dispatch."""
    executor = FakeToolExecutor()
    controller = make_controller(investigation_manager, resource_governor, gateway, executor, approval_provider=None)
    agent = ScriptedAgentProvider(
        [
            make_agent_turn_propose(
                started_investigation.investigation_id, "terminate_process", "target-local-host-01", {"pid": 4821}
            )
        ]
    )

    result = controller.run_turn(started_investigation.investigation_id, agent)

    assert result.outcome == TurnOutcome.AWAITING_APPROVAL
    assert executor.call_count == 0
    assert started_investigation.status == InvestigationStatus.AWAITING_APPROVAL


def test_state_changing_capability_with_accepted_approval_dispatches(
    investigation_manager, resource_governor, gateway, started_investigation
):
    executor = FakeToolExecutor()
    approval_provider = ScriptedApprovalProvider(ApprovalDecisionValue.ACCEPT)
    controller = make_controller(investigation_manager, resource_governor, gateway, executor, approval_provider=approval_provider)
    agent = ScriptedAgentProvider(
        [
            make_agent_turn_propose(
                started_investigation.investigation_id, "terminate_process", "target-local-host-01", {"pid": 4821}
            )
        ]
    )

    result = controller.run_turn(started_investigation.investigation_id, agent)

    assert result.outcome == TurnOutcome.STEP_COMPLETED
    assert executor.call_count == 1
    assert len(approval_provider.requests) == 1
    assert started_investigation.status == InvestigationStatus.RUNNING


def test_state_changing_capability_with_denied_approval_never_dispatches(
    investigation_manager, resource_governor, gateway, started_investigation
):
    """Invariant #6, human side: a denied approval must never become
    execution, and the investigation resumes running (a denial is
    information, not a fatal error)."""
    executor = FakeToolExecutor()
    approval_provider = ScriptedApprovalProvider(ApprovalDecisionValue.DENY)
    controller = make_controller(investigation_manager, resource_governor, gateway, executor, approval_provider=approval_provider)
    agent = ScriptedAgentProvider(
        [
            make_agent_turn_propose(
                started_investigation.investigation_id, "terminate_process", "target-local-host-01", {"pid": 4821}
            )
        ]
    )

    result = controller.run_turn(started_investigation.investigation_id, agent)

    assert result.outcome == TurnOutcome.STEP_DENIED
    assert executor.call_count == 0
    assert started_investigation.status == InvestigationStatus.RUNNING


def test_malformed_agent_turn_output_is_surfaced_without_side_effects(
    investigation_manager, resource_governor, gateway, started_investigation
):
    executor = FakeToolExecutor()
    controller = make_controller(investigation_manager, resource_governor, gateway, executor)
    agent = ScriptedAgentProvider([{"turn_id": "t1", "next_action": "propose_tool_request"}])  # missing required fields

    result = controller.run_turn(started_investigation.investigation_id, agent)

    assert result.outcome == TurnOutcome.MALFORMED_TURN
    assert executor.call_count == 0
    assert started_investigation.status == InvestigationStatus.RUNNING
    assert started_investigation.step_history == ()


def test_malformed_tool_request_never_reaches_the_policy_gateway(
    investigation_manager, resource_governor, gateway, started_investigation
):
    """Invariant #3: malformed ToolRequests cannot reach dispatch — and,
    more strongly, never even reach the Policy Gateway."""
    executor = FakeToolExecutor()
    spy_gateway = SpyPolicyEvaluator(gateway)
    controller = make_controller(investigation_manager, resource_governor, spy_gateway, executor)

    raw_turn = make_agent_turn_propose(started_investigation.investigation_id, "list_listening_ports", "target-local-host-01")
    del raw_turn["tool_request"]["capability"]  # malformed: missing required field
    agent = ScriptedAgentProvider([raw_turn])

    result = controller.run_turn(started_investigation.investigation_id, agent)

    assert result.outcome == TurnOutcome.MALFORMED_REQUEST
    assert spy_gateway.call_count == 0
    assert executor.call_count == 0


def test_step_budget_exhaustion_halts_investigation_and_prevents_further_turns(
    investigation_manager, resource_governor, gateway, started_investigation
):
    """Invariant #7: Runtime limits prevent additional execution."""
    executor = FakeToolExecutor()
    controller = make_controller(investigation_manager, resource_governor, gateway, executor)
    max_steps = resource_governor.limits.max_steps_per_investigation

    for _ in range(max_steps):
        agent = ScriptedAgentProvider(
            [make_agent_turn_propose(started_investigation.investigation_id, "list_listening_ports", "target-local-host-01")]
        )
        result = controller.run_turn(started_investigation.investigation_id, agent)
        assert result.outcome == TurnOutcome.STEP_COMPLETED

    agent = ScriptedAgentProvider(
        [make_agent_turn_propose(started_investigation.investigation_id, "list_listening_ports", "target-local-host-01")]
    )
    result = controller.run_turn(started_investigation.investigation_id, agent)
    assert result.outcome == TurnOutcome.HALTED
    assert started_investigation.status == InvestigationStatus.HALTED

    # Invariant #8: cancellation/halting prevents further execution.
    with pytest.raises(InvestigationTerminatedError):
        controller.run_turn(started_investigation.investigation_id, ScriptedAgentProvider([make_agent_turn_conclude(started_investigation.investigation_id)]))
    assert executor.call_count == max_steps


def test_cancellation_prevents_further_execution(
    investigation_manager, resource_governor, gateway, started_investigation
):
    """Invariant #8."""
    executor = FakeToolExecutor()
    controller = make_controller(investigation_manager, resource_governor, gateway, executor)

    investigation_manager.cancel(started_investigation.investigation_id, cancelled_by="alice")
    assert started_investigation.status == InvestigationStatus.HALTED

    agent = ScriptedAgentProvider(
        [make_agent_turn_propose(started_investigation.investigation_id, "list_listening_ports", "target-local-host-01")]
    )
    with pytest.raises(InvestigationTerminatedError):
        controller.run_turn(started_investigation.investigation_id, agent)
    assert executor.call_count == 0


def test_retry_style_second_proposal_gets_an_independent_policy_decision(
    investigation_manager, resource_governor, gateway, started_investigation
):
    """Invariant #11: a previous PolicyDecision cannot automatically
    authorize a new (retried) proposal — each turn gets its own,
    independently-evaluated PolicyDecision with a distinct id, and the
    dispatch boundary (tested directly in test_dispatch_boundary.py)
    refuses to mix decisions across requests."""
    executor = FakeToolExecutor()
    controller = make_controller(investigation_manager, resource_governor, gateway, executor)

    first_agent = ScriptedAgentProvider(
        [make_agent_turn_propose(started_investigation.investigation_id, "list_listening_ports", "target-local-host-01")]
    )
    second_agent = ScriptedAgentProvider(
        [make_agent_turn_propose(started_investigation.investigation_id, "list_listening_ports", "target-local-host-01")]
    )

    first_result = controller.run_turn(started_investigation.investigation_id, first_agent)
    second_result = controller.run_turn(started_investigation.investigation_id, second_agent)

    first_policy_decision_id = first_result.step_record.policy_decision_id
    second_policy_decision_id = second_result.step_record.policy_decision_id
    assert first_policy_decision_id != second_policy_decision_id
    assert first_result.step_record.tool_request_id != second_result.step_record.tool_request_id
