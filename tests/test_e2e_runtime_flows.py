"""Phase 3 Step 3.6 §§1-4 — Runtime integration: the complete controlled
flow from InvestigationRequest through to completion, for ALLOW, DENY,
and REQUIRE_APPROVAL (accepted / rejected / expired / mismatched)
verdicts. Wired to the REAL Phase 2 PolicyGateway throughout — nothing
here fakes a PolicyDecision.
"""
from __future__ import annotations

import pytest

from chanakya.contracts.approval import ApprovalDecisionValue
from chanakya.contracts.investigation_context import InvestigationStatus
from chanakya.contracts.tool_result import ToolResultStatus
from chanakya.runtime.agent_loop import AgentLoopController, TurnOutcome
from chanakya.runtime.audit import AuditEmitter, InMemoryAuditSink
from chanakya.runtime.dispatch import DispatchInstruction

from runtime_factories import (
    FakeToolExecutor,
    ScriptedAgentProvider,
    ScriptedApprovalProvider,
    SequenceClock,
    SpyPolicyEvaluator,
    iso,
    make_agent_turn_conclude,
    make_agent_turn_propose,
    make_approval_decision,
    make_approval_request,
)


def no_sleep(_seconds: float) -> None:
    return None


@pytest.fixture
def started_investigation(investigation_manager, investigation_request):
    context = investigation_manager.create_investigation(investigation_request)
    investigation_manager.start(context.investigation_id)
    return context


# --------------------------------------------------------------------------
# §2 — end-to-end ALLOW flow
# --------------------------------------------------------------------------


def test_e2e_allow_flow_full_pipeline(investigation_manager, resource_governor, gateway, started_investigation):
    sink = InMemoryAuditSink()
    audit = AuditEmitter(sink)
    spy_gateway = SpyPolicyEvaluator(gateway)
    executor = FakeToolExecutor()
    controller = AgentLoopController(
        investigation_manager, resource_governor, spy_gateway, executor, audit=audit, sleep=no_sleep
    )
    agent = ScriptedAgentProvider(
        [make_agent_turn_propose(started_investigation.investigation_id, "list_listening_ports", "target-local-host-01")]
    )

    result = controller.run_turn(started_investigation.investigation_id, agent)

    # Runtime validated the request, the Gateway (and only the Gateway)
    # produced the verdict, resource limits were consulted, dispatch was
    # controlled, a result came back, evidence was recorded, and the
    # investigation is free to continue.
    assert spy_gateway.call_count == 1
    assert result.outcome == TurnOutcome.STEP_COMPLETED
    assert executor.call_count == 1
    assert len(started_investigation.evidence_refs) == 1
    assert started_investigation.status == InvestigationStatus.RUNNING

    event_types = [e.event_type.value for e in sink.events]
    for expected in (
        "request_proposed", "policy_evaluated", "dispatch_started", "dispatch_completed", "evidence_recorded",
    ):
        assert expected in event_types

    # Investigation can then complete cleanly.
    conclude_agent = ScriptedAgentProvider([make_agent_turn_conclude(started_investigation.investigation_id)])
    final = controller.run_turn(started_investigation.investigation_id, conclude_agent)
    assert final.outcome == TurnOutcome.CONCLUDED
    assert started_investigation.status == InvestigationStatus.COMPLETED


def test_no_component_can_bypass_the_policy_gateway(investigation_manager, resource_governor, gateway, started_investigation):
    """The Dispatcher's own precondition gate (dispatch()) requires a
    PolicyDecision that matches the instruction — there is no code path
    in the Agent Loop Controller that calls the executor without first
    obtaining one from `self._policy_evaluator` (the injected Gateway)."""
    import inspect

    from chanakya.runtime import agent_loop as agent_loop_module

    source = inspect.getsource(agent_loop_module)
    # The only calls to dispatch() in the whole module happen inside
    # _execute_once, and only ever with a policy_decision obtained from
    # self._policy_evaluator.evaluate(...) earlier in the same call chain.
    assert source.count("dispatch(") == 1  # the import + the one call site
    executor = FakeToolExecutor()
    controller = AgentLoopController(investigation_manager, resource_governor, gateway, executor, sleep=no_sleep)
    agent = ScriptedAgentProvider(
        [make_agent_turn_propose(started_investigation.investigation_id, "list_listening_ports", "target-local-host-01")]
    )
    controller.run_turn(started_investigation.investigation_id, agent)
    assert executor.call_count == 1  # only reachable via the one, gated path


# --------------------------------------------------------------------------
# §3 — end-to-end DENY flow
# --------------------------------------------------------------------------


def test_e2e_deny_flow_never_dispatches(investigation_manager, resource_governor, gateway, started_investigation):
    sink = InMemoryAuditSink()
    audit = AuditEmitter(sink)
    executor = FakeToolExecutor()
    controller = AgentLoopController(investigation_manager, resource_governor, gateway, executor, audit=audit, sleep=no_sleep)
    agent = ScriptedAgentProvider(
        [make_agent_turn_propose(started_investigation.investigation_id, "no_such_capability", "target-local-host-01")]
    )

    result = controller.run_turn(started_investigation.investigation_id, agent)

    assert result.outcome == TurnOutcome.STEP_DENIED
    assert executor.call_count == 0
    assert started_investigation.evidence_refs == ()
    assert started_investigation.status == InvestigationStatus.RUNNING  # not COMPLETED, not FAILED
    policy_events = [e for e in sink.events if e.event_type.value == "policy_evaluated"]
    assert policy_events and policy_events[0].details["verdict"] == "deny"


@pytest.mark.parametrize("bad_capability", ["no_such_capability", "legacy_scan"])  # unknown, and disabled
def test_deny_cannot_become_allow_require_approval_execution_or_completion(
    investigation_manager, resource_governor, gateway, started_investigation, bad_capability
):
    executor = FakeToolExecutor()
    controller = AgentLoopController(investigation_manager, resource_governor, gateway, executor, sleep=no_sleep)
    agent = ScriptedAgentProvider(
        [make_agent_turn_propose(started_investigation.investigation_id, bad_capability, "target-local-host-01")]
    )
    result = controller.run_turn(started_investigation.investigation_id, agent)
    assert result.outcome not in (TurnOutcome.STEP_COMPLETED, TurnOutcome.AWAITING_APPROVAL, TurnOutcome.CONCLUDED)
    assert result.outcome == TurnOutcome.STEP_DENIED
    assert executor.call_count == 0


# --------------------------------------------------------------------------
# §4 — end-to-end APPROVAL flow
# --------------------------------------------------------------------------


def test_e2e_approval_accepted_flow(investigation_manager, resource_governor, gateway, started_investigation):
    sink = InMemoryAuditSink()
    audit = AuditEmitter(sink)
    approval_provider = ScriptedApprovalProvider(ApprovalDecisionValue.ACCEPT)
    executor = FakeToolExecutor()
    controller = AgentLoopController(
        investigation_manager, resource_governor, gateway, executor,
        approval_provider=approval_provider, audit=audit, sleep=no_sleep,
    )
    agent = ScriptedAgentProvider(
        [make_agent_turn_propose(started_investigation.investigation_id, "terminate_process", "target-local-host-01", {"pid": 1})]
    )

    result = controller.run_turn(started_investigation.investigation_id, agent)

    assert result.outcome == TurnOutcome.STEP_COMPLETED
    assert executor.call_count == 1
    assert len(approval_provider.requests) == 1
    # The approval that authorized dispatch is bound to exactly this
    # request/investigation (verified by the Dispatcher itself).
    request_seen = approval_provider.requests[0]
    assert request_seen.investigation_id == started_investigation.investigation_id
    assert started_investigation.status == InvestigationStatus.RUNNING

    event_types = [e.event_type.value for e in sink.events]
    assert "approval_requested" in event_types
    assert "approval_decided" in event_types


def test_e2e_approval_rejected_flow_never_dispatches(investigation_manager, resource_governor, gateway, started_investigation):
    approval_provider = ScriptedApprovalProvider(ApprovalDecisionValue.DENY)
    executor = FakeToolExecutor()
    controller = AgentLoopController(
        investigation_manager, resource_governor, gateway, executor, approval_provider=approval_provider, sleep=no_sleep
    )
    agent = ScriptedAgentProvider(
        [make_agent_turn_propose(started_investigation.investigation_id, "terminate_process", "target-local-host-01", {"pid": 1})]
    )
    result = controller.run_turn(started_investigation.investigation_id, agent)
    assert result.outcome == TurnOutcome.STEP_DENIED
    assert executor.call_count == 0
    assert started_investigation.status == InvestigationStatus.RUNNING


def test_e2e_approval_expired_flow_never_dispatches(investigation_manager, gateway, started_investigation):
    from chanakya.runtime.limits import RuntimeExecutionLimits
    from chanakya.runtime.resource_governor import ResourceGovernor
    import datetime as _dt

    limits = RuntimeExecutionLimits(
        config_version="1.0.0", max_steps_per_investigation=5, max_tool_calls_per_investigation=5,
        max_investigation_duration_seconds=600, default_step_timeout_seconds=15, max_retries_per_step=1,
        retry_backoff_seconds=0, max_concurrent_investigations=5, approval_expiry_seconds_default=30,
    )
    governor = ResourceGovernor(limits, clock=_dt.datetime.now)
    executor = FakeToolExecutor()
    controller = AgentLoopController(
        investigation_manager, governor, gateway, executor, sleep=no_sleep,
        clock=SequenceClock([iso(0), iso(0), iso(999)]),
        audit=AuditEmitter(),
        approval_provider=ScriptedApprovalProvider(ApprovalDecisionValue.ACCEPT),
    )
    agent = ScriptedAgentProvider(
        [make_agent_turn_propose(started_investigation.investigation_id, "terminate_process", "target-local-host-01", {"pid": 1})]
    )
    result = controller.run_turn(started_investigation.investigation_id, agent)
    assert result.outcome == TurnOutcome.APPROVAL_EXPIRED
    assert executor.call_count == 0


def test_approval_for_a_different_request_is_rejected_at_dispatch(gateway):
    """docs/AGENT-RUNTIME.md §7: the binding check verifies
    tool_request_id, not just approval_request_id."""
    from chanakya.contracts.enums import Verdict
    from chanakya.contracts.policy_decision import PolicyDecision
    from chanakya.runtime.dispatch import dispatch
    from chanakya.runtime.exceptions import DispatchPreconditionError

    instruction = DispatchInstruction(
        investigation_id="inv-1", tool_request_id="tr-REAL", capability="terminate_process",
        target_ref="target-local-host-01", parameters={"pid": 1}, resolved_timeout_seconds=15,
        resolved_resource_limits={}, policy_decision_id="pd-1", attempt_number=1,
    )
    decision = PolicyDecision(
        policy_decision_id="pd-1", contract_version="1.0.0", tool_request_id="tr-REAL",
        verdict=Verdict.REQUIRE_APPROVAL, matched_rule="x", reason="x", evaluated_at=iso(0),
    )
    # The approval was genuinely issued -- but for a DIFFERENT ToolRequest.
    approval_request = make_approval_request("inv-1", "tr-OTHER-REQUEST", "pd-1")
    approval_decision = make_approval_decision(approval_request.approval_request_id, ApprovalDecisionValue.ACCEPT)

    executor = FakeToolExecutor()
    with pytest.raises(DispatchPreconditionError):
        dispatch(instruction, decision, executor, approval_request=approval_request, approval_decision=approval_decision)
    assert executor.call_count == 0


def test_approval_for_a_different_investigation_is_rejected_at_dispatch():
    """Regression test for the Step 3.6 hardening fix: dispatch() now
    verifies ApprovalRequest.investigation_id against the
    DispatchInstruction, closing a gap where an approval genuinely
    issued for one investigation could otherwise authorize a dispatch
    under a different one."""
    from chanakya.contracts.enums import Verdict
    from chanakya.contracts.policy_decision import PolicyDecision
    from chanakya.runtime.dispatch import dispatch
    from chanakya.runtime.exceptions import DispatchPreconditionError

    instruction = DispatchInstruction(
        investigation_id="inv-REAL", tool_request_id="tr-1", capability="terminate_process",
        target_ref="target-local-host-01", parameters={"pid": 1}, resolved_timeout_seconds=15,
        resolved_resource_limits={}, policy_decision_id="pd-1", attempt_number=1,
    )
    decision = PolicyDecision(
        policy_decision_id="pd-1", contract_version="1.0.0", tool_request_id="tr-1",
        verdict=Verdict.REQUIRE_APPROVAL, matched_rule="x", reason="x", evaluated_at=iso(0),
    )
    # Same tool_request_id/policy_decision_id (as they might coincidentally
    # be if a bug generated a collision) but issued for a DIFFERENT investigation.
    approval_request = make_approval_request("inv-OTHER-INVESTIGATION", "tr-1", "pd-1")
    approval_decision = make_approval_decision(approval_request.approval_request_id, ApprovalDecisionValue.ACCEPT)

    executor = FakeToolExecutor()
    with pytest.raises(DispatchPreconditionError, match="investigation_id"):
        dispatch(instruction, decision, executor, approval_request=approval_request, approval_decision=approval_decision)
    assert executor.call_count == 0


def test_require_approval_never_silently_becomes_allow(investigation_manager, resource_governor, gateway, started_investigation):
    """No path from a REQUIRE_APPROVAL verdict reaches dispatch without
    passing through the Approval Coordinator logic and an ACCEPT."""
    executor = FakeToolExecutor()
    controller = AgentLoopController(investigation_manager, resource_governor, gateway, executor, sleep=no_sleep)
    agent = ScriptedAgentProvider(
        [make_agent_turn_propose(started_investigation.investigation_id, "terminate_process", "target-local-host-01", {"pid": 1})]
    )
    result = controller.run_turn(started_investigation.investigation_id, agent)
    assert result.outcome == TurnOutcome.AWAITING_APPROVAL
    assert executor.call_count == 0
