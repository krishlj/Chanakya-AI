"""dispatch() — docs/AGENT-RUNTIME.md §7. The structural enforcement
point for RT-INV-1 (no dispatch without a favorable PolicyDecision) and
RT-INV-2 (no REQUIRE_APPROVAL dispatch without an accepted, correctly-
bound ApprovalDecision)."""
from __future__ import annotations

import uuid

import pytest

from chanakya.contracts.enums import Verdict
from chanakya.contracts.policy_decision import PolicyDecision
from chanakya.runtime.dispatch import DispatchInstruction, dispatch
from chanakya.runtime.exceptions import DispatchPreconditionError

from runtime_factories import FakeToolExecutor, make_approval_decision, make_approval_request
from chanakya.contracts.approval import ApprovalDecisionValue


def make_instruction(
    tool_request_id: str = "tr-1", policy_decision_id: str = "pd-1", investigation_id: str = "inv-1"
) -> DispatchInstruction:
    return DispatchInstruction(
        investigation_id=investigation_id,
        tool_request_id=tool_request_id,
        capability="list_listening_ports",
        target_ref="target-local-host-01",
        parameters={},
        resolved_timeout_seconds=15,
        resolved_resource_limits={},
        policy_decision_id=policy_decision_id,
        attempt_number=1,
    )


def make_decision(verdict: Verdict, tool_request_id: str = "tr-1", policy_decision_id: str = "pd-1") -> PolicyDecision:
    return PolicyDecision(
        policy_decision_id=policy_decision_id,
        contract_version="1.0.0",
        tool_request_id=tool_request_id,
        verdict=verdict,
        matched_rule="test-rule",
        reason="test",
        evaluated_at="2026-01-01T00:00:00Z",
    )


def test_allow_verdict_dispatches():
    executor = FakeToolExecutor()
    instruction = make_instruction()
    decision = make_decision(Verdict.ALLOW)
    result = dispatch(instruction, decision, executor)
    assert executor.call_count == 1
    assert result.tool_request_id == "tr-1"


def test_deny_verdict_never_dispatches():
    """Invariant #6: DENY cannot become execution."""
    executor = FakeToolExecutor()
    instruction = make_instruction()
    decision = make_decision(Verdict.DENY)
    with pytest.raises(DispatchPreconditionError):
        dispatch(instruction, decision, executor)
    assert executor.call_count == 0


def test_require_approval_without_any_approval_never_dispatches():
    """Invariant #4/#5: the Runtime cannot dispatch without a
    PolicyDecision, and REQUIRE_APPROVAL cannot become execution without
    an accepted ApprovalDecision — here, no approval was even offered."""
    executor = FakeToolExecutor()
    instruction = make_instruction()
    decision = make_decision(Verdict.REQUIRE_APPROVAL)
    with pytest.raises(DispatchPreconditionError):
        dispatch(instruction, decision, executor)
    assert executor.call_count == 0


def test_require_approval_with_denied_decision_never_dispatches():
    executor = FakeToolExecutor()
    instruction = make_instruction()
    decision = make_decision(Verdict.REQUIRE_APPROVAL)
    approval_request = make_approval_request("inv-1", "tr-1", "pd-1")
    approval_decision = make_approval_decision(approval_request.approval_request_id, ApprovalDecisionValue.DENY)
    with pytest.raises(DispatchPreconditionError):
        dispatch(instruction, decision, executor, approval_request=approval_request, approval_decision=approval_decision)
    assert executor.call_count == 0


def test_require_approval_with_accepted_and_correctly_bound_decision_dispatches():
    executor = FakeToolExecutor()
    instruction = make_instruction()
    decision = make_decision(Verdict.REQUIRE_APPROVAL)
    approval_request = make_approval_request("inv-1", "tr-1", "pd-1")
    approval_decision = make_approval_decision(approval_request.approval_request_id, ApprovalDecisionValue.ACCEPT)
    result = dispatch(instruction, decision, executor, approval_request=approval_request, approval_decision=approval_decision)
    assert executor.call_count == 1
    assert result is not None


def test_approval_decision_bound_to_a_different_approval_request_is_rejected():
    """An ApprovalDecision cannot be replayed against a different
    ApprovalRequest than the one it was issued for."""
    executor = FakeToolExecutor()
    instruction = make_instruction()
    decision = make_decision(Verdict.REQUIRE_APPROVAL)
    approval_request = make_approval_request("inv-1", "tr-1", "pd-1")
    other_approval_request_id = str(uuid.uuid4())
    approval_decision = make_approval_decision(other_approval_request_id, ApprovalDecisionValue.ACCEPT)
    with pytest.raises(DispatchPreconditionError):
        dispatch(instruction, decision, executor, approval_request=approval_request, approval_decision=approval_decision)
    assert executor.call_count == 0


def test_approval_request_for_a_different_tool_request_is_rejected():
    executor = FakeToolExecutor()
    instruction = make_instruction(tool_request_id="tr-1")
    decision = make_decision(Verdict.REQUIRE_APPROVAL, tool_request_id="tr-1")
    approval_request = make_approval_request("inv-1", "tr-DIFFERENT", "pd-1")
    approval_decision = make_approval_decision(approval_request.approval_request_id, ApprovalDecisionValue.ACCEPT)
    with pytest.raises(DispatchPreconditionError):
        dispatch(instruction, decision, executor, approval_request=approval_request, approval_decision=approval_decision)
    assert executor.call_count == 0


def test_policy_decision_not_matching_the_instruction_is_rejected():
    """Invariant #11: a previous PolicyDecision cannot automatically
    authorize a new (retried) dispatch — the ids must match."""
    executor = FakeToolExecutor()
    stale_decision = make_decision(Verdict.ALLOW, tool_request_id="tr-OLD", policy_decision_id="pd-OLD")
    new_instruction = make_instruction(tool_request_id="tr-NEW", policy_decision_id="pd-NEW")
    with pytest.raises(DispatchPreconditionError):
        dispatch(new_instruction, stale_decision, executor)
    assert executor.call_count == 0


def test_executor_is_a_mandatory_explicit_dependency():
    """There is no default ToolExecutor — dispatch() cannot be called
    without one, so nothing in this module can fabricate a 'successful'
    execution on its own."""
    import inspect

    from chanakya.runtime.dispatch import dispatch as dispatch_fn

    signature = inspect.signature(dispatch_fn)
    assert signature.parameters["executor"].default is inspect.Parameter.empty
