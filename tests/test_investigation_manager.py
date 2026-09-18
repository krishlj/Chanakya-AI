"""InvestigationManager — creation, lifecycle transitions, and
cancellation (docs/AGENT-RUNTIME.md §1, §17)."""
from __future__ import annotations

import pytest

from chanakya.contracts.investigation_context import InvalidInvestigationTransitionError, InvestigationStatus
from chanakya.contracts.investigation_request import InvestigationRequest
from chanakya.runtime.exceptions import RuntimeInvariantError, UnknownTargetError


def test_create_investigation_from_valid_request(investigation_manager, investigation_request):
    context = investigation_manager.create_investigation(investigation_request)
    assert context.status == InvestigationStatus.PENDING
    assert context.target_refs == ("target-local-host-01",)
    assert context.investigation_request_id == investigation_request.investigation_request_id
    assert investigation_manager.get(context.investigation_id) is context


def test_create_investigation_rejects_unregistered_target(investigation_manager):
    request = InvestigationRequest.from_dict(
        {
            "investigation_request_id": "inv-req-bad",
            "contract_version": "1.0.0",
            "objective": "x",
            "requested_targets": ["target-does-not-exist"],
            "submitted_by": "test-human",
            "submitted_at": "2026-01-01T00:00:00Z",
        }
    )
    with pytest.raises(UnknownTargetError):
        investigation_manager.create_investigation(request)


def test_full_lifecycle_start_to_completion(investigation_manager, investigation_request):
    context = investigation_manager.create_investigation(investigation_request)
    investigation_manager.start(context.investigation_id)
    assert context.status == InvestigationStatus.RUNNING
    investigation_manager.complete(context.investigation_id)
    assert context.status == InvestigationStatus.COMPLETED


def test_full_lifecycle_through_awaiting_approval(investigation_manager, investigation_request):
    context = investigation_manager.create_investigation(investigation_request)
    investigation_manager.start(context.investigation_id)
    investigation_manager.enter_awaiting_approval(context.investigation_id)
    assert context.status == InvestigationStatus.AWAITING_APPROVAL
    investigation_manager.resume_running(context.investigation_id)
    assert context.status == InvestigationStatus.RUNNING


def test_fail_sets_error_state(investigation_manager, investigation_request):
    context = investigation_manager.create_investigation(investigation_request)
    investigation_manager.start(context.investigation_id)
    investigation_manager.fail(context.investigation_id, reason="dispatch_precondition_violation", details={"x": 1})
    assert context.status == InvestigationStatus.FAILED
    assert context.error_state["reason"] == "dispatch_precondition_violation"
    assert context.error_state["x"] == 1


def test_halt_sets_error_state(investigation_manager, investigation_request):
    context = investigation_manager.create_investigation(investigation_request)
    investigation_manager.start(context.investigation_id)
    investigation_manager.halt(context.investigation_id, reason="max_steps_per_investigation_exceeded")
    assert context.status == InvestigationStatus.HALTED
    assert context.error_state["reason"] == "max_steps_per_investigation_exceeded"


def test_invalid_lifecycle_transition_is_rejected(investigation_manager, investigation_request):
    context = investigation_manager.create_investigation(investigation_request)
    # Still PENDING — cannot complete before ever running.
    with pytest.raises(InvalidInvestigationTransitionError):
        investigation_manager.complete(context.investigation_id)


def test_cancel_from_running_halts_with_operator_reason(investigation_manager, investigation_request):
    context = investigation_manager.create_investigation(investigation_request)
    investigation_manager.start(context.investigation_id)
    investigation_manager.cancel(context.investigation_id, cancelled_by="alice")
    assert context.status == InvestigationStatus.HALTED
    assert context.error_state["reason"] == "cancelled_by_operator"
    assert context.error_state["cancelled_by"] == "alice"


def test_cancel_from_awaiting_approval_is_allowed(investigation_manager, investigation_request):
    context = investigation_manager.create_investigation(investigation_request)
    investigation_manager.start(context.investigation_id)
    investigation_manager.enter_awaiting_approval(context.investigation_id)
    investigation_manager.cancel(context.investigation_id, cancelled_by="alice")
    assert context.status == InvestigationStatus.HALTED


@pytest.mark.parametrize("terminal_setup", ["completed", "failed", "halted", "pending"])
def test_cancel_rejected_outside_running_or_awaiting_approval(investigation_manager, investigation_request, terminal_setup):
    context = investigation_manager.create_investigation(investigation_request)
    if terminal_setup != "pending":
        investigation_manager.start(context.investigation_id)
        if terminal_setup == "completed":
            investigation_manager.complete(context.investigation_id)
        elif terminal_setup == "failed":
            investigation_manager.fail(context.investigation_id, reason="x")
        elif terminal_setup == "halted":
            investigation_manager.halt(context.investigation_id, reason="x")

    with pytest.raises(RuntimeInvariantError):
        investigation_manager.cancel(context.investigation_id, cancelled_by="alice")


def test_concurrency_limit_is_enforced(target_registry, resource_governor):
    from chanakya.runtime.exceptions import ResourceLimitExceededError
    from chanakya.runtime.investigation_manager import InvestigationManager

    manager = InvestigationManager(target_registry, resource_governor)
    requests = [
        InvestigationRequest.from_dict(
            {
                "investigation_request_id": f"inv-req-{i}",
                "contract_version": "1.0.0",
                "objective": "x",
                "requested_targets": ["target-local-host-01"],
                "submitted_by": "test-human",
                "submitted_at": "2026-01-01T00:00:00Z",
            }
        )
        for i in range(resource_governor.limits.max_concurrent_investigations + 1)
    ]
    for request in requests[:-1]:
        manager.create_investigation(request)

    with pytest.raises(ResourceLimitExceededError):
        manager.create_investigation(requests[-1])
