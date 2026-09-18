"""InvestigationContext — creation, controlled updates, and the
investigation-level state machine (docs/AGENT-RUNTIME.md §2, §15)."""
from __future__ import annotations

import pytest

from chanakya.contracts.investigation_context import (
    InvalidInvestigationTransitionError,
    InvestigationContext,
    InvestigationStatus,
    StepAlreadyInFlightError,
)
from chanakya.runtime.step_record import StepRecord

from factories import now


def make_context() -> InvestigationContext:
    return InvestigationContext(
        investigation_id="inv-1",
        contract_version="1.0.0",
        investigation_request_id="inv-req-1",
        objective="test objective",
        target_refs=("target-local-host-01",),
        created_at=now(),
        clock=now,
    )


def make_step(step_id: str = "step-1", tool_request_id: str = "tr-1") -> StepRecord:
    return StepRecord(step_id=step_id, tool_request_id=tool_request_id, attempt_number=1, started_at=now(), clock=now)


def test_new_context_starts_pending_with_empty_refs():
    context = make_context()
    assert context.status == InvestigationStatus.PENDING
    assert context.step_history == ()
    assert context.evidence_refs == ()
    assert context.finding_refs == ()
    assert context.risk_assessment_refs == ()
    assert context.recommendation_refs == ()
    assert context.current_step_id is None
    assert context.error_state is None
    assert not context.is_terminal


def test_valid_lifecycle_transitions_are_accepted():
    context = make_context()
    context.transition_status(InvestigationStatus.RUNNING)
    assert context.status == InvestigationStatus.RUNNING

    context.transition_status(InvestigationStatus.AWAITING_APPROVAL)
    assert context.status == InvestigationStatus.AWAITING_APPROVAL

    context.transition_status(InvestigationStatus.RUNNING)
    assert context.status == InvestigationStatus.RUNNING

    context.transition_status(InvestigationStatus.COMPLETED)
    assert context.status == InvestigationStatus.COMPLETED
    assert context.is_terminal


@pytest.mark.parametrize(
    "start, target",
    [
        (InvestigationStatus.PENDING, InvestigationStatus.AWAITING_APPROVAL),
        (InvestigationStatus.PENDING, InvestigationStatus.COMPLETED),
        (InvestigationStatus.PENDING, InvestigationStatus.FAILED),
        (InvestigationStatus.PENDING, InvestigationStatus.HALTED),
        (InvestigationStatus.AWAITING_APPROVAL, InvestigationStatus.COMPLETED),
        (InvestigationStatus.AWAITING_APPROVAL, InvestigationStatus.FAILED),
    ],
)
def test_invalid_transitions_are_rejected(start, target):
    context = make_context()
    if start == InvestigationStatus.AWAITING_APPROVAL:
        context.transition_status(InvestigationStatus.RUNNING)
        context.transition_status(InvestigationStatus.AWAITING_APPROVAL)
    with pytest.raises(InvalidInvestigationTransitionError):
        context.transition_status(target)
    # The rejected transition must not have silently applied.
    assert context.status == start


@pytest.mark.parametrize("terminal", [InvestigationStatus.COMPLETED, InvestigationStatus.FAILED, InvestigationStatus.HALTED])
def test_terminal_states_have_no_outbound_transition(terminal):
    context = make_context()
    context.transition_status(InvestigationStatus.RUNNING)
    context.transition_status(terminal, error_state={"reason": "x"} if terminal != InvestigationStatus.COMPLETED else None)
    for candidate in InvestigationStatus:
        with pytest.raises(InvalidInvestigationTransitionError):
            context.transition_status(candidate)


def test_error_state_set_on_halt_and_defaults_to_empty_mapping():
    context = make_context()
    context.transition_status(InvestigationStatus.RUNNING)
    context.transition_status(InvestigationStatus.HALTED, error_state={"reason": "cancelled_by_operator"})
    assert context.error_state == {"reason": "cancelled_by_operator"}

    other = make_context()
    other.transition_status(InvestigationStatus.RUNNING)
    other.transition_status(InvestigationStatus.FAILED)  # no error_state given
    assert other.error_state == {}


def test_error_state_rejected_for_non_terminal_transition():
    context = make_context()
    with pytest.raises(ValueError):
        context.transition_status(InvestigationStatus.RUNNING, error_state={"reason": "should not be allowed"})


def test_begin_step_appends_and_sets_current_step():
    context = make_context()
    context.transition_status(InvestigationStatus.RUNNING)
    step = make_step()
    context.begin_step(step)
    assert context.step_history == (step,)
    assert context.current_step_id == "step-1"


def test_at_most_one_step_in_flight_rt_inv_10():
    """RT-INV-10: at most one ToolRequest is in flight per investigation
    at a time."""
    context = make_context()
    context.transition_status(InvestigationStatus.RUNNING)
    context.begin_step(make_step("step-1"))
    with pytest.raises(StepAlreadyInFlightError):
        context.begin_step(make_step("step-2"))

    context.end_current_step()
    # Now a new step is allowed to begin.
    context.begin_step(make_step("step-2"))
    assert context.current_step_id == "step-2"


def test_ref_lists_are_append_only_and_return_copies():
    context = make_context()
    context.add_evidence_ref("ev-1")
    context.add_finding_ref("find-1")
    context.add_risk_assessment_ref("risk-1")
    context.add_recommendation_ref("rec-1")
    assert context.evidence_refs == ("ev-1",)
    assert context.finding_refs == ("find-1",)
    assert context.risk_assessment_refs == ("risk-1",)
    assert context.recommendation_refs == ("rec-1",)

    # Returned tuples are copies — mutating the return value must not
    # mutate the context's internal state.
    refs = context.evidence_refs
    assert isinstance(refs, tuple)
    context.add_evidence_ref("ev-2")
    assert refs == ("ev-1",)
    assert context.evidence_refs == ("ev-1", "ev-2")


def test_context_rejects_empty_ref_values():
    context = make_context()
    with pytest.raises(ValueError):
        context.add_evidence_ref("")


def test_context_cannot_become_an_unrestricted_container():
    """B (InvestigationContext): 'must not silently become an
    unrestricted container for arbitrary data' — enforced structurally
    via __slots__."""
    context = make_context()
    with pytest.raises(AttributeError):
        context.arbitrary_field = "should not be settable"  # type: ignore[attr-defined]


def test_context_requires_non_empty_target_refs():
    with pytest.raises(ValueError):
        InvestigationContext(
            investigation_id="inv-2",
            contract_version="1.0.0",
            investigation_request_id="inv-req-2",
            objective="x",
            target_refs=(),
            created_at=now(),
            clock=now,
        )
