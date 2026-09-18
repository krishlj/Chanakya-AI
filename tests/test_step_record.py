"""StepRecord — the Runtime-internal step state machine
(docs/AGENT-RUNTIME.md §15, "Additional contracts")."""
from __future__ import annotations

import pytest

from chanakya.runtime.exceptions import InvalidStepTransitionError
from chanakya.runtime.step_record import StepRecord, StepStatus, TERMINAL_STEP_STATUSES

from factories import now


def make_step() -> StepRecord:
    return StepRecord(step_id="step-1", tool_request_id="tr-1", attempt_number=1, started_at=now(), clock=now)


def test_new_step_starts_proposed():
    step = make_step()
    assert step.status == StepStatus.PROPOSED
    assert step.ended_at is None
    assert not step.is_terminal


def test_full_success_path_is_accepted():
    step = make_step()
    step.transition(StepStatus.VALIDATING)
    step.transition(StepStatus.POLICY_EVALUATING)
    step.transition(StepStatus.DISPATCHING)
    step.transition(StepStatus.EXECUTING)
    step.transition(StepStatus.STEP_COMPLETED)
    step.transition(StepStatus.EVIDENCE_RECORDED)
    assert step.status == StepStatus.EVIDENCE_RECORDED
    assert step.is_terminal
    assert step.ended_at is not None


def test_denial_path_is_accepted():
    step = make_step()
    step.transition(StepStatus.VALIDATING)
    step.transition(StepStatus.POLICY_EVALUATING)
    step.transition(StepStatus.STEP_DENIED)
    assert step.status == StepStatus.STEP_DENIED
    assert step.is_terminal


def test_approval_denial_path_is_accepted():
    step = make_step()
    step.transition(StepStatus.VALIDATING)
    step.transition(StepStatus.POLICY_EVALUATING)
    step.transition(StepStatus.AWAITING_STEP_APPROVAL)
    step.transition(StepStatus.STEP_DENIED)
    assert step.status == StepStatus.STEP_DENIED


@pytest.mark.parametrize(
    "start, invalid_target",
    [
        (StepStatus.PROPOSED, StepStatus.POLICY_EVALUATING),
        (StepStatus.PROPOSED, StepStatus.DISPATCHING),
        (StepStatus.PROPOSED, StepStatus.EVIDENCE_RECORDED),
        (StepStatus.VALIDATING, StepStatus.EXECUTING),
        (StepStatus.VALIDATING, StepStatus.PROPOSED),
        (StepStatus.POLICY_EVALUATING, StepStatus.EVIDENCE_RECORDED),
        (StepStatus.EXECUTING, StepStatus.PROPOSED),
    ],
)
def test_invalid_transitions_are_rejected(start, invalid_target):
    step = make_step()
    # Drive to `start` via the shortest valid path.
    path = {
        StepStatus.VALIDATING: [StepStatus.VALIDATING],
        StepStatus.POLICY_EVALUATING: [StepStatus.VALIDATING, StepStatus.POLICY_EVALUATING],
        StepStatus.EXECUTING: [
            StepStatus.VALIDATING,
            StepStatus.POLICY_EVALUATING,
            StepStatus.DISPATCHING,
            StepStatus.EXECUTING,
        ],
    }.get(start, [])
    for state in path:
        step.transition(state)
    assert step.status == start

    with pytest.raises(InvalidStepTransitionError):
        step.transition(invalid_target)
    assert step.status == start  # rejected transition never applied


@pytest.mark.parametrize("terminal", sorted(TERMINAL_STEP_STATUSES, key=lambda s: s.value))
def test_terminal_step_statuses_have_no_outbound_transition(terminal):
    step = make_step()
    # Force into the terminal state directly is not possible via the
    # public API for every terminal — instead assert the transition table
    # itself has an empty allowed-set, which is what the state machine
    # actually enforces.
    from chanakya.runtime.step_record import ALLOWED_STEP_TRANSITIONS

    assert ALLOWED_STEP_TRANSITIONS[terminal] == frozenset()


def test_attempt_number_must_be_positive():
    with pytest.raises(ValueError):
        StepRecord(step_id="s", tool_request_id="tr", attempt_number=0, started_at=now(), clock=now)


def test_step_record_is_bounded_and_holds_only_identifiers():
    """G (StepRecord): 'Do not store arbitrary secrets or unrestricted
    tool output inside StepRecord' — there is structurally no field to
    put one in (only ids, status, attempt number, and timestamps), and
    __slots__ means nothing else can be bolted on later."""
    step = make_step()
    assert set(StepRecord.__slots__) == {
        "_step_id",
        "_tool_request_id",
        "_attempt_number",
        "_started_at",
        "_ended_at",
        "_status",
        "_policy_decision_id",
        "_approval_request_id",
        "_approval_decision_id",
        "_tool_result_id",
        "_evidence_id",
        "_clock",
    }
    with pytest.raises(AttributeError):
        step.parameters = {"anything": "should not be settable"}  # type: ignore[attr-defined]


def test_setters_reject_empty_values():
    step = make_step()
    with pytest.raises(ValueError):
        step.set_policy_decision_id("")
    with pytest.raises(ValueError):
        step.set_tool_result_id("")
    with pytest.raises(ValueError):
        step.set_evidence_id("")
