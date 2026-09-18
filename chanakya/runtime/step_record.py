"""StepRecord — docs/AGENT-RUNTIME.md "Additional contracts" / §15.

The concrete, Runtime-internal shape of one ``InvestigationContext.
step_history[]`` entry, and its own small state machine (docs/AGENT-
RUNTIME.md §15, "Step-level state machine"). Deliberately bounded: a
``StepRecord`` only ever stores identifiers, a status, an attempt number,
and timestamps — never a ``ToolRequest.parameters`` payload, a
``ToolResult.output``, or anything else that could carry a secret or
unbounded tool output (Phase 3 Step 3.4 scope: "Do not store arbitrary
secrets or unrestricted tool output inside StepRecord").

Per docs/AGENT-RUNTIME.md's "Additional contracts" section: "A retried
step is a **new** StepRecord ... not a mutation of the earlier record."
Consequently this class's state machine is a strict forward chain with no
transition back to ``PROPOSED`` — a retry is modeled by the caller
(Agent Loop Controller) constructing a new ``StepRecord`` with an
incremented ``attempt_number``, never by looping this object's own state.
"""
from __future__ import annotations

from enum import Enum
from typing import Mapping, Optional

from .exceptions import InvalidStepTransitionError


class StepStatus(str, Enum):
    """docs/AGENT-RUNTIME.md §15 — the step-level state machine's states."""

    PROPOSED = "proposed"
    VALIDATING = "validating"
    STEP_FAILED = "step_failed"
    POLICY_EVALUATING = "policy_evaluating"
    STEP_DENIED = "step_denied"
    AWAITING_STEP_APPROVAL = "awaiting_step_approval"
    DISPATCHING = "dispatching"
    EXECUTING = "executing"
    STEP_COMPLETED = "step_completed"
    STEP_TIMED_OUT = "step_timed_out"
    EVIDENCE_RECORDED = "evidence_recorded"
    EVIDENCE_FAILED = "evidence_failed"


#: docs/AGENT-RUNTIME.md §15's step-level diagram, as a transition table.
#: Every state not listed as a source maps implicitly to "no outbound
#: transitions" (terminal).
ALLOWED_STEP_TRANSITIONS: Mapping[StepStatus, frozenset] = {
    StepStatus.PROPOSED: frozenset({StepStatus.VALIDATING}),
    StepStatus.VALIDATING: frozenset({StepStatus.STEP_FAILED, StepStatus.POLICY_EVALUATING}),
    StepStatus.POLICY_EVALUATING: frozenset(
        {StepStatus.STEP_DENIED, StepStatus.AWAITING_STEP_APPROVAL, StepStatus.DISPATCHING}
    ),
    StepStatus.AWAITING_STEP_APPROVAL: frozenset({StepStatus.DISPATCHING, StepStatus.STEP_DENIED}),
    StepStatus.DISPATCHING: frozenset({StepStatus.EXECUTING}),
    StepStatus.EXECUTING: frozenset(
        {StepStatus.STEP_COMPLETED, StepStatus.STEP_FAILED, StepStatus.STEP_TIMED_OUT}
    ),
    # STEP_COMPLETED means dispatch itself genuinely succeeded — that
    # fact is never retracted. EVIDENCE_FAILED (added in Phase 3 Step
    # 3.6, a genuine gap the original design left unrepresented) records
    # that the *subsequent*, separate act of recording Evidence for that
    # already-successful result failed — matching docs/AGENT-RUNTIME.md
    # §9's documented behavior ("the investigation halts rather than
    # continuing without provenance") without silently discarding the
    # true outcome of execution.
    StepStatus.STEP_COMPLETED: frozenset({StepStatus.EVIDENCE_RECORDED, StepStatus.EVIDENCE_FAILED}),
    StepStatus.STEP_DENIED: frozenset(),
    StepStatus.STEP_FAILED: frozenset(),
    StepStatus.STEP_TIMED_OUT: frozenset(),
    StepStatus.EVIDENCE_RECORDED: frozenset(),
    StepStatus.EVIDENCE_FAILED: frozenset(),
}

#: Terminal step-states — reaching one of these is what allows the
#: investigation-level RUNNING -> RUNNING self-transition to fire
#: (docs/AGENT-RUNTIME.md §15).
TERMINAL_STEP_STATUSES = frozenset(
    {
        StepStatus.STEP_DENIED,
        StepStatus.STEP_FAILED,
        StepStatus.STEP_TIMED_OUT,
        StepStatus.EVIDENCE_RECORDED,
        StepStatus.EVIDENCE_FAILED,
    }
)


class StepRecord:
    """One attempt at one investigation step. See module docstring for
    why retries create a new instance rather than looping this one."""

    __slots__ = (
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
    )

    def __init__(self, *, step_id: str, tool_request_id: str, attempt_number: int, started_at: str, clock) -> None:
        if not step_id:
            raise ValueError("StepRecord.step_id must be non-empty")
        if not tool_request_id:
            raise ValueError("StepRecord.tool_request_id must be non-empty")
        if attempt_number < 1:
            raise ValueError("StepRecord.attempt_number must be >= 1")

        self._step_id = step_id
        self._tool_request_id = tool_request_id
        self._attempt_number = attempt_number
        self._started_at = started_at
        self._ended_at: Optional[str] = None
        self._status = StepStatus.PROPOSED
        self._policy_decision_id: Optional[str] = None
        self._approval_request_id: Optional[str] = None
        self._approval_decision_id: Optional[str] = None
        self._tool_result_id: Optional[str] = None
        self._evidence_id: Optional[str] = None
        self._clock = clock

    # -- read-only views ------------------------------------------------

    @property
    def step_id(self) -> str:
        return self._step_id

    @property
    def tool_request_id(self) -> str:
        return self._tool_request_id

    @property
    def attempt_number(self) -> int:
        return self._attempt_number

    @property
    def started_at(self) -> str:
        return self._started_at

    @property
    def ended_at(self) -> Optional[str]:
        return self._ended_at

    @property
    def status(self) -> StepStatus:
        return self._status

    @property
    def policy_decision_id(self) -> Optional[str]:
        return self._policy_decision_id

    @property
    def approval_request_id(self) -> Optional[str]:
        return self._approval_request_id

    @property
    def approval_decision_id(self) -> Optional[str]:
        return self._approval_decision_id

    @property
    def tool_result_id(self) -> Optional[str]:
        return self._tool_result_id

    @property
    def evidence_id(self) -> Optional[str]:
        return self._evidence_id

    @property
    def is_terminal(self) -> bool:
        return self._status in TERMINAL_STEP_STATUSES

    # -- controlled mutation ---------------------------------------------

    def transition(self, new_status: StepStatus) -> None:
        allowed = ALLOWED_STEP_TRANSITIONS.get(self._status, frozenset())
        if new_status not in allowed:
            raise InvalidStepTransitionError(
                f"invalid step state transition: {self._status.value} -> {new_status.value}"
            )
        self._status = new_status
        if new_status in TERMINAL_STEP_STATUSES:
            self._ended_at = self._clock()

    def set_policy_decision_id(self, policy_decision_id: str) -> None:
        if not policy_decision_id:
            raise ValueError("policy_decision_id must be non-empty")
        self._policy_decision_id = policy_decision_id

    def set_approval_request_id(self, approval_request_id: str) -> None:
        if not approval_request_id:
            raise ValueError("approval_request_id must be non-empty")
        self._approval_request_id = approval_request_id

    def set_approval_decision_id(self, approval_decision_id: str) -> None:
        if not approval_decision_id:
            raise ValueError("approval_decision_id must be non-empty")
        self._approval_decision_id = approval_decision_id

    def set_tool_result_id(self, tool_result_id: str) -> None:
        if not tool_result_id:
            raise ValueError("tool_result_id must be non-empty")
        self._tool_result_id = tool_result_id

    def set_evidence_id(self, evidence_id: str) -> None:
        if not evidence_id:
            raise ValueError("evidence_id must be non-empty")
        self._evidence_id = evidence_id
