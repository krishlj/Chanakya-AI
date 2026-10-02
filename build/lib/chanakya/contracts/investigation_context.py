"""InvestigationContext contract — docs/CONTRACTS.md §2.

The Runtime-owned, evolving state for one investigation. Unlike the other
contract objects in this package, ``InvestigationContext`` is not a
frozen dataclass — its whole purpose is to change over the life of an
investigation. It is instead a small, ``__slots__``-based class that
exposes only controlled mutation methods, so it "must not silently
become an unrestricted container for arbitrary data"
(docs/AGENT-RUNTIME.md, Phase 3 Step 3.4 scope):

- there is no way to add a field that was not designed in here (``__slots__``);
- ``status`` can only change via ``transition_status``, which enforces the
  state machine from docs/AGENT-RUNTIME.md §15 and rejects invalid
  transitions;
- the ``*_refs`` lists are append-only and only ever grow by id, never by
  embedding the referenced record itself (docs/CONTRACTS.md §2's own
  design intent: "does not embed large payloads — it references other
  contracts by id");
- ``step_history`` gains one new step record per proposed ``ToolRequest``,
  via ``begin_step``, which also enforces that at most one step is ever
  in flight at a time (RT-INV-10, docs/AGENT-RUNTIME.md §19).

This module deliberately does not import ``chanakya.runtime.step_record``
at runtime (only for type-checking, guarded by ``TYPE_CHECKING``) to keep
``chanakya.contracts`` free of a real dependency on the higher
``chanakya.runtime`` layer — the same pattern already used by
``chanakya.capability.model`` for ``RegistryEntry``.
"""
from __future__ import annotations

from enum import Enum
from typing import TYPE_CHECKING, Any, List, Mapping, Optional, Tuple

if TYPE_CHECKING:  # pragma: no cover - typing only, avoids a layering cycle
    from chanakya.runtime.step_record import StepRecord


class InvestigationStatus(str, Enum):
    """docs/CONTRACTS.md §2 — InvestigationContext.status. Exactly these
    six values; transitions between them are governed by
    ``ALLOWED_INVESTIGATION_TRANSITIONS`` below (docs/AGENT-RUNTIME.md §15)."""

    PENDING = "pending"
    RUNNING = "running"
    AWAITING_APPROVAL = "awaiting_approval"
    COMPLETED = "completed"
    FAILED = "failed"
    HALTED = "halted"


#: docs/AGENT-RUNTIME.md §15 — the investigation-level state machine's
#: valid transitions. Terminal states (COMPLETED, FAILED, HALTED) map to
#: an empty set: no outbound transition exists in this phase's design.
#: The RUNNING -> RUNNING "step concludes, loop continues" self-edge is
#: intentionally *not* listed: staying in RUNNING is not a status change
#: and never calls ``transition_status`` at all.
ALLOWED_INVESTIGATION_TRANSITIONS: Mapping[InvestigationStatus, frozenset] = {
    InvestigationStatus.PENDING: frozenset({InvestigationStatus.RUNNING}),
    InvestigationStatus.RUNNING: frozenset(
        {
            InvestigationStatus.AWAITING_APPROVAL,
            InvestigationStatus.COMPLETED,
            InvestigationStatus.HALTED,
            InvestigationStatus.FAILED,
        }
    ),
    InvestigationStatus.AWAITING_APPROVAL: frozenset(
        {InvestigationStatus.RUNNING, InvestigationStatus.HALTED}
    ),
    InvestigationStatus.COMPLETED: frozenset(),
    InvestigationStatus.FAILED: frozenset(),
    InvestigationStatus.HALTED: frozenset(),
}

#: Terminal states have no outbound transition in this phase's design
#: (docs/AGENT-RUNTIME.md §15 — "a terminated investigation is not
#: resumed"). Exposed for callers that need to check "is this over?"
#: without duplicating the transition table.
TERMINAL_INVESTIGATION_STATUSES = frozenset(
    {InvestigationStatus.COMPLETED, InvestigationStatus.FAILED, InvestigationStatus.HALTED}
)


class InvalidInvestigationTransitionError(ValueError):
    """Raised when a status transition is not present in
    ``ALLOWED_INVESTIGATION_TRANSITIONS`` for the context's current status."""


class StepAlreadyInFlightError(RuntimeError):
    """Raised by ``begin_step`` if a previous step has not reached a
    terminal step-state yet (RT-INV-10: at most one ToolRequest in flight
    per investigation at a time)."""


class InvestigationContext:
    """docs/CONTRACTS.md §2. See module docstring for the encapsulation
    rules this class enforces."""

    __slots__ = (
        "_investigation_id",
        "_contract_version",
        "_investigation_request_id",
        "_objective",
        "_status",
        "_target_refs",
        "_created_at",
        "_updated_at",
        "_step_history",
        "_evidence_refs",
        "_finding_refs",
        "_risk_assessment_refs",
        "_recommendation_refs",
        "_current_step_id",
        "_error_state",
        "_clock",
    )

    def __init__(
        self,
        *,
        investigation_id: str,
        contract_version: str,
        investigation_request_id: str,
        objective: str,
        target_refs: Tuple[str, ...],
        created_at: str,
        clock,
    ) -> None:
        if not investigation_id:
            raise ValueError("InvestigationContext.investigation_id must be non-empty")
        if not target_refs:
            raise ValueError("InvestigationContext.target_refs must be non-empty")

        self._investigation_id = investigation_id
        self._contract_version = contract_version
        self._investigation_request_id = investigation_request_id
        self._objective = objective
        self._status = InvestigationStatus.PENDING
        self._target_refs: Tuple[str, ...] = tuple(target_refs)
        self._created_at = created_at
        self._updated_at = created_at
        self._step_history: List["StepRecord"] = []
        self._evidence_refs: List[str] = []
        self._finding_refs: List[str] = []
        self._risk_assessment_refs: List[str] = []
        self._recommendation_refs: List[str] = []
        self._current_step_id: Optional[str] = None
        self._error_state: Optional[Mapping[str, Any]] = None
        self._clock = clock

    # -- read-only views ------------------------------------------------

    @property
    def investigation_id(self) -> str:
        return self._investigation_id

    @property
    def contract_version(self) -> str:
        return self._contract_version

    @property
    def investigation_request_id(self) -> str:
        return self._investigation_request_id

    @property
    def objective(self) -> str:
        return self._objective

    @property
    def status(self) -> InvestigationStatus:
        return self._status

    @property
    def target_refs(self) -> Tuple[str, ...]:
        return self._target_refs

    @property
    def created_at(self) -> str:
        return self._created_at

    @property
    def updated_at(self) -> str:
        return self._updated_at

    @property
    def step_history(self) -> Tuple["StepRecord", ...]:
        return tuple(self._step_history)

    @property
    def evidence_refs(self) -> Tuple[str, ...]:
        return tuple(self._evidence_refs)

    @property
    def finding_refs(self) -> Tuple[str, ...]:
        return tuple(self._finding_refs)

    @property
    def risk_assessment_refs(self) -> Tuple[str, ...]:
        return tuple(self._risk_assessment_refs)

    @property
    def recommendation_refs(self) -> Tuple[str, ...]:
        return tuple(self._recommendation_refs)

    @property
    def current_step_id(self) -> Optional[str]:
        return self._current_step_id

    @property
    def error_state(self) -> Optional[Mapping[str, Any]]:
        return self._error_state

    @property
    def is_terminal(self) -> bool:
        return self._status in TERMINAL_INVESTIGATION_STATUSES

    # -- controlled mutation ---------------------------------------------

    def transition_status(
        self, new_status: InvestigationStatus, *, error_state: Optional[Mapping[str, Any]] = None
    ) -> None:
        """docs/AGENT-RUNTIME.md §15. Raises
        ``InvalidInvestigationTransitionError`` for any transition not in
        ``ALLOWED_INVESTIGATION_TRANSITIONS`` — including any attempt to
        leave a terminal state."""
        allowed = ALLOWED_INVESTIGATION_TRANSITIONS.get(self._status, frozenset())
        if new_status not in allowed:
            raise InvalidInvestigationTransitionError(
                f"invalid investigation state transition: {self._status.value} -> {new_status.value}"
            )
        self._status = new_status
        self._updated_at = self._clock()
        if new_status in (InvestigationStatus.FAILED, InvestigationStatus.HALTED):
            self._error_state = dict(error_state) if error_state is not None else {}
        elif error_state is not None:
            raise ValueError("error_state may only be set when transitioning to FAILED or HALTED")

    def begin_step(self, step_record: "StepRecord") -> None:
        """Appends a new step and marks it as the in-flight step.

        Raises ``StepAlreadyInFlightError`` if a previously-begun step has
        not yet reached a terminal step-state (RT-INV-10).
        """
        if self._current_step_id is not None:
            raise StepAlreadyInFlightError(
                f"cannot begin step {step_record.step_id!r}: step "
                f"{self._current_step_id!r} is still in flight"
            )
        self._step_history.append(step_record)
        self._current_step_id = step_record.step_id
        self._updated_at = self._clock()

    def end_current_step(self) -> None:
        """Clears ``current_step_id`` once the in-flight step has reached
        a terminal step-state. Does not touch ``step_history`` — the
        StepRecord itself already carries its own terminal status."""
        self._current_step_id = None
        self._updated_at = self._clock()

    def add_evidence_ref(self, evidence_id: str) -> None:
        if not evidence_id:
            raise ValueError("evidence_id must be non-empty")
        self._evidence_refs.append(evidence_id)
        self._updated_at = self._clock()

    def add_finding_ref(self, finding_id: str) -> None:
        if not finding_id:
            raise ValueError("finding_id must be non-empty")
        self._finding_refs.append(finding_id)
        self._updated_at = self._clock()

    def add_risk_assessment_ref(self, risk_assessment_id: str) -> None:
        if not risk_assessment_id:
            raise ValueError("risk_assessment_id must be non-empty")
        self._risk_assessment_refs.append(risk_assessment_id)
        self._updated_at = self._clock()

    def add_recommendation_ref(self, recommendation_id: str) -> None:
        if not recommendation_id:
            raise ValueError("recommendation_id must be non-empty")
        self._recommendation_refs.append(recommendation_id)
        self._updated_at = self._clock()
