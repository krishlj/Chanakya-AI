"""Runtime-side exceptions — docs/AGENT-RUNTIME.md.

Kept in one module because they are raised and caught across several
runtime components and are part of the Runtime's public contract with
its callers (tests included). None of these are ever swallowed silently
by design — see docs/AGENT-RUNTIME.md §11 (Error handling) and RT-INV-6.
"""
from __future__ import annotations


class RuntimeInvariantError(RuntimeError):
    """Base class for a violation of one of the RT-INV invariants in
    docs/AGENT-RUNTIME.md. Never caught-and-ignored by the Runtime itself
    — callers (Agent Loop Controller, Investigation Manager) catch a
    specific subclass to decide the appropriate fail-closed outcome."""


class InvalidStepTransitionError(RuntimeInvariantError):
    """docs/AGENT-RUNTIME.md §15 (step-level state machine). Raised by
    ``StepRecord.transition`` for any transition not present in
    ``ALLOWED_STEP_TRANSITIONS``."""


class DispatchPreconditionError(RuntimeInvariantError):
    """RT-INV-1 / RT-INV-2. Raised by ``chanakya.runtime.dispatch.dispatch``
    whenever a dispatch is attempted without a favorable, matching
    ``PolicyDecision`` or, for a ``require_approval`` verdict, without an
    accepted, correctly-bound ``ApprovalDecision``. This is the concrete
    enforcement point for "the Runtime cannot dispatch without a
    PolicyDecision" and "REQUIRE_APPROVAL cannot become execution without
    an accepted ApprovalDecision"."""


class ResourceLimitExceededError(RuntimeInvariantError):
    """docs/AGENT-RUNTIME.md §18. Raised by ``ResourceGovernor`` when a
    configured ``RuntimeExecutionLimits`` ceiling would be exceeded. The
    Runtime fails closed on this: no further execution is permitted for
    the investigation the limit was hit on."""


class UnknownTargetError(RuntimeInvariantError):
    """Raised by ``InvestigationManager.create_investigation`` when an
    ``InvestigationRequest.requested_targets`` entry does not resolve
    against the injected Target registry (docs/CONTRACTS.md §1 validation
    requirements)."""


class UnknownInvestigationError(RuntimeInvariantError):
    """Raised by ``InvestigationStateStore`` for an unrecognized
    ``investigation_id``."""


class InvestigationTerminatedError(RuntimeInvariantError):
    """Raised when the Agent Loop Controller is asked to run a turn for
    an investigation that has already reached a terminal state
    (``completed``/``failed``/``halted``) — including one ended by
    operator cancellation (RT-INV-9: cancellation prevents further
    execution)."""


class AuditSinkError(RuntimeInvariantError):
    """Wraps any exception raised by an injected ``AuditSink.emit()``
    call (docs/AGENT-RUNTIME.md §14). Per §11's treatment of Audit Log
    write failures ("the Runtime halts rather than let an unaudited
    action proceed"), the Agent Loop Controller routes this specific
    exception type to a ``halted`` terminal state rather than the
    generic ``failed`` used for other unexpected errors — added in Phase
    3 Step 3.6 to make that documented behavior concrete."""


class MalformedAgentTurnOutputError(ValueError):
    """Raised when a raw ``AgentTurnOutput`` payload fails contract
    validation. Must never propagate past the Agent Loop Controller
    boundary — a malformed turn is surfaced as information, never
    corrected on the Agent's behalf (RT-INV-5)."""
