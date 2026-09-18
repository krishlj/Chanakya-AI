"""Retry Controller — docs/AGENT-RUNTIME.md §12.

Bounded, policy-driven retry for transient failures only. Deliberately
stateless: the attempt-count ceiling is derived entirely from the failed
``StepRecord``'s own ``attempt_number`` (docs/AGENT-RUNTIME.md's own
field — "increments on retry") against
``RuntimeExecutionLimits.max_retries_per_step``. There is no separate
counter to keep in sync, and therefore no way for it to drift.

What this class decides: *whether another attempt is permitted at all*,
given only the attempt count so far. It does **not** decide *which kinds*
of outcome are retryable in the first place — that filtering happens in
the caller (``AgentLoopController`` only ever consults ``should_retry``
for a step whose outcome was ``STEP_FAILED``/``STEP_TIMED_OUT``; a
denial, a malformed request, an awaiting-approval step, a cancellation,
or a resource-limit halt never reaches this class at all — see
docs/AGENT-RUNTIME.md §12, "What is never retried").

Nothing here ever sees a ``PolicyDecision`` or an ``ApprovalDecision`` —
this class has no way to reuse one, by construction. Every retry the
caller constructs is a materially new ``ToolRequest``, independently
evaluated by the Policy Gateway and, if required, independently
re-approved (RT-INV-4).
"""
from __future__ import annotations

from .limits import RuntimeExecutionLimits
from .step_record import StepRecord


class RetryController:
    def __init__(self, limits: RuntimeExecutionLimits) -> None:
        self._limits = limits

    @property
    def backoff_seconds(self) -> int:
        return self._limits.retry_backoff_seconds

    @property
    def max_retries_per_step(self) -> int:
        return self._limits.max_retries_per_step

    def should_retry(self, failed_step: StepRecord) -> bool:
        """``max_retries_per_step`` bounds the number of retry ATTEMPTS
        beyond the first: with ``max_retries_per_step == 2``, attempt 1
        failing permits attempts 2 and 3, never a 4th. Always bounded —
        there is no configuration or call sequence that makes this
        return ``True`` indefinitely."""
        return failed_step.attempt_number <= self._limits.max_retries_per_step
