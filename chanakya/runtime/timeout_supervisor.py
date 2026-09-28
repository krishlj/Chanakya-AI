"""Timeout Supervisor — docs/AGENT-RUNTIME.md §10.

Enforces two independent timeout scopes, both sourced from trusted
configuration, never from the Agent:

- **Per-investigation wall-clock timeout** — ``check_investigation_timeout``
  delegates to the Resource Governor's own duration tracking (no
  duplicated counter/state). Kept as a distinctly-named entry point
  because docs/AGENT-RUNTIME.md names the Timeout Supervisor as its own
  Runtime component, even though the underlying bookkeeping lives in the
  Resource Governor.
- **Per-step / tool-execution timeout** — ``execute_with_timeout`` wraps a
  synchronous ``ToolExecutor`` call.

Why this does not use a background thread to "race" the call and abandon
it on timeout: this phase has no real Tool Layer to preempt, and
forcibly killing an arbitrary running Python callable is not something
this orchestration layer can do safely, or at all — a thread that
outlives its deadline keeps running regardless, and treating whatever it
eventually produces as valid would be exactly the unsafe pattern this
step's scope warns against ("avoid unsafe background execution that can
continue after timeout/cancellation"). Instead:

1. A well-behaved executor (current test doubles, or a future real Tool
   Layer built around e.g. ``subprocess.run(..., timeout=N)``) is
   expected to enforce its own timeout internally and signal it by
   raising ``ToolExecutionTimedOut``.
2. As a defense-in-depth backstop against an executor that does *not*
   honor its own timeout, the wall-clock duration of the call is still
   measured. If it exceeds the configured budget, the value the executor
   returned is discarded outright — never trusted, never returned to the
   caller, never eligible to become Evidence — and a synthetic
   ``ToolResult(status=timeout)`` is produced instead. A late or
   overrunning result is never treated as authoritative; this is the
   concrete meaning of "avoid unsafe background execution that can
   continue" in a layer with no process-level sandboxing of its own.

Neither path retries anything itself — a timeout is handed back as an
ordinary step outcome; only the Retry Controller (docs/AGENT-RUNTIME.md
§12) decides whether a further attempt is permitted.

Phase 16 (T-61, NX16-INV-3): the synthetic result's ``error_message`` is a
fixed Runtime code: ``tool_execution_failed: HANDLER_TIMEOUT`` for a
handler's own signal, ``tool_execution_failed: STEP_TIMEOUT_EXCEEDED`` for
a measured overrun. The ``ToolExecutionTimedOut`` message is never read,
and the measured duration is not echoed.
"""
from __future__ import annotations

import uuid
from typing import Optional

from chanakya.contracts.tool_failure import HANDLER_TIMEOUT, STEP_TIMEOUT_EXCEEDED, failure_message
from chanakya.contracts.tool_result import ToolResult, ToolResultStatus

from .clock import elapsed_seconds, utcnow_iso
from .dispatch import DispatchInstruction, ToolExecutor
from .resource_governor import ResourceGovernor

_CONTRACT_VERSION = "1.0.0"


class ToolExecutionTimedOut(Exception):
    """Raised by a ``ToolExecutor`` to signal it hit its own configured
    timeout. Phase 16: a signal only; its message is never read or
    recorded. Never raised by the Runtime against a well-behaved
    executor — only ever consumed here, converted into a synthetic
    ``ToolResult(status=timeout)``, and never re-raised or retried by
    this class itself."""


class TimeoutSupervisor:
    def __init__(self, resource_governor: ResourceGovernor, *, clock=utcnow_iso) -> None:
        self._governor = resource_governor
        self._clock = clock

    def check_investigation_timeout(self, investigation_id: str) -> None:
        """Raises ``chanakya.runtime.exceptions.ResourceLimitExceededError``
        if the investigation has exceeded
        ``RuntimeExecutionLimits.max_investigation_duration_seconds``."""
        self._governor.check_duration(investigation_id)

    def execute_with_timeout(
        self, instruction: DispatchInstruction, executor: ToolExecutor, *, timeout_seconds: int
    ) -> ToolResult:
        start_iso = self._clock()
        try:
            result = executor.execute(instruction)
        except ToolExecutionTimedOut:
            # Phase 16 (NX16-INV-3): the signal is honored; its message is
            # never read. The timeout text is Runtime-owned.
            return self._synthetic_timeout_result(instruction, code=HANDLER_TIMEOUT)

        end_iso = self._clock()
        elapsed = elapsed_seconds(start_iso, end_iso)
        if elapsed is not None and elapsed > timeout_seconds:
            return self._synthetic_timeout_result(instruction, code=STEP_TIMEOUT_EXCEEDED)
        return result

    def bind(self, executor: ToolExecutor, *, timeout_seconds: int) -> ToolExecutor:
        """Returns a ``ToolExecutor``-shaped adapter that routes every
        call through ``execute_with_timeout`` with a fixed budget — used
        by the Agent Loop Controller so ``chanakya.runtime.dispatch.
        dispatch`` (the RT-INV-1/RT-INV-2 precondition gate) never needs
        to know timeouts exist at all."""
        return _TimeoutBoundExecutor(self, executor, timeout_seconds)

    @staticmethod
    def _synthetic_timeout_result(instruction: DispatchInstruction, *, code: str) -> ToolResult:
        now = utcnow_iso()
        return ToolResult(
            tool_result_id=str(uuid.uuid4()),
            contract_version=_CONTRACT_VERSION,
            tool_request_id=instruction.tool_request_id,
            capability=instruction.capability,
            status=ToolResultStatus.TIMEOUT,
            started_at=now,
            completed_at=now,
            error_message=failure_message(code),
        )


class _TimeoutBoundExecutor:
    def __init__(self, supervisor: TimeoutSupervisor, delegate: ToolExecutor, timeout_seconds: int) -> None:
        self._supervisor = supervisor
        self._delegate = delegate
        self._timeout_seconds = timeout_seconds

    def execute(self, instruction: DispatchInstruction) -> ToolResult:
        return self._supervisor.execute_with_timeout(instruction, self._delegate, timeout_seconds=self._timeout_seconds)
