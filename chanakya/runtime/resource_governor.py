"""ResourceGovernor — docs/AGENT-RUNTIME.md §18 (Resource limits).

Tracks, per investigation, step counts, tool-call counts (overall and
per-capability, for building a Policy Gateway ``EvaluationContext``),
start time, and the process-wide concurrent-investigation count. Every
check is fail-closed: exceeding a configured
``RuntimeExecutionLimits`` ceiling raises ``ResourceLimitExceededError``
*before* the corresponding step/call/investigation is allowed to
proceed — it never allows the action through and reports the violation
afterward.
"""
from __future__ import annotations

from datetime import datetime
from typing import Callable, Dict, Mapping, Set

from .exceptions import ResourceLimitExceededError
from .limits import RuntimeExecutionLimits


class ResourceGovernor:
    def __init__(self, limits: RuntimeExecutionLimits, *, clock: Callable[[], datetime]) -> None:
        self._limits = limits
        self._clock = clock
        self._active_investigations: Set[str] = set()
        self._step_counts: Dict[str, int] = {}
        self._tool_call_counts: Dict[str, int] = {}
        self._capability_call_counts: Dict[str, Dict[str, int]] = {}
        self._retry_counts: Dict[str, int] = {}
        self._start_times: Dict[str, datetime] = {}

    @property
    def limits(self) -> RuntimeExecutionLimits:
        return self._limits

    def register_investigation(self, investigation_id: str) -> None:
        if investigation_id in self._active_investigations:
            raise ValueError(f"investigation {investigation_id!r} is already registered")
        if len(self._active_investigations) >= self._limits.max_concurrent_investigations:
            raise ResourceLimitExceededError(
                f"max_concurrent_investigations ({self._limits.max_concurrent_investigations}) exceeded"
            )
        self._active_investigations.add(investigation_id)
        self._start_times[investigation_id] = self._clock()
        self._step_counts[investigation_id] = 0
        self._tool_call_counts[investigation_id] = 0
        self._capability_call_counts[investigation_id] = {}
        self._retry_counts[investigation_id] = 0

    def release_investigation(self, investigation_id: str) -> None:
        """Frees the concurrency slot on termination. Counters are kept
        (not deleted) so a post-hoc caller can still inspect how much of
        the budget an investigation used; only the concurrency slot is
        released."""
        self._active_investigations.discard(investigation_id)

    def record_step_proposed(self, investigation_id: str) -> None:
        count = self._step_counts.get(investigation_id, 0)
        if count >= self._limits.max_steps_per_investigation:
            raise ResourceLimitExceededError(
                f"max_steps_per_investigation ({self._limits.max_steps_per_investigation}) exceeded "
                f"for investigation {investigation_id!r}"
            )
        self._step_counts[investigation_id] = count + 1

    def record_tool_call(self, investigation_id: str, capability: str) -> None:
        total = self._tool_call_counts.get(investigation_id, 0)
        if total >= self._limits.max_tool_calls_per_investigation:
            raise ResourceLimitExceededError(
                f"max_tool_calls_per_investigation ({self._limits.max_tool_calls_per_investigation}) "
                f"exceeded for investigation {investigation_id!r}"
            )
        self._tool_call_counts[investigation_id] = total + 1
        per_capability = self._capability_call_counts.setdefault(investigation_id, {})
        per_capability[capability] = per_capability.get(capability, 0) + 1

    def check_duration(self, investigation_id: str) -> None:
        started = self._start_times.get(investigation_id)
        if started is None:
            return
        elapsed = (self._clock() - started).total_seconds()
        if elapsed > self._limits.max_investigation_duration_seconds:
            raise ResourceLimitExceededError(
                f"max_investigation_duration_seconds ({self._limits.max_investigation_duration_seconds}) "
                f"exceeded for investigation {investigation_id!r}"
            )

    def record_retry(self, investigation_id: str) -> None:
        """Bookkeeping only — the actual retry ceiling is enforced by
        ``RetryController.should_retry`` against a StepRecord's own
        ``attempt_number`` (docs/AGENT-RUNTIME.md §12). This counter
        exists so total retry activity for an investigation is visible
        to the Resource Governor's own accounting (Phase 3 Step 3.5
        scope: "Resource Governor... Complete enforcement of... maximum
        retries"), without introducing a second, independent limit that
        could disagree with the Retry Controller's."""
        self._retry_counts[investigation_id] = self._retry_counts.get(investigation_id, 0) + 1

    def retry_count(self, investigation_id: str) -> int:
        return self._retry_counts.get(investigation_id, 0)

    def capability_call_counts(self, investigation_id: str) -> Mapping[str, int]:
        """The per-capability counters ``EvaluationContext.call_counts``
        needs (docs/AGENT-RUNTIME.md §5) — a read-only snapshot."""
        return dict(self._capability_call_counts.get(investigation_id, {}))

    def step_count(self, investigation_id: str) -> int:
        return self._step_counts.get(investigation_id, 0)

    def tool_call_count(self, investigation_id: str) -> int:
        return self._tool_call_counts.get(investigation_id, 0)
