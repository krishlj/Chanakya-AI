"""Retry Controller — docs/AGENT-RUNTIME.md §12 (Phase 3 Step 3.5).
Bounded, stateless, and never sees a PolicyDecision/ApprovalDecision."""
from __future__ import annotations

import pytest

from chanakya.runtime.limits import RuntimeExecutionLimits
from chanakya.runtime.retry_controller import RetryController
from chanakya.runtime.step_record import StepRecord

from factories import now


def make_step(attempt_number: int) -> StepRecord:
    return StepRecord(step_id="s", tool_request_id="tr", attempt_number=attempt_number, started_at=now(), clock=now)


def _limits(max_retries: int, backoff: int = 2) -> RuntimeExecutionLimits:
    return RuntimeExecutionLimits(
        config_version="1.0.0",
        max_steps_per_investigation=10,
        max_tool_calls_per_investigation=10,
        max_investigation_duration_seconds=600,
        default_step_timeout_seconds=15,
        max_retries_per_step=max_retries,
        retry_backoff_seconds=backoff,
        max_concurrent_investigations=1,
    )


def test_backoff_seconds_reflects_configured_limit():
    controller = RetryController(_limits(2, backoff=7))
    assert controller.backoff_seconds == 7
    assert controller.max_retries_per_step == 2


@pytest.mark.parametrize("max_retries,attempt_number,expected", [
    (2, 1, True),   # attempt 1 failed -> retry to attempt 2 permitted
    (2, 2, True),   # attempt 2 failed -> retry to attempt 3 permitted
    (2, 3, False),  # attempt 3 failed -> no more retries (bounded)
    (1, 1, True),
    (1, 2, False),  # RuntimeExecutionLimits requires max_retries_per_step >= 1
                    # (docs/AGENT-RUNTIME.md "Additional contracts" / Step 3.4
                    # validation) -- "no retries at all" is expressed by a
                    # caller never invoking the Retry Controller, not by 0
                    # here; see test_limits_reject_non_positive_values.
])
def test_should_retry_is_bounded_by_attempt_number(max_retries, attempt_number, expected):
    controller = RetryController(_limits(max_retries))
    step = make_step(attempt_number)
    assert controller.should_retry(step) is expected


def test_retries_are_never_unbounded():
    """No configuration or attempt count makes should_retry always True
    -- this is a structural (not merely default) bound."""
    controller = RetryController(_limits(5))
    for attempt in range(1, 100):
        step = make_step(attempt)
        result = controller.should_retry(step)
        if attempt > 5:
            assert result is False
