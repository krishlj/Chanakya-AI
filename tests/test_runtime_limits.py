"""RuntimeExecutionLimits and ResourceGovernor — docs/AGENT-RUNTIME.md
§18. Every check must fail closed: the action is refused *before* it is
allowed to proceed, never permitted-then-flagged."""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from chanakya.runtime.exceptions import ResourceLimitExceededError
from chanakya.runtime.limits import RuntimeExecutionLimits
from chanakya.runtime.resource_governor import ResourceGovernor


@pytest.mark.parametrize(
    "field_name",
    [
        "max_steps_per_investigation",
        "max_tool_calls_per_investigation",
        "max_investigation_duration_seconds",
        "default_step_timeout_seconds",
        "max_retries_per_step",
        "max_concurrent_investigations",
    ],
)
def test_limits_reject_non_positive_values(field_name):
    base = dict(
        config_version="1.0.0",
        max_steps_per_investigation=5,
        max_tool_calls_per_investigation=5,
        max_investigation_duration_seconds=60,
        default_step_timeout_seconds=15,
        max_retries_per_step=1,
        retry_backoff_seconds=1,
        max_concurrent_investigations=1,
    )
    base[field_name] = 0
    with pytest.raises(ValueError):
        RuntimeExecutionLimits(**base)


def test_retry_backoff_seconds_may_be_zero():
    limits = RuntimeExecutionLimits(
        config_version="1.0.0",
        max_steps_per_investigation=5,
        max_tool_calls_per_investigation=5,
        max_investigation_duration_seconds=60,
        default_step_timeout_seconds=15,
        max_retries_per_step=1,
        retry_backoff_seconds=0,
        max_concurrent_investigations=1,
    )
    assert limits.retry_backoff_seconds == 0


def _limits(**overrides) -> RuntimeExecutionLimits:
    base = dict(
        config_version="1.0.0",
        max_steps_per_investigation=2,
        max_tool_calls_per_investigation=2,
        max_investigation_duration_seconds=60,
        default_step_timeout_seconds=15,
        max_retries_per_step=1,
        retry_backoff_seconds=1,
        max_concurrent_investigations=2,
    )
    base.update(overrides)
    return RuntimeExecutionLimits(**base)


def test_max_steps_per_investigation_is_enforced_and_fails_closed():
    governor = ResourceGovernor(_limits(max_steps_per_investigation=2), clock=lambda: datetime.now(timezone.utc))
    governor.register_investigation("inv-1")
    governor.record_step_proposed("inv-1")
    governor.record_step_proposed("inv-1")
    with pytest.raises(ResourceLimitExceededError):
        governor.record_step_proposed("inv-1")
    # The rejected call must not have been counted.
    assert governor.step_count("inv-1") == 2


def test_max_tool_calls_per_investigation_is_enforced():
    governor = ResourceGovernor(_limits(max_tool_calls_per_investigation=1), clock=lambda: datetime.now(timezone.utc))
    governor.register_investigation("inv-1")
    governor.record_tool_call("inv-1", "list_listening_ports")
    with pytest.raises(ResourceLimitExceededError):
        governor.record_tool_call("inv-1", "list_listening_ports")
    assert governor.tool_call_count("inv-1") == 1


def test_capability_call_counts_are_tracked_per_capability():
    governor = ResourceGovernor(_limits(max_tool_calls_per_investigation=5), clock=lambda: datetime.now(timezone.utc))
    governor.register_investigation("inv-1")
    governor.record_tool_call("inv-1", "list_listening_ports")
    governor.record_tool_call("inv-1", "list_listening_ports")
    governor.record_tool_call("inv-1", "get_os_info")
    counts = governor.capability_call_counts("inv-1")
    assert counts == {"list_listening_ports": 2, "get_os_info": 1}


def test_max_concurrent_investigations_is_enforced():
    governor = ResourceGovernor(_limits(max_concurrent_investigations=1), clock=lambda: datetime.now(timezone.utc))
    governor.register_investigation("inv-1")
    with pytest.raises(ResourceLimitExceededError):
        governor.register_investigation("inv-2")

    governor.release_investigation("inv-1")
    governor.register_investigation("inv-2")  # slot freed, now succeeds


def test_max_investigation_duration_is_enforced_with_a_fake_clock():
    ticks = [datetime(2026, 1, 1, tzinfo=timezone.utc)]

    def fake_clock():
        return ticks[0]

    governor = ResourceGovernor(_limits(max_investigation_duration_seconds=10), clock=fake_clock)
    governor.register_investigation("inv-1")
    governor.check_duration("inv-1")  # no time elapsed yet — fine

    ticks[0] = ticks[0] + timedelta(seconds=11)
    with pytest.raises(ResourceLimitExceededError):
        governor.check_duration("inv-1")
