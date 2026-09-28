"""Timeout Supervisor — docs/AGENT-RUNTIME.md §10 (Phase 3 Step 3.5)."""
from __future__ import annotations

from datetime import datetime, timezone

import pytest

from chanakya.runtime.dispatch import DispatchInstruction
from chanakya.runtime.exceptions import ResourceLimitExceededError
from chanakya.runtime.limits import RuntimeExecutionLimits
from chanakya.runtime.resource_governor import ResourceGovernor
from chanakya.runtime.timeout_supervisor import TimeoutSupervisor, ToolExecutionTimedOut

from runtime_factories import FakeToolExecutor, SequenceClock, iso


def make_instruction() -> DispatchInstruction:
    return DispatchInstruction(
        investigation_id="inv-1",
        tool_request_id="tr-1",
        capability="list_listening_ports",
        target_ref="target-local-host-01",
        parameters={},
        resolved_timeout_seconds=5,
        resolved_resource_limits={},
        policy_decision_id="pd-1",
        attempt_number=1,
    )


def test_investigation_timeout_delegates_to_resource_governor():
    limits = RuntimeExecutionLimits(
        config_version="1.0.0",
        max_steps_per_investigation=5,
        max_tool_calls_per_investigation=5,
        max_investigation_duration_seconds=10,
        default_step_timeout_seconds=5,
        max_retries_per_step=1,
        retry_backoff_seconds=0,
        max_concurrent_investigations=1,
    )
    governor = ResourceGovernor(limits, clock=lambda: datetime(2026, 1, 1, tzinfo=timezone.utc))
    governor.register_investigation("inv-1")
    supervisor = TimeoutSupervisor(governor, clock=lambda: "2026-01-01T00:00:00Z")

    supervisor.check_investigation_timeout("inv-1")  # no time elapsed -- fine

    governor_over_budget = ResourceGovernor(limits, clock=SequenceClock([datetime(2026, 1, 1, tzinfo=timezone.utc), datetime(2026, 1, 1, 0, 0, 11, tzinfo=timezone.utc)]))
    governor_over_budget.register_investigation("inv-2")
    supervisor2 = TimeoutSupervisor(governor_over_budget)
    with pytest.raises(ResourceLimitExceededError):
        supervisor2.check_investigation_timeout("inv-2")


def test_fast_execution_returns_the_real_result_unmodified():
    supervisor = TimeoutSupervisor(ResourceGovernor(
        RuntimeExecutionLimits(
            config_version="1.0.0", max_steps_per_investigation=5, max_tool_calls_per_investigation=5,
            max_investigation_duration_seconds=60, default_step_timeout_seconds=5, max_retries_per_step=1,
            retry_backoff_seconds=0, max_concurrent_investigations=1,
        ),
        clock=lambda: datetime.now(timezone.utc),
    ), clock=SequenceClock([iso(0), iso(1)]))  # 1 second elapsed, well within the 5s budget
    executor = FakeToolExecutor()
    instruction = make_instruction()

    result = supervisor.execute_with_timeout(instruction, executor, timeout_seconds=5)

    assert executor.call_count == 1
    assert result.status.value == "success"


def test_executor_signaled_timeout_becomes_synthetic_timeout_result():
    supervisor = TimeoutSupervisor(
        ResourceGovernor(
            RuntimeExecutionLimits(
                config_version="1.0.0", max_steps_per_investigation=5, max_tool_calls_per_investigation=5,
                max_investigation_duration_seconds=60, default_step_timeout_seconds=5, max_retries_per_step=1,
                retry_backoff_seconds=0, max_concurrent_investigations=1,
            ),
            clock=lambda: datetime.now(timezone.utc),
        ),
        clock=SequenceClock([iso(0), iso(1)]),
    )

    class TimingOutExecutor:
        def execute(self, instruction):
            raise ToolExecutionTimedOut("tool exceeded its own configured timeout")

    result = supervisor.execute_with_timeout(make_instruction(), TimingOutExecutor(), timeout_seconds=5)
    assert result.status.value == "timeout"
    # Phase 16 (NX16-INV-3): the signal's own message is never used.
    assert result.error_message == "tool_execution_failed: HANDLER_TIMEOUT"
    assert "own configured timeout" not in result.error_message


def test_an_overrunning_result_is_discarded_never_trusted():
    """The defense-in-depth backstop: even if the executor returns
    successfully, a result that took longer than its budget is never
    returned to the caller — it is replaced with a synthetic timeout."""
    supervisor = TimeoutSupervisor(
        ResourceGovernor(
            RuntimeExecutionLimits(
                config_version="1.0.0", max_steps_per_investigation=5, max_tool_calls_per_investigation=5,
                max_investigation_duration_seconds=600, default_step_timeout_seconds=5, max_retries_per_step=1,
                retry_backoff_seconds=0, max_concurrent_investigations=1,
            ),
            clock=lambda: datetime.now(timezone.utc),
        ),
        clock=SequenceClock([iso(0), iso(999)]),  # simulated 999s "execution"
    )
    executor = FakeToolExecutor()  # returns SUCCESS immediately (fast in wall-clock reality)

    result = supervisor.execute_with_timeout(make_instruction(), executor, timeout_seconds=5)

    assert executor.call_count == 1  # the call did happen...
    assert result.status.value == "timeout"  # ...but its result was discarded
    assert result.error_message == "tool_execution_failed: STEP_TIMEOUT_EXCEEDED"


def test_bind_routes_calls_through_the_supervisor():
    supervisor = TimeoutSupervisor(
        ResourceGovernor(
            RuntimeExecutionLimits(
                config_version="1.0.0", max_steps_per_investigation=5, max_tool_calls_per_investigation=5,
                max_investigation_duration_seconds=60, default_step_timeout_seconds=5, max_retries_per_step=1,
                retry_backoff_seconds=0, max_concurrent_investigations=1,
            ),
            clock=lambda: datetime.now(timezone.utc),
        ),
        clock=SequenceClock([iso(0), iso(1)]),
    )
    executor = FakeToolExecutor()
    bound = supervisor.bind(executor, timeout_seconds=5)
    result = bound.execute(make_instruction())
    assert executor.call_count == 1
    assert result.status.value == "success"
