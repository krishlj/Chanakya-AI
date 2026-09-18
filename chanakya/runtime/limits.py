"""RuntimeExecutionLimits — docs/AGENT-RUNTIME.md "Additional contracts".

Admin-controlled, trusted configuration — analogous to
``chanakya.policy.rules.PolicySet`` and the Security Tool Registry's own
configuration. Never Agent-writable, never influenced by any
``ToolRequest``/``AgentTurnOutput`` field (docs/AGENT-RUNTIME.md §18).
"""
from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Optional


class ApprovalExpiryAction(str, Enum):
    """docs/AGENT-RUNTIME.md §18 — what happens when a Permission-Level-4
    ``ApprovalRequest`` expires unanswered. Every other permission level
    always resolves expiry to a step-level denial (never a whole-
    investigation halt) — this option exists only to let an operator
    choose a stricter default for the highest-risk tier."""

    FAIL_STEP = "fail_step"
    HALT_INVESTIGATION = "halt_investigation"


@dataclass(frozen=True)
class RuntimeExecutionLimits:
    """docs/AGENT-RUNTIME.md §18. Every field is required except the two
    explicitly marked optional in the design doc; there is no "unlimited"
    sentinel — an operator who wants a very high ceiling sets a very high
    number, so every deployment is fail-closed by construction rather
    than by remembering to configure a limit at all."""

    config_version: str
    max_steps_per_investigation: int
    max_tool_calls_per_investigation: int
    max_investigation_duration_seconds: int
    default_step_timeout_seconds: int
    max_retries_per_step: int
    retry_backoff_seconds: int
    max_concurrent_investigations: int
    approval_expiry_seconds_default: Optional[int] = None
    p4_approval_expiry_action: ApprovalExpiryAction = ApprovalExpiryAction.FAIL_STEP

    def __post_init__(self) -> None:
        for field_name in (
            "max_steps_per_investigation",
            "max_tool_calls_per_investigation",
            "max_investigation_duration_seconds",
            "default_step_timeout_seconds",
            "max_retries_per_step",
            "max_concurrent_investigations",
        ):
            value = getattr(self, field_name)
            if not isinstance(value, int) or isinstance(value, bool) or value <= 0:
                raise ValueError(f"RuntimeExecutionLimits.{field_name} must be a positive integer")
        if not isinstance(self.retry_backoff_seconds, int) or isinstance(self.retry_backoff_seconds, bool) or self.retry_backoff_seconds < 0:
            raise ValueError("RuntimeExecutionLimits.retry_backoff_seconds must be a non-negative integer")
        if self.approval_expiry_seconds_default is not None and self.approval_expiry_seconds_default <= 0:
            raise ValueError("RuntimeExecutionLimits.approval_expiry_seconds_default must be positive if set")
