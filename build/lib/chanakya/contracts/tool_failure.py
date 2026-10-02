"""Runtime-owned failure vocabulary — Phase 16 (docs/THREAT-MODEL.md T-61).

A handler may *signal* a failure (raise), a timeout (raise
``ToolExecutionTimedOut``) or be overtaken by a cancellation. It never
controls the text that crosses a boundary. Every non-success ``ToolResult``
that reaches the audit log, model context, Review or the CLI carries an
``error_message`` from one closed, Runtime-defined vocabulary:

- ``tool_execution_failed: <CODE>`` (this module): handler exceptions,
  malformed handler returns, dispatch-table misses, timeouts, cancellation;
- ``capability_envelope_violation: <CODE>`` (Phase 11);
- ``sensitive_output_rejected: <CODE>`` (Phase 15).

A message is valid only if it is *exactly* one of those strings. There is
no prefix matching, no parsing and no repair: anything else (handler text,
an exception string or class name, an oversized or non-string value,
control characters) is rejected, and the Runtime fails the investigation
closed without recording the rejected text.

The vocabulary is data, not authority. Nothing in the Policy Gateway,
approval, dispatch authorization, the Registry or the Risk Engine reads
it; retry eligibility keeps using ``ToolResult.status`` and the existing
envelope/screening predicates.
"""
from __future__ import annotations

from typing import Any, Optional

from chanakya.capability.envelope import ENVELOPE_REASON_CODES, violation_message
from chanakya.capability.schema import SCHEMA_REASON_CODES

from .tool_output_screening import SCREENING_REASON_CODES, rejection_message
from .tool_result import ToolResult, ToolResultStatus

TOOL_EXECUTION_FAILED_PREFIX = "tool_execution_failed"

#: The handler raised. Its message, arguments and class name are dropped.
HANDLER_EXCEPTION = "HANDLER_EXCEPTION"
#: The handler returned something other than a mapping.
HANDLER_OUTPUT_MALFORMED = "HANDLER_OUTPUT_MALFORMED"
#: No handler is registered for the capability (a wiring error).
HANDLER_NOT_REGISTERED = "HANDLER_NOT_REGISTERED"
#: The instruction's target is not registered.
TARGET_NOT_REGISTERED = "TARGET_NOT_REGISTERED"
#: The handler does not support the target's type.
TARGET_TYPE_UNSUPPORTED = "TARGET_TYPE_UNSUPPORTED"
#: The handler signalled its own timeout. Its message is dropped.
HANDLER_TIMEOUT = "HANDLER_TIMEOUT"
#: The call ran past the resolved step timeout (post-hoc measurement).
STEP_TIMEOUT_EXCEEDED = "STEP_TIMEOUT_EXCEEDED"
#: The investigation ended while the call was in flight; the result was
#: discarded and replaced by this one.
CANCELLED = "CANCELLED"

FAILURE_REASON_CODES = frozenset(
    {
        HANDLER_EXCEPTION,
        HANDLER_OUTPUT_MALFORMED,
        HANDLER_NOT_REGISTERED,
        TARGET_NOT_REGISTERED,
        TARGET_TYPE_UNSUPPORTED,
        HANDLER_TIMEOUT,
        STEP_TIMEOUT_EXCEEDED,
        CANCELLED,
    }
)
TIMEOUT_REASON_CODES = frozenset({HANDLER_TIMEOUT, STEP_TIMEOUT_EXCEEDED})

#: No valid message is longer than this; longer input is rejected before
#: any other check.
MAX_FAILURE_MESSAGE_CHARS = 96

#: Problem codes for a non-success result that cannot cross a boundary.
FAILURE_TEXT_NOT_RUNTIME_OWNED = "FAILURE_TEXT_NOT_RUNTIME_OWNED"
FAILURE_STATUS_MISMATCH = "FAILURE_STATUS_MISMATCH"
FAILURE_CARRIES_CONTENT = "FAILURE_CARRIES_CONTENT"
FAILURE_PROBLEM_CODES = frozenset({FAILURE_TEXT_NOT_RUNTIME_OWNED, FAILURE_STATUS_MISMATCH, FAILURE_CARRIES_CONTENT})


def failure_message(code: str) -> str:
    """The fixed ``ToolResult.error_message`` for a Runtime failure code."""
    if code not in FAILURE_REASON_CODES:
        raise ValueError("unknown tool failure reason code")
    return f"{TOOL_EXECUTION_FAILED_PREFIX}: {code}"


_NON_SUCCESS_STATUSES = frozenset(
    status.value for status in ToolResultStatus if status is not ToolResultStatus.SUCCESS
)
_TIMEOUT_MESSAGES = frozenset(failure_message(code) for code in TIMEOUT_REASON_CODES)

#: Every error_message a non-success ToolResult may carry. Computed once
#: from the three closed code sets; membership is the whole check.
RUNTIME_FAILURE_MESSAGES = frozenset(
    {failure_message(code) for code in FAILURE_REASON_CODES}
    | {violation_message(code) for code in ENVELOPE_REASON_CODES | SCHEMA_REASON_CODES}
    | {rejection_message(code) for code in SCREENING_REASON_CODES}
)

if any(len(message) > MAX_FAILURE_MESSAGE_CHARS for message in RUNTIME_FAILURE_MESSAGES):  # pragma: no cover
    raise RuntimeError("a Runtime failure message exceeds MAX_FAILURE_MESSAGE_CHARS")


def is_runtime_failure_message(value: Any) -> bool:
    """True only for an exact member of ``RUNTIME_FAILURE_MESSAGES``."""
    return type(value) is str and len(value) <= MAX_FAILURE_MESSAGE_CHARS and value in RUNTIME_FAILURE_MESSAGES


def failure_message_problem(status: Any, error_message: Any) -> Optional[str]:
    """``None`` if a non-success ``(status, error_message)`` pair is
    Runtime-owned and consistent, otherwise one fixed problem code. Timeout
    codes go with ``timeout`` status, and only they do. Never echoes the
    input."""
    if not is_runtime_failure_message(error_message):
        return FAILURE_TEXT_NOT_RUNTIME_OWNED
    # ToolResultStatus is a str Enum, so a stored status string compares equal.
    if not isinstance(status, str) or status not in _NON_SUCCESS_STATUSES:
        return FAILURE_STATUS_MISMATCH
    if (status == ToolResultStatus.TIMEOUT) != (error_message in _TIMEOUT_MESSAGES):
        return FAILURE_STATUS_MISMATCH
    return None


def failure_result_problem(result: ToolResult) -> Optional[str]:
    """Phase 16 Runtime backstop for one non-success ``ToolResult``: the
    message must be Runtime-owned and consistent with the status, and the
    result must carry no other content (``output``, ``raw_output``,
    ``warnings``) that could reach a boundary."""
    problem = failure_message_problem(result.status, result.error_message)
    if problem is not None:
        return problem
    if result.output is not None or result.raw_output is not None or tuple(result.warnings or ()):
        return FAILURE_CARRIES_CONTENT
    return None


__all__ = [
    "CANCELLED",
    "FAILURE_CARRIES_CONTENT",
    "FAILURE_PROBLEM_CODES",
    "FAILURE_REASON_CODES",
    "FAILURE_STATUS_MISMATCH",
    "FAILURE_TEXT_NOT_RUNTIME_OWNED",
    "HANDLER_EXCEPTION",
    "HANDLER_NOT_REGISTERED",
    "HANDLER_OUTPUT_MALFORMED",
    "HANDLER_TIMEOUT",
    "MAX_FAILURE_MESSAGE_CHARS",
    "RUNTIME_FAILURE_MESSAGES",
    "STEP_TIMEOUT_EXCEEDED",
    "TARGET_NOT_REGISTERED",
    "TARGET_TYPE_UNSUPPORTED",
    "TIMEOUT_REASON_CODES",
    "TOOL_EXECUTION_FAILED_PREFIX",
    "failure_message",
    "failure_message_problem",
    "failure_result_problem",
    "is_runtime_failure_message",
]
