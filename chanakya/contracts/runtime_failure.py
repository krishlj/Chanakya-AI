"""Runtime-owned error and terminal records — Phase 17 (docs/THREAT-MODEL.md T-62).

Distinct from ``chanakya.contracts.tool_failure`` (Phase 16), which governs
``ToolResult.error_message``. This module governs what the Runtime itself
records when an investigation fails, halts or hits an internal error:

- the ``details`` of ``error`` and ``investigation_halted`` audit events;
- ``InvestigationContext.error_state``;
- ``TurnResult.detail`` (and therefore the CLI).

Exceptions raised by the provider SDK, target/environment adapters, the
stores, the approval provider or anything else are *signals*. Their text,
arguments and class names never become a record. A record is built only
from:

- a ``reason`` from ``TERMINAL_REASONS`` (the Runtime's existing reason
  strings);
- a ``category`` from ``RUNTIME_FAILURE_CATEGORIES``, allowed for that
  reason;
- optional, closed, bounded facts (``FACT_KEYS``).

Everything is validated before it is recorded; anything else is rejected
(``TerminalRecordError``, fixed message). Records are tiny by
construction, so no external text can make a terminal event too large or
unsafe to persist.

The vocabulary is descriptive data, never authority: the Policy Gateway,
approval, the Registry, the Risk Engine and the Retry Controller never
read it.
"""
from __future__ import annotations

import re
from typing import Any, Dict, Mapping, Optional

from .tool_failure import FAILURE_PROBLEM_CODES
from .tool_output_screening import is_credential_shaped_value

# -- categories -----------------------------------------------------------------

PROVIDER_FAILURE = "PROVIDER_FAILURE"
APPROVAL_FAILURE = "APPROVAL_FAILURE"
TOOL_EXECUTOR_FAILURE = "TOOL_EXECUTOR_FAILURE"
RUNTIME_EXCEPTION = "RUNTIME_EXCEPTION"
AUDIT_FAILURE = "AUDIT_FAILURE"
TARGET_CONTEXT_UNAVAILABLE = "TARGET_CONTEXT_UNAVAILABLE"
ENVIRONMENT_UNAVAILABLE = "ENVIRONMENT_UNAVAILABLE"
CONTEXT_SOURCE_REJECTED = "CONTEXT_SOURCE_REJECTED"
EVIDENCE_RECORDING_FAILED = "EVIDENCE_RECORDING_FAILED"
FINDING_RECORDING_FAILED = "FINDING_RECORDING_FAILED"
FINDING_STORE_UNAVAILABLE = "FINDING_STORE_UNAVAILABLE"
RISK_ASSESSMENT_FAILED = "RISK_ASSESSMENT_FAILED"
RESOURCE_LIMIT_EXCEEDED = "RESOURCE_LIMIT_EXCEEDED"
DISPATCH_PRECONDITION_VIOLATION = "DISPATCH_PRECONDITION_VIOLATION"
TOOL_FAILURE_OUTPUT_REJECTED = "TOOL_FAILURE_OUTPUT_REJECTED"
APPROVAL_EXPIRED = "APPROVAL_EXPIRED"
CANCELLED = "CANCELLED"

RUNTIME_FAILURE_CATEGORIES = frozenset(
    {
        PROVIDER_FAILURE, APPROVAL_FAILURE, TOOL_EXECUTOR_FAILURE, RUNTIME_EXCEPTION, AUDIT_FAILURE,
        TARGET_CONTEXT_UNAVAILABLE, ENVIRONMENT_UNAVAILABLE, CONTEXT_SOURCE_REJECTED,
        EVIDENCE_RECORDING_FAILED, FINDING_RECORDING_FAILED, FINDING_STORE_UNAVAILABLE,
        RISK_ASSESSMENT_FAILED, RESOURCE_LIMIT_EXCEEDED, DISPATCH_PRECONDITION_VIOLATION,
        TOOL_FAILURE_OUTPUT_REJECTED, APPROVAL_EXPIRED, CANCELLED,
    }
)

# -- reasons (the Runtime's existing reason strings) and allowed categories --------

#: The backstop's reason; its category says which component failed.
UNHANDLED_RUNTIME_EXCEPTION = "unhandled_runtime_exception"
AUDIT_SINK_FAILURE = "audit_sink_failure"

REASON_CATEGORIES: Mapping[str, frozenset] = {
    UNHANDLED_RUNTIME_EXCEPTION: frozenset({PROVIDER_FAILURE, APPROVAL_FAILURE, TOOL_EXECUTOR_FAILURE, RUNTIME_EXCEPTION}),
    AUDIT_SINK_FAILURE: frozenset({AUDIT_FAILURE}),
    "target_context_unavailable": frozenset({TARGET_CONTEXT_UNAVAILABLE}),
    "environment_context_unavailable": frozenset({ENVIRONMENT_UNAVAILABLE}),
    "context_source_rejected": frozenset({CONTEXT_SOURCE_REJECTED}),
    "finding_store_unavailable": frozenset({FINDING_STORE_UNAVAILABLE}),
    "finding_recording_failed": frozenset({FINDING_RECORDING_FAILED}),
    "evidence_recording_failed": frozenset({EVIDENCE_RECORDING_FAILED}),
    "risk_assessment_failed": frozenset({RISK_ASSESSMENT_FAILED}),
    "dispatch_precondition_violation": frozenset({DISPATCH_PRECONDITION_VIOLATION}),
    "tool_failure_output_rejected": frozenset({TOOL_FAILURE_OUTPUT_REJECTED}),
    "max_investigation_duration_seconds_exceeded": frozenset({RESOURCE_LIMIT_EXCEEDED}),
    "max_context_bytes_exceeded": frozenset({RESOURCE_LIMIT_EXCEEDED}),
    "max_provider_output_bytes_exceeded": frozenset({RESOURCE_LIMIT_EXCEEDED}),
    "max_steps_per_investigation_exceeded": frozenset({RESOURCE_LIMIT_EXCEEDED}),
    "max_tool_calls_per_investigation_exceeded": frozenset({RESOURCE_LIMIT_EXCEEDED}),
    "p4_approval_expired": frozenset({APPROVAL_EXPIRED}),
    "cancelled_by_operator": frozenset({CANCELLED}),
}
TERMINAL_REASONS = frozenset(REASON_CATEGORIES)

# -- facts ------------------------------------------------------------------------

#: The only optional facts a record may carry, each closed or bounded.
FACT_CODE = "code"                  # a Phase 16 failure problem code
FACT_FINDING_COUNT = "finding_count"  # how many findings were dropped (1..MAX_FINDING_COUNT)
FACT_CANCELLED_BY = "cancelled_by"  # the operator who cancelled (asserted, screened, bounded)
FACT_KEYS = frozenset({FACT_CODE, FACT_FINDING_COUNT, FACT_CANCELLED_BY})
MAX_FINDING_COUNT = 1000
MAX_CANCELLED_BY_CHARS = 256

#: ``error`` details of a terminal FAILED transition carry this marker.
INVESTIGATION_STATUS_KEY = "investigation_status"
FAILED_MARKER = "failed"

_LINE_FORBIDDEN = re.compile(r"[\x00-\x1f\x7f]")


class TerminalRecordError(ValueError):
    """A terminal or error record is not in the closed shape. The message
    is fixed; it never contains the rejected value."""

    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(f"terminal record rejected: {code}")


def default_category(reason: str) -> str:
    """The category of a reason that has exactly one."""
    allowed = REASON_CATEGORIES.get(reason)
    if allowed is None or len(allowed) != 1:
        raise TerminalRecordError("CATEGORY_REQUIRED")
    return next(iter(allowed))


def _fact_ok(key: str, value: Any) -> bool:
    if key == FACT_CODE:
        return type(value) is str and value in FAILURE_PROBLEM_CODES
    if key == FACT_FINDING_COUNT:
        return type(value) is int and 1 <= value <= MAX_FINDING_COUNT
    if key == FACT_CANCELLED_BY:
        return (
            type(value) is str
            and 0 < len(value) <= MAX_CANCELLED_BY_CHARS
            and not _LINE_FORBIDDEN.search(value)
            and not is_credential_shaped_value(value)
        )
    return False


def terminal_record(reason: Any, category: Any = None, facts: Optional[Mapping[str, Any]] = None) -> Dict[str, Any]:
    """Builds and validates ``{"reason", "category", **facts}``. Raises
    ``TerminalRecordError`` for an unknown reason, a category not allowed
    for it, or any fact outside ``FACT_KEYS`` or its bounds."""
    if type(reason) is not str or reason not in REASON_CATEGORIES:
        raise TerminalRecordError("REASON_UNKNOWN")
    category = default_category(reason) if category is None else category
    if type(category) is not str or category not in REASON_CATEGORIES[reason]:
        raise TerminalRecordError("CATEGORY_INVALID")
    record: Dict[str, Any] = {"reason": reason, "category": category}
    for key, value in dict(facts or {}).items():
        if key not in FACT_KEYS or not _fact_ok(key, value):
            raise TerminalRecordError("FACT_INVALID")
        record[key] = value
    return record


def validate_terminal_details(event_type: str, details: Any) -> Optional[str]:
    """Review (AuditEvent 1.4.0): ``None`` if stored ``error`` or
    ``investigation_halted`` details are exactly a closed-shape record,
    otherwise a fixed problem code. Never echoes the input."""
    if not isinstance(details, Mapping):
        return "terminal_details_invalid"
    body = dict(details)
    if event_type == "error" and body.get(INVESTIGATION_STATUS_KEY) is not None:
        if body.pop(INVESTIGATION_STATUS_KEY) != FAILED_MARKER:
            return "terminal_details_invalid"
    try:
        facts = {k: v for k, v in body.items() if k not in ("reason", "category")}
        rebuilt = terminal_record(body.get("reason"), body.get("category"), facts)
    except TerminalRecordError:
        return "terminal_details_invalid"
    return None if rebuilt == body else "terminal_details_invalid"


#: In-memory only (never persisted: the sink failed). Marks a terminal
#: state whose audit event could not be written (P17-INV-3).
TERMINAL_RECORD_KEY = "terminal_record"
NOT_DURABLE = "not_durable"


def undurable_terminal_state() -> Dict[str, Any]:
    """``error_state`` of an investigation whose terminal event could not be
    written because the audit sink itself failed."""
    return {"reason": AUDIT_SINK_FAILURE, "category": AUDIT_FAILURE, TERMINAL_RECORD_KEY: NOT_DURABLE}


# -- TurnResult.detail --------------------------------------------------------------

#: Fixed, non-error notes a TurnResult may carry.
AWAITING_APPROVAL_PENDING = "AWAITING_APPROVAL_PENDING"
NO_APPROVAL_PROVIDER = "NO_APPROVAL_PROVIDER"
INVESTIGATION_ENDED_DURING_APPROVAL = "INVESTIGATION_ENDED_DURING_APPROVAL"
INVESTIGATION_ENDED_DURING_EXECUTION = "INVESTIGATION_ENDED_DURING_EXECUTION"
APPROVAL_EXPIRED_STEP_DENIED = "APPROVAL_EXPIRED_STEP_DENIED"
MALFORMED_TURN = "MALFORMED_TURN"
MULTIPLE_TOOL_USE_BLOCKS = "MULTIPLE_TOOL_USE_BLOCKS"
UNSUPPORTED_STOP_REASON = "UNSUPPORTED_STOP_REASON"
RESERVED_CHANNEL_MISUSE = "RESERVED_CHANNEL_MISUSE"
INVALID_FINDINGS = "INVALID_FINDINGS"
MALFORMED_TOOL_REQUEST = "MALFORMED_TOOL_REQUEST"

TURN_NOTE_CODES = frozenset(
    {
        AWAITING_APPROVAL_PENDING, NO_APPROVAL_PROVIDER, INVESTIGATION_ENDED_DURING_APPROVAL,
        INVESTIGATION_ENDED_DURING_EXECUTION, APPROVAL_EXPIRED_STEP_DENIED, MALFORMED_TURN,
        MULTIPLE_TOOL_USE_BLOCKS, UNSUPPORTED_STOP_REASON, RESERVED_CHANNEL_MISUSE, INVALID_FINDINGS,
        MALFORMED_TOOL_REQUEST,
    }
)
#: Every value ``TurnResult.detail`` may take (besides ``None``).
TURN_DETAIL_CODES = frozenset(RUNTIME_FAILURE_CATEGORIES | TURN_NOTE_CODES)


def is_turn_detail(value: Any) -> bool:
    return value is None or (type(value) is str and value in TURN_DETAIL_CODES)


__all__ = [
    "AUDIT_FAILURE", "AUDIT_SINK_FAILURE", "APPROVAL_EXPIRED", "APPROVAL_FAILURE", "CANCELLED",
    "CONTEXT_SOURCE_REJECTED", "DISPATCH_PRECONDITION_VIOLATION", "ENVIRONMENT_UNAVAILABLE",
    "EVIDENCE_RECORDING_FAILED", "FACT_CANCELLED_BY", "FACT_CODE", "FACT_FINDING_COUNT", "FACT_KEYS",
    "FAILED_MARKER", "FINDING_RECORDING_FAILED", "FINDING_STORE_UNAVAILABLE", "INVESTIGATION_STATUS_KEY",
    "PROVIDER_FAILURE", "REASON_CATEGORIES", "RESOURCE_LIMIT_EXCEEDED", "RISK_ASSESSMENT_FAILED",
    "RUNTIME_EXCEPTION", "RUNTIME_FAILURE_CATEGORIES", "TARGET_CONTEXT_UNAVAILABLE", "TERMINAL_REASONS",
    "TOOL_EXECUTOR_FAILURE", "TOOL_FAILURE_OUTPUT_REJECTED", "TURN_DETAIL_CODES", "TURN_NOTE_CODES",
    "NOT_DURABLE", "TERMINAL_RECORD_KEY", "TerminalRecordError", "UNHANDLED_RUNTIME_EXCEPTION",
    "default_category", "is_turn_detail", "terminal_record", "undurable_terminal_state",
    "validate_terminal_details",
]
