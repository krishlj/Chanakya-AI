"""ToolResult contract — docs/CONTRACTS.md §4.

The normalized outcome of actually executing a ``ToolRequest``. Nothing
in this module executes anything; a ``ToolResult`` is only ever produced
by feeding it real execution outcomes (or, in tests, an explicit test
double) — see docs/AGENT-RUNTIME.md §7-8 for why the Runtime never
fabricates a successful one itself.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Mapping, Optional, Sequence


class ToolResultStatus(str, Enum):
    """docs/CONTRACTS.md §4 — ToolResult.status. A closed enum; no
    free-form status strings (per the contract's own validation rule)."""

    SUCCESS = "success"
    FAILURE = "failure"
    TIMEOUT = "timeout"
    ERROR = "error"


@dataclass(frozen=True)
class ToolResult:
    tool_result_id: str
    contract_version: str
    tool_request_id: str
    capability: str
    status: ToolResultStatus
    started_at: str
    completed_at: str
    output: Optional[Mapping[str, Any]] = None
    error_message: Optional[str] = None
    exit_code: Optional[int] = None
    raw_output: Optional[str] = None
    warnings: Sequence[str] = field(default_factory=tuple)

    def __post_init__(self) -> None:
        if self.status == ToolResultStatus.SUCCESS and self.output is None:
            raise ValueError("ToolResult.output is required when status is 'success'")
