"""Evidence hand-off boundary — docs/AGENT-RUNTIME.md §9.

This is deliberately **not** the real Evidence Store described in
``ARCHITECTURE.md`` §10 (durable, append-only, tamper-evident, hashed).
That store is out of scope for Phase 3 Step 3.4. This module only
defines the boundary a future Evidence Writer implements against, plus a
minimal in-memory stub so the Agent Loop Controller's "context/evidence
handoff" step (docs/AGENT-RUNTIME.md's lifecycle diagram) has something
concrete to call without silently pretending to be that real store.
"""
from __future__ import annotations

import uuid
from typing import Protocol

from chanakya.contracts.tool_result import ToolResult


class EvidenceRecorder(Protocol):
    def record(self, tool_result: ToolResult) -> str:
        """Returns an evidence_id. A real implementation would also write
        a full docs/CONTRACTS.md §7 ``Evidence`` record (content_hash,
        storage_ref, provenance) to an append-only store."""
        ...


class StubEvidenceRecorder:
    """NOT an Evidence Store. Assigns a bookkeeping id only — nothing is
    persisted, hashed, or made tamper-evident. This is a placeholder for
    the real Evidence Writer (a later Phase 3 step), used here only so
    the hand-off boundary itself is exercised end-to-end by this step's
    tests."""

    def record(self, tool_result: ToolResult) -> str:
        return f"stub-evidence-{uuid.uuid4()}"
