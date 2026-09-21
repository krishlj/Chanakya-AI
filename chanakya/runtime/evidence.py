"""Evidence hand-off boundary — docs/AGENT-RUNTIME.md §9.

Phase 5.2.3: the real, durable Evidence Store now exists
(``chanakya.evidence.store.EvidenceStore``, Phase 5.2.2). This module
defines the boundary the Agent Loop Controller calls through —
``EvidenceRecorder`` — and two implementations: ``StubEvidenceRecorder``
(unchanged in spirit, still a test/bookkeeping-only double, now updated
to match the new Protocol signature) and ``FilesystemEvidenceRecorder``
(new — a thin delegation wrapper over a real ``EvidenceStore``).

``EvidenceRecorder.record`` now takes a complete
``chanakya.contracts.evidence.Evidence`` object (previously a bare
``ToolResult``) — the caller (``AgentLoopController._execute_once``)
assembles it from context it already holds (see that module for exactly
which fields), the same way it already assembles a ``DispatchInstruction``
before calling a ``ToolExecutor``. Nothing in this module computes a
hash, assigns a storage location, or makes any policy/authorization
decision — those boundaries are unchanged from Phase 5.2.2 and Phase 2
respectively.
"""
from __future__ import annotations

import uuid
from typing import Protocol

from chanakya.contracts.evidence import Evidence
from chanakya.evidence.store import EvidenceStore


class EvidenceRecorder(Protocol):
    def record(self, evidence: Evidence) -> str:
        """Persists ``evidence`` and returns its ``evidence_id``. An
        implementation may replace ``evidence.content_hash``/
        ``recorded_at``/``storage_ref`` with authoritative values of its
        own (a real ``EvidenceStore`` always does — see
        ``FilesystemEvidenceRecorder``); it must never trust the
        caller-supplied placeholders for those three fields as final."""
        ...


class StubEvidenceRecorder:
    """NOT an Evidence Store. Assigns a bookkeeping id only — nothing is
    persisted, hashed, or made tamper-evident. Ignores the ``Evidence``
    object it's given entirely (it still doesn't need any of its fields
    to do its job); kept for tests/callers that want the hand-off
    boundary exercised without any real persistence."""

    def record(self, evidence: Evidence) -> str:
        return f"stub-evidence-{uuid.uuid4()}"


class FilesystemEvidenceRecorder:
    """The real ``EvidenceRecorder``, backed by a real, durable
    ``EvidenceStore`` (Phase 5.2.2). A thin delegation wrapper only:

    - accepts an already-assembled ``Evidence`` object
    - delegates directly to ``EvidenceStore.append()``
    - returns the persisted (Store-authoritative) ``evidence_id``
    - computes no hash itself, assigns no ``storage_ref`` itself —
      ``EvidenceStore`` remains the sole authority for both, exactly as
      it already is for any other caller of ``append()``
    - makes no policy decision, performs no authorization, and does not
      modify ``evidence`` before handing it to the Store

    Any exception ``EvidenceStore.append()`` raises (collision,
    oversized payload, a filesystem error) propagates unchanged — this
    class adds no try/except of its own. The caller
    (``AgentLoopController``) already treats any exception from
    ``record()`` as an evidence-recording failure and halts the
    investigation accordingly (docs/AGENT-RUNTIME.md §9); nothing here
    needs to duplicate that handling.
    """

    def __init__(self, store: EvidenceStore) -> None:
        self._store = store

    def record(self, evidence: Evidence) -> str:
        return self._store.append(evidence).evidence_id
