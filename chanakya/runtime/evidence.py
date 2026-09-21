"""Evidence hand-off boundary — docs/AGENT-RUNTIME.md §9.

Phase 5.2.3: the real, durable Evidence Store now exists
(``chanakya.evidence.store.EvidenceStore``, Phase 5.2.2). This module
defines the boundary the Agent Loop Controller calls through —
``EvidenceRecorder`` — and two implementations: ``StubEvidenceRecorder``
(unchanged in spirit, still a test/bookkeeping-only double) and
``FilesystemEvidenceRecorder`` (a thin delegation wrapper over a real
``EvidenceStore``).

``EvidenceRecorder.record`` takes a complete
``chanakya.contracts.evidence.Evidence`` object — the caller
(``AgentLoopController._execute_once``) assembles it from context it
already holds, the same way it already assembles a ``DispatchInstruction``
before calling a ``ToolExecutor``. Nothing in this module computes a
hash, assigns a storage location, or makes any policy/authorization
decision — those boundaries are unchanged from Phase 5.2.2 and Phase 2
respectively.

Phase 5.3: ``record`` gains an optional ``payload`` parameter — the
actual tool-output content (``ToolResult.output`` and friends), kept out
of the ``Evidence`` object itself per its own, unmodified Phase 5.2.1
design. This module still computes nothing and decides nothing about
it; it is forwarded to ``EvidenceStore.append()`` exactly as received,
which remains the sole authority for hashing, storage, and chaining
(``chanakya.evidence.store``).
"""
from __future__ import annotations

import uuid
from typing import Any, Mapping, Optional, Protocol

from chanakya.contracts.evidence import Evidence
from chanakya.evidence.store import EvidenceStore


class EvidenceRecorder(Protocol):
    def record(self, evidence: Evidence, payload: Optional[Mapping[str, Any]] = None) -> str:
        """Persists ``evidence`` (and, if given, ``payload`` — the
        actual tool-output content) and returns ``evidence.evidence_id``.
        An implementation may replace ``evidence.content_hash``/
        ``recorded_at``/``storage_ref``/``payload_hash`` with
        authoritative values of its own (a real ``EvidenceStore`` always
        does — see ``FilesystemEvidenceRecorder``); it must never trust
        the caller-supplied placeholders for those fields as final, and
        must never itself decide what ``payload`` means beyond storing
        it as opaque data."""
        ...


class StubEvidenceRecorder:
    """NOT an Evidence Store. Assigns a bookkeeping id only — nothing is
    persisted, hashed, or made tamper-evident. Ignores both the
    ``Evidence`` object and the ``payload`` it's given entirely (it
    still doesn't need any of it to do its job); kept for tests/callers
    that want the hand-off boundary exercised without any real
    persistence."""

    def record(self, evidence: Evidence, payload: Optional[Mapping[str, Any]] = None) -> str:
        return f"stub-evidence-{uuid.uuid4()}"


class FilesystemEvidenceRecorder:
    """The real ``EvidenceRecorder``, backed by a real, durable
    ``EvidenceStore`` (Phase 5.2.2, extended Phase 5.3). A thin
    delegation wrapper only:

    - accepts an already-assembled ``Evidence`` object and an optional,
      already-assembled ``payload`` mapping
    - delegates directly to ``EvidenceStore.append(evidence, payload)``
    - returns the persisted (Store-authoritative) ``evidence_id``
    - computes no hash itself, assigns no ``storage_ref``/``payload_hash``
      itself — ``EvidenceStore`` remains the sole authority for all of
      it, exactly as it already is for any other caller of ``append()``
    - makes no policy decision, performs no authorization, and does not
      modify ``evidence``/``payload`` before handing them to the Store

    Any exception ``EvidenceStore.append()`` raises (collision,
    oversized metadata or payload, a filesystem error) propagates
    unchanged — this class adds no try/except of its own. The caller
    (``AgentLoopController``) already treats any exception from
    ``record()`` as an evidence-recording failure and halts the
    investigation accordingly (docs/AGENT-RUNTIME.md §9); nothing here
    needs to duplicate that handling.
    """

    def __init__(self, store: EvidenceStore) -> None:
        self._store = store

    def record(self, evidence: Evidence, payload: Optional[Mapping[str, Any]] = None) -> str:
        return self._store.append(evidence, payload).evidence_id
