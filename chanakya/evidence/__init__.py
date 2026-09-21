"""Filesystem Evidence Store — Phase 5.2.2.

See ``chanakya.evidence.store`` for the implementation and its full
design rationale. Not wired into the Agent Runtime yet (Phase 5.2.3).
"""
from __future__ import annotations

from .store import (
    CorruptEvidenceError,
    EvidenceIdCollisionError,
    EvidenceStore,
    EvidenceStoreError,
    InvalidIdentifierError,
    PayloadTooLargeError,
    UnknownEvidenceError,
)

__all__ = [
    "EvidenceStore",
    "EvidenceStoreError",
    "InvalidIdentifierError",
    "EvidenceIdCollisionError",
    "UnknownEvidenceError",
    "CorruptEvidenceError",
    "PayloadTooLargeError",
]
