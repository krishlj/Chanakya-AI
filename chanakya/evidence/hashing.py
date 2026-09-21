"""Canonical serialization and content hashing — Phase 5.2.2.

Defines exactly what bytes ``chanakya.evidence.store.EvidenceStore``
hashes, and how, so the answer to "what does content_hash actually
cover" lives in one small, auditable place rather than inline inside the
Store's read/write methods.

Stdlib ``json``/``hashlib`` only — no pickle, no ``eval``, no custom
decoder hooks that could reconstruct an arbitrary Python object from
stored bytes. This module performs no filesystem I/O of its own.
"""
from __future__ import annotations

import hashlib
import json
from typing import Any, Mapping

_HASH_PREFIX = "sha256:"


def canonical_bytes(payload: Mapping[str, Any]) -> bytes:
    """Deterministic JSON serialization of ``payload``: keys sorted,
    fixed (no whitespace) separators, and ``ensure_ascii=True`` so every
    non-ASCII character is ``\\uXXXX``-escaped rather than encoded as a
    raw multi-byte UTF-8 sequence — the same logical content always
    produces byte-identical output regardless of platform or locale.
    The result is then UTF-8 encoded to bytes (safe, since the escaped
    JSON text itself is pure ASCII).
    """
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("utf-8")


def compute_content_hash(payload: Mapping[str, Any]) -> str:
    """``"sha256:<hex digest>"`` over ``canonical_bytes(payload)`` —
    matching docs/CONTRACTS.md §7's own documented format
    (``"content_hash": "sha256:9f86d081..."``).

    Callers (``chanakya.evidence.store.EvidenceStore``) MUST pass a
    ``payload`` mapping that excludes any pre-existing ``content_hash``
    key — hashing a record together with its own hash field would be
    circular. This function performs no such exclusion itself; it hashes
    exactly what it is given.
    """
    digest = hashlib.sha256(canonical_bytes(payload)).hexdigest()
    return f"{_HASH_PREFIX}{digest}"
