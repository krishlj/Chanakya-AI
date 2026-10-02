"""FindingStore — durable, append-only Finding storage, Phase 9
(docs/CONTRACTS.md §8, ARCHITECTURE.md §12).

Layout (``root`` supplied by the caller)::

    <root>/<investigation_id>/<finding_id>.json

Each file is ``{"finding": <Finding.to_dict()>, "recorded_at": ...,
"content_hash": "sha256:..."}``. ``recorded_at`` and ``content_hash`` are
store-owned: the hash covers the canonical JSON of ``finding`` and
``recorded_at`` and is re-verified on every read.

Append-only: there is no update, delete, replace or overwrite method. A
record is written to a temp file in the same directory, flushed and
fsynced, then hard-linked to its final name; ``os.link`` fails if that
name exists, so a ``finding_id`` collision fails closed and nothing is
ever overwritten. Identifiers go through the Evidence Store's path-safety
rule. A record over ``MAX_RECORD_BYTES`` is rejected, never truncated.

Like Evidence, a Finding is only as tamper-evident as a local file hash
allows (docs/THREAT-MODEL.md T-18): an edited record fails verification,
but someone able to rewrite the files can recompute the hash.
"""
from __future__ import annotations

import json
import os
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Tuple, Union

from chanakya.contracts.finding import Finding, FindingValidationError
from chanakya.evidence.hashing import canonical_bytes, compute_content_hash
from chanakya.evidence.store import InvalidIdentifierError as _EvidenceInvalidIdentifierError
from chanakya.evidence.store import _validate_identifier as _validate_evidence_identifier

#: Store-owned ceiling on one record's canonical serialized size.
MAX_RECORD_BYTES = 16384

_RECORD_KEYS = frozenset({"finding", "recorded_at", "content_hash"})


class FindingStoreError(Exception):
    """Base class for every error this store raises."""


class InvalidFindingIdentifierError(FindingStoreError):
    """An ``investigation_id`` or ``finding_id`` is not path-safe."""


class FindingIdCollisionError(FindingStoreError):
    """A record with this ``finding_id`` already exists. Never overwritten."""


class FindingRecordTooLargeError(FindingStoreError):
    """The record exceeds ``MAX_RECORD_BYTES``."""


class CorruptFindingError(FindingStoreError):
    """A stored record fails its shape or hash check."""


def _identifier(value: object, field_name: str) -> str:
    try:
        return _validate_evidence_identifier(value, field_name=field_name)
    except _EvidenceInvalidIdentifierError as exc:
        raise InvalidFindingIdentifierError(str(exc)) from None


def _utcnow_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


class FindingStore:
    MAX_RECORD_BYTES = MAX_RECORD_BYTES

    def __init__(self, root: Union[str, Path]) -> None:
        self._root = Path(root)

    @property
    def root(self) -> Path:
        return self._root

    def _dir(self, investigation_id: str) -> Path:
        root = self._root.resolve()
        path = (root / _identifier(investigation_id, "investigation_id")).resolve()
        if path.parent != root:
            raise InvalidFindingIdentifierError("investigation path escapes the store root")
        return path

    def append(self, finding: Finding) -> None:
        """Persists ``finding`` durably, or raises and writes nothing."""
        if not isinstance(finding, Finding):
            raise TypeError("FindingStore.append requires a Finding")
        directory = self._dir(finding.investigation_id)
        name = f"{_identifier(finding.finding_id, 'finding_id')}.json"
        hashed = {"finding": finding.to_dict(), "recorded_at": _utcnow_iso()}
        data = canonical_bytes(dict(hashed, content_hash=compute_content_hash(hashed)))
        if len(data) > MAX_RECORD_BYTES:
            raise FindingRecordTooLargeError(f"finding record is {len(data)} bytes; the limit is {MAX_RECORD_BYTES}")
        directory.mkdir(parents=True, exist_ok=True)
        final_path = directory / name
        if final_path.exists():
            raise FindingIdCollisionError(f"finding {finding.finding_id!r} already exists")
        fd, tmp_name = tempfile.mkstemp(dir=str(directory), prefix=".finding-tmp-", suffix=".tmp")
        tmp_path = Path(tmp_name)
        try:
            with os.fdopen(fd, "wb") as handle:
                handle.write(data)
                handle.flush()
                os.fsync(handle.fileno())
            try:
                os.link(tmp_path, final_path)
            except FileExistsError:
                raise FindingIdCollisionError(f"finding {finding.finding_id!r} already exists") from None
        finally:
            try:
                tmp_path.unlink(missing_ok=True)
            except OSError:
                pass

    def _read(self, path: Path, investigation_id: str) -> Finding:
        try:
            data = json.loads(path.read_bytes().decode("utf-8"))
        except (OSError, UnicodeDecodeError, json.JSONDecodeError):
            raise CorruptFindingError(f"unreadable finding record {path.name!r}") from None
        if not isinstance(data, dict) or set(data) != _RECORD_KEYS:
            raise CorruptFindingError(f"finding record {path.name!r} does not have the record shape")
        hashed = {"finding": data["finding"], "recorded_at": data["recorded_at"]}
        if compute_content_hash(hashed) != data["content_hash"]:
            raise CorruptFindingError(f"content_hash mismatch in finding record {path.name!r}")
        try:
            finding = Finding.from_dict(data["finding"])
        except (FindingValidationError, TypeError):
            raise CorruptFindingError(f"finding record {path.name!r} is not a valid Finding") from None
        if finding.investigation_id != investigation_id or f"{finding.finding_id}.json" != path.name:
            raise CorruptFindingError(f"finding record {path.name!r} is filed under the wrong name or investigation")
        return finding

    def list_by_investigation(self, investigation_id: str) -> Tuple[Finding, ...]:
        """Every Finding of one investigation, verified, ordered by
        ``created_at`` then ``finding_id``. Raises ``CorruptFindingError``
        rather than returning a partial list."""
        directory = self._dir(investigation_id)
        if not directory.is_dir():
            return ()
        findings = [self._read(path, investigation_id) for path in sorted(directory.glob("*.json"))]
        return tuple(sorted(findings, key=lambda f: (f.created_at, f.finding_id)))

    def verify(self, investigation_id: str) -> bool:
        """``False`` if any stored record fails verification."""
        try:
            self.list_by_investigation(investigation_id)
        except InvalidFindingIdentifierError:
            raise
        except Exception:
            return False
        return True


__all__ = [
    "MAX_RECORD_BYTES",
    "CorruptFindingError",
    "FindingIdCollisionError",
    "FindingRecordTooLargeError",
    "FindingStore",
    "FindingStoreError",
    "InvalidFindingIdentifierError",
]
