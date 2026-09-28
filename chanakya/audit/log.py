"""FilesystemAuditLog — the durable Audit Log, Phase 6
(ARCHITECTURE.md §14, docs/AGENT-RUNTIME.md §14, docs/THREAT-MODEL.md T-18).

Implements the existing ``chanakya.runtime.audit.AuditSink`` protocol
(``emit(event)``), so it plugs into the existing ``AuditEmitter`` used by
``InvestigationManager`` and ``AgentLoopController`` with no Runtime change.
Any exception raised here is wrapped by ``AuditEmitter`` in
``AuditSinkError``, which the Agent Loop Controller already routes to a
``halted`` investigation (RT-INV-6): an audit record that cannot be made
durable stops the investigation rather than letting an unaudited action
proceed.

Layout (``root`` is supplied by the caller, never hardcoded)::

    <root>/
        <investigation_id>/
            00000001.json
            00000002.json
            ...
        system.stream/          # events with investigation_id=None
            00000001.json

``system.stream`` contains a ``.``, which no valid investigation id can
(``_validate_identifier`` allows only ``[A-Za-z0-9_-]``), so the system
stream can never collide with an investigation's stream.

Each file holds one record::

    {"sequence": N,
     "previous_record_hash": <record_hash of N-1, or null for N == 1>,
     "recorded_at": <store clock>,
     "event": <the AuditEvent, as plain JSON>,
     "record_hash": "sha256:<hex>"}

``sequence``, ``previous_record_hash``, ``recorded_at`` and
``record_hash`` are store-owned (AL-INV-2): ``AuditEvent`` has no field
for any of them, and ``emit`` computes all four itself. ``record_hash``
covers the canonical JSON (``chanakya.evidence.hashing.canonical_bytes``)
of the other four fields, so each record commits to its predecessor and
the stream forms a hash chain (AL-INV-3). The chain head is re-read from
disk on every append — never cached in memory — so a new process
continues an existing chain (AL-INV-9).

Append-only (AL-INV-1): there is no update/delete/replace/overwrite
method. Each record is written to a temp file in the stream directory,
flushed and fsynced, then hard-linked to its final name; ``os.link``
fails if that name exists, so an existing sequence is never overwritten
and a collision fails closed. ``emit`` returns only after the record is
on disk (AL-INV-4).

Fails closed (AL-INV-5/8): an invalid identifier, a record over
``MAX_RECORD_BYTES``, a credential-shaped ``details`` value, a broken
chain head, a sequence collision, or any I/O error raises. Nothing is
truncated, repaired, or partially written.

Credential screening is best-effort only. Since Phase 16 it is the
canonical tool-output screen (``screen_tool_output``): URL userinfo,
``key=``/``keyword:`` credential assignments, PEM private-key headers and
upper-case env-style assignments, in every ``details`` key and string value
(docs/THREAT-MODEL.md T-20, T-61). It is not a secret scanner; an
unstructured secret is not detected.

Known limitations (documented, not solved here):

- **Tail truncation is undetectable.** Deleting the last N records
  leaves a valid shorter chain. Detecting it needs an external anchor for
  the chain head, which is deferred.
- **The hash is unkeyed.** Someone able to rewrite the files can
  recompute the whole chain; the chain detects partial edits, not a
  full rewrite by a local attacker (T-18 residual, TB-9).
- **Single-process writer.** A lock serializes appends within one
  instance; exclusive linking makes a concurrent collision fail closed,
  but concurrent writers from several processes are not supported.

This module is never read by the Runtime loop, the Policy Gateway, or a
provider (AL-INV-7). ``list_by_investigation``/``verify`` exist for
out-of-band human review.
"""
from __future__ import annotations

import json
import os
import re
import tempfile
import threading
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Mapping, Optional, Sequence, Tuple, Union

from chanakya.contracts.audit_event import AuditEvent, AuditEventType, AuditSeverity
from chanakya.contracts.tool_output_screening import OUTPUT_UNSCREENABLE, screen_tool_output
from chanakya.evidence.hashing import canonical_bytes, compute_content_hash
from chanakya.evidence.store import InvalidIdentifierError as _EvidenceInvalidIdentifierError
from chanakya.evidence.store import _validate_identifier as _validate_evidence_identifier

#: Store-owned ceiling on one record's canonical serialized size, in bytes.
#: Over-limit records are rejected, never truncated.
MAX_RECORD_BYTES = 65536

#: Directory for events with ``investigation_id=None``. Contains ``.``,
#: which no valid investigation id can.
SYSTEM_STREAM = "system.stream"

_SEQUENCE_WIDTH = 8
_MAX_SEQUENCE = 10**_SEQUENCE_WIDTH - 1
_RECORD_NAME = re.compile(r"^(\d{8})\.json$")
_TMP_PREFIX = ".audit-tmp-"
_TMP_SUFFIX = ".tmp"
_RECORD_KEYS = frozenset({"sequence", "previous_record_hash", "recorded_at", "event", "record_hash"})
_EVENT_KEYS = frozenset(
    {
        "audit_event_id",
        "contract_version",
        "event_type",
        "occurred_at",
        "actor",
        "related_ids",
        "investigation_id",
        "details",
        "severity",
    }
)


# -- exceptions ---------------------------------------------------------------


class AuditLogError(Exception):
    """Base class for every error this log raises."""


class InvalidAuditIdentifierError(AuditLogError):
    """An ``investigation_id`` is not a safe storage identifier. Raised
    before any filesystem operation uses it."""


class AuditSequenceCollisionError(AuditLogError):
    """The next sequence number already has a record. Never overwritten."""


class AuditRecordTooLargeError(AuditLogError):
    """A record's canonical serialized size exceeds ``MAX_RECORD_BYTES``."""


class CredentialShapedAuditDataError(AuditLogError):
    """``AuditEvent.details`` contains a credential-shaped key or value
    (best-effort screen). The record is not persisted."""


class CorruptAuditLogError(AuditLogError):
    """A stored stream fails integrity or shape checks. Never repaired,
    skipped, or returned partially."""


# -- stored record -------------------------------------------------------------


@dataclass(frozen=True)
class AuditRecord:
    """One verified stored record: the ``AuditEvent`` plus the four
    store-owned integrity fields."""

    sequence: int
    previous_record_hash: Optional[str]
    recorded_at: str
    record_hash: str
    event: AuditEvent


# -- helpers --------------------------------------------------------------------


def _validate_identifier(value: Any) -> str:
    # Same strict rule as EvidenceStore (charset [A-Za-z0-9_-]{1,128} plus
    # Windows reserved device names), reused rather than re-implemented.
    try:
        return _validate_evidence_identifier(value, field_name="investigation_id")
    except _EvidenceInvalidIdentifierError as exc:
        raise InvalidAuditIdentifierError(str(exc)) from None


def _stream_name(investigation_id: Optional[str]) -> str:
    return SYSTEM_STREAM if investigation_id is None else _validate_identifier(investigation_id)


def _record_filename(sequence: int) -> str:
    return f"{sequence:0{_SEQUENCE_WIDTH}d}.json"


def _utcnow_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def _event_to_dict(event: AuditEvent) -> Dict[str, Any]:
    return {
        "audit_event_id": event.audit_event_id,
        "contract_version": event.contract_version,
        "event_type": AuditEventType(event.event_type).value,
        "occurred_at": event.occurred_at,
        "actor": event.actor,
        "related_ids": dict(event.related_ids),
        "investigation_id": event.investigation_id,
        "details": dict(event.details) if event.details is not None else None,
        "severity": AuditSeverity(event.severity).value if event.severity is not None else None,
    }


def _dict_to_event(data: Any) -> AuditEvent:
    if not isinstance(data, dict) or set(data) != _EVENT_KEYS:
        raise CorruptAuditLogError("stored event does not have the AuditEvent shape")
    try:
        return AuditEvent(
            audit_event_id=data["audit_event_id"],
            contract_version=data["contract_version"],
            event_type=AuditEventType(data["event_type"]),
            occurred_at=data["occurred_at"],
            actor=data["actor"],
            related_ids=data["related_ids"],
            investigation_id=data["investigation_id"],
            details=data["details"],
            severity=AuditSeverity(data["severity"]) if data["severity"] is not None else None,
        )
    except (ValueError, TypeError) as exc:
        raise CorruptAuditLogError(f"stored event is invalid: {exc}") from None


def _hash_input(sequence: int, previous_record_hash: Optional[str], recorded_at: str, event: Mapping[str, Any]) -> Dict[str, Any]:
    return {
        "sequence": sequence,
        "previous_record_hash": previous_record_hash,
        "recorded_at": recorded_at,
        "event": event,
    }


def _screen_credentials(details: Any) -> None:
    """Phase 16 (NX16-INV-4): the audit log screens ``details`` with the
    same function that screens tool output (``screen_tool_output``): every
    string value and key, at any depth, bounded and iterative. It is never
    weaker than the tool-output screen. A hit, or details that cannot be
    screened completely, is rejected; nothing is persisted and the value is
    never echoed."""
    code = screen_tool_output({"details": details})
    if code == OUTPUT_UNSCREENABLE:
        raise AuditLogError("AuditEvent.details cannot be screened; record not persisted")
    if code is not None:
        raise CredentialShapedAuditDataError(f"credential-shaped content in AuditEvent.details ({code}); record not persisted")


# -- the log -------------------------------------------------------------------


class FilesystemAuditLog:
    """Durable, append-only, hash-chained ``AuditSink``. Public API:
    ``emit`` (the sink method), ``list_by_investigation`` and ``verify``
    (out-of-band review). No mutation method exists."""

    MAX_RECORD_BYTES = MAX_RECORD_BYTES

    def __init__(self, root: Union[str, Path]) -> None:
        self._root = Path(root)
        self._lock = threading.Lock()

    @property
    def root(self) -> Path:
        return self._root

    # -- paths --------------------------------------------------------------

    def _stream_dir(self, stream: str) -> Path:
        root = self._root.resolve()
        candidate = (root / stream).resolve()
        # Defense in depth behind identifier validation: the stream must be
        # a direct child of root.
        if candidate.parent != root:
            raise InvalidAuditIdentifierError("stream path escapes the audit root")
        return candidate

    # -- reading ------------------------------------------------------------

    @staticmethod
    def _sequence_files(directory: Path) -> List[Tuple[int, Path]]:
        """Every ``*.json`` entry in ``directory``. Anything that is not a
        well-formed ``<8 digits>.json`` record name is corruption; temp
        files (``.audit-tmp-*.tmp``) are not ``*.json`` and are ignored."""
        found = []
        for path in directory.iterdir():
            if not path.name.endswith(".json"):
                continue
            match = _RECORD_NAME.match(path.name)
            if match is None or not path.is_file():
                raise CorruptAuditLogError(f"unexpected entry in audit stream: {path.name!r}")
            found.append((int(match.group(1)), path))
        found.sort()
        for expected, (sequence, _) in enumerate(found, start=1):
            if sequence != expected:
                raise CorruptAuditLogError(f"audit stream sequence gap or reorder at {expected}")
        return found

    @staticmethod
    def _read_record(path: Path, expected_sequence: int, stream: str) -> Tuple[Dict[str, Any], AuditRecord]:
        try:
            data = json.loads(path.read_bytes().decode("utf-8"))
        except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise CorruptAuditLogError(f"unreadable audit record {path.name!r}: {exc.__class__.__name__}") from None
        if not isinstance(data, dict) or set(data) != _RECORD_KEYS:
            raise CorruptAuditLogError(f"audit record {path.name!r} does not have the record shape")
        sequence = data["sequence"]
        if type(sequence) is not int or sequence != expected_sequence:
            raise CorruptAuditLogError(f"audit record {path.name!r} has a forged sequence")
        previous = data["previous_record_hash"]
        if previous is not None and not isinstance(previous, str):
            raise CorruptAuditLogError(f"audit record {path.name!r} has an invalid previous_record_hash")
        if not isinstance(data["recorded_at"], str) or not isinstance(data["record_hash"], str):
            raise CorruptAuditLogError(f"audit record {path.name!r} has invalid envelope fields")
        recomputed = compute_content_hash(_hash_input(sequence, previous, data["recorded_at"], data["event"]))
        if recomputed != data["record_hash"]:
            raise CorruptAuditLogError(f"record_hash mismatch in audit record {path.name!r}")
        event = _dict_to_event(data["event"])
        expected_owner = None if stream == SYSTEM_STREAM else stream
        if event.investigation_id != expected_owner:
            raise CorruptAuditLogError(f"audit record {path.name!r} belongs to a different stream")
        record = AuditRecord(
            sequence=sequence,
            previous_record_hash=previous,
            recorded_at=data["recorded_at"],
            record_hash=data["record_hash"],
            event=event,
        )
        return data, record

    def _load_stream(self, stream: str) -> Tuple[AuditRecord, ...]:
        directory = self._stream_dir(stream)
        if not directory.is_dir():
            return ()
        records = []
        previous_hash: Optional[str] = None
        for sequence, path in self._sequence_files(directory):
            _, record = self._read_record(path, sequence, stream)
            if record.previous_record_hash != previous_hash:
                raise CorruptAuditLogError(f"audit chain broken at sequence {sequence}")
            records.append(record)
            previous_hash = record.record_hash
        return tuple(records)

    # -- public API --------------------------------------------------------

    def emit(self, event: AuditEvent) -> None:
        """``AuditSink.emit``. Returns only once the record is durably on
        disk; raises (and writes nothing) otherwise."""
        if not isinstance(event, AuditEvent):
            raise TypeError("FilesystemAuditLog.emit requires an AuditEvent")
        stream = _stream_name(event.investigation_id)
        event_dict = _event_to_dict(event)
        _screen_credentials(event_dict["details"])
        # Must be plain JSON; anything else is rejected, never stringified.
        try:
            canonical_bytes(event_dict)
        except (TypeError, ValueError) as exc:
            raise AuditLogError(f"AuditEvent is not JSON-serializable: {exc}") from None

        with self._lock:
            directory = self._stream_dir(stream)
            directory.mkdir(parents=True, exist_ok=True)
            head = self._head(directory, stream)
            sequence = 1 if head is None else head.sequence + 1
            if sequence > _MAX_SEQUENCE:
                raise AuditLogError("audit stream has reached its maximum sequence number")
            previous_hash = None if head is None else head.record_hash
            recorded_at = _utcnow_iso()
            hashed = _hash_input(sequence, previous_hash, recorded_at, event_dict)
            record = dict(hashed, record_hash=compute_content_hash(hashed))
            data = canonical_bytes(record)
            if len(data) > MAX_RECORD_BYTES:
                raise AuditRecordTooLargeError(
                    f"audit record is {len(data)} bytes; the limit is {MAX_RECORD_BYTES}"
                )
            self._write_exclusive(directory / _record_filename(sequence), data)

    def _head(self, directory: Path, stream: str) -> Optional[AuditRecord]:
        """The last record, re-read and hash-verified from disk. Only the
        head is re-verified on append (full-chain checks are ``verify``'s
        job); contiguity of the sequence numbers is always checked."""
        files = self._sequence_files(directory)
        if not files:
            return None
        sequence, path = files[-1]
        _, record = self._read_record(path, sequence, stream)
        return record

    @staticmethod
    def _write_exclusive(final_path: Path, data: bytes) -> None:
        """Temp file in the same directory -> flush -> fsync -> hard-link to
        ``final_path`` (fails if it exists) -> remove the temp name. The
        final name only ever holds complete content, and is never
        replaced."""
        if final_path.exists():
            raise AuditSequenceCollisionError(f"audit record {final_path.name!r} already exists")
        fd, tmp_name = tempfile.mkstemp(dir=str(final_path.parent), prefix=_TMP_PREFIX, suffix=_TMP_SUFFIX)
        tmp_path = Path(tmp_name)
        try:
            with os.fdopen(fd, "wb") as handle:
                handle.write(data)
                handle.flush()
                os.fsync(handle.fileno())
            try:
                os.link(tmp_path, final_path)
            except FileExistsError:
                raise AuditSequenceCollisionError(f"audit record {final_path.name!r} already exists") from None
            if os.name != "nt":  # directory fsync is not available on Windows
                dir_fd = os.open(str(final_path.parent), os.O_RDONLY)
                try:
                    os.fsync(dir_fd)
                finally:
                    os.close(dir_fd)
        finally:
            try:
                tmp_path.unlink(missing_ok=True)
            except OSError:
                pass  # best-effort cleanup; never mask the original outcome

    def list_by_investigation(self, investigation_id: Optional[str]) -> Tuple[AuditRecord, ...]:
        """Every record of one stream (``None`` = system stream), in order,
        after full-chain verification. Raises ``CorruptAuditLogError``
        rather than returning a partial or unverified list."""
        return self._load_stream(_stream_name(investigation_id))

    def verify(self, investigation_id: Optional[str]) -> bool:
        """Full-chain check of one stream: shape, contiguous sequence
        numbers, every ``record_hash``, every ``previous_record_hash`` link,
        and stream ownership. ``False`` on any problem (fail closed);
        ``True`` for an intact or empty stream. Cannot detect tail
        truncation (see module docstring). Raises only for an invalid
        identifier."""
        stream = _stream_name(investigation_id)
        try:
            self._load_stream(stream)
        except InvalidAuditIdentifierError:
            raise
        except Exception:
            return False
        return True


__all__ = [
    "MAX_RECORD_BYTES",
    "SYSTEM_STREAM",
    "AuditLogError",
    "AuditRecord",
    "AuditRecordTooLargeError",
    "AuditSequenceCollisionError",
    "CorruptAuditLogError",
    "CredentialShapedAuditDataError",
    "FilesystemAuditLog",
    "InvalidAuditIdentifierError",
]
