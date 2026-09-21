"""EvidenceStore — a durable, filesystem-backed Evidence Store, Phase 5.2.2.

Implements storage for the ``chanakya.contracts.evidence.Evidence``
contract added in Phase 5.2.1. This module is NOT wired into the Agent
Runtime yet — ``chanakya.runtime.evidence.StubEvidenceRecorder`` remains
the Runtime's evidence hand-off boundary unchanged; Runtime integration
is Phase 5.2.3. The Store is independently constructible and testable.

Layout (extended in Phase 5.3 to add a separate payload object)::

    <root>/
        <investigation_id>/
            <evidence_id>.json                  # metadata (unchanged shape + payload_hash)
            payloads/
                <evidence_id>.json               # NEW — the actual ToolResult.output content

``root`` is supplied by the caller at construction time — never
hardcoded, never machine-specific.

Phase 5.3 (chained-hash payload design): ``append()`` now takes an
optional ``payload`` mapping — the actual tool-output content
(``docs/CONTRACTS.md`` §7 always kept this out of ``Evidence`` itself;
only ``storage_ref``, a pointer, belongs there). When supplied, the
Store persists it as a second, sibling JSON file under a fixed
``payloads/`` subdirectory (never glob-matched by ``list_by_investigation``'s
top-level ``*.json`` scan — no ambiguity with metadata records),
computes its own SHA-256 hash, and — critically — includes that hash as
``Evidence.payload_hash`` in the SAME set of fields ``content_hash`` is
computed over. This chains the two integrity checks: tampering the
payload alone is caught by ``get_payload()``'s independent re-hash;
tampering ``payload_hash`` itself (to match a tampered payload) is
caught by ``content_hash``'s own existing re-verification. When
``payload`` is omitted (the default — including every call from before
Phase 5.3), behavior is byte-for-byte identical to Phase 5.2.2:
``storage_ref`` points at the metadata file itself, ``payload_hash``
stays absent from the persisted record and from the hash input (see
``_evidence_to_dict``), and pre-Phase-5.3 records remain fully
hash-verifiable without any migration.

Trust boundary (docs/THREAT-MODEL.md T-18/T-20/T-22): this Store is
trusted control code; every value it is asked to persist — investigation
id, evidence id, and above all the ``Evidence`` record's own content —
originates from data that may ultimately trace back to a target or tool
this system does not trust. The Store never executes, evaluates,
template-expands, or otherwise interprets any of it; every value is
opaque bytes/text, stored and returned unchanged. Two identifiers
(``investigation_id``, ``evidence_id``) are additionally used as
filesystem path components, so they alone are subject to the strict
identifier validation in this module (see ``_validate_identifier``) —
a storage-safety requirement layered on top of, not a replacement for,
``Evidence``'s own Phase 5.2.1 contract validation (which only requires
"non-empty string," not this module's much narrower path-safe charset).

Authoritative fields (docs/CONTRACTS.md §7 + the approved Phase 5.2.2
design report): ``content_hash``, ``recorded_at``, and ``storage_ref``
are never trusted from a caller-supplied ``Evidence`` instance.
``append()`` discards whatever values the caller passed for these three
fields and substitutes Store-computed ones, via ``dataclasses.replace``
— the same pattern already used elsewhere in this codebase (e.g.
``chanakya.registry.registry.SecurityToolRegistry.set_status``) to
produce a new immutable record rather than mutating one in place.
``storage_ref`` is derived from this Store's own layout convention
(``"<investigation_id>/<evidence_id>.json"``, relative to ``root`` —
never the caller-supplied value, and never an absolute, machine-specific
path) — the task's design brief names ``content_hash``/``recorded_at``
explicitly as Store-assigned; ``storage_ref`` is treated the same way
here because only the Store actually knows where a record ends up, and
a caller-supplied ``storage_ref`` could otherwise point at a location
that doesn't match reality.

Append-only (docs/CONTRACTS.md §7): no ``update``/``delete``/``replace``
method exists anywhere on this class. An ``evidence_id`` collision is
always an error, even for byte-identical content (an ``evidence_id``
identifies one specific execution event; two distinct, legitimate
executions — e.g. an idempotent read-only capability run twice — can
legitimately share a ``content_hash`` without that being any kind of
error).

Concurrency: this Store assumes the same single-writer-per-investigation
posture the Runtime already enforces at RT-INV-10 (at most one step, and
therefore at most one evidence write, in flight per investigation at a
time). No file locking is implemented; per the approved Phase 5.2.2
scope, this is not added "unless testing demonstrates the current design
requires it," and nothing in this Store's test suite does. Separate
investigations, which the Runtime can run concurrently, are isolated by
directory and do not interfere with each other regardless.
"""
from __future__ import annotations

import json
import os
import re
import tempfile
from dataclasses import replace
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Mapping, Optional, Sequence, Union

from chanakya.contracts.enums import Classification
from chanakya.contracts.evidence import Evidence

from .hashing import canonical_bytes, compute_content_hash

_JSON_SUFFIX = ".json"

#: Phase 5.3 — a fixed, non-attacker-controlled path component; payload
#: files live under this subdirectory of each investigation directory so
#: list_by_investigation()'s existing top-level "*.json" glob (unchanged)
#: never matches them, with zero risk of confusing a payload file for a
#: metadata record.
_PAYLOAD_SUBDIR = "payloads"


# -- exceptions ---------------------------------------------------------------


class EvidenceStoreError(Exception):
    """Base class for every error this Store raises. Never caught and
    silently discarded by this module itself — every operation either
    succeeds and returns, or raises a specific subclass of this."""


class InvalidIdentifierError(EvidenceStoreError):
    """Raised when an ``investigation_id``/``evidence_id`` supplied to a
    Store operation is not a safe filesystem-path identifier (see
    ``_validate_identifier``). Always raised before any filesystem
    operation involving that identifier is attempted."""


class EvidenceIdCollisionError(EvidenceStoreError):
    """Raised by ``append()`` when ``evidence.evidence_id`` already has a
    stored record. Never overwritten, replaced, or merged — even if the
    incoming content is byte-identical to what's already stored."""


class UnknownEvidenceError(EvidenceStoreError):
    """Raised by ``get()`` when no record exists for the given
    ``evidence_id`` (after identifier validation succeeds)."""


class CorruptEvidenceError(EvidenceStoreError):
    """Raised by ``get()``/``list_by_investigation()`` when a stored
    record cannot be parsed, does not match the ``Evidence`` contract's
    shape, or fails its content-hash re-verification. Never returned as
    a partial/best-effort record — this is always raised, never silently
    repaired or skipped."""


class PayloadTooLargeError(EvidenceStoreError):
    """Raised by ``append()`` when either ceiling is exceeded: the
    canonically-serialized METADATA record against
    ``EvidenceStore.MAX_PAYLOAD_BYTES`` (unchanged since Phase 5.2.2), or
    — Phase 5.3 — the canonically-serialized tool-output PAYLOAD against
    ``EvidenceStore.MAX_PAYLOAD_CONTENT_BYTES``, a separate, independent
    ceiling. Raised before any filesystem write begins in either case —
    a rejected append leaves no file, partial or otherwise, at any final
    path (metadata or payload)."""


# -- identifier validation (Step 5 — path safety) ------------------------------

#: Deliberately narrow: letters, digits, underscore, hyphen only. Every
#: identifier this codebase already generates (a ``uuid4()`` string, or a
#: human-readable test id like "target-local-host-01") matches this
#: pattern; nothing meaningful is excluded. Because none of '.', '/',
#: '\\', ':', or a null byte is in this character class, every listed
#: attack (../, ..\\, absolute paths, drive letters, UNC paths, embedded
#: separators, null bytes) is rejected by this single regex alone, before
#: any Path/filesystem operation ever sees the value. A generous but
#: bounded max length (128) defends against a pathologically long
#: identifier being used to build an oversized path.
_IDENTIFIER_PATTERN = re.compile(r"^[A-Za-z0-9_-]{1,128}$")

#: Legacy Windows reserved device names — rejected case-insensitively as
#: an additional hardening measure, since this Store is developed and
#: tested on Windows (Step 5's explicit instruction). Not excluded by the
#: character-class check above on its own (these are otherwise
#: valid-looking identifiers), so checked separately.
_WINDOWS_RESERVED_NAMES = frozenset(
    {
        "CON", "PRN", "AUX", "NUL",
        "COM1", "COM2", "COM3", "COM4", "COM5", "COM6", "COM7", "COM8", "COM9",
        "LPT1", "LPT2", "LPT3", "LPT4", "LPT5", "LPT6", "LPT7", "LPT8", "LPT9",
    }
)


def _validate_identifier(value: str, *, field_name: str) -> str:
    """Rejects anything that isn't a safe, narrow, filesystem-path-safe
    identifier. Called on every ``investigation_id``/``evidence_id``
    BEFORE it is used to build any ``Path`` — the first of the two
    defense-in-depth layers Step 5 requires (the second is
    ``EvidenceStore._safe_path``'s resolved-path containment check)."""
    if not isinstance(value, str) or not _IDENTIFIER_PATTERN.match(value):
        raise InvalidIdentifierError(f"{field_name} is not a safe storage identifier: {value!r}")
    if value.upper() in _WINDOWS_RESERVED_NAMES:
        raise InvalidIdentifierError(f"{field_name} is a reserved Windows device name: {value!r}")
    return value


def _utcnow_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


# -- Evidence <-> plain-dict conversion (JSON only, never pickle/eval) --------


def _evidence_to_dict(evidence: Evidence) -> Dict[str, Any]:
    """The full, JSON-serializable representation of ``evidence``,
    including ``content_hash`` — this is what is actually written to
    disk. Contrast with ``_hashable_dict``, which excludes it.

    ``payload_hash`` is included ONLY when set (not even as an explicit
    ``null``) — this is deliberate, not an oversight: it is what makes a
    payload-less Phase 5.3 record byte-for-byte identical in shape to a
    pre-Phase-5.3 record, which is what lets old records' content_hash
    keep re-verifying correctly without any migration (Step 5.3.7). A
    record that DOES have a payload gets a genuinely different-shaped
    (15-key, not 14-key) hash input — correctly reflecting that it
    commits to more than a payload-less record does.
    """
    data: Dict[str, Any] = {
        "evidence_id": evidence.evidence_id,
        "contract_version": evidence.contract_version,
        "investigation_id": evidence.investigation_id,
        "step_id": evidence.step_id,
        "tool_request_id": evidence.tool_request_id,
        "tool_result_id": evidence.tool_result_id,
        "target_id": evidence.target_id,
        "capability": evidence.capability,
        "recorded_at": evidence.recorded_at,
        "content_hash": evidence.content_hash,
        "storage_ref": evidence.storage_ref,
        "classification": evidence.classification.value,
        "tags": list(evidence.tags),
        "redactions_applied": evidence.redactions_applied,
    }
    if evidence.payload_hash is not None:
        data["payload_hash"] = evidence.payload_hash
    return data


def _hashable_dict(evidence: Evidence) -> Dict[str, Any]:
    """Every field of ``evidence`` EXCEPT ``content_hash`` — this, and
    only this, is what ``content_hash`` is computed over (Step 6/7: "NOT
    recursively over content_hash itself"). Including ``recorded_at`` and
    ``storage_ref`` means the hash covers the Store-assigned fields too,
    exactly as they are actually persisted."""
    data = _evidence_to_dict(evidence)
    del data["content_hash"]
    return data


_REQUIRED_KEYS = (
    "evidence_id",
    "contract_version",
    "investigation_id",
    "step_id",
    "tool_request_id",
    "tool_result_id",
    "target_id",
    "capability",
    "recorded_at",
    "content_hash",
    "storage_ref",
    "classification",
)


def _dict_to_evidence(data: Mapping[str, Any]) -> Evidence:
    """Reconstructs an ``Evidence`` instance from a parsed-JSON mapping.
    Raises ``CorruptEvidenceError`` (never ``KeyError``/``TypeError``/
    ``ValueError`` directly) for anything that doesn't match the expected
    shape — a missing key, a wrong type, or an unrecognized
    ``classification`` value. Never repairs or guesses at a malformed
    record; the caller (``EvidenceStore._read_and_verify``) is
    responsible for treating this failure as "fail closed on corruption,"
    not for retrying with a best-effort default.
    """
    if not isinstance(data, Mapping):
        raise CorruptEvidenceError("stored evidence record is not a JSON object")

    missing = [key for key in _REQUIRED_KEYS if key not in data]
    if missing:
        raise CorruptEvidenceError(f"stored evidence record is missing field(s): {', '.join(missing)}")

    try:
        classification = Classification(data["classification"])
    except ValueError as exc:
        raise CorruptEvidenceError(f"stored evidence record has an invalid classification: {data['classification']!r}") from exc

    tags = data.get("tags", [])
    if not isinstance(tags, list) or any(not isinstance(tag, str) for tag in tags):
        raise CorruptEvidenceError("stored evidence record has a malformed 'tags' field")

    redactions_applied = data.get("redactions_applied")
    if redactions_applied is not None and not isinstance(redactions_applied, bool):
        raise CorruptEvidenceError("stored evidence record has a malformed 'redactions_applied' field")

    payload_hash = data.get("payload_hash")
    if payload_hash is not None and not isinstance(payload_hash, str):
        raise CorruptEvidenceError("stored evidence record has a malformed 'payload_hash' field")

    try:
        return Evidence(
            evidence_id=data["evidence_id"],
            contract_version=data["contract_version"],
            investigation_id=data["investigation_id"],
            step_id=data["step_id"],
            tool_request_id=data["tool_request_id"],
            tool_result_id=data["tool_result_id"],
            target_id=data["target_id"],
            capability=data["capability"],
            recorded_at=data["recorded_at"],
            content_hash=data["content_hash"],
            storage_ref=data["storage_ref"],
            classification=classification,
            tags=tuple(tags),
            redactions_applied=redactions_applied,
            payload_hash=payload_hash,
        )
    except (TypeError, ValueError) as exc:
        # Evidence.__post_init__ itself rejects a malformed field (e.g. an
        # empty string in a required position) — surfaced here as the
        # same CorruptEvidenceError as every other structural problem,
        # never as a raw contract-level exception escaping the Store.
        raise CorruptEvidenceError(f"stored evidence record failed contract validation: {exc}") from exc


class EvidenceStore:
    """A durable, append-only, filesystem-backed store for ``Evidence``
    records. See the module docstring for the full design rationale.
    """

    #: Conservative, explicit, and directly justified: matches the
    #: max_output_bytes (65536 / 64 KiB) already declared on Phase 5.1's
    #: one production RegistryEntry (chanakya/registry/bootstrap.py,
    #: observe_local_host_environment). The Store enforces this itself
    #: rather than trusting any upstream limit, because
    #: RegistryEntry.resource_limits is not currently wired into
    #: DispatchInstruction (the Phase 5.1 audit finding this Store
    #: deliberately does not fix — see the approved Phase 5.2.2 design).
    #: Applied to the full canonically-serialized METADATA record (the
    #: same bytes actually written to disk), checked before any write
    #: begins. Unmodified since Phase 5.2.2 — Step 5.3.4 explicitly
    #: requires this ceiling be preserved, not silently changed.
    MAX_PAYLOAD_BYTES = 65536

    #: Phase 5.3 — a SEPARATE, independent ceiling for the actual
    #: tool-output PAYLOAD (the content persisted under payloads/),
    #: distinct from MAX_PAYLOAD_BYTES above. Same starting value and
    #: same justification (Phase 5.1's one production capability's own
    #: declared max_output_bytes) — chosen as a conservative default, not
    #: derived from MAX_PAYLOAD_BYTES, so the two can diverge later
    #: without any naming ambiguity. Checked before any write begins;
    #: exceeding it raises PayloadTooLargeError and leaves no file behind.
    MAX_PAYLOAD_CONTENT_BYTES = 65536

    def __init__(self, root: Union[str, Path]) -> None:
        root_path = Path(root)
        if root_path.exists() and not root_path.is_dir():
            raise ValueError(f"EvidenceStore root exists and is not a directory: {root_path!r}")
        root_path.mkdir(parents=True, exist_ok=True)
        self._root = root_path.resolve()

    @property
    def root(self) -> Path:
        return self._root

    # -- path safety (Step 5) ---------------------------------------------

    def _safe_path(self, *parts: str) -> Path:
        """Joins already-validated ``parts`` onto ``self._root`` and
        confirms, by resolving, that the result still lives inside
        ``self._root`` — the second of the two defense-in-depth layers
        (the first is ``_validate_identifier``, applied by every public
        method to every caller-supplied identifier before it ever reaches
        this method). Deliberately does not rely on ``Path.resolve()``
        alone; the identifier allowlist is what actually prevents
        traversal, and this containment check is a second, independent
        backstop against a future defect in that allowlist."""
        candidate = self._root.joinpath(*parts).resolve()
        if candidate != self._root and self._root not in candidate.parents:
            raise InvalidIdentifierError(
                f"resolved path escapes the configured evidence root: {candidate!r}"
            )
        return candidate

    def _investigation_dir(self, investigation_id: str) -> Path:
        identifier = _validate_identifier(investigation_id, field_name="investigation_id")
        return self._safe_path(identifier)

    def _record_path(self, investigation_id: str, evidence_id: str) -> Path:
        inv = _validate_identifier(investigation_id, field_name="investigation_id")
        ev = _validate_identifier(evidence_id, field_name="evidence_id")
        return self._safe_path(inv, f"{ev}{_JSON_SUFFIX}")

    def _payload_path(self, investigation_id: str, evidence_id: str) -> Path:
        inv = _validate_identifier(investigation_id, field_name="investigation_id")
        ev = _validate_identifier(evidence_id, field_name="evidence_id")
        return self._safe_path(inv, _PAYLOAD_SUBDIR, f"{ev}{_JSON_SUFFIX}")

    def _find_evidence_file(self, evidence_id: str) -> Optional[Path]:
        """``get()``/``exists()``/``verify()`` receive only an
        ``evidence_id`` (per the approved API — no ``investigation_id``
        parameter), so locating the file requires checking each
        investigation directory under ``root``. Directory names
        discovered this way were themselves only ever created by
        ``append()`` after passing identifier validation, so they need no
        re-validation here — only the caller-supplied ``evidence_id``
        does (already validated by the caller of this method)."""
        if not self._root.is_dir():
            return None
        for investigation_dir in sorted(p for p in self._root.iterdir() if p.is_dir()):
            candidate = investigation_dir / f"{evidence_id}{_JSON_SUFFIX}"
            if candidate.is_file():
                return candidate
        return None

    # -- atomic write (Step 9) ---------------------------------------------

    @staticmethod
    def _atomic_write(final_path: Path, data: bytes) -> None:
        """Writes ``data`` to a temp file in ``final_path``'s own parent
        directory (same filesystem, so the final rename is atomic),
        flushes and fsyncs it, then atomically replaces ``final_path``
        with it via ``os.replace`` (atomic on both POSIX and Windows).
        Cleans up the temp file on any failure. Never writes directly to
        ``final_path`` — a reader can only ever observe either nothing at
        ``final_path`` or the complete, final content, never a partial
        write."""
        directory = final_path.parent
        fd, tmp_name = tempfile.mkstemp(dir=str(directory), prefix=".evidence-tmp-", suffix=_JSON_SUFFIX)
        tmp_path = Path(tmp_name)
        try:
            with os.fdopen(fd, "wb") as handle:
                handle.write(data)
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(tmp_path, final_path)
        except BaseException:
            try:
                tmp_path.unlink(missing_ok=True)
            except OSError:
                pass  # best-effort cleanup only — never mask the original failure
            raise

    # -- read + integrity verification (Step 12) ---------------------------

    def _read_and_verify(self, path: Path) -> Evidence:
        try:
            raw_bytes = path.read_bytes()
        except OSError as exc:
            raise CorruptEvidenceError(f"unable to read stored evidence record: {exc}") from exc

        try:
            text = raw_bytes.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise CorruptEvidenceError(f"stored evidence record is not valid UTF-8: {exc}") from exc

        try:
            data = json.loads(text)
        except json.JSONDecodeError as exc:
            raise CorruptEvidenceError(f"stored evidence record is not valid JSON: {exc}") from exc

        evidence = _dict_to_evidence(data)

        recomputed = compute_content_hash(_hashable_dict(evidence))
        if recomputed != evidence.content_hash:
            raise CorruptEvidenceError(
                f"content_hash mismatch for evidence_id={evidence.evidence_id!r}: "
                f"stored={evidence.content_hash!r}, recomputed={recomputed!r}"
            )
        return evidence

    # -- public API (Step 3) -----------------------------------------------

    def append(self, evidence: Evidence, payload: Optional[Mapping[str, Any]] = None) -> Evidence:
        """Persists ``evidence`` and returns the authoritative, stored
        record. ``content_hash``, ``recorded_at``, and ``storage_ref`` on
        the RETURNED record are always Store-computed — any values the
        caller supplied for those three fields are discarded, never
        trusted, never persisted.

        ``payload`` (Phase 5.3, optional, default ``None``) is the
        actual tool-output content (e.g. ``{"output": tool_result.output,
        "error_message": ..., "raw_output": ..., "warnings": [...]}`` —
        this Store has no dependency on ``chanakya.contracts.tool_result``
        and does not care about its exact shape, only that it is a plain,
        JSON-serializable mapping). When supplied, it is persisted as a
        separate file, its own SHA-256 hash is computed and stored as
        ``Evidence.payload_hash`` — chained into ``content_hash`` (see
        the module docstring) — and ``storage_ref`` points at the
        payload file. When omitted, behavior is unchanged from Phase
        5.2.2 exactly: no payload file, ``payload_hash`` stays unset,
        ``storage_ref`` points at the metadata file itself.

        Raises ``InvalidIdentifierError`` if ``investigation_id``/
        ``evidence_id`` aren't safe storage identifiers,
        ``EvidenceIdCollisionError`` if ``evidence_id`` already has a
        stored metadata OR payload record anywhere in this Store, or
        ``PayloadTooLargeError`` if either the canonically serialized
        metadata record exceeds ``MAX_PAYLOAD_BYTES`` or the canonically
        serialized payload exceeds ``MAX_PAYLOAD_CONTENT_BYTES`` — in
        every case, before any file (temporary or final) is created.

        The collision check is global, not scoped to
        ``evidence.investigation_id`` — ``get()``/``exists()``/
        ``verify()`` take only an ``evidence_id`` with no
        ``investigation_id`` to disambiguate (the approved API), so
        ``evidence_id`` must be unique across the whole Store, not merely
        within one investigation's directory, for those lookups to be
        unambiguous.
        """
        if payload is not None and not isinstance(payload, Mapping):
            raise ValueError("EvidenceStore.append: payload must be a mapping if provided")

        metadata_path = self._record_path(evidence.investigation_id, evidence.evidence_id)
        payload_path = self._payload_path(evidence.investigation_id, evidence.evidence_id)

        identifier = _validate_identifier(evidence.evidence_id, field_name="evidence_id")
        if self._find_evidence_file(identifier) is not None:
            raise EvidenceIdCollisionError(f"evidence_id already exists: {evidence.evidence_id!r}")
        if payload_path.exists():
            # An orphaned payload file from a previously failed append()
            # (metadata write failed after the payload write succeeded —
            # see the write-ordering note below) must not be silently
            # reused by a later append() that happens to reuse the same
            # evidence_id.
            raise EvidenceIdCollisionError(
                f"a payload record already exists for evidence_id: {evidence.evidence_id!r}"
            )

        recorded_at = _utcnow_iso()

        payload_hash: Optional[str] = None
        payload_bytes: Optional[bytes] = None
        if payload is not None:
            payload_bytes = canonical_bytes(payload)
            if len(payload_bytes) > self.MAX_PAYLOAD_CONTENT_BYTES:
                raise PayloadTooLargeError(
                    f"evidence payload ({len(payload_bytes)} bytes) exceeds the "
                    f"{self.MAX_PAYLOAD_CONTENT_BYTES}-byte defensive ceiling; not persisted"
                )
            payload_hash = compute_content_hash(payload)
            storage_ref = f"{evidence.investigation_id}/{_PAYLOAD_SUBDIR}/{evidence.evidence_id}{_JSON_SUFFIX}"
        else:
            storage_ref = f"{evidence.investigation_id}/{evidence.evidence_id}{_JSON_SUFFIX}"

        # Compute the authoritative metadata hash over every field except
        # content_hash itself (Step 6/7) — using the final, about-to-be-
        # persisted values for recorded_at/storage_ref/payload_hash, so
        # the hash matches exactly what re-verification on read will
        # recompute. payload_hash being set here (or not) is what chains
        # payload integrity into content_hash.
        provisional = replace(evidence, recorded_at=recorded_at, storage_ref=storage_ref, payload_hash=payload_hash)
        content_hash = compute_content_hash(_hashable_dict(provisional))
        final_evidence = replace(provisional, content_hash=content_hash)

        metadata_bytes = canonical_bytes(_evidence_to_dict(final_evidence))
        if len(metadata_bytes) > self.MAX_PAYLOAD_BYTES:
            raise PayloadTooLargeError(
                f"evidence record ({len(metadata_bytes)} bytes) exceeds the "
                f"{self.MAX_PAYLOAD_BYTES}-byte defensive ceiling; not persisted"
            )

        investigation_dir = self._investigation_dir(evidence.investigation_id)
        investigation_dir.mkdir(parents=True, exist_ok=True)

        # Re-check immediately before writing — narrows, though does not
        # eliminate, the check-then-write race; see the module docstring
        # ("Concurrency") for why a full lock is not implemented here.
        if self._find_evidence_file(identifier) is not None:
            raise EvidenceIdCollisionError(f"evidence_id already exists: {evidence.evidence_id!r}")
        if payload_path.exists():
            raise EvidenceIdCollisionError(
                f"a payload record already exists for evidence_id: {evidence.evidence_id!r}"
            )

        # Payload written first, metadata second: an orphaned payload
        # file with no metadata pointing at it is harmless (caught by
        # the pre-check above on any later reuse of this evidence_id); a
        # metadata record whose storage_ref points at a payload file
        # that was never actually written would be actively misleading.
        if payload_bytes is not None:
            payload_path.parent.mkdir(parents=True, exist_ok=True)
            self._atomic_write(payload_path, payload_bytes)
            try:
                self._atomic_write(metadata_path, metadata_bytes)
            except BaseException:
                try:
                    payload_path.unlink(missing_ok=True)
                except OSError:
                    pass  # best-effort cleanup only — never mask the original failure
                raise
        else:
            self._atomic_write(metadata_path, metadata_bytes)

        return final_evidence

    def get(self, evidence_id: str) -> Evidence:
        """Returns the stored record, with its integrity re-verified.
        Raises ``InvalidIdentifierError`` for an unsafe identifier,
        ``UnknownEvidenceError`` if no record exists, or
        ``CorruptEvidenceError`` if the stored record is malformed or
        fails hash re-verification. Never returns a partial or
        best-effort record."""
        identifier = _validate_identifier(evidence_id, field_name="evidence_id")
        path = self._find_evidence_file(identifier)
        if path is None:
            raise UnknownEvidenceError(f"unknown evidence_id: {evidence_id!r}")
        return self._read_and_verify(path)

    def get_payload(self, evidence_id: str) -> Optional[Mapping[str, Any]]:
        """Phase 5.3. Returns the payload content for ``evidence_id``, or
        ``None`` if this record was persisted without one (including
        every pre-Phase-5.3 record). First calls ``get()`` — which
        re-verifies the metadata record's own ``content_hash`` and, via
        the chain, confirms the stored ``payload_hash`` string itself
        wasn't tampered with — then independently re-hashes the payload
        FILE's actual bytes and compares against that ``payload_hash``.
        Raises ``UnknownEvidenceError``/``CorruptEvidenceError`` exactly
        as ``get()`` does for the metadata half; raises
        ``CorruptEvidenceError`` additionally if the payload file is
        missing, unreadable, malformed, or its content no longer matches
        ``payload_hash`` — tampering the payload file alone, without
        touching the metadata file, is exactly what this second,
        independent check catches. Never returns partial/best-effort
        content."""
        evidence = self.get(evidence_id)
        if evidence.payload_hash is None:
            return None

        path = self._payload_path(evidence.investigation_id, evidence.evidence_id)
        try:
            raw_bytes = path.read_bytes()
        except OSError as exc:
            raise CorruptEvidenceError(f"unable to read stored evidence payload: {exc}") from exc

        try:
            text = raw_bytes.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise CorruptEvidenceError(f"stored evidence payload is not valid UTF-8: {exc}") from exc

        try:
            payload = json.loads(text)
        except json.JSONDecodeError as exc:
            raise CorruptEvidenceError(f"stored evidence payload is not valid JSON: {exc}") from exc

        if not isinstance(payload, Mapping):
            raise CorruptEvidenceError("stored evidence payload is not a JSON object")

        recomputed = compute_content_hash(payload)
        if recomputed != evidence.payload_hash:
            raise CorruptEvidenceError(
                f"payload_hash mismatch for evidence_id={evidence.evidence_id!r}: "
                f"stored={evidence.payload_hash!r}, recomputed={recomputed!r}"
            )
        return payload

    def list_by_investigation(self, investigation_id: str) -> Sequence[Evidence]:
        """Every ``Evidence`` record for ``investigation_id``, ordered
        deterministically by ``(recorded_at, evidence_id)``. Returns an
        empty tuple for an investigation with no directory (unknown or
        no evidence yet — not an error, per the approved API). Raises
        ``CorruptEvidenceError`` if ANY record in that investigation's
        directory fails integrity verification — a partial list that
        silently omitted a corrupted record would itself be a silent
        failure to report corruption, which the approved design forbids
        ("do not silently return corrupted evidence")."""
        investigation_dir = self._investigation_dir(investigation_id)
        if not investigation_dir.is_dir():
            return ()

        records: List[Evidence] = [
            self._read_and_verify(path) for path in sorted(investigation_dir.glob(f"*{_JSON_SUFFIX}"))
        ]
        records.sort(key=lambda e: (e.recorded_at, e.evidence_id))
        return tuple(records)

    def exists(self, evidence_id: str) -> bool:
        """Whether a record for ``evidence_id`` is stored — never reads
        or interprets its content, only checks for file existence."""
        identifier = _validate_identifier(evidence_id, field_name="evidence_id")
        return self._find_evidence_file(identifier) is not None

    def verify(self, evidence_id: str) -> bool:
        """``True`` only if a record exists, its metadata integrity
        check passes, AND — Phase 5.3 — if it has a payload, that
        payload's own integrity check also passes; ``False`` for
        missing, malformed, corrupted, or unsafe-identifier
        ``evidence_id`` values — never raises. Safe to call
        speculatively. Never modifies the record either way."""
        try:
            identifier = _validate_identifier(evidence_id, field_name="evidence_id")
        except InvalidIdentifierError:
            return False
        path = self._find_evidence_file(identifier)
        if path is None:
            return False
        try:
            evidence = self._read_and_verify(path)
        except CorruptEvidenceError:
            return False
        if evidence.payload_hash is None:
            return True
        try:
            self.get_payload(identifier)
        except (UnknownEvidenceError, CorruptEvidenceError):
            return False
        return True
