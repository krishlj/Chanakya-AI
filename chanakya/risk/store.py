"""RiskAssessmentStore — durable, append-only RiskAssessment storage, Phase 10
(docs/CONTRACTS.md §9). Mirrors ``chanakya.findings.FindingStore``.

Layout (``root`` supplied by the caller; the CLI uses ``<workdir>/risk``)::

    <root>/<investigation_id>/<risk_assessment_id>.json

Each file is ``{"risk_assessment": <RiskAssessment.to_dict()>,
"recorded_at": ..., "content_hash": "sha256:..."}``. ``recorded_at`` and
``content_hash`` are store-owned: the hash covers the canonical JSON of
``risk_assessment`` and ``recorded_at`` and is re-verified on every read,
together with the contract (including a supported ``scoring_method`` and
the deterministic id), the filename and the investigation directory.

Append-only: there is no update, delete, replace or overwrite method. A
record is written to a temp file in the same directory, flushed and
fsynced, then hard-linked to its final name; ``os.link`` fails if that
name exists. Because ``risk_assessment_id`` is derived from
investigation, finding and rule set, a second assessment of the same
finding under the same rule set collides and is never written. A record
over ``MAX_RECORD_BYTES`` is rejected, never truncated.

A local attacker able to rewrite files can recompute the hash
(docs/THREAT-MODEL.md T-18, T-48); ``chanakya.risk.provenance`` adds a
recomputation check against the deterministic engine.
"""
from __future__ import annotations

import json
import os
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Tuple, Union

from chanakya.contracts.risk_assessment import RiskAssessment, RiskAssessmentValidationError
from chanakya.evidence.hashing import canonical_bytes, compute_content_hash
from chanakya.evidence.store import InvalidIdentifierError as _EvidenceInvalidIdentifierError
from chanakya.evidence.store import _validate_identifier as _validate_evidence_identifier

#: Store-owned ceiling on one record's canonical serialized size.
MAX_RECORD_BYTES = 8192

_RECORD_KEYS = frozenset({"risk_assessment", "recorded_at", "content_hash"})


class RiskAssessmentStoreError(Exception):
    """Base class for every error this store raises."""


class InvalidRiskAssessmentIdentifierError(RiskAssessmentStoreError):
    """An ``investigation_id`` or ``risk_assessment_id`` is not path-safe."""


class RiskAssessmentIdCollisionError(RiskAssessmentStoreError):
    """A record with this ``risk_assessment_id`` already exists. Never overwritten."""


class RiskAssessmentRecordTooLargeError(RiskAssessmentStoreError):
    """The record exceeds ``MAX_RECORD_BYTES``."""


class CorruptRiskAssessmentError(RiskAssessmentStoreError):
    """A stored record fails its shape, contract, placement or hash check."""


def _identifier(value: object, field_name: str) -> str:
    try:
        return _validate_evidence_identifier(value, field_name=field_name)
    except _EvidenceInvalidIdentifierError as exc:
        raise InvalidRiskAssessmentIdentifierError(str(exc)) from None


def _utcnow_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


class RiskAssessmentStore:
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
            raise InvalidRiskAssessmentIdentifierError("investigation path escapes the store root")
        return path

    def append(self, risk_assessment: RiskAssessment) -> None:
        """Persists ``risk_assessment`` durably, or raises and writes nothing."""
        if not isinstance(risk_assessment, RiskAssessment):
            raise TypeError("RiskAssessmentStore.append requires a RiskAssessment")
        directory = self._dir(risk_assessment.investigation_id)
        name = f"{_identifier(risk_assessment.risk_assessment_id, 'risk_assessment_id')}.json"
        hashed = {"risk_assessment": risk_assessment.to_dict(), "recorded_at": _utcnow_iso()}
        data = canonical_bytes(dict(hashed, content_hash=compute_content_hash(hashed)))
        if len(data) > MAX_RECORD_BYTES:
            raise RiskAssessmentRecordTooLargeError(
                f"risk assessment record is {len(data)} bytes; the limit is {MAX_RECORD_BYTES}"
            )
        directory.mkdir(parents=True, exist_ok=True)
        final_path = directory / name
        if final_path.exists():
            raise RiskAssessmentIdCollisionError(f"risk assessment {risk_assessment.risk_assessment_id!r} already exists")
        fd, tmp_name = tempfile.mkstemp(dir=str(directory), prefix=".risk-tmp-", suffix=".tmp")
        tmp_path = Path(tmp_name)
        try:
            with os.fdopen(fd, "wb") as handle:
                handle.write(data)
                handle.flush()
                os.fsync(handle.fileno())
            try:
                os.link(tmp_path, final_path)
            except FileExistsError:
                raise RiskAssessmentIdCollisionError(
                    f"risk assessment {risk_assessment.risk_assessment_id!r} already exists"
                ) from None
        finally:
            try:
                tmp_path.unlink(missing_ok=True)
            except OSError:
                pass

    def _read(self, path: Path, investigation_id: str) -> RiskAssessment:
        try:
            data = json.loads(path.read_bytes().decode("utf-8"))
        except (OSError, UnicodeDecodeError, json.JSONDecodeError):
            raise CorruptRiskAssessmentError(f"unreadable risk assessment record {path.name!r}") from None
        if not isinstance(data, dict) or set(data) != _RECORD_KEYS:
            raise CorruptRiskAssessmentError(f"risk assessment record {path.name!r} does not have the record shape")
        hashed = {"risk_assessment": data["risk_assessment"], "recorded_at": data["recorded_at"]}
        if compute_content_hash(hashed) != data["content_hash"]:
            raise CorruptRiskAssessmentError(f"content_hash mismatch in risk assessment record {path.name!r}")
        try:
            risk_assessment = RiskAssessment.from_dict(data["risk_assessment"])
        except (RiskAssessmentValidationError, TypeError):
            raise CorruptRiskAssessmentError(f"risk assessment record {path.name!r} is not a valid RiskAssessment") from None
        if (
            risk_assessment.investigation_id != investigation_id
            or f"{risk_assessment.risk_assessment_id}.json" != path.name
        ):
            raise CorruptRiskAssessmentError(
                f"risk assessment record {path.name!r} is filed under the wrong name or investigation"
            )
        return risk_assessment

    def list_by_investigation(self, investigation_id: str) -> Tuple[RiskAssessment, ...]:
        """Every RiskAssessment of one investigation, verified, ordered by
        ``finding_refs`` then ``risk_assessment_id``. Raises
        ``CorruptRiskAssessmentError`` rather than returning a partial list."""
        directory = self._dir(investigation_id)
        if not directory.is_dir():
            return ()
        records = [self._read(path, investigation_id) for path in sorted(directory.glob("*.json"))]
        return tuple(sorted(records, key=lambda r: (r.finding_refs, r.risk_assessment_id)))

    def verify(self, investigation_id: str) -> bool:
        """``False`` if any stored record fails verification."""
        try:
            self.list_by_investigation(investigation_id)
        except InvalidRiskAssessmentIdentifierError:
            raise
        except Exception:
            return False
        return True


__all__ = [
    "MAX_RECORD_BYTES",
    "CorruptRiskAssessmentError",
    "InvalidRiskAssessmentIdentifierError",
    "RiskAssessmentIdCollisionError",
    "RiskAssessmentRecordTooLargeError",
    "RiskAssessmentStore",
    "RiskAssessmentStoreError",
]
