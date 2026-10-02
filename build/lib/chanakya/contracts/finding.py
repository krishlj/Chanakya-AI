"""Finding contract — docs/CONTRACTS.md §8, Phase 9.

An Agent-produced interpretation of one or more pieces of Evidence: an
opinion grounded in fact, never fact itself and never authority. Nothing
in ``chanakya.policy``, Intake, dispatch or approval reads a Finding.

The Runtime builds every ``Finding``: it assigns ``finding_id``,
``investigation_id``, ``created_at`` and ``created_by``, and resolves
``evidence_refs`` to Evidence of the same investigation before
construction. Only ``title``, ``description``, ``category`` and
``confidence`` come from the model, and they are untrusted text.

Validation fails closed and never repairs:

- ``evidence_refs`` must be non-empty, distinct, non-empty strings;
- ``title`` is one line of at most ``MAX_TITLE_LENGTH`` characters;
  ``description`` at most ``MAX_DESCRIPTION_LENGTH``; neither may contain
  control characters other than newline/tab in the description;
- ``category`` is an identifier (``[a-z0-9_]{1,64}``); ``confidence`` is
  ``low``/``medium``/``high``;
- text carrying URL userinfo, a ``password=``/``token:``-style pair
  anywhere in the text, or a PEM private-key header is rejected. This
  reuses the ``TargetLocator`` patterns plus a free-text pattern; it is a
  best-effort screen (docs/THREAT-MODEL.md T-20), not a secret scanner.

Error messages name the field only and never echo its value.
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any, Dict, Optional, Tuple

from .target import _CREDENTIAL_PARAM_PATTERN, _URL_USERINFO_PATTERN

MAX_TITLE_LENGTH = 200
MAX_DESCRIPTION_LENGTH = 4000
MAX_EVIDENCE_REFS = 20

_CONFIDENCES = frozenset({"low", "medium", "high"})
_CATEGORY = re.compile(r"^[a-z0-9_]{1,64}$")
_TITLE_FORBIDDEN = re.compile(r"[\x00-\x1f\x7f]")
_DESCRIPTION_FORBIDDEN = re.compile(r"[\x00-\x08\x0b-\x1f\x7f]")

#: Free-text screen, broader than the locator patterns (which only match a
#: key at the start of a value or after ``?``/``&``/``;``): a credential
#: keyword at any word boundary followed by ``=`` or ``:`` and a value, or
#: a PEM private-key header. Best-effort, and it can over-block phrasing
#: such as "access key: rotated"; a rejected finding is never repaired.
_TEXT_CREDENTIAL_PATTERN = re.compile(
    r"(?i)(?:^|[^A-Za-z0-9_])(password|passwd|pwd|secret|token|api[_-]?key|access[_-]?key|"
    r"private[_-]?key|client[_-]?secret)\s*[=:]\s*\S"
    r"|-----BEGIN [A-Z ]*PRIVATE KEY-----"
)


class FindingValidationError(ValueError):
    """A Finding (or a model-proposed finding) is invalid. Never repaired."""


def _require_text(field_name: str, value: Any, *, max_length: int, forbidden: "re.Pattern[str]") -> None:
    if type(value) is not str or not value.strip():
        raise FindingValidationError(f"Finding.{field_name} must be a non-empty string")
    if len(value) > max_length:
        raise FindingValidationError(f"Finding.{field_name} exceeds {max_length} characters")
    if forbidden.search(value):
        raise FindingValidationError(f"Finding.{field_name} contains control characters")
    if (
        _URL_USERINFO_PATTERN.search(value)
        or _CREDENTIAL_PARAM_PATTERN.search(value)
        or _TEXT_CREDENTIAL_PATTERN.search(value)
    ):
        raise FindingValidationError(f"Finding.{field_name} contains credential-shaped content")


def _require_id(field_name: str, value: Any) -> None:
    if type(value) is not str or not value:
        raise FindingValidationError(f"Finding.{field_name} must be a non-empty string")


@dataclass(frozen=True)
class Finding:
    finding_id: str
    contract_version: str
    investigation_id: str
    title: str
    description: str
    evidence_refs: Tuple[str, ...]
    created_at: str
    created_by: str = "agent"
    category: Optional[str] = None
    confidence: Optional[str] = None

    def __post_init__(self) -> None:
        for field_name in ("finding_id", "contract_version", "investigation_id", "created_at"):
            _require_id(field_name, getattr(self, field_name))
        if self.created_by != "agent":
            raise FindingValidationError("Finding.created_by must be 'agent'")
        _require_text("title", self.title, max_length=MAX_TITLE_LENGTH, forbidden=_TITLE_FORBIDDEN)
        _require_text(
            "description", self.description, max_length=MAX_DESCRIPTION_LENGTH, forbidden=_DESCRIPTION_FORBIDDEN
        )
        refs = self.evidence_refs
        if type(refs) is not tuple or not refs:
            raise FindingValidationError("Finding.evidence_refs must be a non-empty tuple")
        if len(refs) > MAX_EVIDENCE_REFS:
            raise FindingValidationError(f"Finding.evidence_refs exceeds {MAX_EVIDENCE_REFS} entries")
        for ref in refs:
            _require_id("evidence_refs entry", ref)
        if len(set(refs)) != len(refs):
            raise FindingValidationError("Finding.evidence_refs contains duplicates")
        if self.category is not None and (type(self.category) is not str or not _CATEGORY.match(self.category)):
            raise FindingValidationError("Finding.category must match [a-z0-9_]{1,64}")
        if self.confidence is not None and self.confidence not in _CONFIDENCES:
            raise FindingValidationError("Finding.confidence must be low, medium or high")

    def to_dict(self) -> Dict[str, Any]:
        return {
            "finding_id": self.finding_id,
            "contract_version": self.contract_version,
            "investigation_id": self.investigation_id,
            "title": self.title,
            "description": self.description,
            "evidence_refs": list(self.evidence_refs),
            "created_at": self.created_at,
            "created_by": self.created_by,
            "category": self.category,
            "confidence": self.confidence,
        }

    @staticmethod
    def from_dict(data: Any) -> "Finding":
        if not isinstance(data, dict) or set(data) != _DICT_KEYS:
            raise FindingValidationError("Finding record does not have the Finding shape")
        refs = data["evidence_refs"]
        if not isinstance(refs, list):
            raise FindingValidationError("Finding.evidence_refs must be a list")
        return Finding(**dict(data, evidence_refs=tuple(refs)))


_DICT_KEYS = frozenset(
    {
        "finding_id",
        "contract_version",
        "investigation_id",
        "title",
        "description",
        "evidence_refs",
        "created_at",
        "created_by",
        "category",
        "confidence",
    }
)

__all__ = [
    "MAX_DESCRIPTION_LENGTH",
    "MAX_EVIDENCE_REFS",
    "MAX_TITLE_LENGTH",
    "Finding",
    "FindingValidationError",
]
