"""RiskAssessment contract — docs/CONTRACTS.md §9, Phase 10.

A rule-based severity/confidence rating of exactly one Finding, computed by
the deterministic Risk Engine (``chanakya.risk``) under a named, versioned
rule set. It is prioritization, not fact and not authority: nothing in
``chanakya.policy``, Intake, dispatch or approval reads a RiskAssessment.

No field comes from the model. The engine derives ``risk_assessment_id``,
``severity``, ``confidence``, ``rule_ids`` and ``rationale``; the Runtime
supplies ``assessed_at``; ``investigation_id``, ``finding_refs`` and
``evidence_refs`` are copied from the stored Finding and checked by the
Runtime against the Findings it stored in the same conclude turn.

Validation fails closed and never repairs. Beyond field types and sizes,
the record must be internally consistent with its rule set:

- ``risk_assessment_id`` equals ``derive_risk_assessment_id(...)``, so a
  second assessment of one finding under one rule set has the same id and
  collides in the append-only store;
- ``rule_ids`` has the canonical shape ``evidence.verified``,
  ``category.<id>``, ``compat.all|compat.partial``, optional
  ``ceiling.read_only``, ``confidence.<level>``;
- ``severity`` equals the category's base severity, capped at the
  read-only ceiling when ``ceiling.read_only`` is cited, so ``critical`` is
  unreachable under ``chanakya-risk-rules/1.0.0``;
- ``confidence`` matches its rule, and ``compat.partial`` implies ``low``.

``rationale`` is engine-template text (one line, at most 1000 characters,
no control characters) and still passes the Finding credential screen.
``mitigations_suggested`` is not supported (deferred to Recommendations).
Error messages name the field only and never echo its value.
"""
from __future__ import annotations

import re
import uuid
from dataclasses import dataclass
from typing import Any, Dict, Tuple

from .enums import SUPPORTED_CONTRACT_VERSIONS, RiskCategory
from .finding import MAX_EVIDENCE_REFS, _TEXT_CREDENTIAL_PATTERN
from .risk_taxonomy import (
    RULE_CEILING_READ_ONLY,
    RULE_COMPAT_ALL,
    RULE_COMPAT_PARTIAL,
    RULE_EVIDENCE_VERIFIED,
    SEVERITY_ORDER,
    RiskRuleSet,
    RiskRuleSetError,
    registered_scoring_methods,
    resolve_rule_set,
)
from .target import _CREDENTIAL_PARAM_PATTERN, _URL_USERINFO_PATTERN

ASSESSED_BY = "risk_engine"
MAX_RATIONALE_LENGTH = 1000
MAX_RULE_IDS = 16
#: One assessment per Finding, and Phase 9 caps an investigation at 20.
MAX_RISK_ASSESSMENTS_PER_INVESTIGATION = 20

#: The production rule sets a RiskAssessment may name (Phase 13: resolved
#: through ``chanakya.contracts.risk_taxonomy.resolve_rule_set``). An unknown
#: ``scoring_method`` is invalid, including in a stored record.
SUPPORTED_SCORING_METHODS = registered_scoring_methods()


def _rule_set_for(owner: str, scoring_method: Any) -> RiskRuleSet:
    try:
        return resolve_rule_set(scoring_method)
    except RiskRuleSetError:
        raise RiskAssessmentValidationError(f"{owner}.scoring_method is not a supported rule set") from None

#: Fixed namespace for deterministic ids (uuid5 of "urn:chanakya:risk-assessment").
RISK_ASSESSMENT_ID_NAMESPACE = uuid.UUID("0f8d4a4c-89ad-5e05-b0d1-4b1023a25e9c")

NOT_ASSESSED_CATEGORY_UNRATED = "category_unrated"
NOT_ASSESSED_EVIDENCE_INCOMPATIBLE = "evidence_incompatible"
NOT_ASSESSED_REASONS = frozenset({NOT_ASSESSED_CATEGORY_UNRATED, NOT_ASSESSED_EVIDENCE_INCOMPATIBLE})

_CONFIDENCES = ("low", "medium", "high")
_RULE_ID = re.compile(r"^[a-z0-9_.]{1,64}$")
_RATIONALE_FORBIDDEN = re.compile(r"[\x00-\x1f\x7f]")


class RiskAssessmentValidationError(ValueError):
    """A RiskAssessment (or a Risk Engine result) is invalid. Never repaired."""


def derive_risk_assessment_id(investigation_id: str, finding_id: str, scoring_method: str) -> str:
    """The one valid ``risk_assessment_id`` for this finding under this rule set."""
    return str(uuid.uuid5(RISK_ASSESSMENT_ID_NAMESPACE, f"{investigation_id}:{finding_id}:{scoring_method}"))


def severity_rank(severity: str) -> int:
    return SEVERITY_ORDER.index(severity)


def _require_id(field_name: str, value: Any) -> None:
    if type(value) is not str or not value:
        raise RiskAssessmentValidationError(f"RiskAssessment.{field_name} must be a non-empty string")


def _require_id_tuple(field_name: str, value: Any, *, max_items: int) -> None:
    if type(value) is not tuple or not value:
        raise RiskAssessmentValidationError(f"RiskAssessment.{field_name} must be a non-empty tuple")
    if len(value) > max_items:
        raise RiskAssessmentValidationError(f"RiskAssessment.{field_name} exceeds {max_items} entries")
    for item in value:
        _require_id(f"{field_name} entry", item)
    if len(set(value)) != len(value):
        raise RiskAssessmentValidationError(f"RiskAssessment.{field_name} contains duplicates")


@dataclass(frozen=True)
class RiskAssessment:
    risk_assessment_id: str
    contract_version: str
    investigation_id: str
    finding_refs: Tuple[str, ...]
    evidence_refs: Tuple[str, ...]
    severity: RiskCategory
    confidence: str
    scoring_method: str
    rule_ids: Tuple[str, ...]
    assessed_at: str
    assessed_by: str
    rationale: str

    def __post_init__(self) -> None:
        for field_name in ("risk_assessment_id", "contract_version", "investigation_id", "assessed_at"):
            _require_id(field_name, getattr(self, field_name))
        if self.contract_version not in SUPPORTED_CONTRACT_VERSIONS:
            raise RiskAssessmentValidationError("RiskAssessment.contract_version is not supported")
        if self.assessed_by != ASSESSED_BY:
            raise RiskAssessmentValidationError(f"RiskAssessment.assessed_by must be {ASSESSED_BY!r}")
        rule_set = _rule_set_for("RiskAssessment", self.scoring_method)
        _require_id_tuple("finding_refs", self.finding_refs, max_items=1)
        _require_id_tuple("evidence_refs", self.evidence_refs, max_items=MAX_EVIDENCE_REFS)
        if self.risk_assessment_id != derive_risk_assessment_id(
            self.investigation_id, self.finding_refs[0], self.scoring_method
        ):
            raise RiskAssessmentValidationError("RiskAssessment.risk_assessment_id is not the deterministic id")
        if not isinstance(self.severity, RiskCategory):
            raise RiskAssessmentValidationError("RiskAssessment.severity must be a RiskCategory")
        if self.confidence not in _CONFIDENCES:
            raise RiskAssessmentValidationError("RiskAssessment.confidence must be low, medium or high")
        self._check_rules(rule_set)
        self._check_rationale()

    def _check_rules(self, rule_set: RiskRuleSet) -> None:
        """Validates under the rule set the record names (Phase 13), never
        under whichever rule set happens to be active."""
        rules = self.rule_ids
        if type(rules) is not tuple or not rules or len(rules) > MAX_RULE_IDS:
            raise RiskAssessmentValidationError(f"RiskAssessment.rule_ids must be a tuple of 1..{MAX_RULE_IDS} ids")
        vocabulary = rule_set.rule_ids
        for rule in rules:
            if type(rule) is not str or not _RULE_ID.match(rule) or rule not in vocabulary:
                raise RiskAssessmentValidationError("RiskAssessment.rule_ids contains an unknown rule id")
        if len(set(rules)) != len(rules):
            raise RiskAssessmentValidationError("RiskAssessment.rule_ids contains duplicates")
        # Canonical shape: verified, category, compat, [ceiling], confidence.
        if len(rules) not in (4, 5) or rules[0] != RULE_EVIDENCE_VERIFIED:
            raise RiskAssessmentValidationError("RiskAssessment.rule_ids does not have the rule-set shape")
        category = rules[1][len("category."):] if rules[1].startswith("category.") else None
        if category not in rule_set.taxonomy:
            raise RiskAssessmentValidationError("RiskAssessment.rule_ids does not name a rated category")
        if rules[2] not in (RULE_COMPAT_ALL, RULE_COMPAT_PARTIAL):
            raise RiskAssessmentValidationError("RiskAssessment.rule_ids does not have the rule-set shape")
        ceiling = len(rules) == 5
        if ceiling and rules[3] != RULE_CEILING_READ_ONLY:
            raise RiskAssessmentValidationError("RiskAssessment.rule_ids does not have the rule-set shape")
        if rules[-1] != f"confidence.{self.confidence}":
            raise RiskAssessmentValidationError("RiskAssessment.confidence does not match its rule")
        if (rules[2] == RULE_COMPAT_PARTIAL) != (self.confidence == "low"):
            raise RiskAssessmentValidationError("RiskAssessment.confidence does not match its compatibility rule")
        expected = rule_set.taxonomy[category].base_severity
        if ceiling and severity_rank(expected) > severity_rank(rule_set.read_only_severity_ceiling):
            expected = rule_set.read_only_severity_ceiling
        if self.severity.value != expected:
            raise RiskAssessmentValidationError("RiskAssessment.severity does not follow its rule set")
        if severity_rank(self.severity.value) > severity_rank(rule_set.max_severity):
            raise RiskAssessmentValidationError("RiskAssessment.severity exceeds the rule-set ceiling")

    def _check_rationale(self) -> None:
        value = self.rationale
        if type(value) is not str or not value.strip():
            raise RiskAssessmentValidationError("RiskAssessment.rationale must be a non-empty string")
        if len(value) > MAX_RATIONALE_LENGTH:
            raise RiskAssessmentValidationError(f"RiskAssessment.rationale exceeds {MAX_RATIONALE_LENGTH} characters")
        if _RATIONALE_FORBIDDEN.search(value):
            raise RiskAssessmentValidationError("RiskAssessment.rationale contains control characters")
        if (
            _URL_USERINFO_PATTERN.search(value)
            or _CREDENTIAL_PARAM_PATTERN.search(value)
            or _TEXT_CREDENTIAL_PATTERN.search(value)
        ):
            raise RiskAssessmentValidationError("RiskAssessment.rationale contains credential-shaped content")

    @property
    def finding_id(self) -> str:
        return self.finding_refs[0]

    def to_dict(self) -> Dict[str, Any]:
        return {
            "risk_assessment_id": self.risk_assessment_id,
            "contract_version": self.contract_version,
            "investigation_id": self.investigation_id,
            "finding_refs": list(self.finding_refs),
            "evidence_refs": list(self.evidence_refs),
            "severity": self.severity.value,
            "confidence": self.confidence,
            "scoring_method": self.scoring_method,
            "rule_ids": list(self.rule_ids),
            "assessed_at": self.assessed_at,
            "assessed_by": self.assessed_by,
            "rationale": self.rationale,
        }

    @staticmethod
    def from_dict(data: Any) -> "RiskAssessment":
        """Exactly the contract's keys; anything else (``approved``,
        ``verdict``, ``target_ref``, ``mitigations_suggested`` ...) is
        rejected."""
        if not isinstance(data, dict) or set(data) != _DICT_KEYS:
            raise RiskAssessmentValidationError("record does not have the RiskAssessment shape")
        lists = {}
        for key in ("finding_refs", "evidence_refs", "rule_ids"):
            if not isinstance(data[key], list):
                raise RiskAssessmentValidationError(f"RiskAssessment.{key} must be a list")
            lists[key] = tuple(data[key])
        if type(data["severity"]) is not str:
            raise RiskAssessmentValidationError("RiskAssessment.severity must be a string")
        try:
            severity = RiskCategory(data["severity"])
        except ValueError:
            raise RiskAssessmentValidationError("RiskAssessment.severity is not a severity") from None
        return RiskAssessment(**dict(data, severity=severity, **lists))


_DICT_KEYS = frozenset(
    {
        "risk_assessment_id",
        "contract_version",
        "investigation_id",
        "finding_refs",
        "evidence_refs",
        "severity",
        "confidence",
        "scoring_method",
        "rule_ids",
        "assessed_at",
        "assessed_by",
        "rationale",
    }
)


@dataclass(frozen=True)
class NotAssessedFinding:
    """A Finding the rule set cannot rate. Not a failure, and never a
    default severity: the finding is shown as "not assessed"."""

    finding_id: str
    reason: str
    #: Phase 13: the rule set under which assessment was attempted.
    scoring_method: str

    def __post_init__(self) -> None:
        if type(self.finding_id) is not str or not self.finding_id:
            raise RiskAssessmentValidationError("NotAssessedFinding.finding_id must be a non-empty string")
        if self.reason not in NOT_ASSESSED_REASONS:
            raise RiskAssessmentValidationError("NotAssessedFinding.reason is not a known reason")
        _rule_set_for("NotAssessedFinding", self.scoring_method)


@dataclass(frozen=True)
class RiskEngineResult:
    """What a Risk Engine returns for one batch of Findings: every Finding
    appears exactly once, either assessed or not assessed. The Runtime
    re-checks that before storing anything.

    Phase 13: ``scoring_method`` names the one rule set the whole batch was
    produced under; every assessment and not-assessed entry must name the
    same one."""

    assessments: Tuple[RiskAssessment, ...]
    not_assessed: Tuple[NotAssessedFinding, ...]
    scoring_method: str

    def __post_init__(self) -> None:
        if type(self.assessments) is not tuple or not all(isinstance(a, RiskAssessment) for a in self.assessments):
            raise RiskAssessmentValidationError("RiskEngineResult.assessments must be a tuple of RiskAssessment")
        if type(self.not_assessed) is not tuple or not all(
            isinstance(n, NotAssessedFinding) for n in self.not_assessed
        ):
            raise RiskAssessmentValidationError("RiskEngineResult.not_assessed must be a tuple of NotAssessedFinding")
        _rule_set_for("RiskEngineResult", self.scoring_method)
        if any(item.scoring_method != self.scoring_method for item in self.assessments + self.not_assessed):
            raise RiskAssessmentValidationError("RiskEngineResult mixes rule sets")


__all__ = [
    "ASSESSED_BY",
    "MAX_RATIONALE_LENGTH",
    "MAX_RISK_ASSESSMENTS_PER_INVESTIGATION",
    "MAX_RULE_IDS",
    "NOT_ASSESSED_CATEGORY_UNRATED",
    "NOT_ASSESSED_EVIDENCE_INCOMPATIBLE",
    "NOT_ASSESSED_REASONS",
    "RISK_ASSESSMENT_ID_NAMESPACE",
    "SUPPORTED_SCORING_METHODS",
    "NotAssessedFinding",
    "RiskAssessment",
    "RiskAssessmentValidationError",
    "RiskEngineResult",
    "derive_risk_assessment_id",
    "severity_rank",
]
