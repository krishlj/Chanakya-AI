"""Risk taxonomy and rule-set data — docs/CONTRACTS.md §9, Phase 10.

Provider-neutral, authority-free data describing rule set
``chanakya-risk-rules/1.0.0``: the closed set of finding categories the
Risk Engine can rate, each category's base severity and the capabilities
whose Evidence can support it, and the closed vocabulary of rule ids a
``RiskAssessment`` may cite.

It lives in ``chanakya.contracts`` so three consumers can share one
definition without depending on each other: the provider (which lists the
category ids in the ``report_findings`` schema), the Runtime (which
validates engine output without importing ``chanakya.risk``) and the Risk
Engine (which evaluates it). This module imports nothing from ``chanakya``
and decides nothing; severities are plain strings matching
``chanakya.contracts.enums.RiskCategory`` values (asserted in tests).

Changing any value here changes ratings, so it requires a new rule-set id
(docs/THREAT-MODEL.md T-49), never an in-place edit.
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from types import MappingProxyType
from typing import Any, FrozenSet, Mapping, Tuple

#: The only rule set in Phase 10. Stored as ``RiskAssessment.scoring_method``.
RISK_RULE_SET_V1 = "chanakya-risk-rules/1.0.0"

#: Compatibility marker: Evidence from any capability supports the category.
#: Every Evidence capability was Registry-validated before dispatch.
ANY_CAPABILITY = "*"

#: ``RiskCategory`` values, lowest to highest.
SEVERITY_ORDER: Tuple[str, ...] = ("informational", "low", "medium", "high", "critical")

#: Rule 5: the highest severity when every cited Evidence is read-only.
READ_ONLY_SEVERITY_CEILING = "high"

_LIST_LISTENING_PORTS = "list_listening_ports"
_OBSERVE_LOCAL_HOST_ENVIRONMENT = "observe_local_host_environment"


@dataclass(frozen=True)
class RiskCategoryRule:
    category: str
    base_severity: str
    compatible_capabilities: FrozenSet[str]

    @property
    def rule_id(self) -> str:
        return f"category.{self.category}"


RISK_TAXONOMY_V1: Mapping[str, RiskCategoryRule] = MappingProxyType(
    {
        rule.category: rule
        for rule in (
            RiskCategoryRule("network_exposure", "medium", frozenset({_LIST_LISTENING_PORTS})),
            RiskCategoryRule("unexpected_listener", "low", frozenset({_LIST_LISTENING_PORTS})),
            RiskCategoryRule("service_inventory", "informational", frozenset({_LIST_LISTENING_PORTS})),
            RiskCategoryRule("platform_configuration", "low", frozenset({_OBSERVE_LOCAL_HOST_ENVIRONMENT})),
            RiskCategoryRule("unsupported_platform_version", "medium", frozenset({_OBSERVE_LOCAL_HOST_ENVIRONMENT})),
            RiskCategoryRule("observation", "informational", frozenset({ANY_CAPABILITY})),
        )
    }
)

#: Category ids in table order; what the provider offers the model.
RISK_CATEGORY_IDS: Tuple[str, ...] = tuple(RISK_TAXONOMY_V1)

# Rule ids. Every RiskAssessment cites, in this order: evidence.verified,
# its category rule, one compat.* rule, ceiling.read_only when it applied,
# and one confidence.* rule.
RULE_EVIDENCE_VERIFIED = "evidence.verified"
RULE_COMPAT_ALL = "compat.all"
RULE_COMPAT_PARTIAL = "compat.partial"
RULE_CEILING_READ_ONLY = "ceiling.read_only"
RULE_CONFIDENCE_HIGH = "confidence.high"
RULE_CONFIDENCE_MEDIUM = "confidence.medium"
RULE_CONFIDENCE_LOW = "confidence.low"

RULE_IDS_V1: FrozenSet[str] = frozenset(
    {
        RULE_EVIDENCE_VERIFIED,
        RULE_COMPAT_ALL,
        RULE_COMPAT_PARTIAL,
        RULE_CEILING_READ_ONLY,
        RULE_CONFIDENCE_HIGH,
        RULE_CONFIDENCE_MEDIUM,
        RULE_CONFIDENCE_LOW,
    }
    | {rule.rule_id for rule in RISK_TAXONOMY_V1.values()}
)

# -- Phase 13: versioned rule sets ----------------------------------------------
#
# A rule set is trusted, code-defined infrastructure. Its identity is the
# ``scoring_method`` string every risk result carries. The registry below is
# the only place a rule set can be resolved from; it is an immutable mapping
# defined in code, never filled from configuration, environment, CLI, request,
# model, tool, finding or evidence data. Exactly one rule set is active, and
# ``chanakya-risk-rules/1.0.0`` is the only production rule set: Phase 13
# adds versioning, not new rules. A future rule set must be added here under
# a new ``scoring_method``; the v1 data above must never be edited, because
# historical assessments are recomputed under the rule set they record.

_SCORING_METHOD = re.compile(r"^[a-z0-9][a-z0-9._/-]{0,63}$")
_CANONICAL_RULES = frozenset(
    {
        RULE_EVIDENCE_VERIFIED,
        RULE_COMPAT_ALL,
        RULE_COMPAT_PARTIAL,
        RULE_CEILING_READ_ONLY,
        RULE_CONFIDENCE_HIGH,
        RULE_CONFIDENCE_MEDIUM,
        RULE_CONFIDENCE_LOW,
    }
)


class RiskRuleSetError(ValueError):
    """A rule set is unknown or malformed. Never repaired, never defaulted."""


@dataclass(frozen=True)
class RiskRuleSet:
    """One immutable, versioned rule set: its taxonomy (categories, base
    severities, compatible capabilities), its closed rule-id vocabulary, the
    read-only severity ceiling and the highest severity it may ever emit."""

    scoring_method: str
    taxonomy: Mapping[str, RiskCategoryRule]
    rule_ids: FrozenSet[str]
    read_only_severity_ceiling: str
    max_severity: str

    def __post_init__(self) -> None:
        if type(self.scoring_method) is not str or not _SCORING_METHOD.match(self.scoring_method):
            raise RiskRuleSetError("RiskRuleSet.scoring_method is not a valid identifier")
        if not isinstance(self.taxonomy, Mapping) or not self.taxonomy:
            raise RiskRuleSetError("RiskRuleSet.taxonomy must be a non-empty mapping")
        for category, rule in self.taxonomy.items():
            if not isinstance(rule, RiskCategoryRule) or rule.category != category:
                raise RiskRuleSetError("RiskRuleSet.taxonomy entries must be RiskCategoryRule keyed by category")
            if rule.base_severity not in SEVERITY_ORDER or not rule.compatible_capabilities:
                raise RiskRuleSetError("RiskRuleSet.taxonomy entry has an invalid severity or no capabilities")
        for severity in (self.read_only_severity_ceiling, self.max_severity):
            if severity not in SEVERITY_ORDER:
                raise RiskRuleSetError("RiskRuleSet severities must be RiskCategory values")
        expected_rules = _CANONICAL_RULES | {rule.rule_id for rule in self.taxonomy.values()}
        if not isinstance(self.rule_ids, frozenset) or self.rule_ids != expected_rules:
            raise RiskRuleSetError("RiskRuleSet.rule_ids must be exactly the canonical and category rules")
        object.__setattr__(self, "taxonomy", MappingProxyType(dict(self.taxonomy)))

    @property
    def category_ids(self) -> Tuple[str, ...]:
        """Category ids in table order: the model-facing vocabulary."""
        return tuple(self.taxonomy)


#: The v1 rule set, built from the frozen v1 data above.
RISK_RULE_SET_V1_DEFINITION = RiskRuleSet(
    scoring_method=RISK_RULE_SET_V1,
    taxonomy=RISK_TAXONOMY_V1,
    rule_ids=RULE_IDS_V1,
    read_only_severity_ceiling=READ_ONLY_SEVERITY_CEILING,
    max_severity=READ_ONLY_SEVERITY_CEILING,
)

#: Every production rule set, by ``scoring_method``. v1 only.
_RULE_SETS: Mapping[str, RiskRuleSet] = MappingProxyType({RISK_RULE_SET_V1: RISK_RULE_SET_V1_DEFINITION})

#: The single active rule set new assessments are produced under.
_ACTIVE_RULE_SET: RiskRuleSet = RISK_RULE_SET_V1_DEFINITION


def resolve_rule_set(scoring_method: Any) -> RiskRuleSet:
    """The registered rule set named ``scoring_method``. Raises
    ``RiskRuleSetError`` for anything else; there is no fallback."""
    rule_set = _RULE_SETS.get(scoring_method) if type(scoring_method) is str else None
    if rule_set is None:
        raise RiskRuleSetError("unknown risk rule set")
    return rule_set


def active_rule_set() -> RiskRuleSet:
    """The one active rule set. Read at call time from trusted code."""
    return resolve_rule_set(_ACTIVE_RULE_SET.scoring_method)


def registered_scoring_methods() -> FrozenSet[str]:
    return frozenset(_RULE_SETS)


__all__ = [
    "ANY_CAPABILITY",
    "RISK_RULE_SET_V1_DEFINITION",
    "RiskRuleSet",
    "RiskRuleSetError",
    "active_rule_set",
    "registered_scoring_methods",
    "resolve_rule_set",
    "READ_ONLY_SEVERITY_CEILING",
    "RISK_CATEGORY_IDS",
    "RISK_RULE_SET_V1",
    "RISK_TAXONOMY_V1",
    "RULE_CEILING_READ_ONLY",
    "RULE_COMPAT_ALL",
    "RULE_COMPAT_PARTIAL",
    "RULE_CONFIDENCE_HIGH",
    "RULE_CONFIDENCE_LOW",
    "RULE_CONFIDENCE_MEDIUM",
    "RULE_EVIDENCE_VERIFIED",
    "RULE_IDS_V1",
    "RiskCategoryRule",
    "SEVERITY_ORDER",
]
