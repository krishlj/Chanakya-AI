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

from dataclasses import dataclass
from types import MappingProxyType
from typing import FrozenSet, Mapping, Tuple

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

__all__ = [
    "ANY_CAPABILITY",
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
