"""Risk rule evaluation — Phase 10 (docs/CONTRACTS.md §9), versioned in Phase 13.

Pure evaluation of one Finding's category against the verified metadata of
the Evidence it cites, under an explicitly supplied ``RiskRuleSet`` (there is
no default rule set). The rule-set data (categories, base severities,
compatible capabilities, rule ids, ceilings) lives in
``chanakya.contracts.risk_taxonomy``; ``chanakya-risk-rules/1.0.0`` is the
only production rule set. This module applies whichever rule set it is
given:

1. Category gate: no category, or one outside the taxonomy, is not
   assessed (``category_unrated``). No default severity is ever guessed.
2. Evidence verification happens before this module is reached (the
   engine raises on any integrity failure); ``evidence.verified`` records it.
3. Compatibility: if no cited Evidence comes from a compatible capability,
   the finding is not assessed (``evidence_incompatible``).
4. Base severity comes from the category table only.
5. Read-only ceiling: when every cited Evidence is ``read_only``, severity
   is capped at ``high`` (``critical`` is unreachable under 1.0.0).
6. Confidence reflects the evidentiary basis only: ``high`` if all cited
   Evidence is compatible and comes from at least two distinct compatible
   capabilities, ``medium`` if all is compatible, ``low`` if only some is.

Inputs are the category string and ``EvidenceFacts`` (id, investigation,
capability, classification). No finding text, no finding confidence, no
payload and no target data reach this module.
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Optional, Sequence, Tuple, Union

from chanakya.contracts.enums import Classification, RiskCategory
from chanakya.contracts.risk_assessment import (
    MAX_RATIONALE_LENGTH,
    NOT_ASSESSED_CATEGORY_UNRATED,
    NOT_ASSESSED_EVIDENCE_INCOMPATIBLE,
    severity_rank,
)
from chanakya.contracts.risk_taxonomy import (
    ANY_CAPABILITY,
    RULE_CEILING_READ_ONLY,
    RULE_COMPAT_ALL,
    RULE_COMPAT_PARTIAL,
    RULE_CONFIDENCE_HIGH,
    RULE_CONFIDENCE_LOW,
    RULE_CONFIDENCE_MEDIUM,
    RULE_EVIDENCE_VERIFIED,
    RiskRuleSet,
)

#: Registry capability ids that may appear in a rationale.
CAPABILITY_ID_PATTERN = re.compile(r"^[a-z0-9_]{1,64}$")


@dataclass(frozen=True)
class EvidenceFacts:
    """The only Evidence data the engine sees: Runtime-owned provenance,
    already hash- and payload-verified in its own investigation."""

    evidence_id: str
    investigation_id: str
    capability: str
    classification: Classification


@dataclass(frozen=True)
class RuleOutcome:
    severity: RiskCategory
    confidence: str
    rule_ids: Tuple[str, ...]
    rationale: str


def _names(capabilities) -> str:
    return ", ".join(sorted(capabilities)) or "none"


def evaluate(category: Optional[str], facts: Sequence[EvidenceFacts], *, rule_set: RiskRuleSet) -> Union[RuleOutcome, str]:
    """Returns a ``RuleOutcome``, or a not-assessed reason string, under
    ``rule_set`` (Phase 13: always explicit; there is no default)."""
    if not isinstance(rule_set, RiskRuleSet):
        raise TypeError("evaluate requires a RiskRuleSet")
    rule = rule_set.taxonomy.get(category) if isinstance(category, str) else None
    if rule is None:
        return NOT_ASSESSED_CATEGORY_UNRATED

    def compatible(fact: EvidenceFacts) -> bool:
        return ANY_CAPABILITY in rule.compatible_capabilities or fact.capability in rule.compatible_capabilities

    supporting = [f for f in facts if compatible(f)]
    if not supporting:
        return NOT_ASSESSED_EVIDENCE_INCOMPATIBLE
    all_compatible = len(supporting) == len(facts)
    supporting_capabilities = {f.capability for f in supporting}
    other_capabilities = {f.capability for f in facts if not compatible(f)}

    severity = rule.base_severity
    rules = [RULE_EVIDENCE_VERIFIED, rule.rule_id, RULE_COMPAT_ALL if all_compatible else RULE_COMPAT_PARTIAL]
    ceiling = all(f.classification == Classification.READ_ONLY for f in facts)
    if ceiling:
        rules.append(RULE_CEILING_READ_ONLY)
        if severity_rank(severity) > severity_rank(rule_set.read_only_severity_ceiling):
            severity = rule_set.read_only_severity_ceiling

    if all_compatible and len(supporting_capabilities) >= 2:
        confidence, confidence_rule, why = "high", RULE_CONFIDENCE_HIGH, "all cited evidence is compatible and comes from at least two distinct capabilities"
    elif all_compatible:
        confidence, confidence_rule, why = "medium", RULE_CONFIDENCE_MEDIUM, "all cited evidence is compatible"
    else:
        confidence, confidence_rule, why = "low", RULE_CONFIDENCE_LOW, "only some cited evidence is compatible"
    rules.append(confidence_rule)

    def rationale(compatible_text: str, other_text: str) -> str:
        parts = [
            f"Rule set {rule_set.scoring_method}.",
            f"{RULE_EVIDENCE_VERIFIED}: {len(facts)} cited evidence record(s) verified in this investigation.",
            f"{rule.rule_id}: category {rule.category} has base severity {rule.base_severity}.",
            f"{rules[2]}: compatible evidence capabilities: {compatible_text}; incompatible: {other_text}.",
        ]
        if ceiling:
            parts.append(
                f"{RULE_CEILING_READ_ONLY}: all cited evidence is read_only, so severity is at most "
                f"{rule_set.read_only_severity_ceiling}."
            )
        parts.append(f"{confidence_rule}: {why}.")
        parts.append(
            f"Result: severity {severity}, basis confidence {confidence}. "
            "This rates the category and evidence provenance only; it does not verify the finding."
        )
        return " ".join(parts)

    text = rationale(_names(supporting_capabilities), _names(other_capabilities))
    if len(text) > MAX_RATIONALE_LENGTH:
        # Deterministic, bounded fallback: counts instead of names.
        text = rationale(
            f"{len(supporting_capabilities)} distinct", f"{len(other_capabilities)} distinct" if other_capabilities else "none"
        )
    return RuleOutcome(severity=RiskCategory(severity), confidence=confidence, rule_ids=tuple(rules), rationale=text)


__all__ = ["CAPABILITY_ID_PATTERN", "EvidenceFacts", "RuleOutcome", "evaluate"]
