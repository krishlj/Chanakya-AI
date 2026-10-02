"""PolicyRule / PolicySet — docs/POLICY-GATEWAY.md §1-2, extended by
docs/CAPABILITY-PERMISSION-MODEL.md §6 (category/action_type matching).

``validate_policy_set`` implements the load-time checks described in both
design docs. It must be run — and must pass — before a ``PolicySet`` is
handed to a ``PolicyGateway`` (the Gateway's constructor does this
automatically unless explicitly told not to).
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import List, Mapping, Optional, Sequence, Union

from chanakya.capability.model import ActionType
from chanakya.contracts.enums import Classification, RiskCategory, Verdict

WILDCARD = "*"


class PolicySetValidationError(ValueError):
    """Raised by ``validate_policy_set`` when a ``PolicySet`` violates a
    load-time invariant. Callers must reject the whole set on this error and
    keep serving the previously loaded, known-good set
    (docs/POLICY-GATEWAY.md §13) — never partially apply it."""


@dataclass(frozen=True)
class RuleMatch:
    capability: Union[str, Sequence[str]] = WILDCARD
    target_type: Union[str, Sequence[str]] = WILDCARD
    target_id: Optional[Sequence[str]] = None
    classification: Optional[Classification] = None
    category: Optional[str] = None
    action_type: Optional[ActionType] = None

    def capability_list(self) -> Optional[List[str]]:
        if self.capability == WILDCARD:
            return None
        if isinstance(self.capability, str):
            return [self.capability]
        return list(self.capability)

    def target_type_list(self) -> Optional[List[str]]:
        if self.target_type == WILDCARD:
            return None
        if isinstance(self.target_type, str):
            return [self.target_type]
        return list(self.target_type)


@dataclass(frozen=True)
class RuleConditions:
    max_calls_per_investigation: Optional[int] = None


@dataclass(frozen=True)
class PolicyRule:
    rule_id: str
    contract_version: str
    policy_set_version: str
    description: str
    enabled: bool
    priority: int
    match: RuleMatch
    effect: Verdict
    reason_template: str
    created_at: str
    updated_at: str
    owner: str
    conditions: RuleConditions = field(default_factory=RuleConditions)
    risk_category_override: Optional[RiskCategory] = None


@dataclass(frozen=True)
class PolicySet:
    policy_set_version: str
    rules: Sequence[PolicyRule] = field(default_factory=tuple)


def _matches(
    rule: PolicyRule,
    *,
    capability: str,
    target_type: str,
    target_id: str,
    classification: Classification,
    category: str,
    action_type: ActionType,
) -> bool:
    match = rule.match
    caps = match.capability_list()
    if caps is not None and capability not in caps:
        return False
    types = match.target_type_list()
    if types is not None and target_type not in types:
        return False
    if match.target_id is not None and target_id not in match.target_id:
        return False
    if match.classification is not None and match.classification != classification:
        return False
    if match.category is not None and match.category != category:
        return False
    if match.action_type is not None and match.action_type != action_type:
        return False
    return True


def find_matching_rules(policy_set: PolicySet, **kwargs) -> List[PolicyRule]:
    """Enabled rules matching the given (capability, target, classification,
    category, action_type) tuple, ordered by ascending ``priority``."""
    return sorted(
        (rule for rule in policy_set.rules if rule.enabled and _matches(rule, **kwargs)),
        key=lambda rule: rule.priority,
    )


def validate_policy_set(policy_set: PolicySet, registry) -> None:
    """Load-time validation (docs/POLICY-GATEWAY.md §2/§9, extended by
    docs/CAPABILITY-PERMISSION-MODEL.md §6):

    - no duplicate ``rule_id`` within the set;
    - every explicitly-named capability must exist in the Registry;
    - INV-1: ``effect: allow`` may never apply to a ``state_changing``
      capability, whether matched by name or by category/action_type;
    - ``match.classification``, if given alongside an explicit capability
      list, must agree with the Registry's actual classification;
    - CAP-INV-4: any rule matching ``action_type: destructive`` must specify
      an explicit ``match.target_id`` allowlist.

    ``registry`` is any object exposing ``get(capability) -> Optional[entry]``
    (i.e. a ``SecurityToolRegistry``).
    """
    seen_ids: set[str] = set()
    for rule in policy_set.rules:
        if rule.rule_id in seen_ids:
            raise PolicySetValidationError(f"duplicate rule_id: {rule.rule_id!r}")
        seen_ids.add(rule.rule_id)

        caps = rule.match.capability_list()
        if caps is not None:
            for capability in caps:
                entry = registry.get(capability)
                if entry is None:
                    raise PolicySetValidationError(
                        f"rule {rule.rule_id!r} references unregistered capability {capability!r}"
                    )
                if rule.effect == Verdict.ALLOW and entry.classification == Classification.STATE_CHANGING:
                    raise PolicySetValidationError(
                        f"rule {rule.rule_id!r}: INV-1 violation — effect=allow cannot apply to "
                        f"state_changing capability {capability!r}"
                    )
                if rule.match.classification is not None and rule.match.classification != entry.classification:
                    raise PolicySetValidationError(
                        f"rule {rule.rule_id!r}: match.classification "
                        f"({rule.match.classification.value}) disagrees with the Registry's actual "
                        f"classification for {capability!r} ({entry.classification.value})"
                    )
        else:
            # Category/action_type-scoped rule with no explicit capability list:
            # an `allow` here must be pinned to read_only, or it could silently
            # sweep in a state_changing capability sharing that category
            # (docs/CAPABILITY-PERMISSION-MODEL.md §6).
            is_category_scoped = rule.match.category is not None or rule.match.action_type is not None
            if rule.effect == Verdict.ALLOW and is_category_scoped and rule.match.classification != Classification.READ_ONLY:
                raise PolicySetValidationError(
                    f"rule {rule.rule_id!r}: a category/action_type-scoped effect=allow rule must "
                    f"also set match.classification=read_only"
                )

        # CAP-INV-4 (docs/CAPABILITY-PERMISSION-MODEL.md §3).
        if rule.match.action_type == ActionType.DESTRUCTIVE and rule.match.target_id is None:
            raise PolicySetValidationError(
                f"rule {rule.rule_id!r}: CAP-INV-4 — a rule matching action_type=destructive "
                f"must specify an explicit match.target_id allowlist"
            )
