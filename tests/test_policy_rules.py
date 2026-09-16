"""PolicySet load-time validation tests — docs/POLICY-GATEWAY.md §2/§9,
extended by docs/CAPABILITY-PERMISSION-MODEL.md §6.
"""
from __future__ import annotations

import pytest

from chanakya.capability.model import ActionType
from chanakya.contracts.enums import Classification, Verdict
from chanakya.policy.rules import PolicySet, PolicySetValidationError, validate_policy_set

from factories import make_rule


def test_allow_rule_on_state_changing_capability_rejected(registry):
    """INV-1: no rule may set effect=allow for a state_changing capability."""
    rule = make_rule("bad-allow", capability=["terminate_process"], effect=Verdict.ALLOW)
    policy_set = PolicySet(policy_set_version="1.0.0", rules=[rule])
    with pytest.raises(PolicySetValidationError):
        validate_policy_set(policy_set, registry)


def test_rule_referencing_unregistered_capability_rejected(registry):
    rule = make_rule("bad-ref", capability=["does_not_exist"], effect=Verdict.DENY)
    policy_set = PolicySet(policy_set_version="1.0.0", rules=[rule])
    with pytest.raises(PolicySetValidationError):
        validate_policy_set(policy_set, registry)


def test_duplicate_rule_id_rejected(registry):
    rule1 = make_rule("dup", capability=["list_listening_ports"], effect=Verdict.DENY)
    rule2 = make_rule("dup", capability=["terminate_process"], effect=Verdict.DENY)
    policy_set = PolicySet(policy_set_version="1.0.0", rules=[rule1, rule2])
    with pytest.raises(PolicySetValidationError):
        validate_policy_set(policy_set, registry)


def test_rule_classification_disagreeing_with_registry_rejected(registry):
    rule = make_rule(
        "bad-classification",
        capability=["list_listening_ports"],
        effect=Verdict.DENY,
        classification=Classification.STATE_CHANGING,  # actually read_only in the Registry
    )
    policy_set = PolicySet(policy_set_version="1.0.0", rules=[rule])
    with pytest.raises(PolicySetValidationError):
        validate_policy_set(policy_set, registry)


def test_category_scoped_allow_without_read_only_classification_rejected(registry):
    """docs/CAPABILITY-PERMISSION-MODEL.md §6 — extension of INV-1 to
    category/action_type-scoped rules."""
    rule = make_rule("cat-allow", category="process_information", effect=Verdict.ALLOW)
    policy_set = PolicySet(policy_set_version="1.0.0", rules=[rule])
    with pytest.raises(PolicySetValidationError):
        validate_policy_set(policy_set, registry)


def test_category_scoped_allow_with_read_only_classification_accepted(registry):
    rule = make_rule(
        "cat-allow-ro", category="network_information", effect=Verdict.ALLOW, classification=Classification.READ_ONLY
    )
    policy_set = PolicySet(policy_set_version="1.0.0", rules=[rule])
    validate_policy_set(policy_set, registry)  # must not raise


def test_destructive_rule_without_target_id_rejected(registry):
    """CAP-INV-4 (docs/CAPABILITY-PERMISSION-MODEL.md §3)."""
    rule = make_rule("destructive-no-target", action_type=ActionType.DESTRUCTIVE, effect=Verdict.REQUIRE_APPROVAL)
    policy_set = PolicySet(policy_set_version="1.0.0", rules=[rule])
    with pytest.raises(PolicySetValidationError):
        validate_policy_set(policy_set, registry)


def test_destructive_rule_with_target_id_accepted(registry):
    rule = make_rule(
        "destructive-ok",
        action_type=ActionType.DESTRUCTIVE,
        effect=Verdict.REQUIRE_APPROVAL,
        target_id=["target-local-host-01"],
    )
    policy_set = PolicySet(policy_set_version="1.0.0", rules=[rule])
    validate_policy_set(policy_set, registry)  # must not raise


def test_gateway_rejects_invalid_policy_set_at_construction(registry, target_registry):
    from chanakya.policy.gateway import PolicyGateway

    rule = make_rule("bad-allow", capability=["terminate_process"], effect=Verdict.ALLOW)
    policy_set = PolicySet(policy_set_version="1.0.0", rules=[rule])
    with pytest.raises(PolicySetValidationError):
        PolicyGateway(registry, target_registry, policy_set)
