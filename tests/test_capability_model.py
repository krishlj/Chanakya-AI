"""Capability & permission model tests — docs/CAPABILITY-PERMISSION-MODEL.md."""
from __future__ import annotations

from chanakya.capability.model import ActionType, PermissionLevel, derive_permission_level
from chanakya.contracts.enums import Classification, RiskCategory
from chanakya.registry.models import ApprovalRequirement, Status

from factories import make_entry


def test_observe_read_only_is_p1():
    entry = make_entry("x", classification=Classification.READ_ONLY, action_type=ActionType.OBSERVE)
    assert derive_permission_level(entry) == PermissionLevel.P1


def test_observe_flagged_sensitive_via_approval_requirement_is_p2():
    entry = make_entry(
        "x",
        classification=Classification.READ_ONLY,
        action_type=ActionType.OBSERVE,
        approval_requirement=ApprovalRequirement.REQUIRED,
    )
    assert derive_permission_level(entry) == PermissionLevel.P2


def test_observe_flagged_sensitive_via_risk_category_is_p2():
    entry = make_entry(
        "x",
        classification=Classification.READ_ONLY,
        action_type=ActionType.OBSERVE,
        default_risk_category=RiskCategory.HIGH,
    )
    assert derive_permission_level(entry) == PermissionLevel.P2


def test_execute_readonly_probe_is_always_p2():
    entry = make_entry("x", classification=Classification.READ_ONLY, action_type=ActionType.EXECUTE_READONLY_PROBE)
    assert derive_permission_level(entry) == PermissionLevel.P2


def test_mutate_is_p3():
    entry = make_entry("x", classification=Classification.STATE_CHANGING, action_type=ActionType.MUTATE)
    assert derive_permission_level(entry) == PermissionLevel.P3


def test_destructive_is_p4():
    entry = make_entry("x", classification=Classification.STATE_CHANGING, action_type=ActionType.DESTRUCTIVE)
    assert derive_permission_level(entry) == PermissionLevel.P4


def test_disabled_entry_is_p0_regardless_of_action_type():
    entry = make_entry(
        "x", classification=Classification.STATE_CHANGING, action_type=ActionType.DESTRUCTIVE, status=Status.DISABLED
    )
    assert derive_permission_level(entry) == PermissionLevel.P0
