"""Baseline TargetRegistry coverage — flagged as missing by the Phase 4.1
repository inspection ("TargetRegistry currently lacks dedicated tests").

TargetRegistry itself is unchanged by Phase 4.4 (docs/TARGET-MANAGER.md
§7/§19) — these tests establish the regression baseline for its existing,
minimal behavior before TargetManager composes it.
"""
from __future__ import annotations

import pytest

from chanakya.contracts.target import Target
from chanakya.targets.registry import TargetRegistry

from factories import now


def make_target(target_id: str = "target-local-host-01", **overrides) -> Target:
    fields = dict(
        target_id=target_id,
        contract_version="1.0.0",
        target_type="local_host",
        display_name="Primary workstation",
        authorized_scope="This machine only, read-only capabilities",
        registered_at=now(),
    )
    fields.update(overrides)
    return Target(**fields)


def test_get_on_empty_registry_returns_none():
    registry = TargetRegistry()
    assert registry.get("target-local-host-01") is None


def test_register_then_get_returns_the_same_target():
    registry = TargetRegistry()
    target = make_target()
    registry.register(target)
    assert registry.get("target-local-host-01") is target


def test_get_unknown_id_returns_none_not_an_error():
    registry = TargetRegistry([make_target()])
    assert registry.get("target-does-not-exist") is None


def test_duplicate_target_id_registration_is_rejected():
    registry = TargetRegistry([make_target()])
    with pytest.raises(ValueError):
        registry.register(make_target())


def test_duplicate_rejection_does_not_replace_the_existing_record():
    original = make_target(display_name="Original")
    registry = TargetRegistry([original])
    duplicate = make_target(display_name="Attempted overwrite")
    with pytest.raises(ValueError):
        registry.register(duplicate)
    assert registry.get("target-local-host-01") is original
    assert registry.get("target-local-host-01").display_name == "Original"


def test_constructor_accepts_multiple_targets():
    a = make_target(target_id="target-a")
    b = make_target(target_id="target-b")
    registry = TargetRegistry([a, b])
    assert registry.get("target-a") is a
    assert registry.get("target-b") is b


def test_distinct_target_ids_do_not_collide():
    registry = TargetRegistry()
    registry.register(make_target(target_id="target-a", display_name="A"))
    registry.register(make_target(target_id="target-b", display_name="B"))
    assert registry.get("target-a").display_name == "A"
    assert registry.get("target-b").display_name == "B"
