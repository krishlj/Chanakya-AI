"""Security Tool Registry tests — docs/TOOL-REGISTRY.md."""
from __future__ import annotations

import pytest

from chanakya.capability.model import ActionType, CapabilityModelError
from chanakya.contracts.enums import Classification
from chanakya.registry.exceptions import RegistryAdmissionError
from chanakya.registry.models import Status
from chanakya.registry.registry import SecurityToolRegistry

from factories import make_entry


def test_lookup_returns_registered_entry(list_listening_ports_entry):
    registry = SecurityToolRegistry([list_listening_ports_entry])
    assert registry.get("list_listening_ports") is list_listening_ports_entry
    assert registry.get_enabled("list_listening_ports") is list_listening_ports_entry


def test_get_enabled_hides_disabled_entries(disabled_entry):
    registry = SecurityToolRegistry([disabled_entry])
    assert registry.get("legacy_scan") is disabled_entry  # raw lookup still finds it (admin tooling)
    assert registry.get_enabled("legacy_scan") is None  # Gateway-facing lookup hides it


def test_get_enabled_returns_none_for_unregistered_capability(list_listening_ports_entry):
    registry = SecurityToolRegistry([list_listening_ports_entry])
    assert registry.get_enabled("never_registered") is None


def test_duplicate_capability_registration_rejected(list_listening_ports_entry):
    registry = SecurityToolRegistry([list_listening_ports_entry])
    with pytest.raises(RegistryAdmissionError):
        registry.register(list_listening_ports_entry)


def test_action_type_classification_mismatch_rejected():
    """CAP-INV-2 (docs/CAPABILITY-PERMISSION-MODEL.md §1) — a capability
    cannot declare action_type=mutate while classification=read_only."""
    with pytest.raises(CapabilityModelError):
        make_entry(
            "bad_entry",
            classification=Classification.READ_ONLY,
            action_type=ActionType.MUTATE,
        )


def test_catalog_view_hides_disabled_entries_and_reduces_fields(list_listening_ports_entry, disabled_entry):
    """docs/TOOL-REGISTRY.md §4 — the Capability Catalog View filters status
    and strips every field the Agent must never see (REG-INV-3)."""
    registry = SecurityToolRegistry([list_listening_ports_entry, disabled_entry])
    view = registry.catalog_view()
    capabilities = {row["capability"] for row in view}
    assert "list_listening_ports" in capabilities
    assert "legacy_scan" not in capabilities

    row = next(r for r in view if r["capability"] == "list_listening_ports")
    assert set(row.keys()) == {
        "capability",
        "display_name",
        "description",
        "parameters_schema",
        "classification",
        "supported_target_types",
    }


def test_catalog_view_filters_by_target_type(list_listening_ports_entry):
    registry = SecurityToolRegistry([list_listening_ports_entry])
    assert registry.catalog_view(authorized_target_types=["local_host"])
    assert registry.catalog_view(authorized_target_types=["kubernetes"]) == []


def test_status_transition_lifecycle(list_listening_ports_entry):
    registry = SecurityToolRegistry([list_listening_ports_entry])
    updated = registry.set_status("list_listening_ports", Status.DISABLED, actor="admin")
    assert updated.status == Status.DISABLED
    assert registry.get_enabled("list_listening_ports") is None


def test_illegal_status_transition_rejected(list_listening_ports_entry):
    """docs/TOOL-REGISTRY.md §6 — enabled cannot jump directly back to
    proposed; it must go through the defined lifecycle."""
    registry = SecurityToolRegistry([list_listening_ports_entry])
    with pytest.raises(RegistryAdmissionError):
        registry.set_status("list_listening_ports", Status.PROPOSED, actor="admin")


def test_quarantine_can_only_return_via_under_review(list_listening_ports_entry):
    registry = SecurityToolRegistry([list_listening_ports_entry])
    registry.set_status("list_listening_ports", Status.QUARANTINED, actor="system")
    with pytest.raises(RegistryAdmissionError):
        registry.set_status("list_listening_ports", Status.ENABLED, actor="admin")
    # the only legal exit from quarantine is back to under_review
    updated = registry.set_status("list_listening_ports", Status.UNDER_REVIEW, actor="admin")
    assert updated.status == Status.UNDER_REVIEW
