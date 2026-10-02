"""Capability & permission model — docs/CAPABILITY-PERMISSION-MODEL.md.

Defines the ``action_type`` taxonomy (finer than the binary
``read_only``/``state_changing`` classification) and the derived
``PermissionLevel`` (P0-P4) that the Policy Gateway and Security Tool
Registry both consume. Permission levels are always *derived* from a
Registry entry's declared fields — never an independently settable value
(§3 of the design doc).
"""
from __future__ import annotations

from enum import Enum
from typing import TYPE_CHECKING

from chanakya.contracts.enums import Classification, RiskCategory

if TYPE_CHECKING:  # pragma: no cover - typing only, avoids a real import cycle
    from chanakya.registry.models import RegistryEntry


class ActionType(str, Enum):
    """docs/CAPABILITY-PERMISSION-MODEL.md §1 — the coarse effect tier every
    operation declared by a capability must share (CAP-INV-1)."""

    OBSERVE = "observe"
    EXECUTE_READONLY_PROBE = "execute_readonly_probe"
    MUTATE = "mutate"
    DESTRUCTIVE = "destructive"


class PermissionLevel(str, Enum):
    """docs/CAPABILITY-PERMISSION-MODEL.md §3."""

    P0 = "P0"  # not permitted
    P1 = "P1"  # observational, unrestricted within scope
    P2 = "P2"  # observational, sensitive / active read-only probe
    P3 = "P3"  # state-changing, supervised
    P4 = "P4"  # state-changing, high-risk / destructive


class CapabilityModelError(ValueError):
    """Raised when a RegistryEntry violates a capability/permission model
    invariant (CAP-INV-1/CAP-INV-2)."""


_ACTION_TYPE_TO_CLASSIFICATION = {
    ActionType.OBSERVE: Classification.READ_ONLY,
    ActionType.EXECUTE_READONLY_PROBE: Classification.READ_ONLY,
    ActionType.MUTATE: Classification.STATE_CHANGING,
    ActionType.DESTRUCTIVE: Classification.STATE_CHANGING,
}


def expected_classification_for(action_type: ActionType) -> Classification:
    return _ACTION_TYPE_TO_CLASSIFICATION[action_type]


def validate_action_type_classification(action_type: ActionType, classification: Classification) -> None:
    """CAP-INV-2: ``action_type`` and ``classification`` must agree.

    Registry admission rejects any entry where the two disagree — e.g.
    ``action_type: mutate`` can never coexist with ``classification:
    read_only``. Raised as part of ``RegistryEntry.__post_init__``, so an
    inconsistent entry cannot even be constructed.
    """
    expected = expected_classification_for(action_type)
    if classification != expected:
        raise CapabilityModelError(
            f"action_type={action_type.value!r} requires classification={expected.value!r}, "
            f"but got classification={classification.value!r}"
        )


def derive_permission_level(entry: "RegistryEntry") -> PermissionLevel:
    """docs/CAPABILITY-PERMISSION-MODEL.md §3 — the permission-level derivation table.

    A capability that is not ``enabled`` is always P0, regardless of what
    its ``action_type``/``classification`` would otherwise imply.
    """
    # Deferred import: chanakya.registry.models imports this module at module
    # load time (for ActionType / validate_action_type_classification), so a
    # top-level import here would be circular. By the time this function is
    # actually called, chanakya.registry.models is already fully loaded.
    from chanakya.registry.models import ApprovalRequirement, Status

    if entry.status != Status.ENABLED:
        return PermissionLevel.P0

    if entry.action_type == ActionType.OBSERVE:
        sensitive = entry.approval_requirement == ApprovalRequirement.REQUIRED or entry.default_risk_category in (
            RiskCategory.MEDIUM,
            RiskCategory.HIGH,
            RiskCategory.CRITICAL,
        )
        return PermissionLevel.P2 if sensitive else PermissionLevel.P1

    if entry.action_type == ActionType.EXECUTE_READONLY_PROBE:
        return PermissionLevel.P2

    if entry.action_type == ActionType.MUTATE:
        return PermissionLevel.P3

    if entry.action_type == ActionType.DESTRUCTIVE:
        return PermissionLevel.P4

    raise CapabilityModelError(f"unrecognized action_type: {entry.action_type!r}")  # pragma: no cover


#: docs/CAPABILITY-PERMISSION-MODEL.md §2 — the eight requested categories.
#: Organizational only (CAP-INV-3): never consulted for an authorization
#: decision. The taxonomy is open — this set is a reference, not an enum,
#: so a future admin can register a new category without a code change.
KNOWN_CATEGORIES = frozenset(
    {
        "host_information",
        "process_information",
        "network_information",
        "filesystem_observation",
        "log_observation",
        "network_scanning",
        "source_code_analysis",
        "vulnerability_analysis",
    }
)
