"""RegistryEntry schema — docs/TOOL-REGISTRY.md.

One entry per invocable capability. Every field that determines
authorization (``classification``, ``default_risk_category``,
``required_privileges``, ``supported_target_types``,
``approval_requirement``, ``parameters_schema``, ``output_schema``) is
admin-set at construction time — nothing in this module ever derives one of
those fields from ``provenance.self_declared_metadata`` (REG-INV-1). That
field exists purely as an inert, stored record of what a tool/MCP server
claimed about itself, for audit/comparison — it is never read by
``chanakya.policy`` or by anything else in this package.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Mapping, Sequence

from chanakya.capability.model import ActionType, PermissionLevel, derive_permission_level, validate_action_type_classification
from chanakya.contracts.enums import Classification, RiskCategory


class Status(str, Enum):
    """docs/TOOL-REGISTRY.md §6 — lifecycle states. Only ``ENABLED`` is
    invocable or Agent-visible."""

    PROPOSED = "proposed"
    UNDER_REVIEW = "under_review"
    APPROVED = "approved"
    ENABLED = "enabled"
    DISABLED = "disabled"
    QUARANTINED = "quarantined"
    DEPRECATED = "deprecated"
    RETIRED = "retired"
    REJECTED = "rejected"


class ApprovalRequirement(str, Enum):
    """docs/TOOL-REGISTRY.md §1, item 15 — a Registry-declared floor,
    independent of and composable with any Policy rule (most-restrictive-wins,
    docs/TOOL-REGISTRY.md §3)."""

    NONE = "none"
    REQUIRED = "required"


class TrustLevel(str, Enum):
    CORE = "core"
    FIRST_PARTY_ADAPTER = "first_party_adapter"
    VETTED_THIRD_PARTY = "vetted_third_party"
    QUARANTINED = "quarantined"


class OSPrivilege(str, Enum):
    STANDARD_USER = "standard_user"
    ELEVATED = "elevated"


class TargetAccess(str, Enum):
    TARGET_READ = "target_read"
    TARGET_WRITE = "target_write"


@dataclass(frozen=True)
class RequiredPrivileges:
    os_privilege: OSPrivilege
    target_access: TargetAccess


@dataclass(frozen=True)
class ResourceLimits:
    max_output_bytes: int
    max_cpu_seconds: int
    max_memory_mb: int
    max_concurrent_invocations: int


@dataclass(frozen=True)
class Provenance:
    source_type: str
    source_identifier: str
    source_version: str
    implementation_hash: str
    vetted_by: str
    vetted_at: str
    self_declared_metadata: Mapping[str, Any] = field(default_factory=dict)
    review_notes: str = ""


# docs/TOOL-REGISTRY.md §6 — allowed lifecycle transitions.
ALLOWED_STATUS_TRANSITIONS: Mapping[Status, frozenset[Status]] = {
    Status.PROPOSED: frozenset({Status.UNDER_REVIEW}),
    Status.UNDER_REVIEW: frozenset({Status.APPROVED, Status.REJECTED}),
    Status.APPROVED: frozenset({Status.ENABLED}),
    Status.ENABLED: frozenset({Status.DISABLED, Status.QUARANTINED, Status.DEPRECATED}),
    Status.DISABLED: frozenset({Status.ENABLED, Status.RETIRED}),
    Status.QUARANTINED: frozenset({Status.UNDER_REVIEW}),
    Status.DEPRECATED: frozenset({Status.DISABLED}),
    Status.REJECTED: frozenset(),
    Status.RETIRED: frozenset(),
}


@dataclass(frozen=True)
class RegistryEntry:
    tool_id: str
    contract_version: str
    registry_version: str
    capability: str
    display_name: str
    tool_version: str
    description: str
    category: str
    action_type: ActionType
    operations: Sequence[str]
    parameters_schema: Mapping[str, Any]
    output_schema: Mapping[str, Any]
    default_risk_category: RiskCategory
    classification: Classification
    required_privileges: RequiredPrivileges
    supported_target_types: Sequence[str]
    default_timeout_seconds: int
    resource_limits: ResourceLimits
    approval_requirement: ApprovalRequirement
    provenance: Provenance
    trust_level: TrustLevel
    status: Status
    created_at: str
    updated_at: str
    owner: str

    def __post_init__(self) -> None:
        if not self.capability:
            raise ValueError("RegistryEntry.capability must be non-empty")
        if not self.operations:
            raise ValueError("RegistryEntry.operations must be non-empty")
        if not self.supported_target_types:
            raise ValueError("RegistryEntry.supported_target_types must be non-empty")
        # CAP-INV-2 (docs/CAPABILITY-PERMISSION-MODEL.md §1) — enforced at
        # construction time, so an inconsistent entry cannot even exist.
        validate_action_type_classification(self.action_type, self.classification)

    @property
    def permission_level(self) -> PermissionLevel:
        """Derived, never independently settable (docs/CAPABILITY-PERMISSION-MODEL.md §3)."""
        return derive_permission_level(self)
