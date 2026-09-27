"""Phase 5.1 — the first production ``RegistryEntry``.

Not auto-registration: this module only builds the one entry Phase 5.1
approved (approved Phase 5.1 Tool Layer design report §3); a composition
root registers it explicitly (``SecurityToolRegistry.register(...)``) —
nothing here does that on import, and nothing here scans for or discovers
capabilities from anywhere else.

``capability`` below must match ``chanakya.tools.handlers.
local_host_environment.CAPABILITY_ID`` exactly (a plain string match, not
a shared import — see that module's docstring); a regression test asserts
the two stay in agreement.
"""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Optional, Tuple

from chanakya.capability.model import ActionType
from chanakya.capability.schema import find_open_schema_violations
from chanakya.contracts.enums import Classification, ModelEgress, RiskCategory
from chanakya.registry.models import (
    ApprovalRequirement,
    OSPrivilege,
    Provenance,
    RegistryEntry,
    RequiredPrivileges,
    ResourceLimits,
    Status,
    TargetAccess,
    TrustLevel,
)

#: Must equal chanakya.tools.handlers.local_host_environment.CAPABILITY_ID.
OBSERVE_LOCAL_HOST_ENVIRONMENT_CAPABILITY = "observe_local_host_environment"

#: Must equal chanakya.tools.handlers.listening_ports.CAPABILITY_ID.
LIST_LISTENING_PORTS_CAPABILITY = "list_listening_ports"

#: Phase 11: the observation keys LocalHostAdapter.collect_environment
#: emits (asserted against the adapter in tests). A new key must be added
#: here, or the capability's output is rejected by its envelope.
LOCAL_HOST_OBSERVATION_KEYS = (
    "os_name",
    "os_release",
    "os_version",
    "platform",
    "architecture",
    "hostname",
    "python_version",
    "cpu_count",
    "is_containerized",
)

#: Phase 11: ``chanakya.targets.environment.EnvironmentSource`` values
#: (asserted in tests).
ENVIRONMENT_SOURCE_VALUES = (
    "user_declared",
    "local_adapter",
    "cloud_api",
    "kubernetes_api",
    "repository_source",
    "tool_result",
)


def _utcnow_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def make_observe_local_host_environment_entry(*, now: Optional[str] = None) -> RegistryEntry:
    """The Phase 5.1 production capability: read-only (P1), no parameters,
    ``local_host``-only, backed by the already-hardened ``LocalHostAdapter``.
    See the approved Phase 5.1 Tool Layer design report §3 for the full
    derivation of every field below."""
    timestamp = now if now is not None else _utcnow_iso()
    return RegistryEntry(
        tool_id="local-host-environment-observer-v1",
        contract_version="1.0.0",
        registry_version="1.0.0",
        capability=OBSERVE_LOCAL_HOST_ENVIRONMENT_CAPABILITY,
        display_name="Observe Local Host Environment",
        tool_version="1.0.0",
        description=(
            "Collects coarse, non-sensitive OS/platform facts about the local "
            "host (os_name, os_release, platform, architecture, hostname, "
            "python_version, cpu_count, is_containerized) via the existing "
            "LocalHostAdapter. No subprocess, no network access, no "
            "environment-variable reads, no filesystem writes."
        ),
        category="host_information",
        action_type=ActionType.OBSERVE,
        operations=("collect_environment",),
        parameters_schema={"type": "object", "properties": {}, "required": [], "additionalProperties": False},
        # Phase 11 (D-2): closed. Describes exactly what
        # LocalHostEnvironmentHandler returns: the fixed LocalHostAdapter
        # observation keys, each with a string/integer/boolean/null value.
        output_schema={
            "type": "object",
            "properties": {
                "environment_context_id": {"type": "string"},
                "target_id": {"type": "string"},
                "collected_by": {"type": "string"},
                "collected_at": {"type": "string"},
                "source": {"type": "string", "enum": list(ENVIRONMENT_SOURCE_VALUES)},
                "observations": {
                    "type": "array",
                    "items": {
                        "type": "object",
                        "properties": {
                            "key": {"type": "string", "enum": list(LOCAL_HOST_OBSERVATION_KEYS)},
                            "value": {"type": ["string", "integer", "boolean", "null"]},
                            "confidence": {"type": ["string", "null"], "enum": ["low", "medium", "high", None]},
                            "notes": {"type": ["string", "null"]},
                        },
                        "required": ["key", "value", "confidence", "notes"],
                        "additionalProperties": False,
                    },
                },
            },
            "required": [
                "environment_context_id",
                "target_id",
                "collected_by",
                "collected_at",
                "source",
                "observations",
            ],
            "additionalProperties": False,
        },
        default_risk_category=RiskCategory.INFORMATIONAL,
        classification=Classification.READ_ONLY,
        required_privileges=RequiredPrivileges(
            os_privilege=OSPrivilege.STANDARD_USER, target_access=TargetAccess.TARGET_READ
        ),
        supported_target_types=("local_host",),
        default_timeout_seconds=10,
        resource_limits=ResourceLimits(
            max_output_bytes=65536, max_cpu_seconds=5, max_memory_mb=64, max_concurrent_invocations=4
        ),
        approval_requirement=ApprovalRequirement.NONE,
        provenance=Provenance(
            source_type="core",
            source_identifier="chanakya.tools.handlers.local_host_environment.LocalHostEnvironmentHandler",
            source_version="1.0.0",
            implementation_hash="phase-5.1",
            vetted_by="phase-5.1-design-review",
            vetted_at=timestamp,
            self_declared_metadata={},
            review_notes=(
                "Phase 5.1 first production capability. Wraps the already-hardened, "
                "read-only LocalHostAdapter with zero new subprocess/network/credential "
                "surface. See the approved Phase 5.1 Tool Layer design report."
            ),
        ),
        trust_level=TrustLevel.FIRST_PARTY_ADAPTER,
        status=Status.ENABLED,
        created_at=timestamp,
        updated_at=timestamp,
        owner="chanakya-core",
        # Phase 15: coarse platform facts may be shown to the model.
        model_egress=ModelEgress.ALLOWED,
    )


def make_list_listening_ports_entry(*, now: Optional[str] = None) -> RegistryEntry:
    """Phase 8 production capability: read-only (P1), no parameters,
    ``local_host``-only. Shape follows docs/TOOL-REGISTRY.md's
    ``list_listening_ports`` example; ``max_output_bytes`` matches the
    handler's own ``MAX_OUTPUT_BYTES`` (below the Evidence Store's payload
    limit) instead of the example's 262144."""
    timestamp = now if now is not None else _utcnow_iso()
    return RegistryEntry(
        tool_id="local-host-listening-ports-v1",
        contract_version="1.0.0",
        registry_version="1.0.0",
        capability=LIST_LISTENING_PORTS_CAPABILITY,
        display_name="List Listening Ports",
        tool_version="1.0.0",
        description=(
            "Lists TCP and UDP ports listening on the local host, with the owning PID and "
            "executable base name where the OS reveals them. Reads the kernel socket tables "
            "(Linux /proc/net, Windows GetExtendedTcpTable/GetExtendedUdpTable). No subprocess, "
            "no network traffic, no process arguments or environment collected."
        ),
        category="network_information",
        action_type=ActionType.OBSERVE,
        operations=("read_network_state", "resolve_process_name"),
        parameters_schema={"type": "object", "properties": {}, "required": [], "additionalProperties": False},
        output_schema={
            "type": "object",
            "properties": {
                "ports": {
                    "type": "array",
                    "items": {
                        "type": "object",
                        "properties": {
                            "protocol": {"type": "string", "enum": ["tcp", "udp"]},
                            "port": {"type": "integer", "minimum": 1},
                            "local_address": {"type": "string"},
                            "pid": {"type": "integer", "minimum": 0},
                            "process": {"type": "string"},
                        },
                        "required": ["protocol", "port", "local_address"],
                        "additionalProperties": False,
                    },
                }
            },
            "required": ["ports"],
            "additionalProperties": False,
        },
        default_risk_category=RiskCategory.INFORMATIONAL,
        classification=Classification.READ_ONLY,
        required_privileges=RequiredPrivileges(
            os_privilege=OSPrivilege.STANDARD_USER, target_access=TargetAccess.TARGET_READ
        ),
        supported_target_types=("local_host",),
        default_timeout_seconds=15,
        resource_limits=ResourceLimits(
            max_output_bytes=60000, max_cpu_seconds=5, max_memory_mb=128, max_concurrent_invocations=4
        ),
        approval_requirement=ApprovalRequirement.NONE,
        provenance=Provenance(
            source_type="core",
            source_identifier="chanakya.tools.handlers.listening_ports.ListeningPortsHandler",
            source_version="1.0.0",
            implementation_hash="phase-8",
            vetted_by="phase-8-design-review",
            vetted_at=timestamp,
            self_declared_metadata={},
            review_notes=(
                "Phase 8. Stdlib-only reads of the kernel socket tables; strict parsers; output "
                "bounded and never truncated. No subprocess, shell, network traffic, process "
                "arguments or environment."
            ),
        ),
        trust_level=TrustLevel.FIRST_PARTY_ADAPTER,
        status=Status.ENABLED,
        created_at=timestamp,
        updated_at=timestamp,
        owner="chanakya-core",
        # Phase 15: listening sockets may be shown to the model.
        model_egress=ModelEgress.ALLOWED,
    )


def production_registry_entries(*, now: Optional[str] = None) -> Tuple[RegistryEntry, ...]:
    """Every production capability, for a composition root to register.
    Must stay in step with ``chanakya.tools.bootstrap.build_tool_executor``.

    Phase 11 (D-2): every production output schema must be closed
    (``find_open_schema_violations``); an open one fails here, at
    composition, before anything can run under it."""
    entries = (make_observe_local_host_environment_entry(now=now), make_list_listening_ports_entry(now=now))
    for entry in entries:
        if find_open_schema_violations(entry.output_schema):
            raise ValueError(f"production capability {entry.capability!r} does not declare a closed output schema")
    return entries
