"""Test-only factories for building contract objects, Registry entries,
Policy rules, and raw ToolRequest payloads with sensible defaults.

Not part of the ``chanakya`` package itself — these exist purely to keep
the test modules focused on what each test is actually asserting.
"""
from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Any, Mapping, Optional, Sequence

from chanakya.capability.model import ActionType
from chanakya.contracts.enums import Classification, ModelEgress, RiskCategory, Verdict
from chanakya.policy.rules import PolicyRule, RuleConditions, RuleMatch
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


def now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def make_provenance(**overrides: Any) -> Provenance:
    base = dict(
        source_type="core",
        source_identifier="chanakya.tools.test",
        source_version="1.0.0",
        implementation_hash="sha256:test-fixture",
        vetted_by="test-admin",
        vetted_at=now(),
        self_declared_metadata={},
        review_notes="fixture entry for unit tests",
    )
    base.update(overrides)
    return Provenance(**base)


def make_entry(
    capability: str,
    *,
    classification: Classification,
    action_type: ActionType,
    category: str = "network_information",
    status: Status = Status.ENABLED,
    approval_requirement: ApprovalRequirement = ApprovalRequirement.NONE,
    default_risk_category: RiskCategory = RiskCategory.INFORMATIONAL,
    os_privilege: OSPrivilege = OSPrivilege.STANDARD_USER,
    target_access: TargetAccess = TargetAccess.TARGET_READ,
    supported_target_types: Sequence[str] = ("local_host",),
    parameters_schema: Optional[Mapping[str, Any]] = None,
    **overrides: Any,
) -> RegistryEntry:
    fields: dict = dict(
        tool_id=str(uuid.uuid4()),
        contract_version="1.0.0",
        registry_version="1.0.0",
        capability=capability,
        display_name=capability.replace("_", " ").title(),
        tool_version="1.0.0",
        description=f"Test fixture capability: {capability}",
        category=category,
        action_type=action_type,
        operations=[capability],
        parameters_schema=(
            parameters_schema
            if parameters_schema is not None
            else {"type": "object", "properties": {}, "required": [], "additionalProperties": False}
        ),
        output_schema={"type": "object", "properties": {}},
        default_risk_category=default_risk_category,
        classification=classification,
        required_privileges=RequiredPrivileges(os_privilege=os_privilege, target_access=target_access),
        supported_target_types=list(supported_target_types),
        default_timeout_seconds=15,
        resource_limits=ResourceLimits(
            max_output_bytes=65536, max_cpu_seconds=5, max_memory_mb=128, max_concurrent_invocations=4
        ),
        approval_requirement=approval_requirement,
        provenance=make_provenance(),
        trust_level=TrustLevel.CORE,
        status=status,
        created_at=now(),
        updated_at=now(),
        owner="test-admin",
        model_egress=ModelEgress.ALLOWED,  # Phase 15: always declared
    )
    fields.update(overrides)
    return RegistryEntry(**fields)


def make_request(capability: str, target_ref: str, parameters: Optional[Mapping[str, Any]] = None, **overrides: Any) -> dict:
    base = {
        "tool_request_id": str(uuid.uuid4()),
        "contract_version": "1.0.0",
        "investigation_id": "inv-test-1",
        "step_id": "step-1",
        "capability": capability,
        "target_ref": target_ref,
        "parameters": parameters if parameters is not None else {},
        "proposed_by": "agent",
        "proposed_at": now(),
    }
    base.update(overrides)
    return base


def make_rule(
    rule_id: str,
    *,
    effect: Verdict,
    capability: Optional[Sequence[str]] = None,
    target_type: Any = "*",
    target_id: Optional[Sequence[str]] = None,
    classification: Optional[Classification] = None,
    category: Optional[str] = None,
    action_type: Optional[ActionType] = None,
    priority: int = 10,
    max_calls: Optional[int] = None,
    reason_template: str = "capability '{capability}' matched test rule",
) -> PolicyRule:
    return PolicyRule(
        rule_id=rule_id,
        contract_version="1.0.0",
        policy_set_version="1.0.0",
        description=f"test rule: {rule_id}",
        enabled=True,
        priority=priority,
        match=RuleMatch(
            capability=capability if capability is not None else "*",
            target_type=target_type,
            target_id=target_id,
            classification=classification,
            category=category,
            action_type=action_type,
        ),
        effect=effect,
        reason_template=reason_template,
        created_at=now(),
        updated_at=now(),
        owner="test-admin",
        conditions=RuleConditions(max_calls_per_investigation=max_calls),
    )
