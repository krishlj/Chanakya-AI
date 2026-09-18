from __future__ import annotations

import sys
from datetime import datetime, timezone
from pathlib import Path

# Ensure the repo root (containing the `chanakya` package and this `tests`
# helper module) is importable regardless of how pytest is invoked.
_REPO_ROOT = Path(__file__).resolve().parent.parent
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

import pytest

from chanakya.capability.model import ActionType
from chanakya.contracts.enums import Classification, RiskCategory
from chanakya.contracts.investigation_request import InvestigationRequest
from chanakya.contracts.target import Target
from chanakya.policy.gateway import EvaluationContext, PolicyGateway
from chanakya.policy.rules import PolicySet
from chanakya.registry.models import ApprovalRequirement, OSPrivilege, Status, TargetAccess
from chanakya.registry.registry import SecurityToolRegistry
from chanakya.runtime.investigation_manager import InvestigationManager
from chanakya.runtime.limits import RuntimeExecutionLimits
from chanakya.runtime.resource_governor import ResourceGovernor
from chanakya.targets.registry import TargetRegistry

from factories import make_entry, now


@pytest.fixture
def list_listening_ports_entry():
    """Read-only, unrestricted (P1) — docs/CONTRACTS.md §3's own example capability."""
    return make_entry(
        "list_listening_ports",
        classification=Classification.READ_ONLY,
        action_type=ActionType.OBSERVE,
        category="network_information",
    )


@pytest.fixture
def terminate_process_entry():
    """State-changing, supervised (P3) — docs/CONTRACTS.md §11's own example capability."""
    return make_entry(
        "terminate_process",
        classification=Classification.STATE_CHANGING,
        action_type=ActionType.MUTATE,
        category="process_information",
        default_risk_category=RiskCategory.HIGH,
        target_access=TargetAccess.TARGET_WRITE,
        parameters_schema={
            "type": "object",
            "properties": {"pid": {"type": "integer", "minimum": 1}},
            "required": ["pid"],
            "additionalProperties": False,
        },
    )


@pytest.fixture
def dump_env_vars_entry():
    """Read-only but Registry-flagged sensitive (P2) — docs/TOOL-REGISTRY.md §3 example."""
    return make_entry(
        "dump_environment_variables",
        classification=Classification.READ_ONLY,
        action_type=ActionType.OBSERVE,
        category="host_information",
        approval_requirement=ApprovalRequirement.REQUIRED,
        default_risk_category=RiskCategory.MEDIUM,
    )


@pytest.fixture
def disabled_entry():
    """Registered but disabled — must be denied identically to an unknown capability."""
    return make_entry(
        "legacy_scan",
        classification=Classification.READ_ONLY,
        action_type=ActionType.OBSERVE,
        category="network_scanning",
        status=Status.DISABLED,
    )


@pytest.fixture
def elevated_entry():
    """Read-only, but requires elevated OS privilege the test deployment doesn't have."""
    return make_entry(
        "read_protected_security_log",
        classification=Classification.READ_ONLY,
        action_type=ActionType.OBSERVE,
        category="log_observation",
        os_privilege=OSPrivilege.ELEVATED,
    )


@pytest.fixture
def local_host_target():
    return Target(
        target_id="target-local-host-01",
        contract_version="1.0.0",
        target_type="local_host",
        display_name="Primary workstation",
        authorized_scope="This machine only, read-only capabilities",
        registered_at=now(),
    )


@pytest.fixture
def registry(list_listening_ports_entry, terminate_process_entry, dump_env_vars_entry, disabled_entry, elevated_entry):
    return SecurityToolRegistry(
        [list_listening_ports_entry, terminate_process_entry, dump_env_vars_entry, disabled_entry, elevated_entry]
    )


@pytest.fixture
def target_registry(local_host_target):
    return TargetRegistry([local_host_target])


@pytest.fixture
def empty_policy_set():
    return PolicySet(policy_set_version="1.0.0", rules=[])


@pytest.fixture
def gateway(registry, target_registry, empty_policy_set):
    return PolicyGateway(registry, target_registry, empty_policy_set)


@pytest.fixture
def authorized_context():
    return EvaluationContext(authorized_target_refs=frozenset({"target-local-host-01"}))


# -- Phase 3 (Agent Runtime) fixtures ---------------------------------------


@pytest.fixture
def runtime_limits():
    """Generous but finite limits — every ceiling is a small, deliberately
    low number so tests can actually exercise "limit exceeded" behavior
    without looping hundreds of times (docs/AGENT-RUNTIME.md §18)."""
    return RuntimeExecutionLimits(
        config_version="1.0.0",
        max_steps_per_investigation=5,
        max_tool_calls_per_investigation=5,
        max_investigation_duration_seconds=3600,
        default_step_timeout_seconds=15,
        max_retries_per_step=2,
        retry_backoff_seconds=1,
        max_concurrent_investigations=5,
    )


@pytest.fixture
def resource_governor(runtime_limits):
    return ResourceGovernor(runtime_limits, clock=lambda: datetime.now(timezone.utc))


@pytest.fixture
def investigation_manager(target_registry, resource_governor):
    return InvestigationManager(target_registry, resource_governor)


@pytest.fixture
def investigation_manager_factory(target_registry, resource_governor):
    """For tests that need an InvestigationManager wired to a specific
    (e.g. shared) AuditEmitter — the plain ``investigation_manager``
    fixture above always uses the default no-op sink."""

    def _make(**overrides):
        return InvestigationManager(target_registry, resource_governor, **overrides)

    return _make


@pytest.fixture
def investigation_request():
    return InvestigationRequest.from_dict(
        {
            "investigation_request_id": "inv-req-test-1",
            "contract_version": "1.0.0",
            "objective": "Assess this machine for common local misconfigurations",
            "requested_targets": ["target-local-host-01"],
            "submitted_by": "test-human",
            "submitted_at": now(),
        }
    )
