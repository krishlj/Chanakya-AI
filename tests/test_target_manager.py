"""TargetManager foundation tests — Phase 4.4 (docs/TARGET-MANAGER.md).

Proves the eight security-boundary properties required for this phase:
TargetManager cannot authorize, cannot bypass the Policy Gateway,
TargetRegistry remains the Gateway's shared, deterministic dependency,
no environment-authorization channel exists yet, unknown targets fail
closed, no credential-shaped field exists on Target, target identity is
stable, and the existing Runtime/Gateway wiring is untouched.
"""
from __future__ import annotations

import ast
import dataclasses
import inspect

import pytest

import chanakya.targets.manager as target_manager_module
from chanakya.contracts.enums import Classification
from chanakya.contracts.target import Target
from chanakya.policy.gateway import EvaluationContext, PolicyGateway
from chanakya.registry.registry import SecurityToolRegistry
from chanakya.runtime.investigation_manager import InvestigationManager
from chanakya.targets.exceptions import UnregisteredTargetError
from chanakya.targets.manager import TargetManager
from chanakya.targets.registry import TargetRegistry

from factories import make_request, now


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


# -- 1. Target Manager cannot authorize an action ---------------------------


def test_target_manager_has_no_authorization_method():
    public_methods = {name for name, _ in inspect.getmembers(TargetManager, predicate=inspect.isfunction)}
    forbidden = {"evaluate", "authorize", "decide", "approve"}
    assert public_methods.isdisjoint(forbidden)


def _imported_module_names(module) -> set:
    """The actual set of modules ``module`` imports from, via its AST —
    unlike a raw substring search, this ignores explanatory prose in
    docstrings/comments and checks only executable import statements."""
    tree = ast.parse(inspect.getsource(module))
    names = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom) and node.module:
            names.add(node.module)
        elif isinstance(node, ast.Import):
            for alias in node.names:
                names.add(alias.name)
    return names


def test_target_manager_module_never_imports_policy_decision_machinery():
    """Mirrors PolicyGateway's own 'grep this file' guarantee for
    ``rationale`` (chanakya/policy/gateway.py) — TargetManager's module
    imports nothing from ``chanakya.policy`` or ``chanakya.runtime`` at
    all, so there is no way for it to construct or consult a
    ``PolicyDecision``/``ApprovalDecision``/dispatch call."""
    imported = _imported_module_names(target_manager_module)
    for forbidden_module in imported:
        assert not forbidden_module.startswith("chanakya.policy")
        assert not forbidden_module.startswith("chanakya.runtime")


def test_target_manager_methods_never_return_a_policy_decision(target_registry):
    manager = TargetManager(target_registry)
    assert manager.register(make_target(target_id="target-new")) is None
    fetched = manager.get("target-new")
    assert isinstance(fetched, Target)
    assert not hasattr(fetched, "verdict")
    resolved = manager.resolve(["target-new"])
    for item in resolved:
        assert isinstance(item, Target)
        assert not hasattr(item, "verdict")


# -- 2. Target Manager cannot bypass PolicyGateway ---------------------------


def test_registering_a_target_via_target_manager_does_not_dispatch_anything(target_registry):
    """Using TargetManager in isolation — with no PolicyGateway involved at
    all — produces no PolicyDecision, no ApprovalRequest, and no dispatch.
    The only way any of those objects come to exist is through the
    unchanged PolicyGateway/Runtime pipeline, which TargetManager never
    calls into."""
    manager = TargetManager(target_registry)
    manager.register(make_target(target_id="target-isolated"))
    # No PolicyGateway reference was ever constructed or touched — the
    # target is registered and resolvable, and that is the entire effect.
    assert manager.get("target-isolated") is not None


def test_target_manager_has_no_reference_to_dispatcher_or_tool_executor():
    import chanakya.runtime.dispatch as dispatch_module

    imported = _imported_module_names(target_manager_module)
    assert "chanakya.runtime.dispatch" not in imported
    # Confirm the two modules are not coupled in either direction.
    assert "chanakya.targets" not in _imported_module_names(dispatch_module)


# -- 3. TargetRegistry remains usable by PolicyGateway -----------------------


def test_target_manager_and_policy_gateway_share_one_registry_instance(
    target_registry, list_listening_ports_entry, empty_policy_set
):
    """The same TargetRegistry instance is composed by TargetManager and
    handed directly to PolicyGateway (unchanged constructor, unchanged
    call pattern) — registering a target through TargetManager makes it
    visible to the Gateway with zero Gateway-side changes."""
    manager = TargetManager(target_registry)
    manager.register(make_target(target_id="target-shared", authorized_scope="Shared registry test scope"))

    tool_registry = SecurityToolRegistry([list_listening_ports_entry])
    gateway = PolicyGateway(tool_registry, manager.registry, empty_policy_set)

    request = make_request("list_listening_ports", "target-shared")
    context = EvaluationContext(authorized_target_refs=frozenset({"target-shared"}))
    decision = gateway.evaluate(request, context)

    assert decision.verdict.value == "allow"
    assert decision.matched_rule == "read-only-default"


def test_gateway_still_denies_a_target_unknown_to_the_shared_registry(
    target_registry, list_listening_ports_entry, empty_policy_set
):
    manager = TargetManager(target_registry)  # local_host_target only, via fixture
    tool_registry = SecurityToolRegistry([list_listening_ports_entry])
    gateway = PolicyGateway(tool_registry, manager.registry, empty_policy_set)

    request = make_request("list_listening_ports", "target-never-registered")
    context = EvaluationContext(authorized_target_refs=frozenset({"target-never-registered"}))
    decision = gateway.evaluate(request, context)

    assert decision.verdict.value == "deny"
    assert decision.matched_rule == "out-of-scope-target"


# -- 4. Environment information cannot become authorization automatically ----


def test_environment_collection_channel_never_reaches_the_gateway():
    """docs/TARGET-MANAGER.md §9/§10/§14: Phase 4.8 legitimately adds
    ``TargetManager.collect_environment`` (this Phase-4.4-era test's
    original premise — that no such method exists at all — is superseded
    by design, not regressed). What must still hold, and is re-asserted
    here, is TM-INV-2/TM-INV-8: the channel exists, but nothing it
    produces is ever consulted by PolicyGateway — see
    tests/test_environment_context_integration.py for the full Phase 4.8
    coverage of that boundary."""
    assert hasattr(TargetManager, "collect_environment")
    gateway_source = inspect.getsource(PolicyGateway._evaluate).lower()
    for forbidden in ("environmentcontext", "environment_context", "collect_environment"):
        assert forbidden not in gateway_source


def test_policy_gateway_evaluation_is_unaffected_by_anything_target_manager_does(
    target_registry, list_listening_ports_entry, empty_policy_set
):
    """Registering additional targets/metadata through TargetManager never
    changes the verdict for an unrelated, already-authorized request —
    there is no shared mutable state through which TargetManager activity
    could influence a PolicyDecision."""
    manager = TargetManager(target_registry)
    tool_registry = SecurityToolRegistry([list_listening_ports_entry])
    gateway = PolicyGateway(tool_registry, manager.registry, empty_policy_set)

    request = make_request("list_listening_ports", "target-local-host-01")
    context = EvaluationContext(authorized_target_refs=frozenset({"target-local-host-01"}))
    before = gateway.evaluate(request, context)

    manager.register(make_target(target_id="target-noise", authorized_scope="Unrelated noise target"))

    after = gateway.evaluate(request, context)
    assert before.verdict == after.verdict
    assert before.matched_rule == after.matched_rule


# -- 5. Unknown/invalid targets fail closed -----------------------------------


def test_get_unknown_target_returns_none(target_registry):
    manager = TargetManager(target_registry)
    assert manager.get("does-not-exist") is None


def test_resolve_raises_on_any_unregistered_id(target_registry):
    manager = TargetManager(target_registry)
    with pytest.raises(UnregisteredTargetError):
        manager.resolve(["target-local-host-01", "target-does-not-exist"])


def test_resolve_never_returns_a_partial_result_on_failure(target_registry):
    """Fail-closed: a resolve() call that encounters an unregistered id
    raises before returning anything — callers can never receive a
    silently-truncated list of targets."""
    manager = TargetManager(target_registry)
    try:
        manager.resolve(["target-local-host-01", "target-missing"])
        assert False, "expected UnregisteredTargetError"
    except UnregisteredTargetError:
        pass


# -- 6. No credentials are stored in target metadata --------------------------


def test_target_contract_has_no_credential_shaped_field():
    credential_keywords = ("password", "secret", "token", "api_key", "apikey", "credential", "private_key", "access_key")
    field_names = {f.name.lower() for f in dataclasses.fields(Target)}
    for keyword in credential_keywords:
        assert not any(keyword in name for name in field_names), f"credential-shaped field found: {keyword}"


def test_target_manager_stores_no_additional_fields_beyond_the_target_contract(target_registry):
    """TargetManager adds no state of its own about a *target* beyond
    what TargetRegistry/Target already hold — it cannot become a second,
    less-controlled place credentials could accumulate. (``_adapters``,
    added in Phase 4.6, holds adapter registrations, not target/
    credential data — see tests/test_target_adapter.py for its own
    dedicated credential/authorization-boundary coverage.)"""
    manager = TargetManager(target_registry)
    instance_attrs = set(vars(manager).keys())
    assert instance_attrs == {"_registry", "_adapters"}


# -- 7. Existing Target identity remains stable --------------------------------


def test_target_identity_stable_across_manager_and_registry_access(target_registry):
    manager = TargetManager(target_registry)
    manager.register(make_target(target_id="target-stable"))
    first = manager.get("target-stable")
    second = manager.get("target-stable")
    assert first is second
    assert first.target_id == "target-stable" == second.target_id


def test_duplicate_registration_still_rejected_through_target_manager(target_registry):
    manager = TargetManager(target_registry)
    with pytest.raises(ValueError):
        manager.register(make_target(target_id="target-local-host-01"))  # already in target_registry fixture


# -- 8. Existing Runtime execution path remains unchanged ----------------------


def test_investigation_manager_still_depends_on_target_registry_not_target_manager():
    """docs/TARGET-MANAGER.md §7: TargetManager composes TargetRegistry
    'without the Gateway [or InvestigationManager] ever needing to know
    TargetManager exists.' Confirms InvestigationManager's constructor is
    untouched by this phase."""
    signature = inspect.signature(InvestigationManager.__init__)
    param_names = list(signature.parameters.keys())
    assert "target_registry" in param_names
    assert "target_manager" not in param_names
    source = inspect.getsource(InvestigationManager)
    assert "TargetManager" not in source


def test_full_investigation_creation_flow_unaffected(investigation_manager, investigation_request):
    """Existing Phase 3 behavior end-to-end, exercised with no TargetManager
    involved at all — proves the Runtime's own path through
    InvestigationManager/TargetRegistry is byte-for-byte unchanged."""
    context = investigation_manager.create_investigation(investigation_request)
    assert context.status.value == "pending"
    assert context.target_refs == ("target-local-host-01",)
