"""Phase 4.5 — Target Identity & Lifecycle (docs/TARGET-MANAGER.md §3-§7).

Covers: stable identity across revisions, valid/invalid lifecycle
transitions (fail-closed), replacement by ID, deterministic Gateway
lookup after replacement, locator validation and credential rejection,
provenance timestamp semantics (F-3), provenance/environment data never
affecting authorization, TargetManager never producing a PolicyDecision,
and InvestigationContext's unchanged id-only target reference.
"""
from __future__ import annotations

import inspect

import pytest

from chanakya.contracts.enums import Classification
from chanakya.contracts.target import (
    Target,
    TargetLocator,
    TargetProvenance,
    TargetProvenanceSource,
    TargetStatus,
)
from chanakya.policy.gateway import EvaluationContext, PolicyGateway
from chanakya.registry.registry import SecurityToolRegistry
from chanakya.targets.exceptions import InvalidTargetStatusTransitionError, UnregisteredTargetError
from chanakya.targets.manager import TargetManager
from chanakya.targets.registry import TargetRegistry

from factories import make_request, now


def make_target(target_id: str = "target-lifecycle-01", **overrides) -> Target:
    fields = dict(
        target_id=target_id,
        contract_version="1.0.0",
        target_type="local_host",
        display_name="Lifecycle test host",
        authorized_scope="This machine only, read-only capabilities",
        registered_at=now(),
    )
    fields.update(overrides)
    return Target(**fields)


# -- 1. Stable target identity -------------------------------------------------


def test_target_id_is_immutable_across_lifecycle_transitions():
    registry = TargetRegistry()
    manager = TargetManager(registry)
    manager.register(make_target())

    updated = manager.transition_status("target-lifecycle-01", TargetStatus.UNAVAILABLE, actor="admin")

    assert updated.target_id == "target-lifecycle-01"
    assert manager.get("target-lifecycle-01").target_id == "target-lifecycle-01"


def test_transition_changes_only_status_and_never_identity_fields():
    registry = TargetRegistry()
    manager = TargetManager(registry)
    original = make_target(
        display_name="Original name",
        authorized_scope="Original scope",
        metadata={"os": "windows"},
        owner_contact="krish",
    )
    manager.register(original)

    updated = manager.transition_status("target-lifecycle-01", TargetStatus.UNAVAILABLE, actor="admin")

    assert updated.target_type == original.target_type
    assert updated.display_name == original.display_name
    assert updated.authorized_scope == original.authorized_scope
    assert updated.metadata == original.metadata
    assert updated.owner_contact == original.owner_contact
    assert updated.registered_at == original.registered_at


def test_replace_rejects_target_type_drift_under_same_id():
    """docs/TARGET-MANAGER.md §4: target_type is identity, not mutable
    state — TargetRegistry.replace() independently guards this regardless
    of caller intent (defense in depth)."""
    registry = TargetRegistry([make_target(target_type="local_host")])
    drifted = make_target(target_type="container", status=TargetStatus.UNAVAILABLE)
    with pytest.raises(ValueError):
        registry.replace(drifted)


# -- 2 & 3. Valid / invalid lifecycle transitions (fail closed) ---------------


#: The shortest known-valid walk from a registration entry point
#: (DISCOVERED or AUTHORIZED) to each state, used to reach `start` in the
#: parametrized tests below without duplicating the transition table.
_PATH_TO_STATE = {
    TargetStatus.DISCOVERED: [TargetStatus.DISCOVERED],
    TargetStatus.VALIDATED: [TargetStatus.DISCOVERED, TargetStatus.VALIDATED],
    TargetStatus.AUTHORIZED: [TargetStatus.AUTHORIZED],
    TargetStatus.UNAVAILABLE: [TargetStatus.AUTHORIZED, TargetStatus.UNAVAILABLE],
    TargetStatus.REVOKED: [TargetStatus.AUTHORIZED, TargetStatus.REVOKED],
}


def _manager_at_state(target_status: TargetStatus) -> TargetManager:
    path = _PATH_TO_STATE[target_status]
    registry = TargetRegistry()
    manager = TargetManager(registry)
    manager.register(make_target(status=path[0]))
    for step in path[1:]:
        manager.transition_status("target-lifecycle-01", step, actor="admin")
    return manager


@pytest.mark.parametrize(
    "start,end",
    [
        (TargetStatus.DISCOVERED, TargetStatus.VALIDATED),
        (TargetStatus.DISCOVERED, TargetStatus.ARCHIVED),
        (TargetStatus.VALIDATED, TargetStatus.AUTHORIZED),
        (TargetStatus.VALIDATED, TargetStatus.ARCHIVED),
        (TargetStatus.AUTHORIZED, TargetStatus.UNAVAILABLE),
        (TargetStatus.AUTHORIZED, TargetStatus.REVOKED),
        (TargetStatus.UNAVAILABLE, TargetStatus.AUTHORIZED),
        (TargetStatus.UNAVAILABLE, TargetStatus.REVOKED),
        (TargetStatus.REVOKED, TargetStatus.AUTHORIZED),
        (TargetStatus.REVOKED, TargetStatus.ARCHIVED),
    ],
)
def test_valid_transitions_succeed(start, end):
    manager = _manager_at_state(start)
    updated = manager.transition_status("target-lifecycle-01", end, actor="admin")
    assert updated.status == end


@pytest.mark.parametrize(
    "start,end",
    [
        (TargetStatus.DISCOVERED, TargetStatus.AUTHORIZED),  # must pass through VALIDATED
        (TargetStatus.DISCOVERED, TargetStatus.UNAVAILABLE),
        (TargetStatus.DISCOVERED, TargetStatus.REVOKED),
        (TargetStatus.AUTHORIZED, TargetStatus.DISCOVERED),  # nothing transitions back to DISCOVERED
        (TargetStatus.AUTHORIZED, TargetStatus.VALIDATED),
        (TargetStatus.AUTHORIZED, TargetStatus.ARCHIVED),  # must pass through REVOKED
    ],
)
def test_invalid_transitions_fail_closed(start, end):
    registry = TargetRegistry()
    manager = TargetManager(registry)
    manager.register(make_target(status=start))

    with pytest.raises(InvalidTargetStatusTransitionError):
        manager.transition_status("target-lifecycle-01", end, actor="admin")

    # Fail-closed: the stored record is unchanged after a rejected transition.
    assert manager.get("target-lifecycle-01").status == start


def test_archived_is_terminal():
    registry = TargetRegistry()
    manager = TargetManager(registry)
    manager.register(make_target(status=TargetStatus.DISCOVERED))
    manager.transition_status("target-lifecycle-01", TargetStatus.ARCHIVED, actor="admin")

    for candidate in TargetStatus:
        with pytest.raises(InvalidTargetStatusTransitionError):
            manager.transition_status("target-lifecycle-01", candidate, actor="admin")


def test_registration_rejects_invalid_initial_status():
    registry = TargetRegistry()
    manager = TargetManager(registry)
    with pytest.raises(InvalidTargetStatusTransitionError):
        manager.register(make_target(status=TargetStatus.REVOKED))


def test_transition_on_unregistered_target_fails_closed():
    registry = TargetRegistry()
    manager = TargetManager(registry)
    with pytest.raises(UnregisteredTargetError):
        manager.transition_status("target-does-not-exist", TargetStatus.REVOKED, actor="admin")


def test_transition_requires_a_non_empty_actor():
    registry = TargetRegistry()
    manager = TargetManager(registry)
    manager.register(make_target())
    with pytest.raises(ValueError):
        manager.transition_status("target-lifecycle-01", TargetStatus.UNAVAILABLE, actor="")


def test_only_verifying_transitions_update_last_verified_at():
    registry = TargetRegistry()
    manager = TargetManager(registry)
    manager.register(make_target(status=TargetStatus.DISCOVERED))
    assert manager.get("target-lifecycle-01").last_verified_at is None

    validated = manager.transition_status("target-lifecycle-01", TargetStatus.VALIDATED, actor="adapter")
    assert validated.last_verified_at is not None

    authorized = manager.transition_status("target-lifecycle-01", TargetStatus.AUTHORIZED, actor="admin")
    # VALIDATED -> AUTHORIZED is not a "verifying transition" per §12 — the
    # timestamp from the prior step is preserved, not cleared, but also not
    # freshly re-stamped by this specific transition.
    assert authorized.last_verified_at == validated.last_verified_at


# -- 4. Target replacement by ID -----------------------------------------------


def test_replace_requires_the_target_id_to_already_exist():
    registry = TargetRegistry()
    with pytest.raises(ValueError):
        registry.replace(make_target())


def test_replace_swaps_the_stored_revision():
    registry = TargetRegistry([make_target(status=TargetStatus.AUTHORIZED)])
    revised = make_target(status=TargetStatus.UNAVAILABLE)
    registry.replace(revised)
    assert registry.get("target-lifecycle-01").status == TargetStatus.UNAVAILABLE


# -- 5. Deterministic Gateway lookup after replacement -------------------------


def test_gateway_sees_the_replaced_revision_with_zero_gateway_changes(list_listening_ports_entry, empty_policy_set):
    registry = TargetRegistry([make_target(status=TargetStatus.AUTHORIZED)])
    manager = TargetManager(registry)
    tool_registry = SecurityToolRegistry([list_listening_ports_entry])
    gateway = PolicyGateway(tool_registry, registry, empty_policy_set)

    request = make_request("list_listening_ports", "target-lifecycle-01")
    context = EvaluationContext(authorized_target_refs=frozenset({"target-lifecycle-01"}))

    before = gateway.evaluate(request, context)
    assert before.verdict.value == "allow"

    manager.transition_status("target-lifecycle-01", TargetStatus.UNAVAILABLE, actor="adapter")

    after = gateway.evaluate(request, context)
    assert after.verdict.value == "deny"
    assert after.matched_rule == "out-of-scope-target"


def test_revoked_target_is_denied_by_the_gateway(list_listening_ports_entry, empty_policy_set):
    registry = TargetRegistry([make_target(status=TargetStatus.AUTHORIZED)])
    manager = TargetManager(registry)
    tool_registry = SecurityToolRegistry([list_listening_ports_entry])
    gateway = PolicyGateway(tool_registry, registry, empty_policy_set)
    manager.transition_status("target-lifecycle-01", TargetStatus.REVOKED, actor="admin")

    request = make_request("list_listening_ports", "target-lifecycle-01")
    context = EvaluationContext(authorized_target_refs=frozenset({"target-lifecycle-01"}))
    decision = gateway.evaluate(request, context)

    assert decision.verdict.value == "deny"
    assert decision.matched_rule == "out-of-scope-target"


def test_reauthorized_target_is_allowed_again(list_listening_ports_entry, empty_policy_set):
    registry = TargetRegistry([make_target(status=TargetStatus.AUTHORIZED)])
    manager = TargetManager(registry)
    tool_registry = SecurityToolRegistry([list_listening_ports_entry])
    gateway = PolicyGateway(tool_registry, registry, empty_policy_set)
    manager.transition_status("target-lifecycle-01", TargetStatus.REVOKED, actor="admin")
    manager.transition_status("target-lifecycle-01", TargetStatus.AUTHORIZED, actor="admin")

    request = make_request("list_listening_ports", "target-lifecycle-01")
    context = EvaluationContext(authorized_target_refs=frozenset({"target-lifecycle-01"}))
    decision = gateway.evaluate(request, context)

    assert decision.verdict.value == "allow"


# -- 6 & 7. Locator validation and credential rejection ------------------------


def test_valid_locator_is_accepted():
    locator = TargetLocator(locator_type="hostname", value="workstation.local")
    target = make_target(locator=locator)
    assert target.locator.value == "workstation.local"


def test_locator_rejects_empty_type_or_value():
    with pytest.raises(ValueError):
        TargetLocator(locator_type="", value="workstation.local")
    with pytest.raises(ValueError):
        TargetLocator(locator_type="hostname", value="")


@pytest.mark.parametrize(
    "value",
    [
        "https://admin:hunter2@internal-host/api",
        "ftp://user:s3cr3t@10.0.0.5/",
        "https://host/path?password=hunter2",
        "https://host/path?api_key=abc123",
        "https://host/path?token=eyJhbGciOi",
        "https://host/path?client_secret=xyz",
        "https://host/path?access_key=AKIAIOSFODNN7",
    ],
)
def test_locator_rejects_credential_shaped_values(value):
    with pytest.raises(ValueError):
        TargetLocator(locator_type="url", value=value)


def test_locator_does_not_falsely_reject_ordinary_urls():
    TargetLocator(locator_type="url", value="https://internal-host.example.com:8443/api/v1/status")
    TargetLocator(locator_type="repository_uri", value="https://git.example.com/org/repo.git")
    TargetLocator(locator_type="ip_address", value="10.0.0.5")


def test_locator_never_appears_in_gateway_decision_inputs():
    """docs/TARGET-MANAGER.md §13/§14: locator is never Gateway-consulted
    for authorization in this phase — only status/target_type/
    authorized_scope are read."""
    source = inspect.getsource(PolicyGateway._evaluate)
    assert "locator" not in source.lower()


# -- 8. Provenance timestamp semantics (F-3) -----------------------------------


def test_registered_at_never_changes_across_revisions():
    registry = TargetRegistry()
    manager = TargetManager(registry)
    original = make_target(registered_at="2026-01-01T00:00:00Z")
    manager.register(original)

    updated = manager.transition_status("target-lifecycle-01", TargetStatus.UNAVAILABLE, actor="adapter")
    assert updated.registered_at == "2026-01-01T00:00:00Z"


def test_provenance_observed_at_is_a_field_independent_of_registered_at():
    """F-3: the two fields may coincide at creation time for a
    user_declared target, but they are independently settable — changing
    one has no effect on the other."""
    provenance = TargetProvenance(
        source=TargetProvenanceSource.USER_DECLARED,
        registered_by="krish",
        observed_at="2026-02-15T00:00:00Z",  # deliberately different from registered_at
    )
    target = make_target(registered_at="2026-01-01T00:00:00Z", provenance=provenance)
    assert target.registered_at == "2026-01-01T00:00:00Z"
    assert target.provenance.observed_at == "2026-02-15T00:00:00Z"
    assert target.registered_at != target.provenance.observed_at


def test_provenance_observed_at_not_touched_by_lifecycle_transitions():
    """Resolves F-3: last_verified_at (not provenance.observed_at) is the
    field that advances with lifecycle checks."""
    provenance = TargetProvenance(
        source=TargetProvenanceSource.USER_DECLARED,
        registered_by="krish",
        observed_at="2026-01-01T00:00:00Z",
    )
    registry = TargetRegistry()
    manager = TargetManager(registry)
    manager.register(make_target(status=TargetStatus.DISCOVERED, provenance=provenance))

    updated = manager.transition_status("target-lifecycle-01", TargetStatus.VALIDATED, actor="adapter")

    assert updated.provenance.observed_at == "2026-01-01T00:00:00Z"
    assert updated.last_verified_at is not None
    assert updated.last_verified_at != updated.provenance.observed_at


def test_provenance_rejects_empty_fields():
    with pytest.raises(ValueError):
        TargetProvenance(source=TargetProvenanceSource.USER_DECLARED, registered_by="", observed_at=now())
    with pytest.raises(ValueError):
        TargetProvenance(source=TargetProvenanceSource.USER_DECLARED, registered_by="krish", observed_at="")


# -- 9. Provenance cannot affect authorization ----------------------------------


def test_provenance_never_referenced_by_gateway_evaluation():
    source = inspect.getsource(PolicyGateway._evaluate)
    assert "provenance" not in source.lower()


def test_adapter_discovered_provenance_target_evaluated_identically_to_user_declared(
    list_listening_ports_entry, empty_policy_set
):
    """A target's provenance.source must never change the Gateway's
    verdict — only status/target_type/authorized_scope/registration do."""
    user_declared = TargetProvenance(
        source=TargetProvenanceSource.USER_DECLARED, registered_by="krish", observed_at=now()
    )
    adapter_discovered = TargetProvenance(
        source=TargetProvenanceSource.ADAPTER_DISCOVERED, registered_by="system", observed_at=now()
    )

    registry_a = TargetRegistry([make_target(target_id="target-a", provenance=user_declared)])
    registry_b = TargetRegistry([make_target(target_id="target-a", provenance=adapter_discovered)])

    tool_registry_a = SecurityToolRegistry([list_listening_ports_entry])
    tool_registry_b = SecurityToolRegistry([list_listening_ports_entry])
    gateway_a = PolicyGateway(tool_registry_a, registry_a, empty_policy_set)
    gateway_b = PolicyGateway(tool_registry_b, registry_b, empty_policy_set)

    request = make_request("list_listening_ports", "target-a")
    context = EvaluationContext(authorized_target_refs=frozenset({"target-a"}))

    decision_a = gateway_a.evaluate(request, context)
    decision_b = gateway_b.evaluate(request, context)

    assert decision_a.verdict == decision_b.verdict
    assert decision_a.matched_rule == decision_b.matched_rule


# -- 10. TargetManager cannot produce a PolicyDecision (lifecycle surface) -----


def test_transition_status_return_type_is_a_target_not_a_decision():
    registry = TargetRegistry()
    manager = TargetManager(registry)
    manager.register(make_target())
    result = manager.transition_status("target-lifecycle-01", TargetStatus.UNAVAILABLE, actor="admin")
    assert isinstance(result, Target)
    assert not hasattr(result, "verdict")
    assert not hasattr(result, "matched_rule")


def test_target_manager_module_still_imports_nothing_policy_or_runtime_shaped():
    import ast
    import chanakya.targets.manager as manager_module

    tree = ast.parse(inspect.getsource(manager_module))
    imported = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom) and node.module:
            imported.add(node.module)
        elif isinstance(node, ast.Import):
            for alias in node.names:
                imported.add(alias.name)
    for module_name in imported:
        assert not module_name.startswith("chanakya.policy")
        assert not module_name.startswith("chanakya.runtime")


# -- 11. InvestigationContext still references target by ID --------------------


def test_investigation_context_target_refs_unaffected_by_lifecycle_changes(
    investigation_manager, investigation_request, target_registry
):
    context = investigation_manager.create_investigation(investigation_request)
    assert context.target_refs == ("target-local-host-01",)
    assert all(isinstance(ref, str) for ref in context.target_refs)

    # A lifecycle transition via a TargetManager composing the SAME
    # TargetRegistry instance InvestigationManager was constructed with
    # (the `target_registry` fixture) never touches InvestigationContext —
    # it still only holds the id, never a status or any other Target field.
    manager = TargetManager(target_registry)
    manager.transition_status("target-local-host-01", TargetStatus.UNAVAILABLE, actor="admin")

    assert context.target_refs == ("target-local-host-01",)
    # InvestigationContext has its own, unrelated `status` (investigation
    # lifecycle) — it must never gain a target-specific field.
    assert not hasattr(context, "target_status")
    assert not any(hasattr(context, attr) for attr in ("locator", "provenance"))


# -- 12. Existing Phase 2/3 security tests: verified by running the full suite -
