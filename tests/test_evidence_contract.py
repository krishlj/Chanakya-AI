"""Phase 5.2.1 — the Evidence contract (chanakya.contracts.evidence) and
the additive, optional PolicyDecision.classification field.

No Evidence Store exists yet (deliberately, per Phase 5.2.1's scope) —
these are pure contract-level tests: construction, validation,
immutability, and PolicyDecision backward compatibility. Mirrors the
style of tests/test_local_host_adapter.py and tests/test_dispatch_boundary.py
for a single-contract test module.
"""
from __future__ import annotations

import dataclasses
from datetime import datetime, timezone

import pytest

from chanakya.contracts.enums import Classification, Verdict
from chanakya.contracts.evidence import Evidence
from chanakya.contracts.policy_decision import PolicyDecision


def now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def make_evidence(**overrides) -> Evidence:
    fields = dict(
        evidence_id="ev-001",
        contract_version="1.0.0",
        investigation_id="inv-8b2e0a77",
        step_id="step-1",
        tool_request_id="tr-001",
        tool_result_id="res-001",
        target_id="target-local-host-01",
        capability="observe_local_host_environment",
        recorded_at=now(),
        content_hash="sha256:9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08",
        storage_ref="evidence/inv-8b2e0a77/step-1/res-001.json",
        classification=Classification.READ_ONLY,
    )
    fields.update(overrides)
    return Evidence(**fields)


def make_policy_decision(**overrides) -> PolicyDecision:
    fields = dict(
        policy_decision_id="pd-1",
        contract_version="1.0.0",
        tool_request_id="tr-1",
        verdict=Verdict.ALLOW,
        matched_rule="test-rule",
        reason="test",
        evaluated_at=now(),
    )
    fields.update(overrides)
    return PolicyDecision(**fields)


_REQUIRED_STRING_FIELDS = (
    "evidence_id",
    "contract_version",
    "investigation_id",
    "step_id",
    "tool_request_id",
    "tool_result_id",
    "target_id",
    "capability",
    "recorded_at",
    "content_hash",
    "storage_ref",
)


# ===========================================================================
# Evidence — valid construction
# ===========================================================================


def test_valid_construction_matches_docs_contracts_example():
    """docs/CONTRACTS.md §7's own worked example, field-for-field."""
    evidence = Evidence(
        evidence_id="ev-001",
        contract_version="1.0.0",
        investigation_id="inv-8b2e0a77",
        step_id="step-1",
        tool_request_id="tr-001",
        tool_result_id="res-001",
        target_id="target-local-host-01",
        capability="list_listening_ports",
        recorded_at="2026-09-13T18:01:02.200Z",
        content_hash="sha256:9f86d081...",
        storage_ref="evidence/inv-8b2e0a77/step-1/res-001.json",
        classification=Classification.READ_ONLY,
    )
    assert evidence.evidence_id == "ev-001"
    assert evidence.classification == Classification.READ_ONLY
    assert evidence.tags == ()
    assert evidence.redactions_applied is None


def test_valid_construction_via_factory():
    evidence = make_evidence()
    assert evidence.capability == "observe_local_host_environment"


def test_state_changing_classification_is_valid():
    evidence = make_evidence(classification=Classification.STATE_CHANGING)
    assert evidence.classification == Classification.STATE_CHANGING


# ===========================================================================
# Evidence — required-field validation
# ===========================================================================


@pytest.mark.parametrize("field_name", _REQUIRED_STRING_FIELDS)
def test_missing_required_string_field_is_rejected_when_empty(field_name):
    with pytest.raises(ValueError, match=field_name):
        make_evidence(**{field_name: ""})


@pytest.mark.parametrize("field_name", _REQUIRED_STRING_FIELDS)
def test_required_string_field_rejects_non_string_type(field_name):
    with pytest.raises(ValueError, match=field_name):
        make_evidence(**{field_name: 12345})


def test_classification_field_is_required_at_construction():
    """No default is provided — omitting it entirely is a TypeError from
    the dataclass constructor itself, not a ValueError from validation."""
    with pytest.raises(TypeError):
        Evidence(
            evidence_id="ev-001",
            contract_version="1.0.0",
            investigation_id="inv-1",
            step_id="step-1",
            tool_request_id="tr-1",
            tool_result_id="res-1",
            target_id="target-1",
            capability="cap",
            recorded_at=now(),
            content_hash="sha256:abc",
            storage_ref="evidence/inv-1/step-1/res-1.json",
        )


# ===========================================================================
# Evidence — invalid types
# ===========================================================================


def test_classification_rejects_a_plain_string_not_the_enum():
    with pytest.raises(ValueError, match="classification"):
        make_evidence(classification="read_only")  # must be Classification.READ_ONLY, not the raw string


def test_unsupported_contract_version_is_rejected():
    with pytest.raises(ValueError, match="contract_version"):
        make_evidence(contract_version="9.9.9")


def test_tags_rejects_non_sequence():
    with pytest.raises(ValueError, match="tags"):
        make_evidence(tags="not-a-sequence-of-strings")


def test_tags_rejects_non_string_elements():
    with pytest.raises(ValueError, match="tags"):
        make_evidence(tags=[1, 2, 3])


def test_redactions_applied_rejects_non_boolean():
    with pytest.raises(ValueError, match="redactions_applied"):
        make_evidence(redactions_applied="yes")


# ===========================================================================
# Evidence — immutability
# ===========================================================================


def test_evidence_is_frozen():
    evidence = make_evidence()
    with pytest.raises(dataclasses.FrozenInstanceError):
        evidence.content_hash = "sha256:tampered"


def test_evidence_exposes_no_mutation_method():
    """No update()/delete()/set_*() exists anywhere on the contract object
    itself — append-only is enforced by the type having no such method,
    not merely by convention (docs/CONTRACTS.md §7)."""
    evidence = make_evidence()
    forbidden = ("update", "delete", "set_content_hash", "set_storage_ref", "replace", "overwrite")
    for name in forbidden:
        assert not hasattr(evidence, name)


# ===========================================================================
# Evidence — optional fields
# ===========================================================================


def test_tags_defaults_to_empty_tuple():
    evidence = make_evidence()
    assert evidence.tags == ()


def test_tags_can_be_set():
    evidence = make_evidence(tags=("misconfiguration", "network"))
    assert evidence.tags == ("misconfiguration", "network")


def test_redactions_applied_defaults_to_none():
    evidence = make_evidence()
    assert evidence.redactions_applied is None


def test_redactions_applied_can_be_true_or_false():
    assert make_evidence(redactions_applied=True).redactions_applied is True
    assert make_evidence(redactions_applied=False).redactions_applied is False


# ===========================================================================
# Evidence — no payload/content field, no credential-shaped field
# ===========================================================================


def test_evidence_has_no_payload_or_content_field():
    """storage_ref is a pointer only — the actual tool-output payload is
    never embedded in Evidence itself (docs/CONTRACTS.md §7)."""
    field_names = {f.name for f in dataclasses.fields(Evidence)}
    assert "content" not in field_names
    assert "payload" not in field_names
    assert "output" not in field_names


def test_evidence_has_no_credential_shaped_field():
    field_names = {f.name for f in dataclasses.fields(Evidence)}
    assert not any(
        marker in name.lower() for name in field_names for marker in ("credential", "secret", "password", "token")
    )


# ===========================================================================
# PolicyDecision — classification field / backward compatibility
# ===========================================================================


def test_existing_policy_decision_construction_without_classification_still_works():
    """Every pre-existing construction call site across the codebase
    (e.g. tests/factories.py, chanakya/policy/gateway.py) omits
    `classification` entirely — this must keep working unchanged."""
    decision = PolicyDecision(
        policy_decision_id="pd-1",
        contract_version="1.0.0",
        tool_request_id="tr-1",
        verdict=Verdict.ALLOW,
        matched_rule="test-rule",
        reason="test",
        evaluated_at=now(),
    )
    assert decision.classification is None


def test_policy_decision_classification_defaults_to_none():
    decision = make_policy_decision()
    assert decision.classification is None


def test_policy_decision_classification_can_be_set():
    decision = make_policy_decision(classification=Classification.READ_ONLY)
    assert decision.classification == Classification.READ_ONLY


def test_policy_decision_to_dict_omits_classification_when_unset():
    decision = make_policy_decision()
    assert "classification" not in decision.to_dict()


def test_policy_decision_to_dict_includes_classification_when_set():
    decision = make_policy_decision(classification=Classification.STATE_CHANGING)
    assert decision.to_dict()["classification"] == "state_changing"


def test_policy_decision_is_still_frozen():
    decision = make_policy_decision()
    with pytest.raises(dataclasses.FrozenInstanceError):
        decision.classification = Classification.READ_ONLY


def test_policy_gateway_decide_now_sets_classification_deny_still_does_not():
    """Superseded by Phase 5.2.3 (this test originally asserted the
    opposite, back when the field existed but nothing populated it yet —
    see the approved Phase 5.2.1 design). `_decide` now populates
    `classification` from the same `entry` already resolved to produce
    the verdict (no second Registry lookup); `_deny` still does not,
    because it never receives `entry` and a DENY never produces Evidence
    that would need it. Full behavioral coverage (ALLOW/REQUIRE_APPROVAL/
    DENY against a real Gateway) lives in tests/test_gateway.py; this is
    the narrower static-source confirmation."""
    import inspect

    from chanakya.policy.gateway import PolicyGateway

    decide_source = inspect.getsource(PolicyGateway._decide)
    deny_source = inspect.getsource(PolicyGateway._deny)
    assert "classification=" in decide_source
    assert "classification=" not in deny_source
