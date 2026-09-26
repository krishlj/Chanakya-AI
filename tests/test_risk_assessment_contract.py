"""Phase 10 — RiskAssessment contract and risk taxonomy (10.1).

A. Taxonomy data            C. Rule-set consistency (severity, ceiling, confidence)
B. Field validation          D. Closed shape / authority keys / round trip
"""
from __future__ import annotations

import ast
import dataclasses
from pathlib import Path

import pytest

from chanakya.contracts.enums import RiskCategory
from chanakya.contracts.finding import MAX_EVIDENCE_REFS
from chanakya.contracts.risk_assessment import (
    MAX_RATIONALE_LENGTH,
    NotAssessedFinding,
    RiskAssessment,
    RiskAssessmentValidationError,
    RiskEngineResult,
    derive_risk_assessment_id,
)
from chanakya.contracts.risk_taxonomy import (
    ANY_CAPABILITY,
    RISK_CATEGORY_IDS,
    RISK_RULE_SET_V1,
    RISK_TAXONOMY_V1,
    RULE_IDS_V1,
    SEVERITY_ORDER,
)
from chanakya.registry.bootstrap import production_registry_entries

from risk_factories import AUTHORITY_KEYS, make_ra, ra_fields

_REPO_ROOT = Path(__file__).resolve().parent.parent

# ===========================================================================
# A. Taxonomy
# ===========================================================================


def test_taxonomy_is_exactly_the_approved_v1_table():
    table = {
        cat: (rule.base_severity, set(rule.compatible_capabilities)) for cat, rule in RISK_TAXONOMY_V1.items()
    }
    assert table == {
        "network_exposure": ("medium", {"list_listening_ports"}),
        "unexpected_listener": ("low", {"list_listening_ports"}),
        "service_inventory": ("informational", {"list_listening_ports"}),
        "platform_configuration": ("low", {"observe_local_host_environment"}),
        "unsupported_platform_version": ("medium", {"observe_local_host_environment"}),
        "observation": ("informational", {ANY_CAPABILITY}),
    }
    assert RISK_RULE_SET_V1 == "chanakya-risk-rules/1.0.0"
    assert RISK_CATEGORY_IDS == tuple(RISK_TAXONOMY_V1)


def test_taxonomy_is_immutable():
    with pytest.raises(TypeError):
        RISK_TAXONOMY_V1["network_exposure"] = None  # type: ignore[index]
    with pytest.raises(dataclasses.FrozenInstanceError):
        RISK_TAXONOMY_V1["network_exposure"].base_severity = "critical"  # type: ignore[misc]


def test_taxonomy_severities_match_the_risk_category_enum():
    assert SEVERITY_ORDER == tuple(c.value for c in RiskCategory)
    for rule in RISK_TAXONOMY_V1.values():
        RiskCategory(rule.base_severity)
        assert rule.base_severity != "critical"


def test_taxonomy_capabilities_are_registered_production_capabilities():
    registered = {entry.capability for entry in production_registry_entries(now="2026-09-26T00:00:00Z")}
    named = set().union(*(r.compatible_capabilities for r in RISK_TAXONOMY_V1.values())) - {ANY_CAPABILITY}
    assert named <= registered


def test_category_ids_fit_the_finding_category_pattern():
    import re

    assert all(re.fullmatch(r"[a-z0-9_]{1,64}", c) for c in RISK_CATEGORY_IDS)


def test_taxonomy_module_imports_nothing_from_chanakya():
    tree = ast.parse((_REPO_ROOT / "chanakya" / "contracts" / "risk_taxonomy.py").read_text(encoding="utf-8"))
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom):
            assert node.level == 0 and not (node.module or "").startswith("chanakya"), node.module
        elif isinstance(node, ast.Import):
            assert not any(a.name.startswith("chanakya") for a in node.names)


# ===========================================================================
# B. Field validation
# ===========================================================================


def test_valid_assessment_constructs():
    ra = make_ra()
    assert ra.finding_id == "find-1" and ra.assessed_by == "risk_engine"


def test_deterministic_id_is_stable_and_input_sensitive():
    a = derive_risk_assessment_id("inv-10", "find-1", RISK_RULE_SET_V1)
    assert a == derive_risk_assessment_id("inv-10", "find-1", RISK_RULE_SET_V1)
    assert a != derive_risk_assessment_id("inv-11", "find-1", RISK_RULE_SET_V1)
    assert a != derive_risk_assessment_id("inv-10", "find-2", RISK_RULE_SET_V1)
    assert a != derive_risk_assessment_id("inv-10", "find-1", "chanakya-risk-rules/2.0.0")


@pytest.mark.parametrize(
    "overrides",
    [
        {"risk_assessment_id": "not-derived"},
        {"risk_assessment_id": derive_risk_assessment_id("inv-other", "find-1", RISK_RULE_SET_V1)},
        {"contract_version": "2.0.0"},
        {"contract_version": ""},
        {"investigation_id": ""},
        {"investigation_id": 7},
        {"assessed_at": ""},
        {"assessed_by": "agent"},
        {"assessed_by": "Risk_Engine"},
        {"scoring_method": "chanakya-risk-rules/9.9.9"},
        {"scoring_method": "model"},
        {"finding_refs": ()},
        {"finding_refs": ("find-1", "find-2")},
        {"finding_refs": ["find-1"]},
        {"finding_refs": ("",)},
        {"evidence_refs": ()},
        {"evidence_refs": ["ev-1"]},
        {"evidence_refs": ("ev-1", "ev-1")},
        {"evidence_refs": tuple(f"ev-{i}" for i in range(MAX_EVIDENCE_REFS + 1))},
        {"severity": "medium"},
        {"confidence": "absolute"},
        {"confidence": None},
    ],
    ids=lambda o: next(iter(o)) + "=" + repr(next(iter(o.values())))[:30],
)
def test_invalid_fields_are_rejected(overrides):
    with pytest.raises(RiskAssessmentValidationError):
        make_ra(**overrides)


def test_error_messages_never_echo_values():
    with pytest.raises(RiskAssessmentValidationError) as info:
        make_ra(rationale="leaked password=hunter2")
    assert "hunter2" not in str(info.value)


# ===========================================================================
# C. Rule-set consistency
# ===========================================================================

_V = "evidence.verified"


@pytest.mark.parametrize(
    "overrides",
    [
        {"rule_ids": ()},
        {"rule_ids": ["evidence.verified"]},
        {"rule_ids": (_V, "category.network_exposure", "compat.all", "ceiling.read_only", "confidence.medium", "x.y")},
        {"rule_ids": (_V, "category.exposure", "compat.all", "ceiling.read_only", "confidence.medium")},
        {"rule_ids": (_V, "category.network_exposure", "compat.all", "approve.all", "confidence.medium")},
        {"rule_ids": ("category.network_exposure", _V, "compat.all", "ceiling.read_only", "confidence.medium")},
        {"rule_ids": (_V, "category.network_exposure", "compat.all", "confidence.medium", "ceiling.read_only")},
        {"rule_ids": (_V, "category.network_exposure", "compat.all", "ceiling.read_only", "confidence.high")},
        {"rule_ids": (_V, "category.network_exposure", "compat.partial", "ceiling.read_only", "confidence.medium"),
         "confidence": "medium"},
        {"rule_ids": (_V, "category.network_exposure", "compat.all", "ceiling.read_only", "confidence.low"),
         "confidence": "low"},
        {"rule_ids": (_V, "category.network_exposure", "compat.all", "compat.all", "confidence.medium")},
        {"rule_ids": (_V, "category.network_exposure", "compat.all", "ceiling.read_only", "confidence.medium",
                      "confidence.medium")},
    ],
    ids=["empty", "list", "unknown_extra", "unrated_category", "unknown_rule", "wrong_order", "ceiling_last",
         "confidence_rule_mismatch", "partial_but_medium", "all_but_low", "duplicate_compat", "duplicate_confidence"],
)
def test_rule_ids_must_have_the_rule_set_shape(overrides):
    with pytest.raises(RiskAssessmentValidationError):
        make_ra(**overrides)


@pytest.mark.parametrize("severity", [s for s in RiskCategory if s != RiskCategory.MEDIUM])
def test_severity_must_equal_the_category_base_severity(severity):
    with pytest.raises(RiskAssessmentValidationError):
        make_ra(severity=severity)


def test_critical_is_unreachable_under_v1_for_every_category_and_rule_shape():
    for category in RISK_TAXONOMY_V1:
        for ceiling in (True, False):
            rules = (_V, f"category.{category}", "compat.all") + (("ceiling.read_only",) if ceiling else ()) + (
                "confidence.medium",
            )
            with pytest.raises(RiskAssessmentValidationError):
                make_ra(rule_ids=rules, severity=RiskCategory.CRITICAL)


@pytest.mark.parametrize("category", list(RISK_TAXONOMY_V1))
def test_each_category_accepts_exactly_its_base_severity(category):
    base = RiskCategory(RISK_TAXONOMY_V1[category].base_severity)
    rules = (_V, f"category.{category}", "compat.all", "ceiling.read_only", "confidence.high")
    assert make_ra(rule_ids=rules, severity=base, confidence="high").severity == base


def test_state_changing_shape_without_ceiling_is_accepted_at_base_severity():
    rules = (_V, "category.network_exposure", "compat.partial", "confidence.low")
    assert make_ra(rule_ids=rules, confidence="low").severity == RiskCategory.MEDIUM


def test_rule_vocabulary_is_closed():
    assert "category.network_exposure" in RULE_IDS_V1 and len(RULE_IDS_V1) == 7 + len(RISK_TAXONOMY_V1)


@pytest.mark.parametrize(
    "rationale",
    [
        "",
        "   ",
        "x" * (MAX_RATIONALE_LENGTH + 1),
        "two\nparagraphs",
        "tab\there",
        "escape \x1b[31m",
        "token: abc123",
        "see https://user:pw@host/",
        "-----BEGIN RSA PRIVATE KEY-----",
        None,
    ],
    ids=["empty", "blank", "too_long", "newline", "tab", "ansi", "credential", "userinfo", "pem", "none"],
)
def test_rationale_is_one_bounded_clean_line(rationale):
    with pytest.raises(RiskAssessmentValidationError):
        make_ra(rationale=rationale)


def test_rationale_at_the_limit_is_accepted():
    assert len(make_ra(rationale="x" * MAX_RATIONALE_LENGTH).rationale) == MAX_RATIONALE_LENGTH


# ===========================================================================
# D. Closed shape
# ===========================================================================


def test_round_trip():
    ra = make_ra()
    assert RiskAssessment.from_dict(ra.to_dict()) == ra
    assert ra.to_dict()["severity"] == "medium"


@pytest.mark.parametrize("key", AUTHORITY_KEYS)
def test_authority_shaped_keys_are_rejected(key):
    data = dict(make_ra().to_dict(), **{key: True})
    with pytest.raises(RiskAssessmentValidationError):
        RiskAssessment.from_dict(data)


def test_contract_has_no_authority_shaped_fields():
    names = {f.name for f in dataclasses.fields(RiskAssessment)}
    assert not names & set(AUTHORITY_KEYS)


@pytest.mark.parametrize("missing", ["rationale", "rule_ids", "evidence_refs", "assessed_by", "scoring_method"])
def test_missing_keys_are_rejected(missing):
    data = make_ra().to_dict()
    del data[missing]
    with pytest.raises(RiskAssessmentValidationError):
        RiskAssessment.from_dict(data)


@pytest.mark.parametrize(
    "mutate",
    [
        lambda d: d.update(severity="critical"),
        lambda d: d.update(severity="catastrophic"),
        lambda d: d.update(severity=3),
        lambda d: d.update(finding_refs="find-1"),
        lambda d: d.update(evidence_refs=("ev-1",)),
        lambda d: d.update(rule_ids="evidence.verified"),
        lambda d: d.update(scoring_method="chanakya-risk-rules/2.0.0"),
        lambda d: d.update(assessed_by="agent"),
    ],
    ids=["critical", "bad_enum", "int_severity", "refs_str", "refs_tuple", "rules_str", "unknown_method", "agent"],
)
def test_from_dict_rejects_wrong_shapes(mutate):
    data = make_ra().to_dict()
    mutate(data)
    with pytest.raises(RiskAssessmentValidationError):
        RiskAssessment.from_dict(data)


@pytest.mark.parametrize("value", [None, [], "x", 1])
def test_from_dict_rejects_non_mappings(value):
    with pytest.raises(RiskAssessmentValidationError):
        RiskAssessment.from_dict(value)


def test_assessment_is_frozen():
    with pytest.raises(dataclasses.FrozenInstanceError):
        make_ra().severity = RiskCategory.CRITICAL  # type: ignore[misc]


def test_not_assessed_and_result_validation():
    v1 = RISK_RULE_SET_V1
    assert NotAssessedFinding("f", "category_unrated", v1).reason == "category_unrated"
    for bad in [("", "category_unrated", v1), ("f", "safe", v1), ("f", None, v1), ("f", "category_unrated", "risk_v999"),
                ("f", "category_unrated", None)]:
        with pytest.raises(RiskAssessmentValidationError):
            NotAssessedFinding(*bad)
    RiskEngineResult(assessments=(make_ra(),), not_assessed=(), scoring_method=v1)
    for bad in [([make_ra()], (), v1), ((make_ra().to_dict(),), (), v1), ((), ["x"], v1), ((), (), "risk_v999"),
                ((), (), None)]:
        with pytest.raises(RiskAssessmentValidationError):
            RiskEngineResult(*bad)


def test_fields_helper_is_valid():
    assert RiskAssessment(**ra_fields()) == make_ra()
