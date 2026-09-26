"""Phase 13 — versioned risk rule sets.

A. Golden v1 equivalence (RV-INV-3)
B. Registry and the one active rule set (RV-INV-4, RV-INV-5, RV-INV-6)
C. Provenance on every result (RV-INV-1)
D. Runtime: exactly the active rule set, no downgrade (RV-INV-4, RV-INV-6)
E. Recomputation under the recorded rule set (RV-INV-2): provenance verifier and Review
F. Provider vocabulary follows the active rule set
G. Untrusted inputs cannot select a rule set (RV-INV-5)

The second rule set used here exists only in this file (``TEST_RULE_SET``);
it is registered only inside the ``registered`` context manager.
"""
from __future__ import annotations

import ast
import dataclasses
import io
import json
import os
from contextlib import contextmanager
from pathlib import Path
from types import MappingProxyType

import pytest

import chanakya.cli.main as cli_main
import chanakya.contracts.risk_taxonomy as taxonomy
from chanakya.contracts.enums import Classification, RiskCategory
from chanakya.contracts.finding import Finding
from chanakya.contracts.investigation_context import InvestigationStatus
from chanakya.contracts.risk_assessment import (
    NotAssessedFinding,
    RiskAssessment,
    RiskAssessmentValidationError,
    RiskEngineResult,
)
from chanakya.contracts.risk_taxonomy import (
    RISK_RULE_SET_V1,
    RISK_RULE_SET_V1_DEFINITION,
    RISK_TAXONOMY_V1,
    RULE_IDS_V1,
    RiskCategoryRule,
    RiskRuleSet,
    RiskRuleSetError,
    active_rule_set,
    registered_scoring_methods,
    resolve_rule_set,
)
from chanakya.evidence import EvidenceStore
from chanakya.providers import mapping
from chanakya.risk import RiskEngine, RiskEngineError, StoreEvidenceFactsReader, verify_risk_provenance
from chanakya.risk.store import RiskAssessmentStore
from chanakya.runtime.agent_loop import TurnOutcome

from review_factories import Run, codes, finding, rewrite_events
from risk_factories import make_finding, put_evidence
from test_anthropic_provider import _config
from test_findings import assembled

_REPO_ROOT = Path(__file__).resolve().parent.parent
_CHANAKYA = _REPO_ROOT / "chanakya"
GOLDEN = json.loads((Path(__file__).parent / "fixtures" / "risk_v1_golden.json").read_text(encoding="utf-8"))
LLP, ENV = "list_listening_ports", "observe_local_host_environment"

#: Test-only. Deliberately differs from v1: platform_configuration is rated
#: "medium" (v1: "low") and there is a category v1 does not have.
_TEST_TAXONOMY = {
    "platform_configuration": RiskCategoryRule("platform_configuration", "medium", frozenset({ENV})),
    "test_only_category": RiskCategoryRule("test_only_category", "high", frozenset({LLP})),
}
TEST_RULE_SET = RiskRuleSet(
    scoring_method="test-only/risk-rules-9",
    taxonomy=_TEST_TAXONOMY,
    rule_ids=frozenset(
        {"evidence.verified", "compat.all", "compat.partial", "ceiling.read_only", "confidence.high",
         "confidence.medium", "confidence.low"}
        | {rule.rule_id for rule in _TEST_TAXONOMY.values()}
    ),
    read_only_severity_ceiling="high",
    max_severity="high",
)


@contextmanager
def registered(*rule_sets, active=None):
    """Registers test-only rule sets (and optionally makes one active) for
    the duration of a test, then restores the production registry."""
    saved = (taxonomy._RULE_SETS, taxonomy._ACTIVE_RULE_SET)
    taxonomy._RULE_SETS = MappingProxyType({**saved[0], **{r.scoring_method: r for r in rule_sets}})
    if active is not None:
        taxonomy._ACTIVE_RULE_SET = active
    try:
        yield
    finally:
        taxonomy._RULE_SETS, taxonomy._ACTIVE_RULE_SET = saved


# ===========================================================================
# A. Golden v1 equivalence (captured from the Phase 12 code before Phase 13)
# ===========================================================================

_GOLDEN_CASES = [
    ("f-netexp", "network_exposure", ["llp"]),
    ("f-netexp-2", "network_exposure", ["llp", "llp2"]),
    ("f-netexp-partial", "network_exposure", ["llp", "env"]),
    ("f-netexp-sc", "network_exposure", ["llp_sc"]),
    ("f-netexp-mixed", "network_exposure", ["llp", "llp_sc"]),
    ("f-unexp", "unexpected_listener", ["llp"]),
    ("f-svc", "service_inventory", ["llp"]),
    ("f-plat", "platform_configuration", ["env"]),
    ("f-unsup", "unsupported_platform_version", ["env", "llp"]),
    ("f-obs-high", "observation", ["llp", "env"]),
    ("f-obs-other", "observation", ["other"]),
    ("f-unrated", "exposure", ["llp"]),
    ("f-none", None, ["llp"]),
    ("f-incompat", "platform_configuration", ["llp"]),
]


def _golden_inputs(tmp_path):
    store = EvidenceStore(tmp_path / "evidence")
    inv = "inv-golden"
    ev = {
        "llp": put_evidence(store, inv, LLP, evidence_id="ev-llp"),
        "llp2": put_evidence(store, inv, LLP, evidence_id="ev-llp2"),
        "env": put_evidence(store, inv, ENV, evidence_id="ev-env"),
        "other": put_evidence(store, inv, "some_future_capability", evidence_id="ev-other"),
        "llp_sc": put_evidence(store, inv, LLP, evidence_id="ev-llp-sc", classification=Classification.STATE_CHANGING),
    }
    findings = [make_finding(finding_id=fid, investigation_id=inv, category=cat, evidence_refs=tuple(ev[r] for r in refs))
                for fid, cat, refs in _GOLDEN_CASES]
    return store, inv, findings


def test_v1_outputs_are_byte_identical_to_the_pre_phase_13_golden(tmp_path):
    """RV-INV-3: ids, severities, confidences, rule ids, rationales, evidence
    refs and not-assessed reasons are exactly what Phase 12 produced."""
    store, inv, findings = _golden_inputs(tmp_path)
    engine = RiskEngine(StoreEvidenceFactsReader(store), rule_set=active_rule_set())
    result = engine.assess(inv, findings, assessed_at="2026-01-01T00:00:00Z")
    assert [a.to_dict() for a in result.assessments] == GOLDEN["assessments"]
    assert [[n.finding_id, n.reason] for n in result.not_assessed] == GOLDEN["not_assessed"]
    assert json.dumps([a.to_dict() for a in result.assessments], sort_keys=True) == json.dumps(
        GOLDEN["assessments"], sort_keys=True)


def test_v1_taxonomy_severities_and_compatibility_are_frozen():
    assert {c: (r.base_severity, sorted(r.compatible_capabilities)) for c, r in RISK_TAXONOMY_V1.items()} == {
        "network_exposure": ("medium", [LLP]),
        "unexpected_listener": ("low", [LLP]),
        "service_inventory": ("informational", [LLP]),
        "platform_configuration": ("low", [ENV]),
        "unsupported_platform_version": ("medium", [ENV]),
        "observation": ("informational", ["*"]),
    }
    assert RISK_RULE_SET_V1 == "chanakya-risk-rules/1.0.0"
    assert RISK_RULE_SET_V1_DEFINITION.taxonomy == RISK_TAXONOMY_V1
    assert RISK_RULE_SET_V1_DEFINITION.rule_ids == RULE_IDS_V1
    assert RISK_RULE_SET_V1_DEFINITION.read_only_severity_ceiling == "high"
    assert RISK_RULE_SET_V1_DEFINITION.max_severity == "high"


def test_v1_golden_covers_every_branch():
    rules = {rid for a in GOLDEN["assessments"] for rid in a["rule_ids"]}
    assert {"compat.all", "compat.partial", "ceiling.read_only", "confidence.high", "confidence.medium",
            "confidence.low"} <= rules
    assert {a["finding_refs"][0] for a in GOLDEN["assessments"]} >= {"f-netexp-sc", "f-netexp-mixed"}  # no ceiling
    assert {reason for _, reason in GOLDEN["not_assessed"]} == {"category_unrated", "evidence_incompatible"}
    assert {c for c in RISK_TAXONOMY_V1} == {a["rule_ids"][1][len("category."):] for a in GOLDEN["assessments"]}


# ===========================================================================
# B. Registry and the one active rule set
# ===========================================================================


def test_production_registry_contains_v1_only_and_v1_is_active():
    assert registered_scoring_methods() == {RISK_RULE_SET_V1}
    assert resolve_rule_set(RISK_RULE_SET_V1) is RISK_RULE_SET_V1_DEFINITION
    assert active_rule_set() is RISK_RULE_SET_V1_DEFINITION


@pytest.mark.parametrize("name", ["risk_v999", "chanakya-risk-rules/2.0.0", "", None, 1, "CHANAKYA-RISK-RULES/1.0.0",
                                  TEST_RULE_SET.scoring_method])
def test_unknown_rule_sets_fail_closed_without_fallback(name):
    with pytest.raises(RiskRuleSetError):
        resolve_rule_set(name)


def test_test_only_rule_set_is_not_production_visible():
    assert TEST_RULE_SET.scoring_method not in registered_scoring_methods()
    for path in _CHANAKYA.rglob("*.py"):
        assert "test-only/risk-rules-9" not in path.read_text(encoding="utf-8"), path
    with pytest.raises(RiskEngineError):
        RiskEngine(StoreEvidenceFactsReader(EvidenceStore.__new__(EvidenceStore)), rule_set=TEST_RULE_SET)


def test_registry_and_rule_sets_are_immutable():
    with pytest.raises(TypeError):
        taxonomy._RULE_SETS["x"] = TEST_RULE_SET  # type: ignore[index]
    with pytest.raises(TypeError):
        RISK_RULE_SET_V1_DEFINITION.taxonomy["network_exposure"] = None  # type: ignore[index]
    with pytest.raises(dataclasses.FrozenInstanceError):
        RISK_RULE_SET_V1_DEFINITION.scoring_method = "other"  # type: ignore[misc]


@pytest.mark.parametrize(
    "changes",
    [
        {"scoring_method": ""},
        {"scoring_method": "Has Spaces"},
        {"taxonomy": {}},
        {"taxonomy": {"x": RiskCategoryRule("y", "low", frozenset({LLP}))}},
        {"taxonomy": {"x": RiskCategoryRule("x", "catastrophic", frozenset({LLP}))}},
        {"rule_ids": frozenset({"evidence.verified"})},
        {"read_only_severity_ceiling": "extreme"},
        {"max_severity": None},
    ],
    ids=["empty_id", "bad_id", "empty_taxonomy", "misnamed_rule", "bad_severity", "wrong_rule_ids", "bad_ceiling",
         "bad_max"],
)
def test_invalid_rule_set_definitions_fail_closed(changes):
    fields = dict(scoring_method="t", taxonomy=_TEST_TAXONOMY, rule_ids=TEST_RULE_SET.rule_ids,
                  read_only_severity_ceiling="high", max_severity="high")
    fields.update(changes)
    with pytest.raises(RiskRuleSetError):
        RiskRuleSet(**fields)


def test_engine_requires_a_registered_rule_set(tmp_path):
    reader = StoreEvidenceFactsReader(EvidenceStore(tmp_path))
    with pytest.raises(TypeError):
        RiskEngine(reader)  # no default rule set
    for bad in (None, RISK_RULE_SET_V1, [RISK_RULE_SET_V1_DEFINITION],
                dataclasses.replace(RISK_RULE_SET_V1_DEFINITION, max_severity="critical")):
        with pytest.raises(RiskEngineError):
            RiskEngine(reader, rule_set=bad)
    with pytest.raises(RiskEngineError):
        RiskEngine(reader, rule_set=RISK_RULE_SET_V1_DEFINITION).for_scoring_method("risk_v999")


def test_runtime_requires_exactly_one_registered_active_rule_set(tmp_path):
    run = Run(tmp_path)
    controller = run.runtime.controller
    base = dict(risk_assessor=controller._risk_assessor, risk_recorder=controller._risk_recorder)
    from chanakya.runtime.agent_loop import AgentLoopController

    args = (run.runtime.manager, controller._governor, controller._policy_evaluator, controller._executor)
    for bad in (None, (RISK_RULE_SET_V1_DEFINITION,), [RISK_RULE_SET_V1_DEFINITION], RISK_RULE_SET_V1, TEST_RULE_SET,
                dataclasses.replace(RISK_RULE_SET_V1_DEFINITION, max_severity="critical")):
        with pytest.raises(ValueError):
            AgentLoopController(*args, risk_rule_set=bad, **base)
    with pytest.raises(ValueError):
        AgentLoopController(*args, risk_rule_set=RISK_RULE_SET_V1_DEFINITION)  # rule set without an assessor
    assert controller._risk_rule_set is RISK_RULE_SET_V1_DEFINITION


# ===========================================================================
# C. Provenance on every result
# ===========================================================================


def test_every_engine_output_carries_its_scoring_method(tmp_path):
    """RV-INV-1."""
    store, inv, findings = _golden_inputs(tmp_path)
    result = RiskEngine(StoreEvidenceFactsReader(store), rule_set=active_rule_set()).assess(inv, findings, assessed_at="t")
    assert result.scoring_method == RISK_RULE_SET_V1
    assert {a.scoring_method for a in result.assessments} == {RISK_RULE_SET_V1}
    assert {n.scoring_method for n in result.not_assessed} == {RISK_RULE_SET_V1}


def test_results_cannot_mix_or_omit_rule_sets(tmp_path):
    with registered(TEST_RULE_SET):
        with pytest.raises(RiskAssessmentValidationError):
            RiskEngineResult(assessments=(), not_assessed=(NotAssessedFinding("f", "category_unrated", RISK_RULE_SET_V1),),
                             scoring_method=TEST_RULE_SET.scoring_method)
    with pytest.raises(TypeError):
        NotAssessedFinding("f", "category_unrated")  # provenance is required
    with pytest.raises(TypeError):
        RiskEngineResult(assessments=(), not_assessed=())


def test_provenance_survives_serialization_and_storage(tmp_path):
    store, inv, findings = _golden_inputs(tmp_path)
    result = RiskEngine(StoreEvidenceFactsReader(store), rule_set=active_rule_set()).assess(inv, findings, assessed_at="t")
    risk_store = RiskAssessmentStore(tmp_path / "risk")
    for assessment in result.assessments:
        assert RiskAssessment.from_dict(json.loads(json.dumps(assessment.to_dict()))).scoring_method == RISK_RULE_SET_V1
        risk_store.append(assessment)
    assert {a.scoring_method for a in risk_store.list_by_investigation(inv)} == {RISK_RULE_SET_V1}


def test_assessments_are_validated_under_the_rule_set_they_name(tmp_path):
    store = EvidenceStore(tmp_path)
    ev = put_evidence(store, "inv-t", ENV)
    finding_ = make_finding(investigation_id="inv-t", category="platform_configuration", evidence_refs=(ev,))
    with registered(TEST_RULE_SET):
        (ra,) = RiskEngine(StoreEvidenceFactsReader(store), rule_set=TEST_RULE_SET).assess(
            "inv-t", [finding_], assessed_at="t").assessments
        assert ra.severity == RiskCategory.MEDIUM and ra.scoring_method == TEST_RULE_SET.scoring_method
        # The same facts under v1's name are not a valid v1 record (v1 rates it low).
        with pytest.raises(RiskAssessmentValidationError):
            RiskAssessment.from_dict(dict(ra.to_dict(), scoring_method=RISK_RULE_SET_V1))
    with pytest.raises(RiskAssessmentValidationError):  # once unregistered, the record fails closed
        RiskAssessment.from_dict(ra.to_dict())


# ===========================================================================
# D. Runtime: exactly the active rule set, never a downgrade
# ===========================================================================


def _run_with_assessor(tmp_path, *, assessor_rule_set, active):
    run = Run(tmp_path).start()
    controller = run.runtime.controller
    controller._risk_assessor = RiskEngine(StoreEvidenceFactsReader(run.runtime.evidence_store), rule_set=assessor_rule_set)
    controller._risk_rule_set = active
    run.propose()
    return run, run.conclude(lambda ids: [finding(ids, category="platform_configuration")])


def test_runtime_rejects_results_from_a_rule_set_other_than_the_active_one(tmp_path):
    """Mandatory break 2: scoring-method mismatch."""
    with registered(TEST_RULE_SET):
        run, result = _run_with_assessor(tmp_path, assessor_rule_set=TEST_RULE_SET, active=RISK_RULE_SET_V1_DEFINITION)
    assert result.outcome == TurnOutcome.HALTED and run.context.error_state["reason"] == "risk_assessment_failed"
    assert run.runtime.risk_store.list_by_investigation(run.inv) == ()


def test_runtime_never_downgrades_to_v1(tmp_path):
    with registered(TEST_RULE_SET):
        run, result = _run_with_assessor(tmp_path, assessor_rule_set=RISK_RULE_SET_V1_DEFINITION, active=TEST_RULE_SET)
    assert result.outcome == TurnOutcome.HALTED and run.runtime.risk_store.list_by_investigation(run.inv) == ()


def test_runtime_stores_assessments_of_the_active_rule_set(tmp_path):
    with registered(TEST_RULE_SET, active=TEST_RULE_SET):
        run = Run(tmp_path).start()
        run.propose()
        assert run.conclude(lambda ids: [finding(ids, category="platform_configuration")]).outcome == TurnOutcome.CONCLUDED
        (ra,) = run.runtime.risk_store.list_by_investigation(run.inv)
        assert ra.scoring_method == TEST_RULE_SET.scoring_method and ra.severity == RiskCategory.MEDIUM
        (event,) = [e for e in run.events() if e.event_type.value == "risk_assessed"]
        assert event.details["scoring_method"] == TEST_RULE_SET.scoring_method


def test_runtime_rejects_a_tampered_not_assessed_rule_set(tmp_path):
    run = Run(tmp_path).start()
    controller = run.runtime.controller
    real = controller._risk_assessor

    class Relabel:
        def assess(self, investigation_id, findings, *, assessed_at):
            res = real.assess(investigation_id, findings, assessed_at=assessed_at)
            bad = tuple(dataclasses.replace(n) for n in res.not_assessed)
            for n in bad:
                object.__setattr__(n, "scoring_method", "risk_v999")
            fake = dataclasses.replace(res)
            object.__setattr__(fake, "not_assessed", bad)
            return fake

    controller._risk_assessor = Relabel()
    run.propose()
    result = run.conclude(lambda ids: [finding(ids, category="exposure")])
    assert result.outcome == TurnOutcome.HALTED


# ===========================================================================
# E. Recomputation under the recorded rule set
# ===========================================================================


def review_now(run):
    """Review as ``--review`` does: an engine bound to whichever rule set is
    active at review time, not the one the investigation ran under."""
    from chanakya.review import reconstruct_investigation

    rt = run.runtime
    engine = RiskEngine(StoreEvidenceFactsReader(rt.evidence_store), rule_set=active_rule_set())
    return reconstruct_investigation(run.inv, audit_log=rt.audit_log, evidence_store=rt.evidence_store,
                                     finding_store=rt.finding_store, risk_store=rt.risk_store, risk_engine=engine)


def _completed(tmp_path, category="platform_configuration"):
    run = Run(tmp_path).start()
    run.propose()
    run.conclude(lambda ids: [finding(ids, category=category)])
    return run


def test_review_recomputes_under_the_recorded_rule_set(tmp_path):
    """Mandatory break 3: an assessment made under another rule set verifies
    under that rule set, even while v1 is active."""
    with registered(TEST_RULE_SET, active=TEST_RULE_SET):
        run = _completed(tmp_path)
    with registered(TEST_RULE_SET):  # still resolvable, but v1 is active again
        assert active_rule_set() is RISK_RULE_SET_V1_DEFINITION
        review = review_now(run)
        assert review.consistent, codes(review)
        assert review.risk_assessments[0].scoring_method == TEST_RULE_SET.scoring_method
        assert review.risk_assessments[0].severity == "medium"
        code, shown = run.cli_review()  # the real --review path, v1 active
        assert code == cli_main.EXIT_COMPLETED and "consistency: consistent" in shown


def test_review_fails_closed_when_the_recorded_rule_set_is_unavailable(tmp_path):
    with registered(TEST_RULE_SET, active=TEST_RULE_SET):
        run = _completed(tmp_path)
    review = review_now(run)  # test rule set no longer registered: never substituted by v1
    assert "risk_store_unverifiable" in codes(review) and not review.consistent
    assert "risk_recomputation_mismatch" not in codes(review)


def test_review_flags_an_unknown_rule_set_named_in_the_audit(tmp_path):
    run = _completed(tmp_path)

    def relabel(events):
        for event in events:
            if event["event_type"] == "risk_assessed":
                event["details"]["scoring_method"] = "risk_v999"
        return events

    rewrite_events(run.stream_dir(), relabel)
    found = codes(run.review())
    assert "risk_audit_mismatch" in found and "risk_mixed_scoring_methods" in found


def test_historical_v1_assessments_are_never_reinterpreted(tmp_path):
    run = _completed(tmp_path)
    path = next((tmp_path / "risk").rglob("*.json"))
    before = path.read_bytes()
    with registered(TEST_RULE_SET, active=TEST_RULE_SET):
        review = review_now(run)  # reviewed while another rule set is active
        assert review.consistent, codes(review)
        assert review.risk_assessments[0].scoring_method == RISK_RULE_SET_V1
        assert review.risk_assessments[0].severity == "low"  # v1 meaning, not the test set's "medium"
        code, _ = run.cli_review()
        assert code == cli_main.EXIT_COMPLETED
    assert path.read_bytes() == before


def test_current_run_verifier_recomputes_under_the_recorded_set_and_flags_non_active(tmp_path):
    with registered(TEST_RULE_SET, active=TEST_RULE_SET):
        run = _completed(tmp_path)
    with registered(TEST_RULE_SET):
        engine = RiskEngine(StoreEvidenceFactsReader(run.runtime.evidence_store), rule_set=active_rule_set())
        report = verify_risk_provenance(run.inv, risk_store=run.runtime.risk_store,
                                        finding_store=run.runtime.finding_store, engine=engine)
        assert "scoring_method_not_active" in report.problems
        assert "recomputation_mismatch" not in report.problems  # recomputed under its own rule set


def test_v1_review_is_unchanged(tmp_path):
    review = _completed(tmp_path).review()
    assert review.consistent and review.risk_assessments[0].scoring_method == RISK_RULE_SET_V1


# ===========================================================================
# F. Provider vocabulary follows the active rule set
# ===========================================================================


def _provider_categories():
    kwargs = mapping.build_request_kwargs(assembled(), _config(findings_channel=True))
    (tool,) = kwargs["tools"]
    return tool["input_schema"]["properties"]["findings"]["items"]["properties"]["category"]["enum"]


def test_provider_vocabulary_is_v1_and_unchanged():
    assert _provider_categories() == GOLDEN["provider_enum"] == list(RISK_RULE_SET_V1_DEFINITION.category_ids)


def test_provider_vocabulary_follows_the_active_rule_set():
    """Mandatory break 5: a stale hard-coded list would not follow."""
    with registered(TEST_RULE_SET, active=TEST_RULE_SET):
        assert _provider_categories() == ["platform_configuration", "test_only_category"]
    assert _provider_categories() == list(RISK_RULE_SET_V1_DEFINITION.category_ids)


def test_provider_schema_template_is_never_mutated():
    _provider_categories()
    template = mapping._FINDING_TOOL_SCHEMA["properties"]["findings"]["items"]["properties"]["category"]
    assert template["enum"] == []


def test_model_cannot_invent_a_category_rating(tmp_path):
    run = Run(tmp_path).start()
    run.propose()
    run.conclude(lambda ids: [finding(ids, category="test_only_category")])
    assert run.context.status == InvestigationStatus.COMPLETED
    assert run.runtime.risk_store.list_by_investigation(run.inv) == ()  # not rateable under v1


# ===========================================================================
# G. Untrusted inputs cannot select a rule set
# ===========================================================================


def test_model_supplied_scoring_method_is_rejected(tmp_path):
    run = Run(tmp_path).start()
    run.propose()
    result = run.conclude(lambda ids: [finding(ids, scoring_method=TEST_RULE_SET.scoring_method)])
    assert result.outcome == TurnOutcome.MALFORMED_TURN
    assert run.runtime.risk_store.list_by_investigation(run.inv) == ()


def test_finding_tool_result_and_evidence_have_no_rule_set_field():
    from chanakya.contracts.evidence import Evidence
    from chanakya.contracts.tool_result import ToolResult

    for contract in (Finding, Evidence, ToolResult):
        assert "scoring_method" not in {f.name for f in dataclasses.fields(contract)}


def test_evidence_payload_cannot_select_a_rule_set(tmp_path):
    store = EvidenceStore(tmp_path)
    ev = put_evidence(store, "inv-p", ENV, payload={"output": {"scoring_method": TEST_RULE_SET.scoring_method}})
    finding_ = make_finding(investigation_id="inv-p", category="platform_configuration", evidence_refs=(ev,))
    with registered(TEST_RULE_SET):
        result = RiskEngine(StoreEvidenceFactsReader(store), rule_set=RISK_RULE_SET_V1_DEFINITION).assess(
            "inv-p", [finding_], assessed_at="t")
    assert result.scoring_method == RISK_RULE_SET_V1 and result.assessments[0].severity == RiskCategory.LOW


def test_cli_has_no_rule_set_option(tmp_path):
    options = {o for a in cli_main._parser()._actions for o in a.option_strings}
    assert not any("rule" in o or "scoring" in o or "risk" in o for o in options)
    with pytest.raises(SystemExit):
        cli_main._parser().parse_args(["objective", "--scoring-method", TEST_RULE_SET.scoring_method])


def test_environment_cannot_select_a_rule_set(tmp_path, monkeypatch):
    for name in ("CHANAKYA_RISK_RULE_SET", "CHANAKYA_SCORING_METHOD", "RISK_RULE_SET"):
        monkeypatch.setenv(name, TEST_RULE_SET.scoring_method)
    runtime = cli_main.build_runtime(tmp_path, approver="a", output=io.StringIO())
    assert runtime.risk_engine.scoring_method == RISK_RULE_SET_V1
    assert runtime.controller._risk_rule_set is RISK_RULE_SET_V1_DEFINITION


def test_rule_sets_are_never_loaded_from_files_environment_or_imports():
    source = (_CHANAKYA / "contracts" / "risk_taxonomy.py").read_text(encoding="utf-8")
    tree = ast.parse(source)
    imported = {n.module for n in ast.walk(tree) if isinstance(n, ast.ImportFrom)} | {
        a.name for n in ast.walk(tree) if isinstance(n, ast.Import) for a in n.names}
    assert imported <= {"__future__", "re", "dataclasses", "types", "typing"}
    for token in ("open(", "os.environ", "getenv", "import_module", "__import__", "json", "yaml", "eval(", "exec("):
        assert token not in source


def test_active_rule_set_is_chosen_only_by_trusted_composition():
    """Only the CLI composition root reads the active rule set to wire the
    Runtime; the provider reads it for the vocabulary. No other module does."""
    readers = {
        p.relative_to(_REPO_ROOT).as_posix()
        for p in _CHANAKYA.rglob("*.py")
        if "active_rule_set" in p.read_text(encoding="utf-8") and p.name != "risk_taxonomy.py"
    }
    assert readers == {"chanakya/cli/main.py", "chanakya/providers/mapping.py"}
