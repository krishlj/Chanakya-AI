"""Phase 10 — Runtime integration of risk assessment (10.5, 10.6).

conclude → _record_findings → _assess_risk → complete, with a real
AgentLoopController, real Evidence/Finding/RiskAssessment stores and the
real deterministic engine. Malicious or buggy assessors are wrappers around
the real engine whose output the Runtime must reject before storing
anything (RA-INV-4, RA-INV-7, RA-INV-10)."""
from __future__ import annotations

import ast
import dataclasses
import json
from pathlib import Path

import pytest

from chanakya.contracts.audit_event import AuditEventType
from chanakya.contracts.enums import RiskCategory
from chanakya.contracts.investigation_context import InvestigationStatus
from chanakya.contracts.risk_assessment import NotAssessedFinding, RiskEngineResult
from chanakya.evidence import EvidenceStore
from chanakya.findings import FindingStore
from chanakya.risk import RiskAssessmentStore, RiskEngine, StoreEvidenceFactsReader
from chanakya.runtime.agent_loop import AgentLoopController, TurnOutcome
from chanakya.runtime.audit import AuditEmitter, InMemoryAuditSink
from chanakya.runtime.evidence import FilesystemEvidenceRecorder

from risk_factories import HOSTILE_TEXT, make_ra
from runtime_factories import FakeToolExecutor, SpyPolicyEvaluator
from test_findings import Script, finding_dict

E = AuditEventType
_REPO_ROOT = Path(__file__).resolve().parent.parent


class Rig:
    pass


@pytest.fixture
def rig(investigation_manager_factory, resource_governor, gateway, investigation_request, tmp_path):
    r = Rig()
    r.sink = InMemoryAuditSink()
    r.audit = AuditEmitter(r.sink)
    r.manager = investigation_manager_factory(audit=r.audit)
    r.context = r.manager.create_investigation(investigation_request)
    r.manager.start(r.context.investigation_id)
    r.inv = r.context.investigation_id
    r.spy = SpyPolicyEvaluator(gateway)
    r.executor = FakeToolExecutor()
    r.evidence = EvidenceStore(tmp_path / "evidence")
    r.findings = FindingStore(tmp_path / "findings")
    r.risk = RiskAssessmentStore(tmp_path / "risk")
    r.engine = RiskEngine(StoreEvidenceFactsReader(r.evidence))

    def build(assessor="engine", recorder="store", sink=None):
        audit = AuditEmitter(sink) if sink is not None else r.audit
        return AgentLoopController(
            r.manager, resource_governor, r.spy, r.executor, audit=audit,
            evidence_recorder=FilesystemEvidenceRecorder(r.evidence), finding_recorder=r.findings,
            risk_assessor=r.engine if assessor == "engine" else assessor,
            risk_recorder=r.risk if recorder == "store" else recorder,
            sleep=lambda _s: None,
        )

    r.build = build
    return r


def run(rig, build_findings, controller=None, *, proposals=1, before_conclude=None):
    controller = controller or rig.build()
    agent = Script(rig.inv, build_findings, proposals=proposals)
    results = []
    for _ in range(proposals):
        results.append(controller.run_turn(rig.inv, agent, recent_tool_results=[r.tool_result for r in results]))
    if before_conclude:
        before_conclude(results)
    results.append(controller.run_turn(rig.inv, agent, recent_tool_results=[r.tool_result for r in results]))
    return results


def cat(category, **extra):
    return lambda ids: [finding_dict(ids, category=category, **extra)]


def types(rig):
    return [e.event_type for e in rig.sink.events]


# ===========================================================================
# Happy paths
# ===========================================================================


def test_rated_finding_is_assessed_stored_audited_then_completed(rig):
    *_, last = run(rig, cat("network_exposure"))
    assert last.outcome == TurnOutcome.CONCLUDED and rig.context.status == InvestigationStatus.COMPLETED
    (finding,) = rig.findings.list_by_investigation(rig.inv)
    (ra,) = rig.risk.list_by_investigation(rig.inv)
    assert ra.finding_refs == (finding.finding_id,) and ra.evidence_refs == finding.evidence_refs
    assert ra.severity == RiskCategory.MEDIUM and ra.confidence == "medium"
    assert rig.context.risk_assessment_refs == (ra.risk_assessment_id,)
    t = types(rig)
    assert t.index(E.FINDING_CREATED) < t.index(E.RISK_ASSESSED) < t.index(E.INVESTIGATION_COMPLETED)
    (event,) = [e for e in rig.sink.events if e.event_type == E.RISK_ASSESSED]
    assert event.actor == "system" and event.investigation_id == rig.inv
    assert event.related_ids == {"risk_assessment_id": ra.risk_assessment_id, "finding_id": finding.finding_id}
    assert event.details == {
        "evidence_refs": list(ra.evidence_refs), "severity": "medium", "confidence": "medium",
        "scoring_method": "chanakya-risk-rules/1.0.0", "rule_ids": list(ra.rule_ids),
    }
    assert ra.rationale not in json.dumps(event.details) and finding.title not in json.dumps(event.details)


def test_not_assessed_findings_complete_normally_without_risk_records(rig):
    *_, last = run(rig, lambda ids: [finding_dict(ids, category="exposure"), finding_dict(ids, category="platform_configuration")])
    assert last.outcome == TurnOutcome.CONCLUDED and rig.context.status == InvestigationStatus.COMPLETED
    assert rig.risk.list_by_investigation(rig.inv) == ()
    assert E.RISK_ASSESSED not in types(rig) and rig.context.risk_assessment_refs == ()


def test_finding_without_category_is_not_assessed(rig):
    run(rig, lambda ids: [{"title": "t", "description": "d", "evidence_refs": ids}])
    assert rig.context.status == InvestigationStatus.COMPLETED and rig.risk.list_by_investigation(rig.inv) == ()


def test_mixed_batch_stores_only_rated_findings_one_event_each(rig):
    run(rig, lambda ids: [finding_dict(ids, category="network_exposure"), finding_dict(ids, category="exposure"),
                          finding_dict(ids, category="service_inventory")])
    stored = rig.risk.list_by_investigation(rig.inv)
    assert sorted(r.severity.value for r in stored) == ["informational", "medium"]
    assert types(rig).count(E.RISK_ASSESSED) == 2 and len(rig.context.risk_assessment_refs) == 2


def test_conclude_without_findings_never_calls_the_assessor(rig):
    class Never:
        def assess(self, *a, **k):
            raise AssertionError("assessed without findings")

    controller = rig.build(assessor=Never())
    agent = Script(rig.inv, lambda ids: [], proposals=0)
    turn = {"turn_id": "t", "contract_version": "1.0.0", "investigation_id": rig.inv, "next_action": "conclude",
            "produced_at": "2026-09-26T00:00:00Z"}
    agent.next_turn = lambda _a: turn
    assert controller.run_turn(rig.inv, agent).outcome == TurnOutcome.CONCLUDED


def test_rejected_findings_are_never_assessed(rig):
    class Never:
        def assess(self, *a, **k):
            raise AssertionError("assessed rejected findings")

    results = run(rig, lambda ids: [finding_dict(["tr-forged"], category="network_exposure")], rig.build(assessor=Never()))
    assert results[-1].outcome == TurnOutcome.MALFORMED_TURN and rig.context.status == InvestigationStatus.RUNNING


def test_no_risk_configuration_keeps_phase_9_behavior(rig, resource_governor):
    controller = AgentLoopController(
        rig.manager, resource_governor, rig.spy, rig.executor, audit=rig.audit,
        evidence_recorder=FilesystemEvidenceRecorder(rig.evidence), finding_recorder=rig.findings,
        sleep=lambda _s: None,
    )
    run(rig, cat("network_exposure"), controller)
    assert rig.context.status == InvestigationStatus.COMPLETED and E.RISK_ASSESSED not in types(rig)
    assert rig.risk.list_by_investigation(rig.inv) == ()


@pytest.mark.parametrize("which", ["assessor_only", "recorder_only"])
def test_half_configuration_is_a_composition_error(rig, which):
    with pytest.raises(ValueError):
        rig.build(assessor="engine" if which == "assessor_only" else None,
                  recorder="store" if which == "recorder_only" else None)


# ===========================================================================
# Malicious / buggy assessors: validated before any append
# ===========================================================================


class Wrapping:
    """Calls the real engine, then lets a test corrupt the result."""

    def __init__(self, engine, transform):
        self.engine, self.transform = engine, transform

    def assess(self, investigation_id, findings, *, assessed_at):
        return self.transform(self.engine.assess(investigation_id, findings, assessed_at=assessed_at), findings)


def forced(obj, **changes):
    obj = dataclasses.replace(obj)  # copy, then bypass the frozen/validated constructor
    for key, value in changes.items():
        object.__setattr__(obj, key, value)
    return obj


def with_first(transform):
    return lambda res, _f: RiskEngineResult(
        assessments=(transform(res.assessments[0]),) + res.assessments[1:], not_assessed=res.not_assessed)


class Unvalidated:
    """Duck-typed result that skips RiskEngineResult's own checks."""

    def __init__(self, assessments, not_assessed=()):
        self.assessments, self.not_assessed = assessments, not_assessed


CORRUPTIONS = {
    "critical_for_read_only": with_first(lambda ra: forced(ra, severity=RiskCategory.CRITICAL)),
    "high_severity": with_first(lambda ra: forced(ra, severity=RiskCategory.HIGH)),
    "wrong_deterministic_id": with_first(lambda ra: forced(ra, risk_assessment_id="00000000-0000-0000-0000-000000000000")),
    "unknown_rule_id": with_first(lambda ra: forced(ra, rule_ids=ra.rule_ids[:-1] + ("approve.all",))),
    "unknown_scoring_method": with_first(lambda ra: forced(ra, scoring_method="llm-judgment/1.0")),
    "assessed_by_agent": with_first(lambda ra: forced(ra, assessed_by="agent")),
    "evidence_mismatch": with_first(lambda ra: forced(ra, evidence_refs=("ev-forged",))),
    "evidence_reordered_or_extra": with_first(lambda ra: forced(ra, evidence_refs=ra.evidence_refs + ("ev-extra",))),
    "wrong_category_rule": with_first(lambda ra: make_ra(
        investigation_id=ra.investigation_id, finding_refs=ra.finding_refs, evidence_refs=ra.evidence_refs,
        severity=RiskCategory.INFORMATIONAL,
        rule_ids=("evidence.verified", "category.service_inventory", "compat.all", "ceiling.read_only", "confidence.medium"))),
    "foreign_investigation": with_first(lambda ra: make_ra(
        investigation_id="inv-foreign", finding_refs=ra.finding_refs, evidence_refs=ra.evidence_refs)),
    "fabricated_finding": lambda res, f: RiskEngineResult(
        assessments=res.assessments + (make_ra(investigation_id=f[0].investigation_id, finding_refs=("find-ghost",),
                                               evidence_refs=f[0].evidence_refs),), not_assessed=()),
    "missing_finding": lambda res, f: RiskEngineResult(assessments=res.assessments[1:], not_assessed=res.not_assessed),
    "duplicate_assessment": lambda res, f: RiskEngineResult(assessments=res.assessments * 2, not_assessed=()),
    "assessed_and_not_assessed": lambda res, f: RiskEngineResult(
        assessments=res.assessments, not_assessed=(NotAssessedFinding(res.assessments[0].finding_id, "evidence_incompatible"),)),
    "suppressed_as_unrated": lambda res, f: RiskEngineResult(
        assessments=res.assessments[1:], not_assessed=(NotAssessedFinding(res.assessments[0].finding_id, "category_unrated"),)),
    "excessive": lambda res, f: RiskEngineResult(assessments=res.assessments * 21, not_assessed=()),
    "wrong_type_dict": lambda res, f: {"assessments": [], "not_assessed": []},
    "none": lambda res, f: None,
    "duck_typed_dict_items": lambda res, f: Unvalidated([ra.to_dict() for ra in res.assessments]),
    "duck_typed_result": lambda res, f: Unvalidated(res.assessments, res.not_assessed),
    "string_severity": with_first(lambda ra: forced(ra, severity="medium")),
}


@pytest.mark.parametrize("name", list(CORRUPTIONS))
def test_invalid_engine_output_halts_and_stores_nothing(rig, name):
    controller = rig.build(assessor=Wrapping(rig.engine, CORRUPTIONS[name]))
    *_, last = run(rig, lambda ids: [finding_dict(ids, category="network_exposure"),
                                     finding_dict(ids, category="service_inventory")], controller)
    assert last.outcome == TurnOutcome.HALTED, name
    assert rig.context.status == InvestigationStatus.HALTED
    assert rig.context.error_state["reason"] == "risk_assessment_failed"
    assert rig.risk.list_by_investigation(rig.inv) == ()  # validated before the first append
    assert E.RISK_ASSESSED not in types(rig) and E.INVESTIGATION_COMPLETED not in types(rig)
    assert len(rig.findings.list_by_investigation(rig.inv)) == 2 and rig.findings.verify(rig.inv)


def test_engine_exception_halts_and_findings_survive(rig):
    class Boom:
        def assess(self, *a, **k):
            raise RuntimeError("engine crashed")

    *_, last = run(rig, cat("network_exposure"), rig.build(assessor=Boom()))
    assert last.outcome == TurnOutcome.HALTED and rig.context.error_state["reason"] == "risk_assessment_failed"
    assert len(rig.findings.list_by_investigation(rig.inv)) == 1


@pytest.mark.parametrize("category", ["network_exposure", "exposure", None])
def test_evidence_corruption_is_a_failure_not_not_assessed(rig, category):
    def tamper(results):
        ev = results[0].step_record.evidence_id
        (rig.evidence.root / rig.inv / "payloads" / f"{ev}.json").write_text('{"output": "forged"}', encoding="utf-8")

    extra = {} if category is None else {"category": category}
    build = lambda ids: [dict({"title": "t", "description": "d", "evidence_refs": ids}, **extra)]
    *_, last = run(rig, build, before_conclude=tamper)
    assert last.outcome == TurnOutcome.HALTED and rig.context.error_state["reason"] == "risk_assessment_failed"
    assert rig.context.status != InvestigationStatus.COMPLETED


# ===========================================================================
# Storage and audit failures
# ===========================================================================


class FailingRecorder:
    def __init__(self, store, fail_on):
        self.store, self.fail_on, self.calls = store, fail_on, 0

    def append(self, ra):
        self.calls += 1
        if self.calls == self.fail_on:
            raise OSError("disk full")
        self.store.append(ra)


def two_rated(ids):
    return [finding_dict(ids, category="network_exposure"), finding_dict(ids, category="service_inventory")]


def test_storage_failure_on_first_append_halts_without_completion(rig):
    *_, last = run(rig, two_rated, rig.build(recorder=FailingRecorder(rig.risk, 1)))
    assert last.outcome == TurnOutcome.HALTED and rig.context.error_state["reason"] == "risk_assessment_failed"
    assert rig.risk.list_by_investigation(rig.inv) == () and E.INVESTIGATION_COMPLETED not in types(rig)
    assert len(rig.findings.list_by_investigation(rig.inv)) == 2


def test_storage_failure_mid_batch_leaves_a_durable_partial_batch(rig):
    *_, last = run(rig, two_rated, rig.build(recorder=FailingRecorder(rig.risk, 2)))
    assert last.outcome == TurnOutcome.HALTED
    (stored,) = rig.risk.list_by_investigation(rig.inv)
    assert rig.context.risk_assessment_refs == (stored.risk_assessment_id,)
    assert types(rig).count(E.RISK_ASSESSED) == 1 and E.INVESTIGATION_COMPLETED not in types(rig)


def test_duplicate_store_collision_halts(rig):
    class Twice:
        def __init__(self, store):
            self.store = store

        def append(self, ra):
            self.store.append(ra)
            self.store.append(ra)

    *_, last = run(rig, cat("network_exposure"), rig.build(recorder=Twice(rig.risk)))
    assert last.outcome == TurnOutcome.HALTED and len(rig.risk.list_by_investigation(rig.inv)) == 1


class FailOnRiskEvent(InMemoryAuditSink):
    def emit(self, event):
        if event.event_type == E.RISK_ASSESSED:
            raise OSError("audit disk full")
        super().emit(event)


def test_audit_failure_halts_with_audit_sink_failure(rig):
    sink = FailOnRiskEvent()
    *_, last = run(rig, cat("network_exposure"), rig.build(sink=sink))
    assert last.outcome == TurnOutcome.HALTED
    assert rig.context.error_state["reason"] == "audit_sink_failure"
    assert E.INVESTIGATION_COMPLETED not in [e.event_type for e in sink.events + rig.sink.events]


# ===========================================================================
# Input isolation and authority (RA-INV-1, 2, 5, 6)
# ===========================================================================


@pytest.mark.parametrize("text", [t for t in HOSTILE_TEXT if "\x1b" not in t])
def test_hostile_finding_text_has_no_effect_at_runtime(rig, text):
    run(rig, cat("network_exposure", title=text[:200], description=text, confidence="high"))
    (ra,) = rig.risk.list_by_investigation(rig.inv)
    assert ra.severity == RiskCategory.MEDIUM and ra.confidence == "medium"
    for path in rig.risk.root.rglob("*.json"):
        assert text not in path.read_text(encoding="utf-8")
    for event in rig.sink.events:
        assert text not in json.dumps(event.details or {})


def test_risk_path_creates_no_policy_decision_approval_or_dispatch(rig):
    run(rig, cat("network_exposure"))
    assert rig.executor.call_count == 1  # only the one proposed tool call
    assert types(rig).count(E.POLICY_EVALUATED) == 1 and E.APPROVAL_REQUESTED not in types(rig)
    assert types(rig).count(E.DISPATCH_STARTED) == 1


def test_runtime_risk_path_calls_no_intake_policy_approval_or_dispatch():
    source = (_REPO_ROOT / "chanakya" / "runtime" / "agent_loop.py").read_text(encoding="utf-8")
    tree = ast.parse(source)
    checked = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.FunctionDef) and node.name in (
            "_assess_risk", "_halt_risk_assessment", "_validate_risk_result"
        ):
            checked.add(node.name)
            body = ast.get_source_segment(source, node)
            for forbidden in ("ToolRequestIntake", "_policy_evaluator", "_approval_provider", "dispatch(",
                              "_execute_once", "_executor", "_context_assembler", "next_turn"):
                assert forbidden not in body, (node.name, forbidden)
    assert checked == {"_assess_risk", "_halt_risk_assessment", "_validate_risk_result"}


def test_risk_assessments_are_never_fed_back_to_the_model(rig):
    seen = []

    class Recording(Script):
        def next_turn(self, assembled):
            seen.append(json.dumps([e.content for e in assembled.data], default=str))
            return super().next_turn(assembled)

    controller = rig.build()
    agent = Recording(rig.inv, cat("network_exposure"), proposals=1)
    first = controller.run_turn(rig.inv, agent)
    controller.run_turn(rig.inv, agent, recent_tool_results=[first.tool_result])
    (ra,) = rig.risk.list_by_investigation(rig.inv)
    assert all(ra.risk_assessment_id not in s and "chanakya-risk-rules" not in s for s in seen)
