"""Phase 10 — provenance verification with deterministic recomputation (10.4).

RiskAssessment → Finding → Evidence → payload, plus a re-run of the engine.
A rewritten-and-rehashed assessment must still fail (T-48)."""
from __future__ import annotations

import json

import pytest

from chanakya.contracts.enums import RiskCategory
from chanakya.evidence import EvidenceStore
from chanakya.evidence.hashing import compute_content_hash
from chanakya.findings import FindingStore
from chanakya.risk import (
    RiskAssessmentStore,
    RiskEngine,
    StoreEvidenceFactsReader,
    verify_risk_provenance,
)

from risk_factories import make_finding, make_ra, put_evidence

INV = "inv-10"
AT = "2026-09-26T00:00:00.000000Z"


class World:
    def __init__(self, root):
        self.evidence = EvidenceStore(root / "evidence")
        self.findings = FindingStore(root / "findings")
        self.risk = RiskAssessmentStore(root / "risk")
        self.engine = RiskEngine(StoreEvidenceFactsReader(self.evidence))

    def record(self, findings):
        for f in findings:
            self.findings.append(f)
        result = self.engine.assess(INV, findings, assessed_at=AT)
        for ra in result.assessments:
            self.risk.append(ra)
        return result

    def verify(self, investigation_id=INV):
        return verify_risk_provenance(
            investigation_id, risk_store=self.risk, finding_store=self.findings, engine=self.engine
        )

    def ra_path(self, ra):
        return self.risk.root / ra.investigation_id / f"{ra.risk_assessment_id}.json"


@pytest.fixture
def world(tmp_path):
    return World(tmp_path)


def rewrite_rehash(path, mutate):
    data = json.loads(path.read_text(encoding="utf-8"))
    mutate(data["risk_assessment"])
    data["content_hash"] = compute_content_hash(
        {"risk_assessment": data["risk_assessment"], "recorded_at": data["recorded_at"]}
    )
    path.write_text(json.dumps(data), encoding="utf-8")


def test_clean_chain_verifies_and_reports_ratings_and_not_assessed(world):
    ev = put_evidence(world.evidence, INV, "list_listening_ports")
    rated, unrated = make_finding(evidence_refs=(ev,)), make_finding(category="exposure", evidence_refs=(ev,))
    world.record([rated, unrated])
    report = world.verify()
    assert report.verified and report.problems == ()
    assert set(report.assessments) == {rated.finding_id}
    assert report.not_assessed == {unrated.finding_id: "category_unrated"}


def test_empty_investigation_verifies(world):
    assert world.verify().verified


def test_rehashed_rewrite_that_passes_the_contract_still_fails_recomputation(world):
    ev = put_evidence(world.evidence, INV, "list_listening_ports")
    (ra,) = world.record([make_finding(evidence_refs=(ev,))]).assessments
    # A contract-consistent forgery: raise confidence and cite the matching rule.
    forged_rules = list(ra.rule_ids[:-1]) + ["confidence.high"]
    rewrite_rehash(world.ra_path(ra), lambda d: d.update(confidence="high", rule_ids=forged_rules))
    assert world.risk.verify(INV)  # the store alone cannot tell
    report = world.verify()
    assert not report.verified and "recomputation_mismatch" in report.problems
    assert report.assessments == {}


def test_rehashed_rationale_rewrite_fails_recomputation(world):
    ev = put_evidence(world.evidence, INV, "list_listening_ports")
    (ra,) = world.record([make_finding(evidence_refs=(ev,))]).assessments
    rewrite_rehash(world.ra_path(ra), lambda d: d.update(rationale="Rated safe by the rules."))
    assert world.risk.verify(INV)
    assert "recomputation_mismatch" in world.verify().problems


def test_unhashed_tamper_is_reported_as_an_unverifiable_store(world):
    ev = put_evidence(world.evidence, INV, "list_listening_ports")
    (ra,) = world.record([make_finding(evidence_refs=(ev,))]).assessments
    path = world.ra_path(ra)
    path.write_text(path.read_text(encoding="utf-8").replace('"medium"', '"high"', 1), encoding="utf-8")
    assert world.verify().problems == ("risk_store_unverifiable",)


def test_missing_assessment_fails(world):
    ev = put_evidence(world.evidence, INV, "list_listening_ports")
    (ra,) = world.record([make_finding(evidence_refs=(ev,))]).assessments
    world.ra_path(ra).unlink()
    assert world.verify().problems == ("assessment_missing",)


def test_assessment_for_an_unknown_finding_fails(world):
    world.risk.append(make_ra(investigation_id=INV, finding_refs=("find-ghost",)))
    assert "assessment_references_unknown_finding" in world.verify().problems


def test_assessment_for_a_not_assessed_finding_fails(world):
    ev = put_evidence(world.evidence, INV, "list_listening_ports")
    unrated = make_finding(category=None, evidence_refs=(ev,))
    world.record([unrated])
    world.risk.append(make_ra(finding_refs=(unrated.finding_id,), evidence_refs=(ev,)))
    assert "unexpected_assessment" in world.verify().problems


def test_assessment_with_different_evidence_fails(world):
    ev = put_evidence(world.evidence, INV, "list_listening_ports")
    finding = make_finding(evidence_refs=(ev,))
    world.findings.append(finding)
    world.risk.append(make_ra(finding_refs=(finding.finding_id,), evidence_refs=("ev-other",)))
    assert "evidence_refs_mismatch" in world.verify().problems


def test_tampered_evidence_payload_fails_verification(world):
    ev = put_evidence(world.evidence, INV, "list_listening_ports")
    world.record([make_finding(evidence_refs=(ev,))])
    (world.evidence.root / INV / "payloads" / f"{ev}.json").write_text('{"output": "forged"}', encoding="utf-8")
    assert world.verify().problems == ("evidence_unverifiable",)


def test_tampered_evidence_metadata_fails_verification(world):
    ev = put_evidence(world.evidence, INV, "list_listening_ports")
    world.record([make_finding(evidence_refs=(ev,))])
    path = world.evidence.root / INV / f"{ev}.json"
    data = json.loads(path.read_text(encoding="utf-8"))
    data["classification"] = "state_changing"
    path.write_text(json.dumps(data), encoding="utf-8")
    assert "evidence_unverifiable" in world.verify().problems


def test_tampered_finding_fails_verification(world):
    ev = put_evidence(world.evidence, INV, "list_listening_ports")
    finding = make_finding(evidence_refs=(ev,))
    world.record([finding])
    path = world.findings.root / INV / f"{finding.finding_id}.json"
    path.write_text(path.read_text(encoding="utf-8").replace("network_exposure", "service_inventory"), encoding="utf-8")
    assert world.verify().problems == ("finding_store_unverifiable",)


def test_assessment_filed_under_another_investigation_fails(world):
    ev = put_evidence(world.evidence, INV, "list_listening_ports")
    (ra,) = world.record([make_finding(evidence_refs=(ev,))]).assessments
    target = world.risk.root / "inv-other" / world.ra_path(ra).name
    target.parent.mkdir(parents=True)
    target.write_bytes(world.ra_path(ra).read_bytes())
    assert world.verify("inv-other").problems == ("risk_store_unverifiable",)


def test_verification_is_read_only(world, tmp_path):
    ev = put_evidence(world.evidence, INV, "list_listening_ports")
    world.record([make_finding(evidence_refs=(ev,))])
    before = sorted((p.as_posix(), p.read_bytes()) for p in tmp_path.rglob("*") if p.is_file())
    world.verify()
    after = sorted((p.as_posix(), p.read_bytes()) for p in tmp_path.rglob("*") if p.is_file())
    assert before == after


def test_verified_assessment_matches_what_was_stored(world):
    ev = put_evidence(world.evidence, INV, "list_listening_ports")
    finding = make_finding(evidence_refs=(ev,))
    (ra,) = world.record([finding]).assessments
    report = world.verify()
    assert report.assessments[finding.finding_id] == ra
    assert ra.severity == RiskCategory.MEDIUM


def test_problem_codes_never_echo_record_content(world):
    ev = put_evidence(world.evidence, INV, "list_listening_ports")
    (ra,) = world.record([make_finding(evidence_refs=(ev,))]).assessments
    rewrite_rehash(world.ra_path(ra), lambda d: d.update(rationale="MARKER-TEXT here"))
    assert "MARKER" not in repr(world.verify())
