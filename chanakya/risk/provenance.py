"""Risk provenance verification — Phase 10 (docs/CONTRACTS.md §9).

``verify_risk_provenance`` re-walks, for one investigation::

    RiskAssessment → Finding → Evidence (record hash) → Evidence payload (payload hash)

and re-runs the deterministic Risk Engine over the stored Findings. Every
stored RiskAssessment must:

- reference exactly one Finding stored for the same investigation;
- carry exactly that Finding's ``evidence_refs``, in order;
- equal the recomputed assessment in every field except ``assessed_at``
  (id, severity, confidence, rule ids, rationale, references, rule set).

Every Finding the engine rates must have a stored assessment, and no
Finding the engine does not rate may have one. Cited Evidence is verified
in its own investigation by the engine's reader, so missing, foreign or
tampered Evidence or payloads fail verification too.

Because the rating is recomputed, a RiskAssessment rewritten with a
recomputed ``content_hash`` still fails unless the Finding and Evidence it
was computed from were rewritten consistently as well (docs/THREAT-MODEL.md
T-48 residual).

Read-only: it writes nothing, and it never reads the Audit Log (AL-INV-7).
Problems are reported as fixed codes, never as record content.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List, Mapping, Tuple

from chanakya.contracts.risk_assessment import RiskAssessment
from chanakya.findings.store import FindingStore

from .engine import RiskEngine
from .store import RiskAssessmentStore

_COMPARED_FIELDS = (
    "risk_assessment_id",
    "contract_version",
    "investigation_id",
    "finding_refs",
    "evidence_refs",
    "severity",
    "confidence",
    "scoring_method",
    "rule_ids",
    "assessed_by",
    "rationale",
)

_RECOMPUTED_AT = "recomputation"


@dataclass(frozen=True)
class RiskProvenanceReport:
    investigation_id: str
    #: Fixed problem codes; empty means verified.
    problems: Tuple[str, ...]
    #: finding_id → verified assessment. Empty unless ``verified``.
    assessments: Mapping[str, RiskAssessment] = field(default_factory=dict)
    #: finding_id → not-assessed reason, as recomputed. Empty unless ``verified``.
    not_assessed: Mapping[str, str] = field(default_factory=dict)

    @property
    def verified(self) -> bool:
        return not self.problems


def _failed(investigation_id: str, *problems: str) -> RiskProvenanceReport:
    return RiskProvenanceReport(investigation_id=investigation_id, problems=tuple(problems))


def verify_risk_provenance(
    investigation_id: str,
    *,
    risk_store: RiskAssessmentStore,
    finding_store: FindingStore,
    engine: RiskEngine,
) -> RiskProvenanceReport:
    try:
        stored = risk_store.list_by_investigation(investigation_id)
    except Exception:
        return _failed(investigation_id, "risk_store_unverifiable")
    try:
        findings = finding_store.list_by_investigation(investigation_id)
    except Exception:
        return _failed(investigation_id, "finding_store_unverifiable")

    problems: List[str] = []
    by_finding = {f.finding_id: f for f in findings}
    stored_by_finding: Dict[str, RiskAssessment] = {}
    for ra in stored:
        finding = by_finding.get(ra.finding_id)
        if ra.investigation_id != investigation_id or finding is None:
            problems.append("assessment_references_unknown_finding")
            continue
        if ra.finding_id in stored_by_finding:
            problems.append("duplicate_assessment")
            continue
        if ra.evidence_refs != finding.evidence_refs:
            problems.append("evidence_refs_mismatch")
        stored_by_finding[ra.finding_id] = ra

    try:
        recomputed = engine.assess(investigation_id, findings, assessed_at=_RECOMPUTED_AT)
    except Exception:
        return _failed(investigation_id, *problems, "evidence_unverifiable")

    for expected in recomputed.assessments:
        actual = stored_by_finding.get(expected.finding_id)
        if actual is None:
            problems.append("assessment_missing")
        elif any(getattr(actual, name) != getattr(expected, name) for name in _COMPARED_FIELDS):
            problems.append("recomputation_mismatch")
    for item in recomputed.not_assessed:
        if item.finding_id in stored_by_finding:
            problems.append("unexpected_assessment")

    if problems:
        return _failed(investigation_id, *problems)
    return RiskProvenanceReport(
        investigation_id=investigation_id,
        problems=(),
        assessments=dict(stored_by_finding),
        not_assessed={item.finding_id: item.reason for item in recomputed.not_assessed},
    )


__all__ = ["RiskProvenanceReport", "verify_risk_provenance"]
