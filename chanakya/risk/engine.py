"""Deterministic Risk Engine — Phase 10 (ARCHITECTURE.md §11).

``RiskEngine.assess`` rates each Finding stored in one conclude turn under
rule set ``chanakya-risk-rules/1.0.0`` (``chanakya.risk.rules``) and returns
a ``RiskEngineResult``: every Finding exactly once, either as a
``RiskAssessment`` or as a ``NotAssessedFinding``.

What the engine reads, and nothing else:

- from each Finding: ``finding_id``, ``investigation_id``, ``category`` and
  ``evidence_refs``. Never ``title``, ``description`` or ``confidence``.
- from each cited Evidence: ``EvidenceFacts`` (id, investigation,
  capability, classification) through an ``EvidenceFactsReader``. The
  production reader verifies the record and its payload inside the
  investigation's own directory and returns metadata only, so the engine
  never receives payload content, tool output or target data.

Every cited Evidence of every Finding is verified before any Finding is
rated. Missing, foreign or corrupt Evidence raises ``RiskEngineError``: an
integrity failure fails closed and is never reported as "not assessed".

The engine is pure: the same Findings, the same Evidence and the same rule
set give the same ids, severities, confidences, rule ids and rationales.
``assessed_at`` is supplied by the caller and is the only varying field.
It holds no state between calls and has no path to the Policy Gateway,
approval, dispatch, a ToolExecutor, a provider or the Audit Log.
"""
from __future__ import annotations

from typing import Any, Dict, List, Protocol, Sequence

from chanakya.contracts.risk_assessment import (
    ASSESSED_BY,
    MAX_RISK_ASSESSMENTS_PER_INVESTIGATION,
    NotAssessedFinding,
    RiskAssessment,
    RiskAssessmentValidationError,
    RiskEngineResult,
    derive_risk_assessment_id,
)
from chanakya.evidence.store import EvidenceStore, EvidenceStoreError

from .rules import CAPABILITY_ID_PATTERN, SCORING_METHOD, EvidenceFacts, RuleOutcome, evaluate

_CONTRACT_VERSION = "1.0.0"


class RiskEngineError(Exception):
    """The engine cannot rate this batch: invalid input or an Evidence
    integrity failure. The caller must fail closed."""


class EvidenceFactsReader(Protocol):
    def evidence_facts(self, investigation_id: str, evidence_id: str) -> EvidenceFacts:
        """Verified metadata of one Evidence record of ``investigation_id``.
        Raises if it is missing there, foreign or fails verification."""
        ...


class StoreEvidenceFactsReader:
    """``EvidenceFactsReader`` over an ``EvidenceStore``. Uses only
    ``EvidenceStore.verify_in_investigation`` (record hash, id/investigation
    match and payload hash, all scoped to one investigation directory) and
    passes on four metadata fields. Payload content is never returned."""

    def __init__(self, store: EvidenceStore) -> None:
        self._store = store

    def evidence_facts(self, investigation_id: str, evidence_id: str) -> EvidenceFacts:
        try:
            evidence = self._store.verify_in_investigation(investigation_id, evidence_id)
        except EvidenceStoreError as exc:
            raise RiskEngineError(f"cited evidence failed verification: {exc.__class__.__name__}") from None
        return EvidenceFacts(
            evidence_id=evidence.evidence_id,
            investigation_id=evidence.investigation_id,
            capability=evidence.capability,
            classification=evidence.classification,
        )


class RiskEngine:
    scoring_method = SCORING_METHOD

    def __init__(self, evidence_reader: EvidenceFactsReader) -> None:
        self._reader = evidence_reader

    def assess(self, investigation_id: str, findings: Sequence[Any], *, assessed_at: str) -> RiskEngineResult:
        if type(investigation_id) is not str or not investigation_id:
            raise RiskEngineError("investigation_id must be a non-empty string")
        findings = tuple(findings)
        if len(findings) > MAX_RISK_ASSESSMENTS_PER_INVESTIGATION:
            raise RiskEngineError(f"more than {MAX_RISK_ASSESSMENTS_PER_INVESTIGATION} findings to assess")
        inputs = [self._finding_inputs(investigation_id, finding) for finding in findings]
        if len({finding_id for finding_id, _, _ in inputs}) != len(inputs):
            raise RiskEngineError("duplicate finding ids in one batch")

        facts: Dict[str, EvidenceFacts] = {}
        for _, _, refs in inputs:
            for ref in refs:
                if ref not in facts:
                    facts[ref] = self._verified_facts(investigation_id, ref)

        assessments: List[RiskAssessment] = []
        not_assessed: List[NotAssessedFinding] = []
        for finding_id, category, refs in inputs:
            outcome = evaluate(category, [facts[ref] for ref in refs])
            if isinstance(outcome, RuleOutcome):
                assessments.append(self._assessment(investigation_id, finding_id, refs, outcome, assessed_at))
            else:
                not_assessed.append(NotAssessedFinding(finding_id=finding_id, reason=outcome))
        return RiskEngineResult(assessments=tuple(assessments), not_assessed=tuple(not_assessed))

    @staticmethod
    def _finding_inputs(investigation_id: str, finding: Any):
        # The four fields the rule set may use; nothing else is read.
        finding_id = finding.finding_id
        if type(finding_id) is not str or not finding_id:
            raise RiskEngineError("finding_id must be a non-empty string")
        if finding.investigation_id != investigation_id:
            raise RiskEngineError("finding belongs to another investigation")
        category = finding.category
        if category is not None and type(category) is not str:
            raise RiskEngineError("finding category must be a string or None")
        refs = finding.evidence_refs
        if type(refs) is not tuple or not refs or not all(type(r) is str and r for r in refs):
            raise RiskEngineError("finding evidence_refs must be a non-empty tuple of ids")
        if len(set(refs)) != len(refs):
            raise RiskEngineError("finding evidence_refs contains duplicates")
        return finding_id, category, refs

    def _verified_facts(self, investigation_id: str, evidence_id: str) -> EvidenceFacts:
        try:
            fact = self._reader.evidence_facts(investigation_id, evidence_id)
        except RiskEngineError:
            raise
        except Exception as exc:
            raise RiskEngineError(f"cited evidence failed verification: {exc.__class__.__name__}") from None
        if not isinstance(fact, EvidenceFacts):
            raise RiskEngineError("evidence reader returned an unexpected type")
        if fact.evidence_id != evidence_id or fact.investigation_id != investigation_id:
            raise RiskEngineError("cited evidence is foreign to this investigation")
        if type(fact.capability) is not str or not CAPABILITY_ID_PATTERN.match(fact.capability):
            raise RiskEngineError("cited evidence has an invalid capability id")
        return fact

    def _assessment(self, investigation_id, finding_id, refs, outcome: RuleOutcome, assessed_at) -> RiskAssessment:
        try:
            return RiskAssessment(
                risk_assessment_id=derive_risk_assessment_id(investigation_id, finding_id, self.scoring_method),
                contract_version=_CONTRACT_VERSION,
                investigation_id=investigation_id,
                finding_refs=(finding_id,),
                evidence_refs=refs,
                severity=outcome.severity,
                confidence=outcome.confidence,
                scoring_method=self.scoring_method,
                rule_ids=outcome.rule_ids,
                assessed_at=assessed_at,
                assessed_by=ASSESSED_BY,
                rationale=outcome.rationale,
            )
        except RiskAssessmentValidationError as exc:
            raise RiskEngineError(f"engine produced an invalid assessment: {exc}") from None


__all__ = ["EvidenceFactsReader", "RiskEngine", "RiskEngineError", "StoreEvidenceFactsReader"]
