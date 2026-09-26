"""Risk Engine — Phase 10 (ARCHITECTURE.md §11).

Deterministic, versioned rating of evidence-grounded Findings
(``chanakya-risk-rules/1.0.0``), its append-only store and a read-only
provenance verifier. Nothing here authorizes, dispatches or executes
anything, and nothing in the Policy Gateway, Registry, Tool Layer or
approval reads it. The Runtime reaches it only through injected Protocols;
the CLI composition root wires it.
"""
from __future__ import annotations

from .engine import EvidenceFactsReader, RiskEngine, RiskEngineError, StoreEvidenceFactsReader
from .provenance import RiskProvenanceReport, verify_risk_provenance
from .rules import SCORING_METHOD, EvidenceFacts
from .store import (
    MAX_RECORD_BYTES,
    CorruptRiskAssessmentError,
    InvalidRiskAssessmentIdentifierError,
    RiskAssessmentIdCollisionError,
    RiskAssessmentRecordTooLargeError,
    RiskAssessmentStore,
    RiskAssessmentStoreError,
)

__all__ = [
    "MAX_RECORD_BYTES",
    "SCORING_METHOD",
    "CorruptRiskAssessmentError",
    "EvidenceFacts",
    "EvidenceFactsReader",
    "InvalidRiskAssessmentIdentifierError",
    "RiskAssessmentIdCollisionError",
    "RiskAssessmentRecordTooLargeError",
    "RiskAssessmentStore",
    "RiskAssessmentStoreError",
    "RiskEngine",
    "RiskEngineError",
    "RiskProvenanceReport",
    "StoreEvidenceFactsReader",
    "verify_risk_provenance",
]
