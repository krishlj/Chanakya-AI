"""Shared contract-level enums, per docs/CONTRACTS.md.

Kept in one module because ``Verdict``, ``Classification``, and
``RiskCategory`` are each referenced by more than one contract object
(``ToolRequest``/``PolicyDecision``/``Evidence`` in the design docs) and by
both the Registry and the Policy Gateway implementations here.
"""
from __future__ import annotations

from enum import Enum


class Verdict(str, Enum):
    """docs/CONTRACTS.md §5 — PolicyDecision.verdict. Exactly these three
    values are valid; there is no fourth option."""

    ALLOW = "allow"
    DENY = "deny"
    REQUIRE_APPROVAL = "require_approval"


class Classification(str, Enum):
    """docs/CONTRACTS.md §7 — Evidence.classification / the Security Tool
    Registry's read-only vs. state-changing classification (SR-1)."""

    READ_ONLY = "read_only"
    STATE_CHANGING = "state_changing"


class RiskCategory(str, Enum):
    """docs/CONTRACTS.md §9 — RiskAssessment.severity; also used as the
    Security Tool Registry's `default_risk_category` (docs/TOOL-REGISTRY.md)."""

    INFORMATIONAL = "informational"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class ModelEgress(str, Enum):
    """Phase 15: whether a capability's verified output may leave the host
    as model context. Declared by the administrator in the Registry and
    carried in the CapabilityEnvelope. A data-flow constraint, never an
    authorization verdict. There is no default: a missing or unknown value
    fails closed."""

    ALLOWED = "allowed"
    EVIDENCE_ONLY = "evidence_only"


#: docs/CONTRACTS.md conventions — "a consumer must reject or explicitly
#: handle a version it does not recognize rather than guessing at an
#: unfamiliar shape."
SUPPORTED_CONTRACT_VERSIONS = frozenset({"1.0.0"})
