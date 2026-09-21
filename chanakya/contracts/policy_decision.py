"""PolicyDecision contract — docs/CONTRACTS.md §5.

Immutable once issued (a frozen dataclass): "a changed mind requires a new
`ToolRequest` and a new `PolicyDecision`, preserving a clean audit trail."

``classification`` (Phase 5.2.1) is an additive, optional field — every
existing construction call site that omits it continues to work
unchanged, defaulting to ``None``. It exists solely so a future Evidence
Writer can snapshot the Registry's ``classification`` for a capability
*as it was at the moment this decision was made* (docs/CONTRACTS.md §7's
``Evidence.classification`` requirement — "so history remains accurate
even if the Registry entry later changes"), without a second, later
Registry lookup that could observe a since-changed value. Adding this
field does not itself populate it: ``chanakya.policy.gateway.
PolicyGateway`` is unmodified by this phase and does not yet set it on
any ``PolicyDecision`` it constructs — that wiring is deferred to the
phase that actually needs it.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Optional

from .enums import Classification, RiskCategory, Verdict


@dataclass(frozen=True)
class PolicyDecision:
    policy_decision_id: str
    contract_version: str
    tool_request_id: str
    verdict: Verdict
    matched_rule: str
    reason: str
    evaluated_at: str
    risk_category: Optional[RiskCategory] = None
    notes: Optional[str] = None
    classification: Optional[Classification] = None

    def to_dict(self) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "policy_decision_id": self.policy_decision_id,
            "contract_version": self.contract_version,
            "tool_request_id": self.tool_request_id,
            "verdict": self.verdict.value,
            "matched_rule": self.matched_rule,
            "reason": self.reason,
            "evaluated_at": self.evaluated_at,
        }
        if self.risk_category is not None:
            payload["risk_category"] = self.risk_category.value
        if self.notes is not None:
            payload["notes"] = self.notes
        if self.classification is not None:
            payload["classification"] = self.classification.value
        return payload
