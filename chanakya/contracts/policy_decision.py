"""PolicyDecision contract — docs/CONTRACTS.md §5.

Immutable once issued (a frozen dataclass): "a changed mind requires a new
`ToolRequest` and a new `PolicyDecision`, preserving a clean audit trail."
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Optional

from .enums import RiskCategory, Verdict


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
        return payload
