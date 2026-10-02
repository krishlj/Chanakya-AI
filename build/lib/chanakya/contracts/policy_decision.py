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

``capability_envelope`` (Phase 11) is a second additive, optional snapshot:
the ``CapabilityEnvelope`` (output schema, maximum output bytes, declared
timeout) the Gateway derived from the same ``RegistryEntry`` it used for
this decision. The Runtime dispatches under it and the Tool Layer enforces
it, so execution is constrained by the Registry state that was authorized,
with no second Registry lookup on the execution path. Like
``classification`` it is never an authorization signal: the verdict alone
decides whether anything runs.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Optional

from chanakya.capability.envelope import CapabilityEnvelope

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
    capability_envelope: Optional[CapabilityEnvelope] = None

    def __post_init__(self) -> None:
        if self.capability_envelope is not None and not isinstance(self.capability_envelope, CapabilityEnvelope):
            raise TypeError("PolicyDecision.capability_envelope must be a CapabilityEnvelope")

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
        if self.capability_envelope is not None:
            payload["capability_envelope"] = self.capability_envelope.to_dict()
        return payload
