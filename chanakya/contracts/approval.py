"""ApprovalRequest / ApprovalDecision contracts — docs/CONTRACTS.md §11-12.

The only pair of contracts that can convert a ``require_approval``
``PolicyDecision`` into an executable action. Nothing in this module
grants approval on its own — these are pure data records; the Runtime's
Approval Coordinator (docs/AGENT-RUNTIME.md §13) and the dispatch
precondition check (docs/AGENT-RUNTIME.md §7) are what actually gate
execution on them.
"""
from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Any, Mapping, Optional

#: docs/CONTRACTS.md §12 validation requirements: "decided_by must
#: identify a human, never a system or agent identity."
_RESERVED_IDENTITIES = frozenset({"agent", "system"})


class ApprovalStatus(str, Enum):
    """docs/CONTRACTS.md §11 — ApprovalRequest.status."""

    PENDING = "pending"
    DECIDED = "decided"
    EXPIRED = "expired"


class ApprovalDecisionValue(str, Enum):
    """docs/CONTRACTS.md §12 — ApprovalDecision.decision. Exactly these
    two values; there is no partial/conditional value (SR-7)."""

    ACCEPT = "accept"
    DENY = "deny"


@dataclass(frozen=True)
class ApprovalRequest:
    approval_request_id: str
    contract_version: str
    investigation_id: str
    tool_request_id: str
    policy_decision_id: str
    risk_context: Mapping[str, Any]
    status: ApprovalStatus
    requested_at: str
    expires_at: Optional[str] = None
    risk_assessment_ref: Optional[str] = None


@dataclass(frozen=True)
class ApprovalDecision:
    approval_decision_id: str
    contract_version: str
    approval_request_id: str
    decision: ApprovalDecisionValue
    decided_by: str
    decided_at: str
    justification: Optional[str] = None

    def __post_init__(self) -> None:
        if not self.decided_by or self.decided_by in _RESERVED_IDENTITIES:
            raise ValueError(
                "ApprovalDecision.decided_by must identify a human, not "
                f"the reserved identity {self.decided_by!r}"
            )
