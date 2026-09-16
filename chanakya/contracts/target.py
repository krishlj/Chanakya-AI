"""Target contract — docs/CONTRACTS.md §6.

Metadata describing a resolvable target only — never a live connection or
credential handle (those belong to a future Target Adapter, not this
object; see docs/ARCHITECTURE.md §7 and the Phase 2 implementation notes'
"known limitations").
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Mapping, Optional


@dataclass(frozen=True)
class Target:
    target_id: str
    contract_version: str
    target_type: str
    display_name: str
    authorized_scope: str
    registered_at: str
    metadata: Mapping[str, Any] = field(default_factory=dict)
    owner_contact: Optional[str] = None

    def __post_init__(self) -> None:
        # docs/CONTRACTS.md §6 validation requirements: "authorized_scope is
        # required and must be specific — a target record with an empty or
        # wildcard scope must be rejected at registration."
        if not self.authorized_scope or not self.authorized_scope.strip():
            raise ValueError("Target.authorized_scope must be non-empty and specific")
        if self.authorized_scope.strip() in {"*", "any", "all"}:
            raise ValueError("Target.authorized_scope must not be an unbounded wildcard")
