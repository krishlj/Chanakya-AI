"""EnvironmentContext / TargetObservation — docs/TARGET-MANAGER.md §10.

The minimum contract required for Phase 4.6's ``TargetAdapter`` protocol
to have a concrete, meaningful return type for ``collect_environment``.
This module defines the **data shape only** — no collection logic, no
freshness/caching (docs/TARGET-MANAGER.md §12 — deferred), and no wiring
into the Context Assembler or any LLM prompt path (docs/TARGET-MANAGER.md
§9's Phase 4.8, "Policy Integration"). Nothing here is produced by a real
adapter yet — Phase 4.7 implements the first one (``LocalHostAdapter``).

``Target`` = stable identity/authorization descriptor.
``EnvironmentContext`` = time-sensitive descriptive observations.
Neither this module nor anything that consumes it may ever treat an
``EnvironmentContext``/``TargetObservation`` as an authorization input —
``PolicyGateway`` never imports this module (TM-INV-2, TM-INV-8).
"""
from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Any, Optional, Tuple


class ObservationConfidence(str, Enum):
    """docs/TARGET-MANAGER.md §13 — reuses the same three-value pattern
    already established for ``Finding.confidence``/``RiskAssessment.confidence``
    in docs/CONTRACTS.md."""

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"


class EnvironmentSource(str, Enum):
    """docs/TARGET-MANAGER.md §13 — where an ``EnvironmentContext`` came
    from. Every value except ``USER_DECLARED`` is untrusted-until-
    consistent descriptive data (docs/TARGET-MANAGER.md §13's "critical
    rule"), and even ``USER_DECLARED`` here is never authorization-bearing
    — see the module docstring."""

    USER_DECLARED = "user_declared"
    LOCAL_ADAPTER = "local_adapter"
    CLOUD_API = "cloud_api"
    KUBERNETES_API = "kubernetes_api"
    REPOSITORY_SOURCE = "repository_source"
    TOOL_RESULT = "tool_result"


@dataclass(frozen=True)
class TargetObservation:
    """The atomic unit — one discrete descriptive fact (docs/TARGET-MANAGER.md
    §10). Never a credential carrier; never itself authorization-bearing."""

    key: str
    value: Any
    confidence: Optional[ObservationConfidence] = None
    notes: Optional[str] = None

    def __post_init__(self) -> None:
        if not self.key or not self.key.strip():
            raise ValueError("TargetObservation.key must be non-empty")


@dataclass(frozen=True)
class EnvironmentContext:
    """The aggregate — one adapter collection run (docs/TARGET-MANAGER.md
    §10). References ``target_id`` only — never re-declares
    ``target_type``/``authorized_scope``/``display_name`` (no second
    Target-shaped object, §4). Never read by ``PolicyGateway.evaluate()``
    — not filtered out afterward, never passed in the first place
    (TM-INV-2)."""

    environment_context_id: str
    contract_version: str
    target_id: str
    collected_by: str
    collected_at: str
    observations: Tuple[TargetObservation, ...]
    source: EnvironmentSource
    overall_confidence: Optional[ObservationConfidence] = None

    def __post_init__(self) -> None:
        for field_name in ("environment_context_id", "contract_version", "target_id", "collected_by", "collected_at"):
            if not getattr(self, field_name):
                raise ValueError(f"EnvironmentContext.{field_name} must be non-empty")
