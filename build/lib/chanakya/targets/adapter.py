"""TargetAdapter protocol — docs/TARGET-MANAGER.md §8 (Phase 4.6).

A conceptual interface only — no concrete adapter is implemented in this
phase (``LocalHostAdapter`` is Phase 4.7). Mirrors how
docs/AGENT-RUNTIME.md §7 defined ``DispatchInstruction``/``ToolExecutor``
as a stable interface before any Tool Layer existed to implement it.

Hard rule (docs/TARGET-MANAGER.md §8, restated): **a ``TargetAdapter``
MUST NOT create an independent execution path.** This module — and every
type it defines — has no reference to ``chanakya.policy`` or
``chanakya.runtime`` at all, so there is nothing here through which a
policy decision could be produced, consulted, or bypassed, and nothing
here that could invoke the Dispatcher. If a future adapter's target type
needs an execution-capable operation, that operation must be represented
as a Registry-registered capability and dispatched through the existing,
unchanged pipeline:

    Agent Runtime -> Policy Gateway -> Tool Registry -> Dispatcher -> Adapter/tool

Every result type below is plain, descriptive data — none of them has a
field resembling a verdict, an approval, or a credential.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Mapping, Optional, Protocol, Sequence, Tuple, runtime_checkable

from chanakya.contracts.target import Target

from .environment import EnvironmentContext


@dataclass(frozen=True)
class DiscoveryResult:
    """Proposed ``DISCOVERED``-status candidate targets (docs/TARGET-MANAGER.md
    §6/§8). Reuses ``Target`` rather than inventing a parallel shape —
    no second Target-shaped object is introduced (§4). Not consumed by
    anything in this phase; no discovery workflow is implemented yet."""

    candidates: Tuple[Target, ...] = field(default_factory=tuple)


@dataclass(frozen=True)
class ValidationResult:
    """Feeds a future ``DISCOVERED -> VALIDATED`` transition
    (docs/TARGET-MANAGER.md §6/§12). A descriptive signal only — it does
    not itself perform the transition; that remains
    ``TargetManager.transition_status``'s exclusive job."""

    is_valid: bool
    reason: Optional[str] = None


@dataclass(frozen=True)
class AvailabilityResult:
    """Feeds a future ``AUTHORIZED <-> UNAVAILABLE`` transition
    (docs/TARGET-MANAGER.md §6/§12). Same non-authoritative status as
    ``ValidationResult`` above."""

    is_available: bool
    reason: Optional[str] = None


@runtime_checkable
class TargetAdapter(Protocol):
    """docs/TARGET-MANAGER.md §8. Structural (``Protocol``) interface —
    an adapter conforms by shape, not by inheritance. ``TargetManager``
    checks conformance at registration time via ``isinstance`` (see
    ``chanakya.targets.manager.TargetManager.register_adapter``).

    Trust level: semi-trusted, execution-**incapable** at the Target
    Manager boundary (docs/TARGET-MANAGER.md §8). An adapter can propose
    facts and signals; it cannot authorize anything and cannot execute
    anything on Target Manager's behalf.
    """

    adapter_id: str
    supported_target_types: Sequence[str]

    def discover(self, config: Mapping[str, Any]) -> DiscoveryResult:
        ...

    def validate(self, target: Target) -> ValidationResult:
        ...

    def check_availability(self, target: Target) -> AvailabilityResult:
        ...

    def collect_environment(self, target: Target) -> EnvironmentContext:
        ...
