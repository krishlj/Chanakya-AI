"""TargetManager — docs/TARGET-MANAGER.md (Phase 4.4 foundation, extended
in Phase 4.5 with identity/lifecycle).

Composes the existing ``TargetRegistry`` (docs/TARGET-MANAGER.md §7:
"Target Manager composes TargetRegistry — it does not wrap it thinly,
extend it by subclassing, or replace it"). ``TargetRegistry``'s interface
and role are unchanged; ``PolicyGateway`` and ``InvestigationManager``
continue to depend on it directly, exactly as today, entirely unaware
this class exists.

Phase 4.5 adds lifecycle transitions (docs/TARGET-MANAGER.md §6):
``Target`` stores ``status`` (frozen — a transition produces a new
revision, never mutates in place); ``TargetManager`` is the sole owner of
transition *logic*, enforcing ``ALLOWED_TARGET_STATUS_TRANSITIONS`` and
failing closed (``InvalidTargetStatusTransitionError``) on anything not
in that table; ``PolicyGateway`` only ever reads ``status`` (see
``chanakya.policy.gateway``'s step-4 scope check) and never calls a
transition method.

Phase 4.6 adds adapter registration/selection (docs/TARGET-MANAGER.md §8):
``register_adapter``/``select_adapter`` maintain an explicit,
admin-driven ``target_type -> TargetAdapter`` mapping — fail-closed on an
unknown type, rejecting duplicate/conflicting registrations, and never
selecting an adapter from untrusted (e.g. Agent- or target-supplied)
data. No concrete adapter is implemented yet (``LocalHostAdapter`` is
Phase 4.7), and no adapter method is ever called by this class in this
phase — registration/selection is the entire surface.

Phase 4.8 adds ``collect_environment`` (docs/TARGET-MANAGER.md §9/§14):
the explicit, never-automatic wiring from a registered target through a
registered adapter to an ``EnvironmentContext``. Nothing calls this
method automatically — not ``register``, not ``transition_status``, not
anything else in this class. It fails closed with respect to
authorization on every error path (unknown target, unregistered adapter,
or the adapter's own collection raising): the result is always a
structured ``EnvironmentCollectionResult``, never a raised exception that
could be mistaken for something else, and never a ``Target`` mutation of
any kind — mirrors ``PolicyGateway.evaluate()``'s own documented
fail-closed ``try/except Exception`` precedent (SR-9), applied here to
descriptive collection rather than to authorization.

Still deliberately NOT implemented (later phases in the approved design):

- remote/non-local adapters, discovery workflows            -> future phases

Security boundary (docs/TARGET-MANAGER.md §2, TM-INV-1/TM-INV-3): this
module imports nothing from ``chanakya.policy`` or ``chanakya.runtime``.
It has no method that returns, constructs, or is consulted for a
``PolicyDecision``, an ``ApprovalDecision``, or a dispatch. It cannot
authorize a tool request and cannot execute anything. A lifecycle
transition changes only ``status`` (and, for the two checks named in
§12, ``last_verified_at``) — every other field, including every identity
field, carries over unchanged from the prior revision (TM-INV-9;
Phase 4.3 finding F-2's "replacing target metadata cannot silently
create a different target identity").
"""
from __future__ import annotations

import dataclasses
from datetime import datetime, timezone
from typing import Iterable, Optional, Tuple

from chanakya.contracts.target import (
    ALLOWED_INITIAL_TARGET_STATUSES,
    ALLOWED_TARGET_STATUS_TRANSITIONS,
    Target,
    TargetStatus,
)

from .adapter import TargetAdapter
from .environment import EnvironmentContext
from .exceptions import (
    DuplicateAdapterRegistrationError,
    InvalidTargetStatusTransitionError,
    NoAdapterRegisteredError,
    UnregisteredTargetError,
)
from .registry import TargetRegistry


@dataclasses.dataclass(frozen=True)
class EnvironmentCollectionResult:
    """The structured, always-returned (never-raised) outcome of
    ``TargetManager.collect_environment`` (docs/TARGET-MANAGER.md §9/§14,
    Phase 4.8 error-handling requirement: "return structured failure
    information where appropriate"). Exactly one of
    ``environment_context``/``error`` is set. Never itself authorization-
    bearing — nothing about this object is read by ``PolicyGateway``."""

    target_id: str
    environment_context: Optional[EnvironmentContext] = None
    error: Optional[str] = None

    @property
    def succeeded(self) -> bool:
        return self.environment_context is not None


def _utcnow_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


#: docs/TARGET-MANAGER.md §12 — the only two transitions that update
#: ``last_verified_at``: a discovery candidate being confirmed, and an
#: unavailable target's recovery check. Named explicitly rather than
#: updating it on every transition into AUTHORIZED/VALIDATED, so it
#: doesn't become redundant with ``provenance.observed_at`` (F-3).
_VERIFYING_TRANSITIONS = frozenset(
    {
        (TargetStatus.DISCOVERED, TargetStatus.VALIDATED),
        (TargetStatus.UNAVAILABLE, TargetStatus.AUTHORIZED),
    }
)


class TargetManager:
    """Identifies and contextualizes targets. Never decides whether an
    action against one is permitted — that is exclusively the Policy
    Gateway's job (docs/TARGET-MANAGER.md, design principle)."""

    def __init__(self, registry: TargetRegistry) -> None:
        self._registry = registry
        self._adapters: dict = {}

    # -- target registration / lookup ---------------------------------------

    def register(self, target: Target) -> None:
        """Delegates to the composed ``TargetRegistry``, after enforcing
        the one lifecycle rule that applies at registration time: the
        initial ``status`` must be one docs/TARGET-MANAGER.md §6 actually
        allows as an entry point (``DISCOVERED`` or ``AUTHORIZED`` — every
        other state is reachable only via ``transition_status``, never as
        a starting point). Fails closed, mirroring
        ``transition_status``'s own behavior, rather than silently
        accepting an invalid initial state.
        """
        if target.status not in ALLOWED_INITIAL_TARGET_STATUSES:
            raise InvalidTargetStatusTransitionError(
                f"cannot register target with initial status {target.status.value!r}; "
                f"only {sorted(s.value for s in ALLOWED_INITIAL_TARGET_STATUSES)} are valid "
                f"registration entry points"
            )
        self._registry.register(target)

    def get(self, target_id: str) -> Optional[Target]:
        """Delegates to the composed ``TargetRegistry``. Returns ``None``
        for an unknown id — never raises, mirroring
        ``TargetRegistry.get``'s existing behavior exactly."""
        return self._registry.get(target_id)

    # -- investigation-scoped target management ------------------------------

    def resolve(self, target_ids: Iterable[str]) -> Tuple[Target, ...]:
        """Resolves every id to a registered ``Target``, failing closed.

        Raises ``UnregisteredTargetError`` on the first id that does not
        resolve — never silently drops or substitutes a target. This is
        the same check ``InvestigationManager.create_investigation``
        already performs inline against its own injected
        ``TargetRegistry`` (unchanged in this phase); ``TargetManager``
        exposes it as a reusable capability without altering that
        existing Runtime code path.
        """
        resolved = []
        for target_id in target_ids:
            target = self._registry.get(target_id)
            if target is None:
                raise UnregisteredTargetError(f"target is not registered: {target_id!r}")
            resolved.append(target)
        return tuple(resolved)

    # -- lifecycle transitions --------------------------------------------------

    def transition_status(self, target_id: str, new_status: TargetStatus, *, actor: str) -> Target:
        """The sole entry point for changing a registered ``Target``'s
        ``status`` (docs/TARGET-MANAGER.md §6 ownership model:
        "TargetManager: performs lifecycle transitions"). Fails closed —
        raises ``UnregisteredTargetError`` for an unknown target and
        ``InvalidTargetStatusTransitionError`` for any transition not in
        ``ALLOWED_TARGET_STATUS_TRANSITIONS`` — never silently coerces to
        the nearest valid state.

        ``actor`` is required and must be non-empty (accountability
        anchor, mirroring ``ApprovalDecision.decided_by``'s pattern
        elsewhere in this codebase) even though Phase 4.5 does not yet
        wire it into an audit trail (docs/TARGET-MANAGER.md §17 defers
        dedicated ``AuditEvent`` values for target lifecycle events).

        Every field other than ``status`` (and, for the two verifying
        transitions named in §12, ``last_verified_at``) is carried over
        unchanged from the current revision — this is what makes a
        lifecycle transition unable to silently change a target's
        identity, locator, authorized_scope, or provenance (TM-INV-9).
        """
        if not actor or not actor.strip():
            raise ValueError("TargetManager.transition_status requires a non-empty actor")

        current = self._registry.get(target_id)
        if current is None:
            raise UnregisteredTargetError(f"target is not registered: {target_id!r}")

        allowed = ALLOWED_TARGET_STATUS_TRANSITIONS.get(current.status, frozenset())
        if new_status not in allowed:
            raise InvalidTargetStatusTransitionError(
                f"invalid target status transition for {target_id!r}: "
                f"{current.status.value} -> {new_status.value}"
            )

        changes = {"status": new_status}
        if (current.status, new_status) in _VERIFYING_TRANSITIONS:
            changes["last_verified_at"] = _utcnow_iso()

        updated = dataclasses.replace(current, **changes)
        self._registry.replace(updated)
        return updated

    # -- adapter registration / selection ---------------------------------------

    def register_adapter(self, adapter: TargetAdapter) -> None:
        """Explicit, admin-driven registration only — nothing in this
        class ever registers an adapter on the Agent's or a target's
        behalf. Fails closed on:

        - an object that does not structurally conform to the
          ``TargetAdapter`` protocol (``TypeError``);
        - an empty ``supported_target_types`` declaration (``ValueError``);
        - any ``target_type`` that already has an adapter registered
          (``DuplicateAdapterRegistrationError`` — checked across every
          declared type *before* committing any of them, so a conflict on
          one type never leaves a partial registration for the others).

        Selection later is keyed only by this trusted, admin-established
        ``target_type -> adapter`` mapping — never inferred from a
        ``Target``'s locator, metadata, or any other untrusted data
        (docs/TARGET-MANAGER.md §8/§19 Phase 4.6).
        """
        if not isinstance(adapter, TargetAdapter):
            raise TypeError("adapter does not conform to the TargetAdapter protocol")
        if not adapter.supported_target_types:
            raise ValueError("adapter.supported_target_types must be non-empty")

        for target_type in adapter.supported_target_types:
            existing = self._adapters.get(target_type)
            if existing is not None:
                raise DuplicateAdapterRegistrationError(
                    f"an adapter is already registered for target_type {target_type!r}: "
                    f"{existing.adapter_id!r} (attempted: {adapter.adapter_id!r})"
                )

        for target_type in adapter.supported_target_types:
            self._adapters[target_type] = adapter

    def select_adapter(self, target_type: str) -> TargetAdapter:
        """Fails closed for an unregistered ``target_type`` — never
        silently falls back to any other adapter or a default."""
        adapter = self._adapters.get(target_type)
        if adapter is None:
            raise NoAdapterRegisteredError(f"no adapter registered for target_type: {target_type!r}")
        return adapter

    # -- environment collection ---------------------------------------------

    def collect_environment(self, target_id: str) -> EnvironmentCollectionResult:
        """Explicit, caller-invoked collection only — never automatic,
        never triggered by registration or a lifecycle transition
        (docs/TARGET-MANAGER.md §9/§14, Phase 4.8). Always returns an
        ``EnvironmentCollectionResult``; never raises. Every failure path
        — unregistered target, no adapter registered for its type, or the
        adapter's own ``collect_environment`` raising — produces a
        result with ``environment_context=None`` and a descriptive
        ``error``, never a fabricated success and never any mutation of
        the ``Target`` or its lifecycle state (fail-closed with respect to
        authorization, mirroring ``PolicyGateway.evaluate()``'s own
        documented outer ``try/except Exception`` — SR-9 — applied here to
        descriptive collection).
        """
        target = self._registry.get(target_id)
        if target is None:
            return EnvironmentCollectionResult(target_id=target_id, error=f"target is not registered: {target_id!r}")

        try:
            adapter = self.select_adapter(target.target_type)
        except NoAdapterRegisteredError as exc:
            return EnvironmentCollectionResult(target_id=target_id, error=str(exc))

        try:
            environment_context = adapter.collect_environment(target)
        except Exception as exc:  # adapter failure must never look like authorization — SR-9-style fail-closed
            return EnvironmentCollectionResult(
                target_id=target_id, error=f"{exc.__class__.__name__}: {exc}"
            )

        return EnvironmentCollectionResult(target_id=target_id, environment_context=environment_context)

    # -- accessors ------------------------------------------------------------

    @property
    def registry(self) -> TargetRegistry:
        """Read-only access to the composed registry — e.g. so a caller
        that already holds a ``TargetManager`` can still hand the same
        ``TargetRegistry`` instance to ``PolicyGateway``/
        ``InvestigationManager`` (docs/TARGET-MANAGER.md §7: both must
        share one registry instance, never a disconnected private copy)."""
        return self._registry
