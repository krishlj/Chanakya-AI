"""Per-turn EnvironmentContext source — docs/TARGET-AWARE-AGENT-CONTEXT.md
§13a (Phase 5.7.6).

``TargetManagerEnvironmentSource`` structurally satisfies the Runtime's
narrow ``EnvironmentContextSource`` Protocol
(``chanakya.runtime.context_assembler``) on top of the existing, explicit
``TargetManager.collect_environment``. It is opt-in: the Runtime only
collects environment data when an operator constructs one of these and
hands it to ``AgentLoopController(environment_context_source=...)``.

Freshness (docs/TARGET-MANAGER.md §11): every call re-collects through the
registered adapter. Nothing is cached — not per target, not per
investigation, not globally — so one investigation can never observe
another's snapshot and a stale observation is never reused.

Fails closed: if any requested target cannot be collected (unregistered
target, no adapter for its type, adapter raised, adapter returned
something other than an ``EnvironmentContext`` for that exact
``target_id``), the whole call raises
``EnvironmentContextUnavailableError`` and returns nothing — never a
partial result with that target silently missing.

Exposes nothing but the one collection method: no lifecycle transition,
no adapter registration/selection, no registry handle.
"""
from __future__ import annotations

from typing import Sequence, Tuple

from .environment import EnvironmentContext
from .manager import TargetManager


class EnvironmentContextUnavailableError(RuntimeError):
    """Environment collection failed for at least one requested target."""


class TargetManagerEnvironmentSource:
    def __init__(self, target_manager: TargetManager) -> None:
        if not isinstance(target_manager, TargetManager):
            raise TypeError("TargetManagerEnvironmentSource requires a TargetManager")
        self.__target_manager = target_manager

    def collect_environment_contexts(self, target_ids: Sequence[str]) -> Tuple[EnvironmentContext, ...]:
        """One fresh ``EnvironmentContext`` per distinct id, in
        first-occurrence order."""
        if isinstance(target_ids, (str, bytes)):
            raise TypeError("collect_environment_contexts requires a collection of target ids, not a single string")

        collected = []
        seen = set()
        for target_id in target_ids:
            if target_id in seen:
                continue
            seen.add(target_id)
            result = self.__target_manager.collect_environment(target_id)
            if not result.succeeded:
                # Phase 17: a fixed message; the adapter's text never travels.
                raise EnvironmentContextUnavailableError("environment collection failed")
            environment_context = result.environment_context
            # Phase 5.7.7: an adapter asked about one target must answer
            # about that target. Without this, a context the adapter labels
            # with a different in-scope target_id would pass the Runtime's
            # binding check and be shown to the model as that other
            # target's observations.
            if not isinstance(environment_context, EnvironmentContext):
                raise EnvironmentContextUnavailableError("environment collection did not return an EnvironmentContext")
            if type(environment_context.target_id) is not str or environment_context.target_id != target_id:
                raise EnvironmentContextUnavailableError("environment collection returned a context for a different target")
            collected.append(environment_context)
        return tuple(collected)


__all__ = ["EnvironmentContextUnavailableError", "TargetManagerEnvironmentSource"]
