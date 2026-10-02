"""A minimal, descriptive-only target registry.

This backs the Policy Gateway's target-scope checks (docs/POLICY-GATEWAY.md
§4) with the same descriptive ``Target`` record defined in
docs/CONTRACTS.md §6. It is deliberately NOT the future Target Manager /
Target Adapters (docs/ARCHITECTURE.md §6-7): it holds no live
connection/credential handle and resolves no adapter — it only stores and
looks up ``Target`` metadata, which is all the Gateway needs to validate
that a requested target is registered and of the right type. See the
Phase 2 implementation notes' "known limitations" for what a real Target
Manager will still need to add.
"""
from __future__ import annotations

from typing import Dict, Iterable, Optional

from chanakya.contracts.target import Target


class TargetRegistry:
    def __init__(self, targets: Iterable[Target] = ()) -> None:
        self._by_id: Dict[str, Target] = {}
        for target in targets:
            self.register(target)

    def register(self, target: Target) -> None:
        if target.target_id in self._by_id:
            raise ValueError(f"target already registered: {target.target_id!r}")
        self._by_id[target.target_id] = target

    def get(self, target_id: str) -> Optional[Target]:
        return self._by_id.get(target_id)

    def replace(self, target: Target) -> None:
        """docs/TARGET-MANAGER.md §7 (Phase 4.3 finding F-2) — a
        controlled revision swap for an *already-registered* ``target_id``,
        the mirror opposite of ``register()`` (which requires the id NOT
        to already exist). Used exclusively by ``TargetManager``'s
        lifecycle-transition methods, never called directly by
        ``PolicyGateway`` or anything else.

        ``get()``'s signature and behavior are unchanged — a caller
        (the Gateway included) sees the new revision on its next call,
        with no new dependency and no widened contract.

        Guards against identity drift under the same ``target_id``: the
        new revision's ``target_type`` must match the current one exactly
        (docs/TARGET-MANAGER.md §4 groups ``target_type`` under
        *identity*, not mutable state) — this is a defense-in-depth check
        independent of whatever a caller intended, mirroring this
        codebase's existing pattern of runtime assertions alongside
        caller-level discipline (e.g. ``PolicyGateway``'s INV-1 check).
        """
        current = self._by_id.get(target.target_id)
        if current is None:
            raise ValueError(f"cannot replace unregistered target: {target.target_id!r}")
        if current.target_type != target.target_type:
            raise ValueError(
                f"cannot replace target {target.target_id!r}: target_type would change "
                f"from {current.target_type!r} to {target.target_type!r} (identity drift)"
            )
        self._by_id[target.target_id] = target
