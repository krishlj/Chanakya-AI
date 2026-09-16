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
