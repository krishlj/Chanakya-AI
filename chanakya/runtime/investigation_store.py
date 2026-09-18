"""InvestigationStateStore — docs/AGENT-RUNTIME.md component map.

The authoritative, single-writer store of ``InvestigationContext``
instances for the life of an investigation. Deliberately trivial: an
in-memory, dict-backed lookup. Persistence is out of scope for this
step (Phase 2's registries are in-memory too — see
docs/PHASE-2-IMPLEMENTATION.md "known limitations"; the same applies
here by design continuity, not oversight).
"""
from __future__ import annotations

from typing import Dict, Iterator

from chanakya.contracts.investigation_context import InvestigationContext

from .exceptions import UnknownInvestigationError


class InvestigationStateStore:
    def __init__(self) -> None:
        self._by_id: Dict[str, InvestigationContext] = {}

    def create(self, context: InvestigationContext) -> None:
        if context.investigation_id in self._by_id:
            raise ValueError(f"investigation already exists: {context.investigation_id!r}")
        self._by_id[context.investigation_id] = context

    def get(self, investigation_id: str) -> InvestigationContext:
        try:
            return self._by_id[investigation_id]
        except KeyError as exc:
            raise UnknownInvestigationError(f"unknown investigation: {investigation_id!r}") from exc

    def exists(self, investigation_id: str) -> bool:
        return investigation_id in self._by_id

    def __iter__(self) -> Iterator[InvestigationContext]:
        return iter(self._by_id.values())

    def __len__(self) -> int:
        return len(self._by_id)
