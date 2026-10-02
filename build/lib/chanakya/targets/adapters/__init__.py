"""Concrete Target Adapters — docs/ARCHITECTURE.md §7's ``targets/adapters/``
module. Phase 4.7 implements the first (and, in this phase, only) one:
``LocalHostAdapter``.
"""
from .local_host import LocalHostAdapter

__all__ = ["LocalHostAdapter"]
