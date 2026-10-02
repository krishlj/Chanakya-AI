"""Tool Layer — docs/ARCHITECTURE.md §8 (MCP / Tool Layer), Phase 5.1.

The first concrete implementation of ``chanakya.runtime.dispatch.ToolExecutor``.
Everything upstream (ToolRequest Intake, Policy Gateway, Security Tool
Registry, Dispatcher) is unmodified and unaware this package exists beyond
the ``ToolExecutor`` Protocol it already defined in Phase 3. See the
approved Phase 5.1 Tool Layer design report for the full rationale.
"""
from __future__ import annotations

from .executor import CapabilityDispatchExecutor, CapabilityHandler

__all__ = ["CapabilityDispatchExecutor", "CapabilityHandler"]
