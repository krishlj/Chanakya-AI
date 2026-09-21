"""Phase 5.1 Tool Layer wiring — a composition root only, no logic of its
own. Builds the one ``CapabilityDispatchExecutor`` Phase 5.1 needs, with
its handler map fixed to exactly the capabilities
``chanakya.registry.bootstrap`` registers. Consumed by whatever future
composition root (a CLI, Phase 5.4) constructs the full Runtime; nothing
in ``chanakya/runtime`` or ``chanakya/policy`` imports this module.
"""
from __future__ import annotations

from chanakya.targets.registry import TargetRegistry

from .executor import CapabilityDispatchExecutor
from .handlers.local_host_environment import CAPABILITY_ID, LocalHostEnvironmentHandler


def build_tool_executor(target_registry: TargetRegistry) -> CapabilityDispatchExecutor:
    """The Phase 5.1 production ``ToolExecutor``: one capability,
    ``observe_local_host_environment``, backed by ``LocalHostEnvironmentHandler``."""
    return CapabilityDispatchExecutor(
        target_registry,
        {CAPABILITY_ID: LocalHostEnvironmentHandler()},
    )
