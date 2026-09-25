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
from .handlers import listening_ports
from .handlers.local_host_environment import CAPABILITY_ID, LocalHostEnvironmentHandler


def build_tool_executor(target_registry: TargetRegistry) -> CapabilityDispatchExecutor:
    """The production ``ToolExecutor``: ``observe_local_host_environment``
    (Phase 5.1) and ``list_listening_ports`` (Phase 8). Must stay in step
    with ``chanakya.registry.bootstrap.production_registry_entries``."""
    return CapabilityDispatchExecutor(
        target_registry,
        {
            CAPABILITY_ID: LocalHostEnvironmentHandler(),
            listening_ports.CAPABILITY_ID: listening_ports.ListeningPortsHandler(),
        },
    )
