"""Phase 5.1 Tool Layer wiring — a composition root only, no logic of its
own. Builds the one ``CapabilityDispatchExecutor`` Phase 5.1 needs, with
its handler map fixed to exactly the capabilities
``chanakya.registry.bootstrap`` registers. Consumed by whatever future
composition root (a CLI, Phase 5.4) constructs the full Runtime; nothing
in ``chanakya/runtime`` or ``chanakya/policy`` imports this module.

Phase 11: given the ``capability_registry`` the Policy Gateway uses, the
executor also receives one Registry-derived ``CapabilityEnvelope`` per
handler (``envelope_from_registry_entry``, the same conversion the Gateway
uses) and refuses any instruction whose envelope differs. A handler
without an enabled Registry entry, or whose entry declares an open output
schema, fails here at composition.
"""
from __future__ import annotations

from typing import Any, Optional

from chanakya.capability.envelope import envelope_from_registry_entry
from chanakya.capability.schema import find_open_schema_violations
from chanakya.targets.registry import TargetRegistry

from .executor import CapabilityDispatchExecutor
from .handlers import http_probe_local, listening_ports
from .handlers.local_host_environment import CAPABILITY_ID, LocalHostEnvironmentHandler


def build_tool_executor(
    target_registry: TargetRegistry, *, capability_registry: Optional[Any] = None
) -> CapabilityDispatchExecutor:
    """The production ``ToolExecutor``: ``observe_local_host_environment``
    (Phase 5.1), ``list_listening_ports`` (Phase 8) and ``http_probe_local``
    (the local web-security POC probe). Must stay in step with
    ``chanakya.registry.bootstrap.production_registry_entries``.

    ``capability_registry`` is anything with ``get_enabled(capability)``
    (a ``SecurityToolRegistry``). It is read once, here, to build the
    parity envelopes; it is never consulted at execution time."""
    handlers = {
        CAPABILITY_ID: LocalHostEnvironmentHandler(),
        listening_ports.CAPABILITY_ID: listening_ports.ListeningPortsHandler(),
        http_probe_local.CAPABILITY_ID: http_probe_local.HttpProbeLocalHandler(),
    }
    envelopes = None
    if capability_registry is not None:
        envelopes = {}
        for capability in handlers:
            entry = capability_registry.get_enabled(capability)
            if entry is None:
                raise ValueError(f"handler {capability!r} has no enabled Registry entry")
            if find_open_schema_violations(entry.output_schema):
                raise ValueError(f"capability {capability!r} does not declare a closed output schema")
            envelopes[capability] = envelope_from_registry_entry(entry)
    return CapabilityDispatchExecutor(target_registry, handlers, envelopes=envelopes)
