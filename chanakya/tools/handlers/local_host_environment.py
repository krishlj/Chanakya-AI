"""observe_local_host_environment — Phase 5.1's first, and only, production
capability (approved Phase 5.1 Tool Layer design report §3).

Wraps ``chanakya.targets.adapters.local_host.LocalHostAdapter.
collect_environment`` — unmodified, reused as-is — as an explicit,
Agent-invocable capability. This is a distinct integration path from that
adapter's existing, separate use for automatic environment-context
priming (docs/TARGET-MANAGER.md §11/§14, Phase 4.8): both call the same
adapter method, but only this path goes through ToolRequest -> Policy
Gateway -> Dispatcher -> ToolResult -> Evidence.

Accepts no parameters — the Registry's ``parameters_schema`` for this
capability is closed (``{"type": "object", "properties": {}, ...
"additionalProperties": false}``), so nothing Agent-supplied ever reaches
this handler. It performs no logic of its own beyond calling the adapter
and projecting its return value (an ``EnvironmentContext``) into a plain,
JSON-shaped dict for ``ToolResult.output`` — the same projection
``chanakya.runtime.context_assembler.ContextAssembler`` already uses for
this data elsewhere, so there is exactly one serialization convention for
it in the codebase.
"""
from __future__ import annotations

from typing import Any, Mapping, Optional, Sequence

from chanakya.contracts.target import Target
from chanakya.targets.adapters.local_host import LocalHostAdapter

#: Must match the ``capability`` field of the production ``RegistryEntry``
#: this handler is wired to (``chanakya.registry.bootstrap``) — kept as a
#: plain string constant, not a cross-package import, matching this
#: codebase's existing convention of matching capability identifiers by
#: value (e.g. ``"list_listening_ports"``) rather than a shared symbol.
CAPABILITY_ID = "observe_local_host_environment"

_SUPPORTED_TARGET_TYPES: Sequence[str] = ("local_host",)


class LocalHostEnvironmentHandler:
    """``CapabilityHandler`` wrapping ``LocalHostAdapter.collect_environment``."""

    supported_target_types = _SUPPORTED_TARGET_TYPES

    def __init__(self, adapter: Optional[LocalHostAdapter] = None) -> None:
        self._adapter = adapter if adapter is not None else LocalHostAdapter()

    def run(self, target: Target, parameters: Mapping[str, Any]) -> Mapping[str, Any]:
        environment_context = self._adapter.collect_environment(target)
        return {
            "environment_context_id": environment_context.environment_context_id,
            "target_id": environment_context.target_id,
            "collected_by": environment_context.collected_by,
            "collected_at": environment_context.collected_at,
            "source": environment_context.source.value,
            "observations": [
                {
                    "key": observation.key,
                    "value": observation.value,
                    "confidence": observation.confidence.value if observation.confidence is not None else None,
                    "notes": observation.notes,
                }
                for observation in environment_context.observations
            ],
        }
