"""CapabilityDispatchExecutor — the concrete ``ToolExecutor`` (Phase 5.1).

Implements ``chanakya.runtime.dispatch.ToolExecutor`` exactly: the sole
public method is ``execute(instruction: DispatchInstruction) -> ToolResult``.
This class is a fixed dispatch table, never a plugin system — the handler
map is supplied once at construction from a small, reviewed list (see
``chanakya.tools.bootstrap``); nothing here discovers, imports, or invokes
a handler by any name it wasn't explicitly given.

Security boundary (Phase 5.1 design report §2):

- Receives only an already-authorized ``DispatchInstruction``. By the time
  ``dispatch()`` (``chanakya/runtime/dispatch.py``) calls
  ``executor.execute``, a ``PolicyDecision`` has already authorized this
  exact request (and, if required, an accepted ``ApprovalDecision`` is
  already bound to it) — this class never re-derives, reinterprets, or
  second-guesses that decision.
- Makes no policy decision, authorizes nothing, writes nothing to the
  Registry, and cannot reach ``chanakya.policy`` or ``chanakya.runtime.
  dispatch.dispatch`` at all — there is no import of either anywhere in
  this module, so there is no code path back into authorization.
- Never accepts raw Agent/LLM output directly — its only input is the
  Runtime-constructed ``DispatchInstruction``, never an ``AgentTurnOutput``
  or a raw ``ToolRequest``.
- Re-validates target/type binding independently of the Policy Gateway's
  own check (defense in depth, mirroring ``LocalHostAdapter``'s existing
  posture): a handler is never invoked against a target type it doesn't
  declare support for, even though the Gateway should already have
  rejected any such request upstream.
- Normalizes every handler-raised exception (other than a handler's own
  ``ToolExecutionTimedOut``, which must propagate unchanged so
  ``TimeoutSupervisor`` can convert it) into ``ToolResult(status=error)``
  — a buggy or failing handler must never fail the whole investigation via
  an unhandled exception reaching ``AgentLoopController``'s fail-closed
  backstop, and must never be treated as an implicit authorization of
  anything.
- Rejects a non-mapping handler return value as malformed rather than
  constructing a ``ToolResult`` around it — a handler's output shape is
  enforced here, not assumed.
"""
from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Any, Mapping, Protocol, Sequence, runtime_checkable

from chanakya.contracts.target import Target
from chanakya.contracts.tool_result import ToolResult, ToolResultStatus
from chanakya.runtime.dispatch import DispatchInstruction
from chanakya.runtime.timeout_supervisor import ToolExecutionTimedOut
from chanakya.targets.registry import TargetRegistry

_CONTRACT_VERSION = "1.0.0"


def _utcnow_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


@runtime_checkable
class CapabilityHandler(Protocol):
    """One capability's execution logic. Receives only the resolved
    ``Target`` and the already-schema-validated ``parameters`` mapping —
    never the full ``DispatchInstruction`` — so a handler has no way to
    read ``policy_decision_id``, ``approval_decision_id``, or any other
    Runtime bookkeeping field it has no business touching."""

    supported_target_types: Sequence[str]

    def run(self, target: Target, parameters: Mapping[str, Any]) -> Mapping[str, Any]:
        """Returns the ``ToolResult.output`` payload directly (not a
        ``ToolResult``) — this class owns every other field of the result.
        Raise on failure; ``CapabilityDispatchExecutor`` normalizes the
        exception into a structured ``ToolResult(status=error)``. Raise
        ``chanakya.runtime.timeout_supervisor.ToolExecutionTimedOut``
        specifically to signal a handler's own internal timeout."""
        ...


class CapabilityDispatchExecutor:
    """The concrete ``chanakya.runtime.dispatch.ToolExecutor``. Holds a
    fixed ``capability -> CapabilityHandler`` map and a read-only
    ``TargetRegistry`` reference, both supplied at construction; neither is
    ever mutated after that (no ``register``/``add_handler`` method
    exists) — the set of invocable capabilities for a given executor
    instance is closed for its lifetime."""

    def __init__(self, target_registry: TargetRegistry, handlers: Mapping[str, CapabilityHandler]) -> None:
        self._targets = target_registry
        self._handlers = dict(handlers)

    @property
    def registered_capabilities(self) -> Sequence[str]:
        """Read-only introspection — used by tests/wiring code to confirm
        this executor's handler map agrees with what the Registry has
        enabled; never consulted by any authorization logic."""
        return tuple(self._handlers.keys())

    def execute(self, instruction: DispatchInstruction) -> ToolResult:
        started_at = _utcnow_iso()

        handler = self._handlers.get(instruction.capability)
        if handler is None:
            return self._error_result(
                instruction, started_at, f"no Tool Layer handler registered for capability {instruction.capability!r}"
            )

        target = self._targets.get(instruction.target_ref)
        if target is None:
            return self._error_result(
                instruction, started_at, f"target {instruction.target_ref!r} is not registered"
            )

        if target.target_type not in handler.supported_target_types:
            return self._error_result(
                instruction,
                started_at,
                f"handler for capability {instruction.capability!r} does not support "
                f"target_type {target.target_type!r} (supports: {tuple(handler.supported_target_types)!r})",
            )

        try:
            output = handler.run(target, instruction.parameters)
        except ToolExecutionTimedOut:
            # Propagate unchanged — this is TimeoutSupervisor's signal to
            # convert to a synthetic ToolResult(status=timeout); it must
            # never be normalized into a generic ERROR result here.
            raise
        except Exception as exc:  # every other handler exception — never let it escape.
            return self._error_result(instruction, started_at, f"{exc.__class__.__name__}: {exc}")

        if not isinstance(output, Mapping):
            return self._error_result(
                instruction,
                started_at,
                f"handler for capability {instruction.capability!r} returned a non-mapping "
                f"output ({type(output).__name__}) — rejected as malformed",
            )

        return ToolResult(
            tool_result_id=str(uuid.uuid4()),
            contract_version=_CONTRACT_VERSION,
            tool_request_id=instruction.tool_request_id,
            capability=instruction.capability,
            status=ToolResultStatus.SUCCESS,
            started_at=started_at,
            completed_at=_utcnow_iso(),
            output=dict(output),
        )

    @staticmethod
    def _error_result(instruction: DispatchInstruction, started_at: str, message: str) -> ToolResult:
        return ToolResult(
            tool_result_id=str(uuid.uuid4()),
            contract_version=_CONTRACT_VERSION,
            tool_request_id=instruction.tool_request_id,
            capability=instruction.capability,
            status=ToolResultStatus.ERROR,
            started_at=started_at,
            completed_at=_utcnow_iso(),
            error_message=message,
        )
