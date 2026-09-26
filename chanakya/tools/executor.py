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

Phase 11 — capability execution envelope (CE-INV-1, 2, 4, 5):

- Runs a handler only under ``instruction.capability_envelope``: the
  envelope the Policy Gateway attached to the authorizing decision, which
  ``dispatch()`` has already bound to it. No envelope, or one naming
  another capability, is an error and the handler never runs.
- When built with ``envelopes`` (the production composition root does,
  from the same Registry the Gateway uses), the instruction's envelope must
  also equal the one registered for that capability; a mismatch fails
  closed before the handler runs. These are a cross-check only: limits are
  always taken from the instruction, never from this map.
- After the handler returns, ``chanakya.capability.envelope.check_output``
  checks JSON compatibility, canonical UTF-8 size against
  ``max_output_bytes`` and the declared ``output_schema``. A violation is a
  ``ToolResult(status=error)`` whose message is the fixed
  ``capability_envelope_violation: <CODE>``, never the output; nothing is
  truncated, repaired or stripped, and only SUCCESS results become
  Evidence. The Runtime does not retry envelope violations.
- The imports here are still free of ``chanakya.policy``; the validator
  lives in ``chanakya.capability.schema``.
"""
from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Any, Dict, Mapping, Optional, Protocol, Sequence, runtime_checkable

from chanakya.capability.envelope import (
    ENVELOPE_MISMATCH,
    ENVELOPE_MISSING,
    CapabilityEnvelope,
    check_output,
    violation_message,
)
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

    def __init__(
        self,
        target_registry: TargetRegistry,
        handlers: Mapping[str, CapabilityHandler],
        *,
        envelopes: Optional[Mapping[str, CapabilityEnvelope]] = None,
    ) -> None:
        self._targets = target_registry
        self._handlers = dict(handlers)
        self._envelopes: Optional[Dict[str, CapabilityEnvelope]] = None
        if envelopes is not None:
            # Parity: exactly one Registry-derived envelope per handler.
            if set(envelopes) != set(self._handlers):
                raise ValueError("capability envelopes must cover exactly the registered handlers")
            for capability, envelope in envelopes.items():
                if not isinstance(envelope, CapabilityEnvelope) or envelope.capability != capability:
                    raise ValueError("capability envelope does not match its capability")
            self._envelopes = dict(envelopes)

    @property
    def registered_capabilities(self) -> Sequence[str]:
        """Read-only introspection — used by tests/wiring code to confirm
        this executor's handler map agrees with what the Registry has
        enabled; never consulted by any authorization logic."""
        return tuple(self._handlers.keys())

    def execute(self, instruction: DispatchInstruction) -> ToolResult:
        started_at = _utcnow_iso()

        envelope = instruction.capability_envelope
        if not isinstance(envelope, CapabilityEnvelope):
            return self._error_result(instruction, started_at, violation_message(ENVELOPE_MISSING))
        if envelope.capability != instruction.capability or (
            self._envelopes is not None and self._envelopes.get(instruction.capability) != envelope
        ):
            return self._error_result(instruction, started_at, violation_message(ENVELOPE_MISMATCH))

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

        # Phase 11: size and schema, before anything can become Evidence.
        violation = check_output(envelope, output)
        if violation is not None:
            return self._error_result(instruction, started_at, violation_message(violation))

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
