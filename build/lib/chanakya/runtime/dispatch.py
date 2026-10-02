"""Dispatcher / execution boundary — docs/AGENT-RUNTIME.md §7.

The only code path permitted to invoke tool execution. Enforces
RT-INV-1 and RT-INV-2 structurally: ``dispatch()`` requires a
``PolicyDecision`` and a ``ToolExecutor`` as mandatory parameters, and a
``require_approval`` verdict additionally requires a correctly-bound,
accepted ``ApprovalDecision`` — there is no overload or default that
allows omitting either.

The binding check for ``require_approval`` verifies every identifier an
``ApprovalRequest``/``ApprovalDecision`` pair carries against the current
``DispatchInstruction``: the originating ``tool_request_id``, the
``policy_decision_id`` it was linked to, the ``approval_request_id`` the
decision answers, and — added in Phase 3 Step 3.6 as a hardening fix
after this check was found to be missing — the owning
``investigation_id``. Without the last check, an approval genuinely
issued for one investigation could theoretically authorize a dispatch
under a different investigation whose request happened to carry the same
``tool_request_id``/``policy_decision_id`` (never possible in the normal
flow, where the Agent Loop Controller always constructs these for the
current investigation, but not something the precondition gate itself
was verifying). See docs/AGENT-RUNTIME.md's "Additional contracts"
section for ``DispatchInstruction``'s field list, now including
``investigation_id``.

There is no default ``ToolExecutor`` in this module, and it never
fabricates a successful ``ToolResult`` on its own. Callers must supply an
explicit ``ToolExecutor``: in production, ``chanakya.tools.executor``
(built by ``chanakya.tools.bootstrap.build_tool_executor``); tests supply
their own.

Phase 11: ``DispatchInstruction.capability_envelope`` carries the
``CapabilityEnvelope`` the Gateway attached to the ``PolicyDecision``.
``dispatch()`` refuses an instruction whose envelope differs from the
decision's, names another capability, or claims a timeout or output limit
looser than the envelope. It does not add the envelope when both are
absent (callers that build decisions by hand); the Agent Loop Controller
never dispatches without one, and the production Tool Layer refuses to run
a handler without one.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Mapping, Optional, Protocol

from chanakya.capability.envelope import CapabilityEnvelope
from chanakya.contracts.approval import ApprovalDecision, ApprovalDecisionValue, ApprovalRequest
from chanakya.contracts.enums import Verdict
from chanakya.contracts.policy_decision import PolicyDecision
from chanakya.contracts.tool_result import ToolResult

from .exceptions import DispatchPreconditionError


@dataclass(frozen=True)
class DispatchInstruction:
    """docs/AGENT-RUNTIME.md "Additional contracts". The Runtime -> Tool
    Layer internal call shape. Never includes a credential (RT-INV-11 —
    those remain scoped to a future Target Adapter) and is never visible
    to the Agent."""

    investigation_id: str
    tool_request_id: str
    capability: str
    target_ref: str
    parameters: Mapping[str, Any]
    resolved_timeout_seconds: int
    resolved_resource_limits: Mapping[str, Any]
    policy_decision_id: str
    attempt_number: int
    approval_decision_id: Optional[str] = None
    #: Phase 11 — the authorized envelope, copied from the PolicyDecision.
    capability_envelope: Optional[CapabilityEnvelope] = None


def _check_envelope_binding(instruction: DispatchInstruction, policy_decision: PolicyDecision) -> None:
    envelope = instruction.capability_envelope
    if envelope != policy_decision.capability_envelope:
        raise DispatchPreconditionError("DispatchInstruction.capability_envelope differs from the PolicyDecision's")
    if envelope is None:
        return
    if envelope.capability != instruction.capability:
        raise DispatchPreconditionError("capability envelope was issued for a different capability")
    if not 0 < instruction.resolved_timeout_seconds <= envelope.timeout_seconds:
        raise DispatchPreconditionError("resolved timeout exceeds the capability envelope")
    if dict(instruction.resolved_resource_limits) != {"max_output_bytes": envelope.max_output_bytes}:
        raise DispatchPreconditionError("resolved resource limits differ from the capability envelope")


class ToolExecutor(Protocol):
    """The interface the Tool Layer implements (production:
    ``chanakya.tools.executor``). See the module docstring."""

    def execute(self, instruction: DispatchInstruction) -> ToolResult:
        ...


def dispatch(
    instruction: DispatchInstruction,
    policy_decision: PolicyDecision,
    executor: ToolExecutor,
    *,
    approval_request: Optional[ApprovalRequest] = None,
    approval_decision: Optional[ApprovalDecision] = None,
) -> ToolResult:
    """RT-INV-1 / RT-INV-2. Raises ``DispatchPreconditionError`` — and
    calls ``executor.execute`` for nothing else — unless every
    precondition below holds. This function never itself decides
    whether an action is safe (that was already decided by the Policy
    Gateway and, where required, a human approver); it only verifies
    that the decision it was handed actually authorizes *this* dispatch.
    """
    if policy_decision.tool_request_id != instruction.tool_request_id:
        raise DispatchPreconditionError(
            "PolicyDecision.tool_request_id does not match this DispatchInstruction"
        )
    if policy_decision.policy_decision_id != instruction.policy_decision_id:
        raise DispatchPreconditionError(
            "PolicyDecision.policy_decision_id does not match this DispatchInstruction"
        )

    if policy_decision.verdict == Verdict.DENY:
        raise DispatchPreconditionError("cannot dispatch: PolicyDecision.verdict is DENY")

    if policy_decision.verdict == Verdict.ALLOW:
        _check_envelope_binding(instruction, policy_decision)
        return executor.execute(instruction)

    if policy_decision.verdict == Verdict.REQUIRE_APPROVAL:
        if approval_request is None or approval_decision is None:
            raise DispatchPreconditionError(
                "cannot dispatch: PolicyDecision.verdict is REQUIRE_APPROVAL but no "
                "ApprovalRequest/ApprovalDecision was provided"
            )
        if approval_request.tool_request_id != instruction.tool_request_id:
            raise DispatchPreconditionError("ApprovalRequest.tool_request_id does not match this DispatchInstruction")
        if approval_request.investigation_id != instruction.investigation_id:
            raise DispatchPreconditionError(
                "ApprovalRequest.investigation_id does not match this DispatchInstruction "
                "(no cross-investigation approval reuse permitted)"
            )
        if approval_request.policy_decision_id != policy_decision.policy_decision_id:
            raise DispatchPreconditionError("ApprovalRequest is not linked to this PolicyDecision")
        if approval_decision.approval_request_id != approval_request.approval_request_id:
            raise DispatchPreconditionError(
                "ApprovalDecision is not bound to this ApprovalRequest (no cross-request reuse permitted)"
            )
        if approval_decision.decision != ApprovalDecisionValue.ACCEPT:
            raise DispatchPreconditionError(
                "cannot dispatch: ApprovalDecision.decision is not ACCEPT"
            )
        _check_envelope_binding(instruction, policy_decision)
        return executor.execute(instruction)

    # Defensive — Verdict is a closed, three-value enum, so this should be
    # unreachable, but the Dispatcher must never fail open on an
    # unrecognized verdict.
    raise DispatchPreconditionError(f"cannot dispatch: unrecognized PolicyDecision.verdict {policy_decision.verdict!r}")
