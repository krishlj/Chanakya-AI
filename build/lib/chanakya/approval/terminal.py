"""TerminalApprovalProvider — the Human Approval Mechanism for the CLI
(ARCHITECTURE.md §13, docs/AGENT-RUNTIME.md §13), Phase 7.

Implements the existing ``chanakya.runtime.agent_loop.ApprovalProvider``
protocol: ``request_approval(ApprovalRequest) -> ApprovalDecision``. The
Agent Loop Controller calls it only for a Policy Gateway
``require_approval`` verdict, and ``dispatch()`` independently refuses to
run unless the returned ACCEPT is bound to that exact request. This class
therefore decides nothing about policy: it shows the human what the
Runtime already decided needs approval and returns the human's answer.

- Only the literal word ``approve`` (after trimming and lower-casing,
  ASCII only) produces ACCEPT; only ``deny`` produces DENY. ``y``, ``yes``,
  ``accept``, ``approved``, ``approve!`` or anything carrying escape
  sequences are invalid.
- Invalid input re-prompts up to ``max_attempts`` times, then raises
  ``ApprovalInputError``. EOF and Ctrl+C raise ``ApprovalAborted``. Both
  are ordinary ``Exception`` subclasses, so the Runtime's existing backstop
  fails the investigation (audited) and nothing is dispatched. Neither ever
  becomes ACCEPT.
- Every value shown comes from the Agent's proposal and is untrusted. Each
  one is rendered with ``json.dumps(..., ensure_ascii=True)``, so control
  characters and ANSI escape sequences are printed escaped, never raw.
  The human's input is never echoed.
- Reads only the ``ApprovalRequest`` it is given and never mutates it. It
  holds no reference to the Gateway, Dispatcher, ToolExecutor, provider,
  or any credential.
"""
from __future__ import annotations

import json
import sys
import uuid
from typing import Any, Callable, Optional, TextIO

from chanakya.contracts.approval import ApprovalDecision, ApprovalDecisionValue, ApprovalRequest
from chanakya.runtime.clock import utcnow_iso

_CONTRACT_VERSION = "1.0.0"
_RESERVED_APPROVERS = frozenset({"agent", "system"})
_ANSWERS = {"approve": ApprovalDecisionValue.ACCEPT, "deny": ApprovalDecisionValue.DENY}
_PROMPT = "Type 'approve' or 'deny': "


class ApprovalAborted(Exception):
    """The human ended input (EOF or Ctrl+C) without a decision."""


class ApprovalInputError(Exception):
    """No valid answer within ``max_attempts``."""


def _safe(value: Any) -> str:
    """Terminal-safe rendering of an untrusted value."""
    return json.dumps(value, ensure_ascii=True, sort_keys=True, default=repr)


class TerminalApprovalProvider:
    def __init__(
        self,
        approver: str,
        *,
        input_fn: Callable[[str], str] = input,
        output: Optional[TextIO] = None,
        max_attempts: int = 3,
    ) -> None:
        if not isinstance(approver, str) or not approver.strip():
            raise ValueError("approver must be a non-empty string")
        if approver.strip().lower() in _RESERVED_APPROVERS:
            raise ValueError("approver must identify a human, not a reserved actor name")
        if isinstance(max_attempts, bool) or not isinstance(max_attempts, int) or max_attempts < 1:
            raise ValueError("max_attempts must be a positive integer")
        self._approver = approver.strip()
        self._input = input_fn
        self._output = output if output is not None else sys.stdout
        self._max_attempts = max_attempts

    @property
    def approver(self) -> str:
        return self._approver

    def _write(self, text: str) -> None:
        self._output.write(text)
        self._output.flush()

    def _show(self, request: ApprovalRequest) -> None:
        context = request.risk_context
        self._write(
            "\n=== Human approval required ===\n"
            f"investigation: {_safe(request.investigation_id)}\n"
            f"capability:    {_safe(context.get('capability'))}\n"
            f"target_ref:    {_safe(context.get('target_ref'))}\n"
            f"parameters:    {_safe(context.get('parameters'))}\n"
            f"expires_at:    {_safe(request.expires_at)}\n"
            "The Policy Gateway requires your decision before this action can run.\n"
        )

    def _read_answer(self) -> ApprovalDecisionValue:
        for _ in range(self._max_attempts):
            try:
                raw = self._input(_PROMPT)
            except EOFError:
                raise ApprovalAborted("input ended before an approval decision was made") from None
            except KeyboardInterrupt:
                raise ApprovalAborted("approval interrupted before a decision was made") from None
            answer = raw.strip().lower() if isinstance(raw, str) else ""
            if answer.isascii() and answer in _ANSWERS:
                return _ANSWERS[answer]
            self._write("Invalid answer. Only 'approve' or 'deny' is accepted.\n")
        raise ApprovalInputError(f"no valid approval answer after {self._max_attempts} attempts")

    def request_approval(self, approval_request: ApprovalRequest) -> ApprovalDecision:
        if not isinstance(approval_request, ApprovalRequest):
            raise TypeError("request_approval requires an ApprovalRequest")
        self._show(approval_request)
        decision = self._read_answer()
        self._write(f"Recorded: {decision.value} by {_safe(self._approver)}\n")
        return ApprovalDecision(
            approval_decision_id=str(uuid.uuid4()),
            contract_version=_CONTRACT_VERSION,
            approval_request_id=approval_request.approval_request_id,
            decision=decision,
            decided_by=self._approver,
            decided_at=utcnow_iso(),
        )


__all__ = ["ApprovalAborted", "ApprovalInputError", "TerminalApprovalProvider"]
