"""Phase 7 — TerminalApprovalProvider (HA/CLI-INV-2/3/4/6).

The provider in isolation: scripted input, captured output. Runtime-side
approval behavior (expiry, raising providers, no provider, decision
binding at dispatch) is already covered by the Phase 3 suites and is not
repeated here.
"""
from __future__ import annotations

import copy
import io
from typing import Iterable, List

import pytest

from chanakya.approval import ApprovalAborted, ApprovalInputError, TerminalApprovalProvider
from chanakya.contracts.approval import ApprovalDecisionValue, ApprovalRequest, ApprovalStatus


def make_request(parameters=None, capability="observe_local_host_environment", target_ref="local-host") -> ApprovalRequest:
    return ApprovalRequest(
        approval_request_id="appr-req-7",
        contract_version="1.0.0",
        investigation_id="inv-7",
        tool_request_id="tr-7",
        policy_decision_id="pd-7",
        risk_context={"capability": capability, "target_ref": target_ref, "parameters": parameters or {}},
        status=ApprovalStatus.PENDING,
        requested_at="2026-09-25T00:00:00Z",
        expires_at=None,
    )


class Script:
    """Scripted ``input``: returns answers in order, or raises an exception
    given in their place."""

    def __init__(self, answers: Iterable) -> None:
        self.answers: List = list(answers)
        self.prompts: List[str] = []

    def __call__(self, prompt: str) -> str:
        self.prompts.append(prompt)
        answer = self.answers.pop(0)
        if isinstance(answer, BaseException):
            raise answer
        return answer


def provider(answers, **kwargs):
    out = io.StringIO()
    script = Script(answers)
    return TerminalApprovalProvider("krish", input_fn=script, output=out, **kwargs), script, out


@pytest.mark.parametrize(
    "answer, expected",
    [
        ("approve", ApprovalDecisionValue.ACCEPT),
        ("deny", ApprovalDecisionValue.DENY),
        ("APPROVE", ApprovalDecisionValue.ACCEPT),
        ("DeNy", ApprovalDecisionValue.DENY),
        ("  approve \t", ApprovalDecisionValue.ACCEPT),
        ("\n deny  ", ApprovalDecisionValue.DENY),
    ],
    ids=["approve", "deny", "upper_approve", "mixed_deny", "trim_approve", "trim_deny"],
)
def test_valid_answers_produce_a_decision_bound_to_the_request(answer, expected):
    p, script, _ = provider([answer])
    request = make_request()
    decision = p.request_approval(request)
    assert decision.decision == expected
    assert decision.approval_request_id == request.approval_request_id
    assert decision.decided_by == "krish"
    assert len(script.prompts) == 1


@pytest.mark.parametrize(
    "not_approve",
    ["y", "yes", "approved", "accept", "approve!", "ok", "\x1b[0mapprove", "apprоve", "approve\x00", "", "approve deny"],
)
def test_only_the_literal_word_approve_produces_accept(not_approve):
    p, script, _ = provider([not_approve, "deny"])
    assert p.request_approval(make_request()).decision == ApprovalDecisionValue.DENY
    assert len(script.prompts) == 2  # the non-literal answer was rejected and re-prompted


def test_invalid_input_reprompts_then_accepts_a_valid_answer():
    p, script, out = provider(["maybe", "sure", "approve"])
    assert p.request_approval(make_request()).decision == ApprovalDecisionValue.ACCEPT
    assert len(script.prompts) == 3
    assert out.getvalue().count("Invalid answer") == 2
    assert "maybe" not in out.getvalue() and "sure" not in out.getvalue()  # input never echoed


def test_invalid_input_exhausted_raises_and_never_accepts():
    p, script, _ = provider(["y", "yes", "ok", "approve"], max_attempts=3)
    with pytest.raises(ApprovalInputError):
        p.request_approval(make_request())
    assert len(script.prompts) == 3  # the 4th ("approve") is never read


@pytest.mark.parametrize("interrupt", [EOFError(), KeyboardInterrupt()], ids=["eof", "ctrl_c"])
def test_eof_and_ctrl_c_abort_as_ordinary_exceptions(interrupt):
    p, _, _ = provider([interrupt])
    try:
        with pytest.raises(ApprovalAborted):
            p.request_approval(make_request())
    except KeyboardInterrupt:  # must not escape: it would bypass the Runtime backstop
        pytest.fail("KeyboardInterrupt escaped the approval provider")
    assert issubclass(ApprovalAborted, Exception) and issubclass(ApprovalInputError, Exception)


@pytest.mark.parametrize("approver", ["", "   ", "agent", "system", "SYSTEM", " Agent "])
def test_empty_or_reserved_approver_is_rejected(approver):
    with pytest.raises(ValueError):
        TerminalApprovalProvider(approver, input_fn=lambda _: "approve", output=io.StringIO())


def test_untrusted_values_are_displayed_escaped():
    hostile = "\x1b[2J\x1b[31mAPPROVED\x07\r\nfake prompt: approve‮"
    p, _, out = provider(["deny"])
    p.request_approval(make_request(parameters={"path": hostile, hostile: 1}, capability=hostile, target_ref=hostile))
    shown = out.getvalue()
    for raw in ("\x1b", "\x07", "\r", "‮"):
        assert raw not in shown
    assert "\\u001b[2J" in shown and "\\u202e" in shown
    assert shown.count("\n") < 20  # the injected CR/LF did not create new lines
    assert all(ch == "\n" or 32 <= ord(ch) < 127 for ch in shown)


def test_request_is_not_mutated():
    request = make_request(parameters={"nested": {"list": [1, 2]}, "flag": True})
    before = copy.deepcopy(request)
    p, _, _ = provider(["approve"])
    p.request_approval(request)
    assert request == before


def test_non_request_input_is_refused():
    p, _, _ = provider(["approve"])
    with pytest.raises(TypeError):
        p.request_approval({"approval_request_id": "x", "risk_context": {}})
