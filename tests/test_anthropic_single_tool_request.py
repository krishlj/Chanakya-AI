"""Anthropic parallel tool request compatibility.

The Runtime accepts one action per turn (CT-INV-3) and rejects a response
carrying several ``tool_use`` blocks as a whole. The Anthropic Messages API
allows parallel tool use unless the request disables it, so every request
that carries tools now also carries::

    tool_choice = {"type": "auto", "disable_parallel_tool_use": True}

These tests pin that request field, show that nothing else about the
request, transport, identity or turn record changed, and show that the
Runtime's multiple_tool_use_blocks rejection still stands as the backstop.
"""
from __future__ import annotations

import dataclasses
import json
from pathlib import Path
from typing import Any, Dict, List, Mapping

import anthropic
import httpx2
import pytest

import chanakya.cli.main as cli_main
from chanakya.contracts import runtime_failure as rf
from chanakya.contracts.agent_turn import hash_value
from chanakya.contracts.audit_event import AuditEventType
from chanakya.contracts.investigation_context import InvestigationStatus
from chanakya.providers import mapping
from chanakya.providers.anthropic_provider import AnthropicProvider
from chanakya.providers.config import ProviderConfig
from chanakya.runtime.agent_loop import TurnOutcome
from chanakya.runtime.context_assembler import AssembledContext, UntrustedData
from review_factories import ENV, Run

SENTINEL_KEY = "sk-ant-single-tool-SENTINEL-do-not-persist"
PORTS = "list_listening_ports"
E = AuditEventType
TOOL_CHOICE = {"type": "auto", "disable_parallel_tool_use": True}

#: Every audit event a tool request produces once it passes turn validation.
_ACTION_EVENTS = {
    E.REQUEST_PROPOSED, E.POLICY_EVALUATED, E.APPROVAL_REQUESTED, E.APPROVAL_DECIDED,
    E.DISPATCH_STARTED, E.DISPATCH_COMPLETED, E.DISPATCH_FAILED, E.EVIDENCE_RECORDED,
}


# ===========================================================================
# Helpers
# ===========================================================================


class _Transport:
    def __init__(self, responses: List[Mapping[str, Any]]) -> None:
        self.responses = list(responses)
        self.requests: List[httpx2.Request] = []

    def handler(self, request: httpx2.Request) -> httpx2.Response:
        self.requests.append(request)
        return httpx2.Response(200, json=self.responses.pop(0))

    def body(self, index: int = -1) -> Dict[str, Any]:
        return json.loads(self.requests[index].content)


def _config(**overrides: Any) -> ProviderConfig:
    fields = dict(provider="anthropic", model="claude-test-model", api_key_env_var="ANTHROPIC_API_KEY",
                  timeout_seconds=30.0, findings_channel=True)
    fields.update(overrides)
    return ProviderConfig(**fields)


def _provider(*responses: Mapping[str, Any], **config: Any):
    transport = _Transport(list(responses))
    cfg = _config(**config)
    client = anthropic.Anthropic(
        api_key=SENTINEL_KEY, base_url=cfg.effective_endpoint, max_retries=0,
        http_client=httpx2.Client(trust_env=False, transport=httpx2.MockTransport(transport.handler)),
    )
    return AnthropicProvider(cfg, SENTINEL_KEY, client=client), transport


def _message(content: List[Mapping[str, Any]], stop_reason: str = "end_turn") -> Dict[str, Any]:
    return {
        "id": "msg_single_tool", "type": "message", "role": "assistant", "model": "claude-test-model",
        "content": content, "stop_reason": stop_reason, "stop_sequence": None,
        "usage": {"input_tokens": 5, "output_tokens": 5},
    }


def _tool(name: str, block_id: str = "toolu_1") -> Dict[str, Any]:
    return {"type": "tool_use", "id": block_id, "name": name, "input": {"target_ref": cli_main.LOCAL_TARGET_ID}}


def _two_tools() -> Dict[str, Any]:
    return _message([_tool(ENV, "toolu_1"), _tool(PORTS, "toolu_2")], "tool_use")


def _catalog_entry(capability: str = PORTS) -> Dict[str, Any]:
    return {"capability": capability, "description": "read-only observation",
            "parameters_schema": {"type": "object", "properties": {}, "additionalProperties": False}}


def _assembled(catalog=None, data=()) -> AssembledContext:
    return AssembledContext(
        investigation_id="inv-single-tool",
        instructions="TRUSTED INSTRUCTIONS",
        data=list(data),
        capability_catalog=list(catalog if catalog is not None else [_catalog_entry()]),
    )


def _turn(run: Run, agent):
    return run.runtime.controller.run_turn(run.inv, agent, capability_catalog=run.runtime.registry.catalog_view())


def _event_types(run: Run) -> List[AuditEventType]:
    return [e.event_type for e in run.events()]


def _audit_text(root: Path) -> str:
    return "\n".join(p.read_text(encoding="utf-8") for p in sorted((root / "audit").rglob("*.json")))


# ===========================================================================
# 1-3. The request field
# ===========================================================================


def test_request_with_tools_carries_auto_tool_choice_without_parallel_use():
    kwargs = mapping.build_request_kwargs(_assembled(), _config())
    assert kwargs["tool_choice"]["type"] == "auto"
    assert kwargs["tool_choice"]["disable_parallel_tool_use"] is True
    assert kwargs["tool_choice"] == TOOL_CHOICE


def test_findings_channel_alone_still_gets_auto_tool_choice():
    """``auto`` (never ``any``/``tool``) keeps a text-only conclusion possible."""
    kwargs = mapping.build_request_kwargs(_assembled(catalog=[]), _config(findings_channel=True))
    assert [t["name"] for t in kwargs["tools"]] == ["report_findings"]
    assert kwargs["tool_choice"] == TOOL_CHOICE


@pytest.mark.parametrize("findings_channel", [True, False])
@pytest.mark.parametrize("catalog", [[_catalog_entry()], [_catalog_entry(ENV), _catalog_entry(PORTS)]])
def test_tool_choice_never_forces_a_tool(catalog, findings_channel):
    kwargs = mapping.build_request_kwargs(_assembled(catalog=catalog), _config(findings_channel=findings_channel))
    assert kwargs["tool_choice"]["type"] == "auto"
    assert set(kwargs["tool_choice"]) == {"type", "disable_parallel_tool_use"}


def test_no_tools_means_no_tool_choice():
    kwargs = mapping.build_request_kwargs(_assembled(catalog=[]), _config(findings_channel=False))
    assert "tools" not in kwargs and "tool_choice" not in kwargs
    assert set(kwargs) == {"model", "system", "messages", "max_tokens"}


def test_tool_choice_is_a_fresh_value_per_request():
    first = mapping.build_request_kwargs(_assembled(), _config())
    first["tool_choice"]["disable_parallel_tool_use"] = False
    assert mapping.build_request_kwargs(_assembled(), _config())["tool_choice"] == TOOL_CHOICE
    assert mapping._TOOL_CHOICE == TOOL_CHOICE


def test_tool_choice_is_on_the_wire_request_sent_through_the_sdk():
    provider, transport = _provider(_message([{"type": "text", "text": "done"}]))
    provider.next_turn(_assembled())
    (request,) = transport.requests
    body = transport.body()
    assert body["tool_choice"] == TOOL_CHOICE
    assert set(body) == {"model", "system", "messages", "max_tokens", "tools", "tool_choice"}


def test_wire_request_without_tools_has_no_tool_choice():
    provider, transport = _provider(_message([{"type": "text", "text": "done"}]), findings_channel=False)
    provider.next_turn(_assembled(catalog=[]))
    assert "tool_choice" not in transport.body() and "tools" not in transport.body()


# ===========================================================================
# 4-5. Nothing else about the request, transport or identity changed
# ===========================================================================


def test_only_tool_choice_was_added_to_the_request():
    context = _assembled(data=[UntrustedData("tool_result:r1", {"k": "v"})])
    kwargs = mapping.build_request_kwargs(context, _config())
    without = {k: v for k, v in kwargs.items() if k != "tool_choice"}
    assert without == {
        "model": "claude-test-model",
        "system": "TRUSTED INSTRUCTIONS",
        "messages": [{"role": "user", "content": json.dumps(
            {"investigation_id": "inv-single-tool", "untrusted_data": [{"source": "tool_result:r1", "content": {"k": "v"}}]}
        )}],
        "max_tokens": mapping._DEFAULT_MAX_TOKENS,
        "tools": kwargs["tools"],
    }
    assert [t["name"] for t in kwargs["tools"]] == [PORTS, "report_findings"]
    assert "tool_choice" not in json.dumps(kwargs["tools"]) and "tool_choice" not in kwargs["system"]


def test_endpoint_path_headers_retries_and_identity_unchanged():
    provider, transport = _provider(_message([{"type": "text", "text": "done"}]))
    before = provider.provider_identity()
    provider.next_turn(_assembled())
    (request,) = transport.requests
    assert request.method == "POST"
    assert str(request.url) == "https://api.anthropic.com/v1/messages"
    assert request.headers["x-api-key"] == SENTINEL_KEY  # only in the auth header
    assert SENTINEL_KEY not in request.content.decode()
    assert provider.provider_identity() == before
    assert before.endpoint == "https://api.anthropic.com" and before.max_tokens == 4096
    transport_policy = dataclasses.asdict(before.transport)
    assert transport_policy["retries"] == 0 and transport_policy["redirects"] is False
    assert transport_policy["proxy"] == "none" and transport_policy["env_trust"] is False
    assert transport_policy["sdk_debug_logging"] is False  # TLS trust: covered by identity equality above
    assert "tool_choice" not in json.dumps(dataclasses.asdict(before), default=str)


def test_output_limit_unchanged():
    kwargs = mapping.build_request_kwargs(_assembled(), _config(max_output_tokens=321))
    assert kwargs["max_tokens"] == 321
    assert kwargs["tool_choice"] == TOOL_CHOICE


def test_target_context_unaffected_by_tool_choice():
    from chanakya.targets.context import TargetContextView  # noqa: F401 - shape documented by target tests

    kwargs = mapping.build_request_kwargs(_assembled(), _config())
    payload = json.loads(kwargs["messages"][0]["content"])
    assert "tool_choice" not in payload and "disable_parallel_tool_use" not in kwargs["messages"][0]["content"]
    for tool in kwargs["tools"]:
        if tool["name"] != "report_findings":
            assert tool["input_schema"]["properties"]["target_ref"]["description"] == mapping._TARGET_REF_DESCRIPTION


# ===========================================================================
# 12. Request hashing: deterministic, and it covers tool_choice
# ===========================================================================


def test_prepared_request_is_deterministic_and_hash_covers_tool_choice():
    provider, _ = _provider()
    first = provider.prepare_turn(_assembled())
    second = provider.prepare_turn(_assembled())
    assert first.request_hash == second.request_hash == hash_value(first.payload)
    assert first.payload["tool_choice"] == TOOL_CHOICE
    without = {k: v for k, v in first.payload.items() if k != "tool_choice"}
    assert hash_value(without) != first.request_hash


def test_tampered_tool_choice_is_refused_before_sending():
    provider, transport = _provider(_two_tools())
    prepared = provider.prepare_turn(_assembled())
    payload = dict(prepared.payload)
    payload["tool_choice"] = {"type": "auto", "disable_parallel_tool_use": False}
    with pytest.raises(ValueError, match="does not match its recorded hash"):
        provider.send_turn(dataclasses.replace(prepared, payload=payload))
    assert transport.requests == []


def test_recorded_manifest_hash_is_the_hash_of_the_sent_request(tmp_path):
    run = Run(tmp_path).start()
    provider, transport = _provider(_message([{"type": "text", "text": "done"}]))
    _turn(run, provider)
    (manifest,) = [dict(e.details) for e in run.events() if e.event_type == E.AGENT_TURN_REQUESTED]
    body = transport.body()
    assert body["tool_choice"] == TOOL_CHOICE
    assert manifest["provider_request_hash"] == hash_value(body)
    assert "tool_choice" not in json.dumps(manifest)


# ===========================================================================
# 6-11. The Runtime backstop (CT-INV-3) still rejects a multi-tool reply
# ===========================================================================


def test_multiple_tool_use_reply_is_still_rejected_as_a_whole(tmp_path):
    """Even with parallel tool use disabled in the request, a reply that
    carries two tool_use blocks is rejected by the Runtime: nothing is
    proposed, evaluated, approved, dispatched or recorded as evidence."""
    run = Run(tmp_path, require_approval=True, answer="approve").start()
    provider, transport = _provider(_two_tools())

    result = _turn(run, provider)

    assert transport.body()["tool_choice"] == TOOL_CHOICE  # the request asked for one tool
    assert result.outcome == TurnOutcome.MALFORMED_TURN
    assert result.detail == rf.MULTIPLE_TOOL_USE_BLOCKS
    (rejected,) = [dict(e.details) for e in run.events() if e.event_type == E.AGENT_TURN_REJECTED]
    assert rejected["outcome"] == "multiple_tool_use_blocks" and rejected["accepted"] is False
    assert rejected["tool_use_blocks"] == 2 and rejected["proposed_capability"] is None
    assert _ACTION_EVENTS.isdisjoint(_event_types(run))  # no Gateway call, approval, dispatch or evidence
    assert run.runtime.evidence_store.list_by_investigation(run.inv) == ()
    assert run.context.evidence_refs == ()
    assert run.context.status == InvestigationStatus.RUNNING
    assert "approval" not in run.out.getvalue().lower()  # no approval prompt was shown


@pytest.mark.parametrize(
    "content",
    [
        [_tool(ENV, "toolu_1"), _tool(PORTS, "toolu_2")],
        [_tool(ENV, "toolu_1"), _tool(ENV, "toolu_2")],
        [_tool(PORTS, "toolu_1"), _tool("report_findings", "toolu_2")],
        [{"type": "text", "text": "both"}, _tool(ENV, "toolu_1"), _tool(PORTS, "toolu_2"), _tool(ENV, "toolu_3")],
    ],
    ids=["two_capabilities", "duplicate", "with_findings", "three_blocks"],
)
def test_no_multi_tool_reply_can_partially_execute(tmp_path, content):
    run = Run(tmp_path, require_approval=True, answer="approve").start()
    provider, _ = _provider(_message(content, "tool_use"))
    assert _turn(run, provider).detail == rf.MULTIPLE_TOOL_USE_BLOCKS
    assert _ACTION_EVENTS.isdisjoint(_event_types(run))
    assert E.FINDING_CREATED not in _event_types(run)
    assert run.runtime.evidence_store.list_by_investigation(run.inv) == ()


def test_one_tool_use_block_still_flows_through_gateway_approval_and_evidence(tmp_path):
    run = Run(tmp_path, require_approval=True, answer="approve").start()
    provider, transport = _provider(_message([_tool(ENV)], "tool_use"))
    result = _turn(run, provider)
    assert transport.body()["tool_choice"] == TOOL_CHOICE
    assert result.outcome == TurnOutcome.STEP_COMPLETED, result
    types = _event_types(run)
    for expected in (E.REQUEST_PROPOSED, E.POLICY_EVALUATED, E.APPROVAL_REQUESTED, E.APPROVAL_DECIDED,
                     E.DISPATCH_STARTED, E.DISPATCH_COMPLETED, E.EVIDENCE_RECORDED):
        assert types.count(expected) == 1, expected
    assert len(run.runtime.evidence_store.list_by_investigation(run.inv)) == 1


# ===========================================================================
# 13. No credential or provider secret reaches the audit log
# ===========================================================================


def test_no_api_key_in_audit_records(tmp_path):
    run = Run(tmp_path, require_approval=True, answer="approve").start()
    provider, _ = _provider(_two_tools(), _message([_tool(ENV)], "tool_use"))
    _turn(run, provider)
    _turn(run, provider)
    text = _audit_text(tmp_path)
    assert SENTINEL_KEY not in text
    assert "x-api-key" not in text.lower()
