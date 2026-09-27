"""Phase 15 — tool-output sensitive-data screening and model-egress control.

Covers NX-INV-1..6 (docs/AGENT-RUNTIME.md "Tool-output screening and model
egress (Phase 15)") and the fifteen adversarial breaks of the Phase 15
brief, plus the mandatory end-to-end T-60 scenario.
"""
from __future__ import annotations

import ast
import dataclasses
import json
from pathlib import Path
from typing import Any, Dict, List

import anthropic
import httpx2
import pytest

import chanakya.cli.main as cli_main
from chanakya.capability.envelope import CapabilityEnvelope, CapabilityEnvelopeError, envelope_from_registry_entry
from chanakya.contracts.agent_turn import ContextEntry, hash_json_normalized
from chanakya.contracts.audit_details import AuditFactError
from chanakya.contracts.audit_event import AuditEventType
from chanakya.contracts.enums import Classification, ModelEgress, Verdict
from chanakya.contracts.evidence import Evidence
from chanakya.contracts.investigation_context import InvestigationStatus
from chanakya.contracts.tool_output_screening import (
    CREDENTIAL_SHAPED_KEY,
    CREDENTIAL_SHAPED_VALUE,
    MAX_SCREEN_DEPTH,
    MAX_SCREEN_NODES,
    OUTPUT_UNSCREENABLE,
    TOOL_OUTPUT_SCREENING_VERSION,
    is_sensitive_output_rejection,
    rejection_message,
    screen_tool_output,
)
from chanakya.contracts.tool_result import ToolResultStatus
from chanakya.evidence import EvidenceStore
from chanakya.evidence.hashing import compute_content_hash
from chanakya.capability.model import ActionType
from chanakya.policy import PolicyGateway, PolicySet
from chanakya.policy.gateway import EvaluationContext
from chanakya.providers.anthropic_provider import AnthropicProvider
from chanakya.providers.config import ProviderConfig
from chanakya.registry.registry import SecurityToolRegistry
from chanakya.runtime.agent_loop import AgentLoopController, TurnOutcome, _ContextSource
from chanakya.runtime.audit import AuditEmitter, InMemoryAuditSink
from chanakya.runtime.evidence import FilesystemEvidenceRecorder, UnscreenedEvidenceError
from chanakya.tools.handlers.local_host_environment import LocalHostEnvironmentHandler
from factories import make_entry, make_request
from review_factories import Run, codes, load_stream, rewrite_events
from runtime_factories import (
    FakeToolExecutor,
    ScriptedAgentProvider,
    SpyPolicyEvaluator,
    make_agent_turn_conclude,
    make_agent_turn_propose,
    make_tool_result,
    output_executor,
)

_REPO = Path(__file__).resolve().parent.parent
_CHANAKYA = _REPO / "chanakya"
TARGET = "target-local-host-01"
SECRET = "super-secret-value-7f3a9c"
LEAKY = {"ports": [{"protocol": "tcp", "port": 8080, "local_address": "0.0.0.0",
                    "process": f"svc --api_key={SECRET}"}]}
E = AuditEventType


@pytest.fixture
def started_investigation(investigation_manager, investigation_request):
    context = investigation_manager.create_investigation(investigation_request)
    investigation_manager.start(context.investigation_id)
    return context


def _controller(manager, governor, gateway, executor, **kwargs):
    return AgentLoopController(manager, governor, gateway, executor, sleep=lambda _s: None, **kwargs)


def _propose(inv, parameters=None, capability="list_listening_ports"):
    return ScriptedAgentProvider([make_agent_turn_propose(inv, capability, TARGET, parameters or {})])


class _Capturing:
    def __init__(self, turns):
        self.inner = ScriptedAgentProvider(turns)
        self.contexts: List[Any] = []

    def next_turn(self, assembled):
        self.contexts.append(assembled)
        return self.inner.next_turn(assembled)


class _SpyRecorder:
    def __init__(self):
        self.records: List[Any] = []

    def record(self, evidence, payload=None):
        self.records.append((evidence, payload))
        return evidence.evidence_id


def _gateway_with(target_registry, entry):
    return PolicyGateway(SecurityToolRegistry([entry]), target_registry, PolicySet(policy_set_version="1.0.0", rules=()))


def _ports_entry(**overrides):
    return make_entry("list_listening_ports", classification=Classification.READ_ONLY, action_type=ActionType.OBSERVE,
                      category="network_information", **overrides)


def _files_text(root: Path) -> str:
    return "\n".join(p.read_text(encoding="utf-8") for p in root.rglob("*.json")) if root.exists() else ""


# ===========================================================================
# 1. The screen itself (NX-INV-1)
# ===========================================================================


@pytest.mark.parametrize(
    "content, code",
    [
        ({"processes": [{"name": "service", "command": "KEY=super-secret-value"}]}, CREDENTIAL_SHAPED_VALUE),  # the brief's example
        ({"a": {"b": {"c": "token=abc123"}}}, CREDENTIAL_SHAPED_VALUE),       # nested dict
        ({"a": [["x", ["password: hunter2"]]]}, CREDENTIAL_SHAPED_VALUE),      # nested list
        ({"a": [{"inner": {"password": "x"}}]}, CREDENTIAL_SHAPED_KEY),        # nested dict key
        ({"api_key": "value"}, CREDENTIAL_SHAPED_KEY),                        # top-level key
        ({"url": "https://admin:pw@db.example"}, CREDENTIAL_SHAPED_VALUE),     # URL userinfo
        ({"k": "-----BEGIN OPENSSH PRIVATE KEY-----"}, CREDENTIAL_SHAPED_VALUE),  # PEM header
        ({"cmd": "run AWS_SECRET_ACCESS_KEY=AKIA0000 x"}, CREDENTIAL_SHAPED_VALUE),
        ({"cmd": "svc --client-secret=abc"}, CREDENTIAL_SHAPED_VALUE),
    ],
)
def test_screen_detects_credentials_at_any_depth(content, code):
    """BREAK 2: values, keys, nested lists and nested dicts are all screened."""
    assert screen_tool_output({"output": content, "error_message": None, "raw_output": None, "warnings": []}) == code


def test_screen_covers_every_persisted_payload_field():
    base = {"output": {"ok": 1}, "error_message": None, "raw_output": None, "warnings": []}
    assert screen_tool_output(base) is None
    assert screen_tool_output(dict(base, raw_output="password=x")) == CREDENTIAL_SHAPED_VALUE
    assert screen_tool_output(dict(base, warnings=["token=abc"])) == CREDENTIAL_SHAPED_VALUE


def test_screen_passes_the_real_production_outputs(target_registry, local_host_target):
    env_output = LocalHostEnvironmentHandler().run(local_host_target, {})
    assert screen_tool_output({"output": env_output, "warnings": []}) is None
    ports = {"ports": [{"protocol": "tcp", "port": 445, "local_address": "0.0.0.0", "pid": 4, "process": "System"},
                       {"protocol": "udp", "port": 53, "local_address": "127.0.0.1", "pid": 900, "process": "dns.exe"}]}
    assert screen_tool_output({"output": ports}) is None
    assert screen_tool_output({"output": {"note": "the api key was rotated yesterday"}}) is None  # prose


def test_screen_is_bounded_and_fails_closed():
    deep: Dict[str, Any] = {}
    cursor = deep
    for _ in range(MAX_SCREEN_DEPTH + 2):
        cursor["x"] = {}
        cursor = cursor["x"]
    wide = {"items": list(range(MAX_SCREEN_NODES + 1))}
    assert screen_tool_output(deep) == OUTPUT_UNSCREENABLE
    assert screen_tool_output(wide) == OUTPUT_UNSCREENABLE
    assert screen_tool_output({"x": "a" * 2_000_000}) == OUTPUT_UNSCREENABLE
    assert screen_tool_output({"x": object()}) == OUTPUT_UNSCREENABLE
    assert screen_tool_output({1: "x"}) == OUTPUT_UNSCREENABLE
    assert screen_tool_output(["not", "a", "mapping"]) == OUTPUT_UNSCREENABLE


def test_rejection_message_is_a_fixed_code():
    for code in (CREDENTIAL_SHAPED_KEY, CREDENTIAL_SHAPED_VALUE, OUTPUT_UNSCREENABLE):
        assert rejection_message(code) == f"sensitive_output_rejected: {code}"
        assert is_sensitive_output_rejection(rejection_message(code))
    assert not is_sensitive_output_rejection("sensitive_output_rejected: CREDENTIAL_SHAPED_VALUE extra")
    with pytest.raises(ValueError):
        rejection_message(f"leak {SECRET}")


# ===========================================================================
# 2. Runtime gate: rejection, no Evidence, no context, no retry (NX-INV-1/2/5)
# ===========================================================================


def test_t60_sensitive_output_never_reaches_evidence_context_or_provider(
    investigation_manager, resource_governor, gateway, started_investigation, tmp_path
):
    """MANDATORY (T-60), BREAK 1/4/8: Tool -> successful result with a
    credential -> Runtime -> (no) Evidence -> (no) context -> (no) provider."""
    inv = started_investigation.investigation_id
    store = EvidenceStore(tmp_path / "evidence")
    sink = InMemoryAuditSink()
    executor = output_executor(LEAKY)
    controller = _controller(investigation_manager, resource_governor, gateway, executor,
                             evidence_recorder=FilesystemEvidenceRecorder(store), audit=AuditEmitter(sink))

    first = controller.run_turn(inv, _propose(inv))

    assert first.outcome == TurnOutcome.STEP_FAILED
    assert first.tool_result.status == ToolResultStatus.ERROR
    assert first.tool_result.error_message == "sensitive_output_rejected: CREDENTIAL_SHAPED_VALUE"
    assert first.tool_result.output is None and first.tool_result.raw_output is None
    assert executor.call_count == 1  # retry budget is 2, yet no retry
    assert started_investigation.evidence_refs == ()
    assert store.list_by_investigation(inv) == ()
    assert controller._context_window(inv) == ()

    transport_requests: List[httpx2.Request] = []

    def handler(request):
        transport_requests.append(request)
        return httpx2.Response(200, json={
            "id": "m", "type": "message", "role": "assistant", "model": "claude-test-model",
            "content": [{"type": "text", "text": "done"}], "stop_reason": "end_turn", "stop_sequence": None,
            "usage": {"input_tokens": 1, "output_tokens": 1}})

    config = ProviderConfig(provider="anthropic", model="claude-test-model", api_key_env_var="K", timeout_seconds=5)
    client = anthropic.Anthropic(api_key="sk-test", base_url=config.effective_endpoint,
                                 http_client=httpx2.Client(transport=httpx2.MockTransport(handler)))
    second = controller.run_turn(inv, AnthropicProvider(config, "sk-test", client=client))

    assert second.outcome == TurnOutcome.CONCLUDED
    (sent,) = transport_requests
    body = sent.content.decode()
    assert SECRET not in body
    assert first.tool_result.tool_result_id not in body  # the rejected result is not even referenced
    assert json.loads(json.loads(body)["messages"][0]["content"])["untrusted_data"] == []
    everything = json.dumps([dataclasses.asdict(e) for e in sink.events], default=str)
    assert SECRET not in everything and SECRET not in str(first.detail)
    failed = [e for e in sink.events if e.event_type == E.DISPATCH_FAILED]
    assert [(e.details["retry_scheduled"], e.details["reason"]) for e in failed] == [(False, "sensitive_output_rejected")]


def test_rejection_never_retries_even_with_budget(investigation_manager, resource_governor, gateway, started_investigation):
    """BREAK 4."""
    inv = started_investigation.investigation_id
    executor = output_executor({"blob": "token=abc"})
    controller = _controller(investigation_manager, resource_governor, gateway, executor)
    result = controller.run_turn(inv, _propose(inv))
    assert result.outcome == TurnOutcome.STEP_FAILED
    assert executor.call_count == 1
    assert resource_governor.retry_count(inv) == 0


def test_rejection_error_contains_only_the_fixed_code(investigation_manager, resource_governor, gateway, started_investigation):
    """BREAK 8."""
    inv = started_investigation.investigation_id
    controller = _controller(investigation_manager, resource_governor, gateway, output_executor(LEAKY))
    result = controller.run_turn(inv, _propose(inv))
    message = result.tool_result.error_message
    assert message == rejection_message(CREDENTIAL_SHAPED_VALUE)
    assert SECRET not in message and "api_key" not in message and "svc" not in message
    assert SECRET not in json.dumps(dataclasses.asdict(result.tool_result), default=str)


def test_injected_evidence_recorder_never_sees_rejected_output(investigation_manager, resource_governor, gateway, started_investigation):
    """BREAK 3 (injected recorder): the gate runs before any recorder."""
    inv = started_investigation.investigation_id
    spy = _SpyRecorder()
    controller = _controller(investigation_manager, resource_governor, gateway, output_executor(LEAKY), evidence_recorder=spy)
    controller.run_turn(inv, _propose(inv))
    assert spy.records == []


def _evidence(**overrides):
    fields = dict(evidence_id="ev-1", contract_version="1.0.0", investigation_id="inv-1", step_id="s", tool_request_id="tr",
                  tool_result_id="res", target_id=TARGET, capability="list_listening_ports", recorded_at="t",
                  content_hash="pending", storage_ref="pending", classification=Classification.READ_ONLY)
    fields.update(overrides)
    return Evidence(**fields)


def test_production_recorder_refuses_unscreened_or_unmarked_evidence(tmp_path):
    """BREAK 3 (alternate path): calling the production recorder directly
    with unmarked Evidence, or a marker on unscreened content, persists
    nothing; the error is a fixed code."""
    store = EvidenceStore(tmp_path / "evidence")
    recorder = FilesystemEvidenceRecorder(store)
    payload = {"output": LEAKY, "error_message": None, "raw_output": None, "warnings": []}
    with pytest.raises(UnscreenedEvidenceError, match="^evidence_screening_missing$"):
        recorder.record(_evidence(), {"output": {"ok": 1}})
    with pytest.raises(UnscreenedEvidenceError) as caught:
        recorder.record(_evidence(redactions_applied=False, screening_version=TOOL_OUTPUT_SCREENING_VERSION), payload)
    assert str(caught.value) == "sensitive_output_rejected: CREDENTIAL_SHAPED_VALUE"
    assert SECRET not in _files_text(tmp_path)
    clean = recorder.record(_evidence(redactions_applied=False, screening_version=TOOL_OUTPUT_SCREENING_VERSION),
                            {"output": {"ok": 1}})
    assert store.get(clean).screening_version == TOOL_OUTPUT_SCREENING_VERSION


# ===========================================================================
# 3. Evidence provenance (NX-INV-4)
# ===========================================================================


def test_clean_evidence_records_screening_provenance(tmp_path):
    run = Run(tmp_path).start()
    run.propose()
    (evidence,) = run.runtime.evidence_store.list_by_investigation(run.inv)
    assert evidence.screening_version == TOOL_OUTPUT_SCREENING_VERSION
    assert evidence.redactions_applied is False  # screened, never redacted


def test_evidence_contract_validates_screening_provenance():
    with pytest.raises(ValueError, match="screening"):
        _evidence(redactions_applied=False, screening_version="chanakya-tool-output-screen/9.9.9")
    with pytest.raises(ValueError, match="screening"):
        _evidence(redactions_applied=False, screening_version="anything goes")
    with pytest.raises(ValueError, match="redact"):
        _evidence(redactions_applied=True, screening_version=TOOL_OUTPUT_SCREENING_VERSION)
    with pytest.raises(ValueError, match="redact"):
        _evidence(screening_version=TOOL_OUTPUT_SCREENING_VERSION)  # redactions_applied must be explicit False
    assert _evidence().screening_version is None  # a historical (pre-Phase-15) record stays valid


def test_historical_evidence_without_marker_still_verifies(tmp_path):
    store = EvidenceStore(tmp_path)
    stored = store.append(_evidence(), {"output": {"x": 1}})
    record = json.loads((tmp_path / "inv-1" / "ev-1.json").read_text(encoding="utf-8"))
    assert "screening_version" not in record  # exact pre-Phase-15 shape and hash input
    assert store.verify_in_investigation("inv-1", stored.evidence_id).screening_version is None


# ===========================================================================
# 4. Model egress (NX-INV-3)
# ===========================================================================


@pytest.mark.parametrize("value", [None, "allowed", "anything", 1, True])
def test_registry_requires_a_declared_egress(value):
    """BREAK 13 (invalid) / BREAK 14 (missing): no permissive default."""
    with pytest.raises(ValueError, match="model_egress"):
        _ports_entry(model_egress=value)


def test_envelope_requires_a_declared_egress():
    entry = _ports_entry(model_egress=ModelEgress.EVIDENCE_ONLY)
    envelope = envelope_from_registry_entry(entry)
    assert envelope.model_egress is ModelEgress.EVIDENCE_ONLY  # from the Registry, nothing else
    data = envelope.to_dict()
    assert data["model_egress"] == "evidence_only"
    with pytest.raises(CapabilityEnvelopeError):
        CapabilityEnvelope.from_dict(dict(data, model_egress="anything"))
    with pytest.raises(CapabilityEnvelopeError):
        CapabilityEnvelope.from_dict({k: v for k, v in data.items() if k != "model_egress"})
    with pytest.raises(CapabilityEnvelopeError, match="model_egress"):
        CapabilityEnvelope(capability="c", output_schema={"type": "object"}, max_output_bytes=1, timeout_seconds=1,
                           model_egress="allowed")


def test_evidence_only_output_is_evidence_but_never_model_context(
    investigation_manager, resource_governor, target_registry, started_investigation
):
    inv = started_investigation.investigation_id
    gateway = _gateway_with(target_registry, _ports_entry(model_egress=ModelEgress.EVIDENCE_ONLY))
    sink = InMemoryAuditSink()
    controller = _controller(investigation_manager, resource_governor, gateway, output_executor({"ports": []}), audit=AuditEmitter(sink))
    assert controller.run_turn(inv, _propose(inv)).outcome == TurnOutcome.STEP_COMPLETED
    assert len(started_investigation.evidence_refs) == 1  # stored as Evidence
    agent = _Capturing([make_agent_turn_conclude(inv)])
    assert controller.run_turn(inv, agent).outcome == TurnOutcome.CONCLUDED
    assert agent.contexts[0].data == ()  # never shown to the model
    manifest = [e for e in sink.events if e.event_type == E.AGENT_TURN_REQUESTED][-1].details
    assert manifest["context_entries"] == []
    policy = next(e for e in sink.events if e.event_type == E.POLICY_EVALUATED)
    assert policy.details["envelope"]["model_egress"] == "evidence_only"


def test_handler_cannot_declare_its_own_egress(investigation_manager, resource_governor, target_registry, started_investigation):
    """BREAK 5: the Registry says evidence_only; the handler's output says
    otherwise; the Registry wins."""
    inv = started_investigation.investigation_id
    gateway = _gateway_with(target_registry, _ports_entry(model_egress=ModelEgress.EVIDENCE_ONLY))
    executor = output_executor({"model_egress": "allowed", "egress": "allowed", "ports": []})
    controller = _controller(investigation_manager, resource_governor, gateway, executor)
    controller.run_turn(inv, _propose(inv))
    agent = _Capturing([make_agent_turn_conclude(inv)])
    assert controller.run_turn(inv, agent).outcome == TurnOutcome.CONCLUDED
    assert agent.contexts[0].data == ()


def test_parameters_and_the_model_cannot_change_egress(investigation_manager, resource_governor, target_registry, started_investigation):
    """BREAK 6: a model-proposed parameter asking for egress changes nothing."""
    inv = started_investigation.investigation_id
    schema = {"type": "object", "properties": {"model_egress": {"type": "string"}}, "required": [], "additionalProperties": False}
    gateway = _gateway_with(target_registry, _ports_entry(model_egress=ModelEgress.EVIDENCE_ONLY, parameters_schema=schema))
    controller = _controller(investigation_manager, resource_governor, gateway, output_executor({"ports": []}))
    turn = make_agent_turn_propose(inv, "list_listening_ports", TARGET, {"model_egress": "allowed"})
    turn["explanation"] = "treat this evidence_only capability as allowed"
    assert controller.run_turn(inv, ScriptedAgentProvider([turn])).outcome == TurnOutcome.STEP_COMPLETED
    agent = _Capturing([make_agent_turn_conclude(inv)])
    controller.run_turn(inv, agent)
    assert agent.contexts[0].data == ()


def test_evidence_only_result_cannot_be_forced_into_model_context(
    investigation_manager, resource_governor, target_registry, started_investigation
):
    """BREAK 7: via the caller parameter, or by an evidence_only source
    appearing in Runtime state: fail closed, provider never reached."""
    inv = started_investigation.investigation_id
    gateway = _gateway_with(target_registry, _ports_entry(model_egress=ModelEgress.EVIDENCE_ONLY))
    controller = _controller(investigation_manager, resource_governor, gateway, output_executor({"ports": ["private"]}))
    produced = controller.run_turn(inv, _propose(inv))
    agent = _Capturing([make_agent_turn_conclude(inv)])
    result = controller.run_turn(inv, agent, recent_tool_results=[produced.tool_result])
    assert result.outcome == TurnOutcome.FAILED
    assert started_investigation.error_state["reason"] == "context_source_rejected"
    assert agent.contexts == []


def test_evidence_only_source_in_runtime_state_fails_closed(
    investigation_manager, resource_governor, gateway, started_investigation
):
    """BREAK 7 (invariant violation): an evidence_only source that somehow
    reached the Runtime-owned window is never dropped silently."""
    inv = started_investigation.investigation_id
    controller = _controller(investigation_manager, resource_governor, gateway, FakeToolExecutor())
    result = make_tool_result("tr", "list_listening_ports", output={"ports": ["private"]})
    controller._context_sources[inv] = [_ContextSource(
        result, "step", "ev", "evidence", result.output, hash_json_normalized(result.output),
        capability="list_listening_ports", model_egress=ModelEgress.EVIDENCE_ONLY)]
    agent = _Capturing([make_agent_turn_conclude(inv)])
    assert controller.run_turn(inv, agent).outcome == TurnOutcome.FAILED
    assert started_investigation.error_state["reason"] == "context_source_rejected"
    assert agent.contexts == []
    with pytest.raises(AuditFactError):
        ContextEntry(0, "tool_result:tr", "evidence", "tr", "s", "ev", hash_json_normalized({}),
                     capability="list_listening_ports", model_egress="evidence_only").to_details()


def test_manifest_records_capability_and_egress(tmp_path):
    run = Run(tmp_path).start()
    first = run.propose()
    run.conclude()
    manifest = [e.details for e in run.events() if e.event_type == E.AGENT_TURN_REQUESTED][-1]
    (entry,) = manifest["context_entries"]
    assert entry["capability"] == first.tool_result.capability
    assert entry["model_egress"] == "allowed"


# ===========================================================================
# 5. Review (NX-INV-3/4)
# ===========================================================================


def _forge_evidence(run: Run, change) -> None:
    """A local attacker rewrites an Evidence record (and payload) and
    recomputes every hash, so the store itself still verifies."""
    evidence_dir = run.workdir / "evidence" / run.inv
    record_path = next(evidence_dir.glob("*.json"))
    record = json.loads(record_path.read_text(encoding="utf-8"))
    payload_path = evidence_dir / "payloads" / record_path.name
    payload = json.loads(payload_path.read_text(encoding="utf-8"))
    change(record, payload)
    payload_path.write_text(json.dumps(payload), encoding="utf-8")
    record["payload_hash"] = compute_content_hash(payload)
    record["content_hash"] = compute_content_hash({k: v for k, v in record.items() if k != "content_hash"})
    record_path.write_text(json.dumps(record), encoding="utf-8")


def test_review_of_a_phase_15_run_is_consistent_and_shows_screening(tmp_path):
    run = Run(tmp_path).start()
    run.propose()
    run.conclude()
    review = run.review()
    assert review.consistent, codes(review)
    (evidence,) = review.evidence
    assert evidence.screening_version == TOOL_OUTPUT_SCREENING_VERSION and evidence.screening_required
    assert review.requests[0].policy.envelope_model_egress == "allowed"
    code, text = run.cli_review()
    assert code == cli_main.EXIT_COMPLETED
    assert f"screened \"{TOOL_OUTPUT_SCREENING_VERSION}\"" in text and "model egress \"allowed\"" in text


def test_review_flags_missing_screening_marker(tmp_path):
    run = Run(tmp_path).start()
    run.propose()
    _forge_evidence(run, lambda record, payload: record.pop("screening_version"))
    assert "evidence_screening_missing" in codes(run.review())
    assert "NOT SCREENED" in run.cli_review()[1]


def test_review_flags_a_forged_screening_marker(tmp_path):
    """BREAK 9: Evidence that claims screening but carries a credential."""
    run = Run(tmp_path).start()
    run.propose()
    _forge_evidence(run, lambda record, payload: payload["output"].update(note=f"password={SECRET}"))
    review = run.review()
    assert "evidence_screening_inconsistent" in codes(review)
    code, text = run.cli_review()
    assert SECRET not in text  # Review reports codes, never the content


def _mutate(run: Run, event_type: str, occurrence: int, change) -> None:
    def mutate(events):
        seen = 0
        for event in events:
            if event["event_type"] == event_type:
                seen += 1
                if seen == occurrence:
                    change(event)
        return events

    rewrite_events(run.stream_dir(), mutate)


def test_review_flags_forged_manifest_egress(tmp_path):
    """BREAK 10."""
    run = Run(tmp_path).start()
    run.propose()
    run.conclude()
    _mutate(run, "agent_turn_requested", 2, lambda e: e["details"]["context_entries"][0].update(model_egress="evidence_only"))
    assert {"turn_context_egress_not_allowed", "turn_context_egress_mismatch"} <= set(codes(run.review()))

    run2 = Run(tmp_path / "b").start()
    run2.propose()
    run2.conclude()
    # The authorizing decision said evidence_only, yet the manifest says allowed.
    _mutate(run2, "policy_evaluated", 1, lambda e: e["details"]["envelope"].update(model_egress="evidence_only"))
    assert "turn_context_egress_mismatch" in codes(run2.review())

    run3 = Run(tmp_path / "c").start()
    run3.propose()
    run3.conclude()
    _mutate(run3, "agent_turn_requested", 2, lambda e: e["details"]["context_entries"][0].update(capability="other_capability"))
    assert "turn_context_capability_mismatch" in codes(run3.review())


def test_review_flags_mixed_contract_versions(tmp_path):
    """BREAK 11."""
    run = Run(tmp_path).start()
    run.propose()
    run.conclude()
    _mutate(run, "investigation_started", 1, lambda e: e.update(contract_version="1.1.0"))
    review = run.review()
    assert review.audit_verified
    assert "mixed_contract_versions" in codes(review)
    assert not review.consistent

    run2 = Run(tmp_path / "b").start()
    run2.propose()
    _mutate(run2, "evidence_recorded", 1, lambda e: e.update(contract_version="1.0.0"))
    assert "mixed_contract_versions" in codes(run2.review())


def test_historical_streams_predate_the_control_and_are_not_reported_as_screened(tmp_path):
    """A homogeneous 1.1.0 (Phase 14) stream whose Evidence has no marker is
    consistent, and is reported as predating Phase 15, not as screened."""
    run = Run(tmp_path).start()
    run.propose()
    run.conclude()
    _forge_evidence(run, lambda record, payload: record.pop("screening_version"))

    def downgrade(events):
        for event in events:
            event["contract_version"] = "1.1.0"
            details = event.get("details") or {}
            if event["event_type"] == "policy_evaluated" and details.get("envelope"):
                details["envelope"].pop("model_egress")
            if event["event_type"] == "agent_turn_requested":
                for entry in details["context_entries"]:
                    entry.pop("capability")
                    entry.pop("model_egress")
        return events

    rewrite_events(run.stream_dir(), downgrade)
    review = run.review()
    assert review.consistent, codes(review)
    (evidence,) = review.evidence
    assert evidence.screening_version is None and not evidence.screening_required
    assert "not assessed (predates Phase 15)" in run.cli_review()[1]


# ===========================================================================
# 6. No authority (NX-INV-6)
# ===========================================================================

_AUTHORITY_PATHS = [_CHANAKYA / "policy", _CHANAKYA / "approval", _CHANAKYA / "risk",
                    _CHANAKYA / "runtime" / "dispatch.py", _CHANAKYA / "runtime" / "tool_request_intake.py"]
_FORBIDDEN_NAMES = {"model_egress", "ModelEgress", "screening_version", "screen_tool_output", "tool_output_screening",
                    "is_sensitive_output_rejection", "TOOL_OUTPUT_SCREENING_VERSION"}


def _python_files():
    for path in _AUTHORITY_PATHS:
        yield from ([path] if path.is_file() else path.rglob("*.py"))


def test_screening_and_egress_are_unreachable_from_authorization():
    """BREAK 12: policy, approval, risk, dispatch and intake never reference
    screening or egress metadata."""
    offenders = []
    for path in _python_files():
        for node in ast.walk(ast.parse(path.read_text(encoding="utf-8"))):
            names = set()
            if isinstance(node, ast.Name):
                names.add(node.id)
            elif isinstance(node, ast.Attribute):
                names.add(node.attr)
            elif isinstance(node, ast.ImportFrom):
                names |= {a.name for a in node.names} | {node.module or ""}
            elif isinstance(node, ast.Import):
                names |= {a.name for a in node.names}
            if any(any(f in n for f in _FORBIDDEN_NAMES) for n in names):
                offenders.append(path.relative_to(_REPO).as_posix())
    assert offenders == []


def test_egress_never_changes_a_policy_verdict(target_registry):
    request = make_request("list_listening_ports", TARGET)
    context = EvaluationContext(authorized_target_refs=frozenset({TARGET}))
    verdicts = []
    for egress in ModelEgress:
        decision = _gateway_with(target_registry, _ports_entry(model_egress=egress)).evaluate(request, context)
        verdicts.append((decision.verdict, decision.matched_rule, decision.classification, decision.risk_category))
    assert verdicts[0] == verdicts[1] == (Verdict.ALLOW, "read-only-default", Classification.READ_ONLY, verdicts[0][3])


def test_screening_rejection_changes_no_policy_approval_or_risk(investigation_manager, resource_governor, gateway, started_investigation):
    inv = started_investigation.investigation_id
    spy = SpyPolicyEvaluator(gateway)
    controller = _controller(investigation_manager, resource_governor, spy, output_executor(LEAKY))
    controller.run_turn(inv, _propose(inv))
    assert spy.call_count == 1  # evaluated once, before execution, as always
    assert started_investigation.status == InvestigationStatus.RUNNING  # not halted, not approved, just failed data


# ===========================================================================
# 7. Provider retries (BREAK 15)
# ===========================================================================


def test_one_recorded_turn_is_one_provider_send(tmp_path):
    """BREAK 15: a retryable failure (529, x-should-retry) with an injected
    client that would retry twice still produces exactly one send."""
    sends: List[httpx2.Request] = []

    def handler(request):
        sends.append(request)
        return httpx2.Response(529, headers={"x-should-retry": "true"},
                               json={"type": "error", "error": {"type": "overloaded_error", "message": "busy"}})

    config = ProviderConfig(provider="anthropic", model="claude-test-model", api_key_env_var="K", timeout_seconds=5)
    client = anthropic.Anthropic(api_key="sk-test", base_url=config.effective_endpoint, max_retries=2,
                                 http_client=httpx2.Client(transport=httpx2.MockTransport(handler)))
    run = Run(tmp_path).start()
    result = run.runtime.controller.run_turn(run.inv, AnthropicProvider(config, "sk-test", client=client))
    assert result.outcome == TurnOutcome.FAILED
    assert len(sends) == 1
    turn_events = [e.event_type for e in run.events() if e.event_type.value.startswith("agent_turn")]
    assert turn_events == [E.AGENT_TURN_REQUESTED, E.AGENT_TURN_REJECTED]
