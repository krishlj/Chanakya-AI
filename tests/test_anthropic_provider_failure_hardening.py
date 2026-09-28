"""Phase 5.6.5 — Provider Failure & Timeout Hardening.

Hardens (by proving, not by adding code) the failure/timeout boundary
between the REAL ``AgentLoopController`` and the REAL
``chanakya.providers.anthropic_provider.AnthropicProvider``. Every test
here uses the real provider, the real Runtime pipeline (Investigation
Manager, ResourceGovernor, ToolRequestIntake, PolicyGateway,
CapabilityDispatchExecutor, FilesystemEvidenceRecorder, AuditEmitter —
mirroring ``tests/test_anthropic_provider_runtime_integration.py``'s
Phase 5.6.4 fixture pattern) and a deterministic fake Anthropic SDK
transport (``httpx2.MockTransport`` — this installed SDK build vendors
``httpx2``, not ``httpx``).

This phase adds NO new retry/failure-handling code anywhere in
``chanakya``. Every scenario below exercises EXISTING Runtime/provider
behavior and records what that behavior actually is. Where a defect was
found, it is reported, not silently patched (see the module-level
report delivered alongside this file, section "Production changes").

SDK exception-hierarchy and retry-policy facts this file's tests depend
on (established by direct inspection of the installed ``anthropic==1.7.0``
build before writing any test — see the accompanying report for the
full trail):

- ``AuthenticationError`` / ``RateLimitError`` / other 4xx-5xx status
  errors all derive from ``APIStatusError(APIError(AnthropicError))``.
- ``APITimeoutError`` derives from ``APIConnectionError(APIError(...))``
  — a timeout IS a connection-error subtype in this SDK's hierarchy.
- The SDK's OWN default retry policy (``anthropic.Anthropic(max_retries=2)``
  by default) retries HTTP 408/409/429/5xx responses and
  ``APIConnectionError``/``APITimeoutError``/``RetryableError``
  exceptions, with exponential backoff (starting 0.5s, capped at 8s,
  jittered) — entirely INSIDE the SDK, before ``AnthropicProvider`` or
  the Runtime ever sees a raised exception. HTTP 401 (authentication)
  is NOT in the SDK's retryable status set, so it is never retried
  regardless of ``max_retries``.
- Tests that need a single, deterministic transport call construct the
  injected test client with ``max_retries=0`` — this is a TEST-side SDK
  configuration choice, not a Chanakya retry mechanism, and it exists
  specifically to keep "the provider/Runtime pipeline never retries"
  assertions unambiguous in the presence of the SDK's own retry policy
  (see ``test_sdk_default_retry_is_an_sdk_concern_not_chanakyas`` for the
  one test that deliberately leaves the SDK's retry enabled, to document
  — not exploit — that behavior).
"""
from __future__ import annotations

import json
import time
from datetime import datetime, timezone
from typing import Any, Dict, List, Mapping, Optional

import anthropic
import httpx2
import pytest

from chanakya.capability.model import ActionType
from chanakya.contracts.enums import Classification
from chanakya.contracts.investigation_context import InvestigationStatus
from chanakya.contracts.investigation_request import InvestigationRequest
from chanakya.contracts.target import Target
from chanakya.contracts.tool_result import ToolResultStatus
from chanakya.evidence import EvidenceStore
from chanakya.policy.gateway import PolicyGateway
from chanakya.policy.rules import PolicySet
from chanakya.providers.anthropic_provider import AnthropicProvider
from chanakya.providers.config import ProviderConfig
from chanakya.registry.bootstrap import make_observe_local_host_environment_entry
from chanakya.registry.registry import SecurityToolRegistry
from chanakya.runtime.agent_loop import AgentLoopController, TurnOutcome
from chanakya.runtime.audit import AuditEmitter, InMemoryAuditSink
from chanakya.runtime.dispatch import DispatchInstruction
from chanakya.runtime.evidence import FilesystemEvidenceRecorder
from chanakya.runtime.investigation_manager import InvestigationManager
from chanakya.runtime.limits import RuntimeExecutionLimits
from chanakya.runtime.resource_governor import ResourceGovernor
from chanakya.targets.registry import TargetRegistry
from chanakya.tools.bootstrap import build_tool_executor
from chanakya.tools.handlers.local_host_environment import CAPABILITY_ID

from factories import make_entry
from runtime_factories import SpyPolicyEvaluator

FAKE_API_KEY = "test-key-not-real"


def no_sleep(_seconds: float) -> None:
    return None


def now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


# ===========================================================================
# Structural guarantee: no test in this module can reach the real network.
# ===========================================================================


@pytest.fixture(autouse=True)
def _no_real_network_transport(monkeypatch):
    def _forbidden(*_args: Any, **_kwargs: Any) -> None:
        raise AssertionError(
            "a real network transport call was attempted — every test in "
            "this module must route through httpx2.MockTransport"
        )

    monkeypatch.setattr(httpx2.HTTPTransport, "handle_request", _forbidden)


# ===========================================================================
# Fake Anthropic SDK transports
# ===========================================================================


class RecordingTransport:
    """Returns the same configured response/status for every call."""

    def __init__(self, response_json: Optional[Mapping[str, Any]] = None, *, status_code: int = 200) -> None:
        self.requests: List[httpx2.Request] = []
        self._response_json = response_json
        self._status_code = status_code

    def handler(self, request: httpx2.Request) -> httpx2.Response:
        self.requests.append(request)
        return httpx2.Response(self._status_code, json=self._response_json)

    def client(self, *, max_retries: int = 0, timeout: Optional[float] = None) -> anthropic.Anthropic:
        kwargs: Dict[str, Any] = dict(
            api_key=FAKE_API_KEY,
            http_client=httpx2.Client(trust_env=False, transport=httpx2.MockTransport(self.handler)),
            max_retries=max_retries,
        )
        if timeout is not None:
            kwargs["timeout"] = timeout
        return anthropic.Anthropic(**kwargs)


class RaisingTransport:
    """Every call raises the configured exception from inside the
    transport handler itself (used for connection/timeout simulation —
    deterministic, no real socket, no real sleep)."""

    def __init__(self, exc_factory) -> None:
        self._exc_factory = exc_factory
        self.requests: List[httpx2.Request] = []

    def handler(self, request: httpx2.Request) -> httpx2.Response:
        self.requests.append(request)
        raise self._exc_factory(request)

    def client(self, *, max_retries: int = 0) -> anthropic.Anthropic:
        return anthropic.Anthropic(
            api_key=FAKE_API_KEY,
            http_client=httpx2.Client(trust_env=False, transport=httpx2.MockTransport(self.handler)),
            max_retries=max_retries,
        )


class SequencedTransport:
    """Returns a different pre-configured (status, json) pair per call,
    in order — used for Scenario 8 (success, then failure, across two
    separate Runtime turns using the SAME provider/client)."""

    def __init__(self, responses: List["tuple[int, Mapping[str, Any]]"]) -> None:
        self._responses = list(responses)
        self.requests: List[httpx2.Request] = []

    def handler(self, request: httpx2.Request) -> httpx2.Response:
        index = len(self.requests)
        self.requests.append(request)
        status_code, payload = self._responses[index]
        return httpx2.Response(status_code, json=payload)

    def client(self) -> anthropic.Anthropic:
        return anthropic.Anthropic(
            api_key=FAKE_API_KEY,
            http_client=httpx2.Client(trust_env=False, transport=httpx2.MockTransport(self.handler)),
            max_retries=0,
        )


class _RawExceptionMessages:
    """A duck-typed stand-in for ``anthropic.Anthropic().messages`` whose
    ``create`` raises an exception that is NOT part of the Anthropic SDK's
    own exception hierarchy at all — isolating "a truly unexpected
    provider-side exception" from the SDK's own (fairly aggressive, as
    discovered above) habit of wrapping arbitrary transport-layer
    exceptions into ``APIConnectionError``. This is the deterministic
    seam for Scenario 6."""

    def __init__(self, exc: BaseException) -> None:
        self._exc = exc
        self.calls = 0

    def create(self, **_kwargs: Any) -> Any:
        self.calls += 1
        raise self._exc


def _RawExceptionClient(exc: BaseException):
    """Phase 18: a real, transport-verified SDK client (environment trust
    off, in-process transport) whose ``messages`` resource raises ``exc``
    directly, so the exception is still NOT a member of the SDK hierarchy.
    Duck-typed non-SDK clients are rejected by the provider (they cannot be
    verified)."""
    raw = _RawExceptionMessages(exc)
    # A subclass property survives the SDK's with_options() copy.
    client_class = type("_RawClient", (anthropic.Anthropic,), {"messages": property(lambda self: raw)})
    return client_class(
        api_key="sk-test-raw", base_url="https://api.anthropic.com", max_retries=0,
        http_client=httpx2.Client(trust_env=False, transport=httpx2.MockTransport(lambda request: httpx2.Response(500))),
    )


def _conclude_response(text: str = "investigation complete") -> Dict[str, Any]:
    return {
        "id": "msg_conclude",
        "type": "message",
        "role": "assistant",
        "model": "claude-test-model",
        "content": [{"type": "text", "text": text}],
        "stop_reason": "end_turn",
        "stop_sequence": None,
        "usage": {"input_tokens": 5, "output_tokens": 5},
    }


def _tool_use_response(capability: str, input_payload: Mapping[str, Any]) -> Dict[str, Any]:
    return {
        "id": "msg_tool_use",
        "type": "message",
        "role": "assistant",
        "model": "claude-test-model",
        "content": [{"type": "tool_use", "id": "toolu_1", "name": capability, "input": dict(input_payload)}],
        "stop_reason": "tool_use",
        "stop_sequence": None,
        "usage": {"input_tokens": 5, "output_tokens": 5},
    }


def _error_body(error_type: str, message: str) -> Dict[str, Any]:
    return {"type": "error", "error": {"type": error_type, "message": message}}


def _config(**overrides: Any) -> ProviderConfig:
    fields: Dict[str, Any] = dict(
        provider="anthropic",
        model="claude-test-model",
        api_key_env_var="ANTHROPIC_API_KEY",
        timeout_seconds=30.0,
    )
    fields.update(overrides)
    return ProviderConfig(**fields)


class RecordingProviderWrapper:
    """Counts every ``next_turn`` attempt (even ones that raise) and
    records every value successfully returned — the seam used throughout
    this file to distinguish "the Runtime called the provider N times"
    from "the SDK transport received M requests" (N is always 1 in every
    scenario here; M can differ when SDK-level retry is deliberately left
    enabled, per ``test_sdk_default_retry_is_an_sdk_concern_not_chanakyas``)."""

    def __init__(self, delegate: AnthropicProvider) -> None:
        self._delegate = delegate
        self.call_count = 0
        self.returned: List[Any] = []

    def next_turn(self, assembled_context):
        self.call_count += 1
        value = self._delegate.next_turn(assembled_context)
        self.returned.append(value)
        return value


class SpyToolExecutor:
    def __init__(self, delegate: Any) -> None:
        self._delegate = delegate
        self.calls: List[DispatchInstruction] = []

    def execute(self, instruction: DispatchInstruction):
        self.calls.append(instruction)
        return self._delegate.execute(instruction)


# ===========================================================================
# Runtime fixtures — mirrors tests/test_anthropic_provider_runtime_integration.py
# ===========================================================================


@pytest.fixture
def local_host_target() -> Target:
    return Target(
        target_id="target-local-host-01",
        contract_version="1.0.0",
        target_type="local_host",
        display_name="Primary workstation",
        authorized_scope="This machine only, read-only capabilities",
        registered_at=now(),
    )


@pytest.fixture
def target_registry(local_host_target):
    return TargetRegistry([local_host_target])


@pytest.fixture
def production_entry():
    return make_observe_local_host_environment_entry()


@pytest.fixture
def terminate_process_entry():
    return make_entry(
        "terminate_process",
        classification=Classification.STATE_CHANGING,
        action_type=ActionType.MUTATE,
        parameters_schema={
            "type": "object",
            "properties": {"pid": {"type": "integer", "minimum": 1}},
            "required": ["pid"],
            "additionalProperties": False,
        },
    )


@pytest.fixture
def registry(production_entry, terminate_process_entry):
    return SecurityToolRegistry([production_entry, terminate_process_entry])


@pytest.fixture
def empty_policy_set():
    return PolicySet(policy_set_version="1.0.0", rules=[])


@pytest.fixture
def gateway(registry, target_registry, empty_policy_set):
    return PolicyGateway(registry, target_registry, empty_policy_set)


@pytest.fixture
def tool_executor(target_registry):
    return build_tool_executor(target_registry)


@pytest.fixture
def evidence_store(tmp_path):
    return EvidenceStore(tmp_path / "evidence-root")


@pytest.fixture
def evidence_recorder(evidence_store):
    return FilesystemEvidenceRecorder(evidence_store)


@pytest.fixture
def runtime_limits():
    return RuntimeExecutionLimits(
        config_version="1.0.0",
        max_steps_per_investigation=6,
        max_tool_calls_per_investigation=5,
        max_investigation_duration_seconds=3600,
        default_step_timeout_seconds=10,
        max_retries_per_step=1,
        retry_backoff_seconds=0,
        max_concurrent_investigations=5,
    )


@pytest.fixture
def resource_governor(runtime_limits):
    return ResourceGovernor(runtime_limits, clock=lambda: datetime.now(timezone.utc))


@pytest.fixture
def investigation_manager(target_registry, resource_governor):
    return InvestigationManager(target_registry, resource_governor)


def make_investigation_request(target_ids, req_id: str = "inv-req-failure-hardening-1") -> InvestigationRequest:
    return InvestigationRequest.from_dict(
        {
            "investigation_request_id": req_id,
            "contract_version": "1.0.0",
            "objective": "Exercise Phase 5.6.5 provider failure/timeout hardening",
            "requested_targets": list(target_ids),
            "submitted_by": "test-human",
            "submitted_at": now(),
        }
    )


@pytest.fixture
def investigation_request(local_host_target):
    return make_investigation_request([local_host_target.target_id])


@pytest.fixture
def started_investigation(investigation_manager, investigation_request):
    context = investigation_manager.create_investigation(investigation_request)
    investigation_manager.start(context.investigation_id)
    return context


def _controller(investigation_manager, resource_governor, gateway, executor, *, evidence_recorder=None, audit=None):
    return AgentLoopController(
        investigation_manager,
        resource_governor,
        gateway,
        executor,
        evidence_recorder=evidence_recorder,
        audit=audit,
        sleep=no_sleep,
    )


# ===========================================================================
# Scenario 1 — Authentication failure
# ===========================================================================


def test_scenario1_authentication_failure_reaches_existing_failed_state(
    investigation_manager, resource_governor, gateway, tool_executor, evidence_recorder, started_investigation
):
    transport = RecordingTransport(_error_body("authentication_error", "invalid x-api-key"), status_code=401)
    # Default max_retries (2) deliberately left in place here: 401 is not
    # in the SDK's own retryable-status set (408/409/429/5xx only), so
    # this also documents that fact empirically, not just by citation.
    provider = AnthropicProvider(_config(), FAKE_API_KEY, client=transport.client(max_retries=2))
    wrapper = RecordingProviderWrapper(provider)
    spy_gateway = SpyPolicyEvaluator(gateway)
    spy_executor = SpyToolExecutor(tool_executor)
    sink = InMemoryAuditSink()
    audit = AuditEmitter(sink)
    controller = _controller(
        investigation_manager, resource_governor, spy_gateway, spy_executor, evidence_recorder=evidence_recorder, audit=audit
    )

    result = controller.run_turn(started_investigation.investigation_id, wrapper)

    assert result.outcome == TurnOutcome.FAILED
    assert started_investigation.status == InvestigationStatus.FAILED
    assert wrapper.call_count == 1  # Runtime called the provider exactly once — no Chanakya retry
    assert len(transport.requests) == 1  # 401 is not retried by the SDK even with max_retries=2
    assert wrapper.returned == []  # never returned a value — always raised
    assert spy_gateway.call_count == 0
    assert spy_executor.calls == []
    assert started_investigation.evidence_refs == ()
    event_types = [e.event_type.value for e in sink.events]
    assert "policy_evaluated" not in event_types
    assert "approval_requested" not in event_types
    assert "dispatch_started" not in event_types
    assert "evidence_recorded" not in event_types
    assert "error" in event_types


# ===========================================================================
# Scenario 2 — Rate limit
# ===========================================================================


def test_scenario2_rate_limit_failure_is_a_controlled_failure(
    investigation_manager, resource_governor, gateway, tool_executor, evidence_recorder, started_investigation
):
    transport = RecordingTransport(_error_body("rate_limit_error", "rate limited"), status_code=429)
    # max_retries=0: 429 IS in the SDK's retryable set, so this isolates
    # Chanakya/Runtime behavior from the SDK's own retry timing — see the
    # module docstring and test_sdk_default_retry_is_an_sdk_concern_...
    # below for the SDK-retry behavior documented on its own terms.
    provider = AnthropicProvider(_config(), FAKE_API_KEY, client=transport.client(max_retries=0))
    wrapper = RecordingProviderWrapper(provider)
    spy_gateway = SpyPolicyEvaluator(gateway)
    spy_executor = SpyToolExecutor(tool_executor)
    controller = _controller(
        investigation_manager, resource_governor, spy_gateway, spy_executor, evidence_recorder=evidence_recorder
    )

    result = controller.run_turn(started_investigation.investigation_id, wrapper)

    assert result.outcome == TurnOutcome.FAILED
    assert started_investigation.status == InvestigationStatus.FAILED
    assert wrapper.call_count == 1
    assert len(transport.requests) == 1
    assert spy_gateway.call_count == 0
    assert spy_executor.calls == []
    assert started_investigation.evidence_refs == ()


# ===========================================================================
# Scenario 3 — API status failure (HTTP 500)
# ===========================================================================


def test_scenario3_api_status_failure_reaches_existing_failed_state(
    investigation_manager, resource_governor, gateway, tool_executor, evidence_recorder, started_investigation
):
    transport = RecordingTransport(_error_body("api_error", "internal server error"), status_code=500)
    provider = AnthropicProvider(_config(), FAKE_API_KEY, client=transport.client(max_retries=0))
    wrapper = RecordingProviderWrapper(provider)
    spy_gateway = SpyPolicyEvaluator(gateway)
    spy_executor = SpyToolExecutor(tool_executor)
    controller = _controller(
        investigation_manager, resource_governor, spy_gateway, spy_executor, evidence_recorder=evidence_recorder
    )

    result = controller.run_turn(started_investigation.investigation_id, wrapper)

    assert result.outcome == TurnOutcome.FAILED
    assert started_investigation.status == InvestigationStatus.FAILED
    assert wrapper.call_count == 1
    assert len(transport.requests) == 1
    assert spy_gateway.call_count == 0
    assert spy_executor.calls == []
    assert started_investigation.evidence_refs == ()


def test_sdk_default_retry_is_an_sdk_concern_not_chanakyas(
    investigation_manager, resource_governor, gateway, tool_executor, evidence_recorder, started_investigation
):
    """Deliberately leaves the SDK's own retry policy ENABLED (max_retries=1
    — a smaller-than-default value purely to keep this test's real,
    SDK-internal backoff sleep short; the SDK's actual default is 2,
    confirmed separately by source inspection, not re-executed here to
    avoid an unnecessary ~1.5s sleep in the suite) against a 500 response,
    which IS in the SDK's retryable status set. This proves the retry
    happens entirely BELOW AnthropicProvider — the transport sees more
    than one request, but the Runtime still only ever calls
    AnthropicProvider.next_turn ONCE, and still reaches the same FAILED
    outcome as every max_retries=0 test above. No Chanakya code changed
    the SDK's behavior, and no Chanakya code added a second retry layer
    on top of it.
    """
    transport = RecordingTransport(_error_body("api_error", "internal server error"), status_code=500)
    provider = AnthropicProvider(_config(), FAKE_API_KEY, client=transport.client(max_retries=1))
    wrapper = RecordingProviderWrapper(provider)
    spy_gateway = SpyPolicyEvaluator(gateway)
    spy_executor = SpyToolExecutor(tool_executor)
    controller = _controller(
        investigation_manager, resource_governor, spy_gateway, spy_executor, evidence_recorder=evidence_recorder
    )

    result = controller.run_turn(started_investigation.investigation_id, wrapper)

    assert result.outcome == TurnOutcome.FAILED
    assert wrapper.call_count == 1  # Chanakya/Runtime: exactly one provider call
    # Phase 15: the provider turns SDK retries off even on an injected client
    # (max_retries=1 here), so one recorded turn is exactly one send.
    assert len(transport.requests) == 1
    assert spy_gateway.call_count == 0
    assert spy_executor.calls == []


# ===========================================================================
# Scenario 4 — Connection failure
# ===========================================================================


def test_scenario4_connection_failure_no_chanakya_retry(
    investigation_manager, resource_governor, gateway, tool_executor, evidence_recorder, started_investigation
):
    transport = RaisingTransport(lambda request: httpx2.ConnectError("connection refused", request=request))
    provider = AnthropicProvider(_config(), FAKE_API_KEY, client=transport.client(max_retries=0))
    wrapper = RecordingProviderWrapper(provider)
    spy_gateway = SpyPolicyEvaluator(gateway)
    spy_executor = SpyToolExecutor(tool_executor)
    controller = _controller(
        investigation_manager, resource_governor, spy_gateway, spy_executor, evidence_recorder=evidence_recorder
    )

    result = controller.run_turn(started_investigation.investigation_id, wrapper)

    assert result.outcome == TurnOutcome.FAILED
    assert started_investigation.status == InvestigationStatus.FAILED
    assert wrapper.call_count == 1  # Runtime never retries a connection failure
    assert len(transport.requests) == 1  # max_retries=0 — SDK didn't retry either
    assert spy_gateway.call_count == 0
    assert spy_executor.calls == []
    assert started_investigation.evidence_refs == ()


# ===========================================================================
# Scenario 5 — Timeout
# ===========================================================================


def test_scenario5_timeout_reaches_existing_failed_state_without_hanging(
    investigation_manager, resource_governor, gateway, tool_executor, evidence_recorder, started_investigation
):
    """The mock transport raises ``httpx2.ReadTimeout`` directly — a
    deterministic simulation of "the request timed out" with no real
    time elapsed and no dependency on wall-clock nondeterminism (per the
    phase's "prefer deterministic transport, avoid sleep-based tests"
    instruction). The SDK converts this into ``anthropic.APITimeoutError``
    (confirmed by direct inspection: ``except httpx2.TimeoutException:
    raise APITimeoutError(...) from err`` in ``anthropic._base_client``).
    """
    transport = RaisingTransport(lambda request: httpx2.ReadTimeout("simulated timeout", request=request))
    provider = AnthropicProvider(_config(timeout_seconds=5.0), FAKE_API_KEY, client=transport.client(max_retries=0))
    wrapper = RecordingProviderWrapper(provider)
    spy_gateway = SpyPolicyEvaluator(gateway)
    spy_executor = SpyToolExecutor(tool_executor)
    controller = _controller(
        investigation_manager, resource_governor, spy_gateway, spy_executor, evidence_recorder=evidence_recorder
    )

    started_at = time.monotonic()
    result = controller.run_turn(started_investigation.investigation_id, wrapper)
    elapsed = time.monotonic() - started_at

    assert elapsed < 2.0  # did not hang — no real wall-clock timeout was ever waited out
    assert result.outcome == TurnOutcome.FAILED
    assert started_investigation.status == InvestigationStatus.FAILED
    assert wrapper.call_count == 1
    assert len(transport.requests) == 1
    assert spy_gateway.call_count == 0
    assert spy_executor.calls == []
    assert started_investigation.evidence_refs == ()
    assert FAKE_API_KEY not in str(result.detail)


def test_provider_config_timeout_seconds_reaches_the_sdk_client():
    """Reconfirms (at this phase's boundary, not just Phase 5.6.3's unit
    test) that ``ProviderConfig.timeout_seconds`` — and ONLY that field —
    is what configures the provider's SDK request timeout when
    ``AnthropicProvider`` builds its own client (no ``client=`` override).
    No second, Chanakya-specific timeout setting exists anywhere in
    ``anthropic_provider.py``/``mapping.py`` (grepped: neither module
    defines a timeout-shaped field or constant)."""
    import unittest.mock as mock

    captured: Dict[str, Any] = {}
    real_init = anthropic.Anthropic.__init__

    def spy_init(self, *args, **kwargs):
        captured.update(kwargs)
        return real_init(self, *args, **kwargs)

    with mock.patch.object(anthropic.Anthropic, "__init__", spy_init):
        AnthropicProvider(_config(timeout_seconds=12.5), FAKE_API_KEY)

    assert captured["timeout"] == 12.5


def test_runtime_execution_limits_and_provider_timeout_are_distinct_settings():
    """Structural: RuntimeExecutionLimits (tool-execution/investigation
    governance) and ProviderConfig.timeout_seconds (the LLM request
    timeout) are two different objects with disjoint field sets — a
    provider timeout is never a substitute for, and never modifies,
    Runtime resource governance, and vice versa."""
    import dataclasses

    provider_fields = {f.name for f in dataclasses.fields(ProviderConfig)}
    limits_fields = {f.name for f in dataclasses.fields(RuntimeExecutionLimits)}
    assert provider_fields.isdisjoint(limits_fields)
    assert "timeout_seconds" in provider_fields
    assert "timeout_seconds" not in limits_fields
    # RuntimeExecutionLimits' own existing timeout concerns are entirely
    # separate concepts: per-step tool-execution timeout and
    # per-investigation wall-clock duration — neither is "the LLM
    # provider's HTTP request timeout".
    assert "default_step_timeout_seconds" in limits_fields
    assert "max_investigation_duration_seconds" in limits_fields


# ===========================================================================
# Scenario 6 — Unexpected provider exception
# ===========================================================================


def test_scenario6_unexpected_exception_is_not_swallowed(
    investigation_manager, resource_governor, gateway, tool_executor, evidence_recorder, started_investigation
):
    """Uses a duck-typed fake client (see module docstring) so the raised
    exception is NOT a member of the Anthropic SDK's own hierarchy at
    all — proving AnthropicProvider performs no broad
    ``except Exception`` conversion of its own (grepped: no ``try``/
    ``except`` exists anywhere in ``anthropic_provider.py``) and the
    Runtime's existing generic fail-closed backstop
    (``AgentLoopController.run_turn``'s outer ``except Exception``) is
    what actually catches it."""

    class UnexpectedProviderBug(RuntimeError):
        pass

    fake_client = _RawExceptionClient(UnexpectedProviderBug("simulated unexpected SDK-internal bug"))
    provider = AnthropicProvider(_config(), FAKE_API_KEY, client=fake_client)
    wrapper = RecordingProviderWrapper(provider)
    spy_gateway = SpyPolicyEvaluator(gateway)
    spy_executor = SpyToolExecutor(tool_executor)
    controller = _controller(
        investigation_manager, resource_governor, spy_gateway, spy_executor, evidence_recorder=evidence_recorder
    )

    result = controller.run_turn(started_investigation.investigation_id, wrapper)

    assert result.outcome == TurnOutcome.FAILED
    assert started_investigation.status == InvestigationStatus.FAILED
    assert fake_client.messages.calls == 1
    assert wrapper.call_count == 1
    assert spy_gateway.call_count == 0
    assert spy_executor.calls == []
    assert started_investigation.evidence_refs == ()


def test_anthropic_provider_module_has_no_broad_exception_handling():
    import ast
    import inspect

    import chanakya.providers.anthropic_provider as provider_module

    tree = ast.parse(inspect.getsource(provider_module))
    try_nodes = [node for node in ast.walk(tree) if isinstance(node, ast.Try)]
    assert try_nodes == []  # no try/except anywhere in this module


# ===========================================================================
# Scenario 7 — Failure during a tool-request-expected turn
# ===========================================================================


def test_scenario7_failure_prevents_any_partial_execution(
    investigation_manager, resource_governor, gateway, tool_executor, evidence_recorder, started_investigation
):
    """A capability catalog is passed (so the model, if it had succeeded,
    would have been shown observe_local_host_environment as a candidate)
    but the transport fails outright — proving the failure happens before
    ANY output (conclude or tool_request) could ever be classified."""
    transport = RecordingTransport(_error_body("api_error", "boom"), status_code=500)
    provider = AnthropicProvider(_config(), FAKE_API_KEY, client=transport.client(max_retries=0))
    spy_gateway = SpyPolicyEvaluator(gateway)
    spy_executor = SpyToolExecutor(tool_executor)
    sink = InMemoryAuditSink()
    audit = AuditEmitter(sink)
    controller = _controller(
        investigation_manager, resource_governor, spy_gateway, spy_executor, evidence_recorder=evidence_recorder, audit=audit
    )
    catalog = [
        {
            "capability": CAPABILITY_ID,
            "display_name": "Observe local host environment",
            "description": "Collect local host environment facts.",
            "parameters_schema": {"type": "object", "properties": {}, "additionalProperties": False},
            "classification": "read_only",
            "supported_target_types": ["local_host"],
        }
    ]

    result = controller.run_turn(
        started_investigation.investigation_id, provider, capability_catalog=catalog
    )

    assert result.outcome == TurnOutcome.FAILED
    assert result.tool_result is None  # no ToolResult was ever produced
    assert spy_gateway.call_count == 0  # no PolicyDecision
    assert spy_executor.calls == []  # no ToolExecutor call — no partial execution
    assert started_investigation.evidence_refs == ()  # no Evidence
    event_types = [e.event_type.value for e in sink.events]
    assert "approval_requested" not in event_types  # no ApprovalRequest
    assert "policy_evaluated" not in event_types
    assert "dispatch_started" not in event_types


# ===========================================================================
# Scenario 8 — Failure after a previous successful tool step
# ===========================================================================


def test_scenario8_failure_after_previous_successful_tool_step_preserves_prior_evidence(
    investigation_manager, resource_governor, gateway, tool_executor, evidence_recorder, evidence_store, started_investigation
):
    transport = SequencedTransport(
        [
            (200, _tool_use_response(CAPABILITY_ID, {"target_ref": "target-local-host-01"})),
            (500, _error_body("api_error", "boom")),
        ]
    )
    provider = AnthropicProvider(_config(), FAKE_API_KEY, client=transport.client())
    spy_gateway = SpyPolicyEvaluator(gateway)
    spy_executor = SpyToolExecutor(tool_executor)
    sink = InMemoryAuditSink()
    audit = AuditEmitter(sink)
    controller = _controller(
        investigation_manager, resource_governor, spy_gateway, spy_executor, evidence_recorder=evidence_recorder, audit=audit
    )

    # Turn 1 — succeeds and records real Evidence.
    result1 = controller.run_turn(started_investigation.investigation_id, provider)
    assert result1.outcome == TurnOutcome.STEP_COMPLETED
    assert len(started_investigation.evidence_refs) == 1
    first_evidence_id = started_investigation.evidence_refs[0]
    stored_after_turn1 = evidence_store.get(first_evidence_id)

    # Turn 2 — the provider fails outright.
    result2 = controller.run_turn(started_investigation.investigation_id, provider)
    assert result2.outcome == TurnOutcome.FAILED
    assert started_investigation.status == InvestigationStatus.FAILED

    # Turn 1's evidence is untouched: same single ref, same stored content.
    assert started_investigation.evidence_refs == (first_evidence_id,)
    stored_after_turn2 = evidence_store.get(first_evidence_id)
    assert stored_after_turn2.content_hash == stored_after_turn1.content_hash
    assert stored_after_turn2.recorded_at == stored_after_turn1.recorded_at
    assert stored_after_turn2.storage_ref == stored_after_turn1.storage_ref

    # No duplicate/second execution occurred because of the turn-2 failure.
    assert spy_gateway.call_count == 1  # only turn 1 ever reached the Gateway
    assert len(spy_executor.calls) == 1  # only turn 1 ever dispatched

    # Audit trail: turn 1's success events are present exactly once, plus
    # exactly one 'error' event from turn 2's fail-closed backstop.
    event_types = [e.event_type.value for e in sink.events]
    assert event_types.count("dispatch_completed") == 1
    assert event_types.count("evidence_recorded") == 1
    assert event_types.count("error") == 1


# ===========================================================================
# Scenario 9 — Failure must not become CONCLUDE
# ===========================================================================


@pytest.mark.parametrize(
    "make_provider",
    [
        lambda: AnthropicProvider(
            _config(), FAKE_API_KEY,
            client=RecordingTransport(_error_body("authentication_error", "bad key"), status_code=401).client(max_retries=0),
        ),
        lambda: AnthropicProvider(
            _config(), FAKE_API_KEY,
            client=RecordingTransport(_error_body("rate_limit_error", "slow down"), status_code=429).client(max_retries=0),
        ),
        lambda: AnthropicProvider(
            _config(), FAKE_API_KEY,
            client=RecordingTransport(_error_body("api_error", "boom"), status_code=500).client(max_retries=0),
        ),
        lambda: AnthropicProvider(
            _config(), FAKE_API_KEY,
            client=RaisingTransport(lambda request: httpx2.ConnectError("refused", request=request)).client(max_retries=0),
        ),
        lambda: AnthropicProvider(
            _config(), FAKE_API_KEY,
            client=RaisingTransport(lambda request: httpx2.ReadTimeout("timeout", request=request)).client(max_retries=0),
        ),
        lambda: AnthropicProvider(_config(), FAKE_API_KEY, client=_RawExceptionClient(RuntimeError("unexpected"))),
    ],
    ids=["auth", "rate_limit", "api_status", "connection", "timeout", "unexpected"],
)
def test_scenario9_no_failure_path_ever_produces_conclude(
    investigation_manager, resource_governor, gateway, tool_executor, evidence_recorder, started_investigation, make_provider
):
    provider = make_provider()
    controller = _controller(investigation_manager, resource_governor, gateway, tool_executor, evidence_recorder=evidence_recorder)

    result = controller.run_turn(started_investigation.investigation_id, provider)

    assert result.outcome == TurnOutcome.FAILED
    assert result.outcome != TurnOutcome.CONCLUDED
    assert started_investigation.status == InvestigationStatus.FAILED
    assert started_investigation.status != InvestigationStatus.COMPLETED


# ===========================================================================
# Scenario 10 — Failure must not become a ToolRequest
# ===========================================================================


@pytest.mark.parametrize(
    "make_provider",
    [
        lambda: AnthropicProvider(
            _config(), FAKE_API_KEY,
            client=RecordingTransport(_error_body("authentication_error", "bad key"), status_code=401).client(max_retries=0),
        ),
        lambda: AnthropicProvider(
            _config(), FAKE_API_KEY,
            client=RecordingTransport(_error_body("rate_limit_error", "slow down"), status_code=429).client(max_retries=0),
        ),
        lambda: AnthropicProvider(
            _config(), FAKE_API_KEY,
            client=RecordingTransport(_error_body("api_error", "boom"), status_code=500).client(max_retries=0),
        ),
        lambda: AnthropicProvider(
            _config(), FAKE_API_KEY,
            client=RaisingTransport(lambda request: httpx2.ConnectError("refused", request=request)).client(max_retries=0),
        ),
        lambda: AnthropicProvider(
            _config(), FAKE_API_KEY,
            client=RaisingTransport(lambda request: httpx2.ReadTimeout("timeout", request=request)).client(max_retries=0),
        ),
        lambda: AnthropicProvider(_config(), FAKE_API_KEY, client=_RawExceptionClient(RuntimeError("unexpected"))),
    ],
    ids=["auth", "rate_limit", "api_status", "connection", "timeout", "unexpected"],
)
def test_scenario10_no_failure_path_ever_produces_a_tool_request(
    investigation_manager, resource_governor, gateway, tool_executor, evidence_recorder, started_investigation, make_provider
):
    provider = make_provider()
    spy_gateway = SpyPolicyEvaluator(gateway)
    spy_executor = SpyToolExecutor(tool_executor)
    controller = _controller(
        investigation_manager, resource_governor, spy_gateway, spy_executor, evidence_recorder=evidence_recorder
    )

    controller.run_turn(started_investigation.investigation_id, provider)

    assert spy_gateway.call_count == 0  # no ToolRequest was ever intake'd/evaluated
    assert spy_executor.calls == []  # no dispatch, cached or otherwise


# ===========================================================================
# Scenario 11 — Credential safety during errors (Runtime-visible surfaces)
# ===========================================================================


@pytest.mark.parametrize(
    "make_provider",
    [
        lambda: AnthropicProvider(
            _config(), FAKE_API_KEY,
            client=RecordingTransport(_error_body("authentication_error", "bad key"), status_code=401).client(max_retries=0),
        ),
        lambda: AnthropicProvider(
            _config(), FAKE_API_KEY,
            client=RecordingTransport(_error_body("rate_limit_error", "slow down"), status_code=429).client(max_retries=0),
        ),
        lambda: AnthropicProvider(
            _config(), FAKE_API_KEY,
            client=RecordingTransport(_error_body("api_error", "boom"), status_code=500).client(max_retries=0),
        ),
        lambda: AnthropicProvider(
            _config(), FAKE_API_KEY,
            client=RaisingTransport(lambda request: httpx2.ConnectError("refused", request=request)).client(max_retries=0),
        ),
        lambda: AnthropicProvider(
            _config(), FAKE_API_KEY,
            client=RaisingTransport(lambda request: httpx2.ReadTimeout("timeout", request=request)).client(max_retries=0),
        ),
        lambda: AnthropicProvider(_config(), FAKE_API_KEY, client=_RawExceptionClient(RuntimeError("unexpected"))),
    ],
    ids=["auth", "rate_limit", "api_status", "connection", "timeout", "unexpected"],
)
def test_scenario11_credential_absent_from_every_runtime_visible_surface(
    investigation_manager, resource_governor, gateway, tool_executor, evidence_recorder, started_investigation, make_provider
):
    provider = make_provider()
    spy_gateway = SpyPolicyEvaluator(gateway)
    spy_executor = SpyToolExecutor(tool_executor)
    sink = InMemoryAuditSink()
    audit = AuditEmitter(sink)
    controller = _controller(
        investigation_manager, resource_governor, spy_gateway, spy_executor, evidence_recorder=evidence_recorder, audit=audit
    )

    result = controller.run_turn(started_investigation.investigation_id, provider)

    assert result.outcome == TurnOutcome.FAILED
    assert FAKE_API_KEY not in str(result.detail)
    assert FAKE_API_KEY not in (
        started_investigation.investigation_id + started_investigation.status.value + repr(started_investigation.step_history)
    )
    for event in sink.events:
        assert FAKE_API_KEY not in json.dumps(
            {"event_type": event.event_type.value, "related_ids": dict(event.related_ids), "details": event.details},
            default=str,
        )
    assert started_investigation.evidence_refs == ()  # nothing to check in Evidence — none was ever created


# ===========================================================================
# Scenario 12 — Exception content / credential-leak analysis (direct, at
# the provider/SDK boundary, bypassing the Runtime's own catch-and-record
# behavior so the raw exception object itself can be inspected).
# ===========================================================================


def test_authentication_error_string_forms_never_contain_the_credential():
    transport = RecordingTransport(_error_body("authentication_error", "invalid x-api-key"), status_code=401)
    provider = AnthropicProvider(_config(), FAKE_API_KEY, client=transport.client(max_retries=0))

    with pytest.raises(anthropic.AuthenticationError) as excinfo:
        provider.next_turn(_minimal_assembled_context())

    exc = excinfo.value
    assert FAKE_API_KEY not in str(exc)
    assert FAKE_API_KEY not in repr(exc)
    assert FAKE_API_KEY not in exc.message
    assert FAKE_API_KEY not in json.dumps(exc.body, default=str)


def test_status_error_message_is_built_only_from_response_body_not_request_headers():
    """Direct evidence for the report's exception-content analysis: the
    SDK constructs ``APIStatusError.message`` exclusively from the HTTP
    response status code and body (``anthropic._base_client.
    _make_status_error_from_response``) — never from the request, so it
    structurally cannot include the ``x-api-key``/``Authorization``
    request header this SDK attaches to every outgoing call. The
    credential IS present on ``exc.request.headers`` (an SDK-internal
    attribute), but nothing in ``chanakya`` ever reads that attribute —
    confirmed by ``test_anthropic_provider_module_has_no_broad_exception_handling``
    above and this file's own grep-backed claim in the module docstring
    that no code in ``anthropic_provider.py`` touches a caught
    exception's attributes at all (it never catches one)."""
    transport = RecordingTransport(_error_body("authentication_error", "invalid x-api-key"), status_code=401)
    provider = AnthropicProvider(_config(), FAKE_API_KEY, client=transport.client(max_retries=0))

    with pytest.raises(anthropic.AuthenticationError) as excinfo:
        provider.next_turn(_minimal_assembled_context())

    exc = excinfo.value
    # The finding, stated as executable fact rather than only prose:
    assert "x-api-key" in exc.request.headers  # the header exists (SDK's own design)
    assert FAKE_API_KEY in exc.request.headers["x-api-key"]  # and does carry the real key
    assert FAKE_API_KEY not in str(exc)  # ...but str()/repr()/.message never surface it
    assert FAKE_API_KEY not in repr(exc)
    assert FAKE_API_KEY not in exc.message


def test_connection_and_timeout_error_messages_are_generic_static_text():
    for exc_factory, expected_type in (
        (lambda request: httpx2.ConnectError("refused", request=request), anthropic.APIConnectionError),
        (lambda request: httpx2.ReadTimeout("timeout", request=request), anthropic.APITimeoutError),
    ):
        transport = RaisingTransport(exc_factory)
        provider = AnthropicProvider(_config(), FAKE_API_KEY, client=transport.client(max_retries=0))
        with pytest.raises(expected_type) as excinfo:
            provider.next_turn(_minimal_assembled_context())
        assert FAKE_API_KEY not in str(excinfo.value)
        assert FAKE_API_KEY not in repr(excinfo.value)


def _minimal_assembled_context():
    from chanakya.runtime.context_assembler import AssembledContext

    return AssembledContext(
        investigation_id="inv-direct-exception-probe",
        instructions="probe only",
        capability_catalog=(),
        data=(),
    )


# ===========================================================================
# Final sanity: this module never made a real network request.
# ===========================================================================


def test_module_used_only_mock_transports(
    investigation_manager, resource_governor, gateway, tool_executor, evidence_recorder, started_investigation
):
    transport = RecordingTransport(_conclude_response())
    provider = AnthropicProvider(_config(), FAKE_API_KEY, client=transport.client(max_retries=0))
    controller = _controller(investigation_manager, resource_governor, gateway, tool_executor, evidence_recorder=evidence_recorder)

    controller.run_turn(started_investigation.investigation_id, provider)

    assert len(transport.requests) == 1
    for request in transport.requests:
        assert request.url.host in ("api.anthropic.com", "localhost")
