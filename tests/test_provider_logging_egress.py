"""Phase 19 — provider egress logging completeness (T-64).

Covers P19-INV-1..6 (docs/AGENT-RUNTIME.md "Provider egress logging
completeness (Phase 19)") and the required adversarial tests.

The Phase 19 inspection reproduced T-64: Phase 18's ``check_sdk_logging``
tested only the ``anthropic``/``httpx2``/``httpcore2`` parent loggers, but the
SDK emits the request (body included) through the child logger
``anthropic._base_client``. Setting that child to DEBUG passed the check,
the investigation objective appeared in the debug log, the manifest recorded
``sdk_debug_logging: false`` and Review reported the stream consistent.

Every test restores the global logging state it touches (levels, handlers,
``logging.disable`` and any logger it created). Markers and keys are fakes;
no test uses the network.
"""
from __future__ import annotations

import ast
import io
import logging
import logging.config
from pathlib import Path
from typing import List

import anthropic
import httpx2
import pytest

import chanakya.cli.main as cli_main
import chanakya.providers.anthropic_provider as provider_module
from chanakya.providers.anthropic_provider import AnthropicProvider
from chanakya.providers.config import ProviderConfig
from chanakya.providers.transport import (
    SDK_LOGGER_NAMESPACES,
    ProviderTransportError,
    check_sdk_logging,
)
from chanakya.runtime.agent_loop import TurnOutcome
from chanakya.runtime.context_assembler import AssembledContext, UntrustedData
from review_factories import Run, codes

_REPO = Path(__file__).resolve().parent.parent
_CHANAKYA = _REPO / "chanakya"
OBJECTIVE_MARKER = "TEST_OBJECTIVE_MARKER_P19"
EVIDENCE_MARKER = "TEST_EVIDENCE_MARKER_P19"
API_KEY_MARKER = "sk-TEST_API_KEY_MARKER_P19"
MARKERS = (OBJECTIVE_MARKER, EVIDENCE_MARKER, API_KEY_MARKER)


# ===========================================================================
# helpers
# ===========================================================================


class _Capture(logging.Handler):
    """A capture list only; nothing is persisted."""

    def __init__(self) -> None:
        super().__init__(logging.DEBUG)
        self.records: List[str] = []

    def emit(self, record: logging.LogRecord) -> None:
        self.records.append(f"{record.name}|{record.levelname}|{record.getMessage()}")

    @property
    def text(self) -> str:
        return "\n".join(self.records)


@pytest.fixture(autouse=True)
def logging_state():
    """Snapshot and restore every piece of global logging state a test may
    change (the logger registry itself, each logger's level, handlers,
    propagate/disabled flags and parent link, the root logger and
    ``logging.disable``), so neither the tests nor a developer's
    configuration leak between tests."""
    manager = logging.Logger.manager
    registry = dict(manager.loggerDict)
    saved = {name: (entry.level, list(entry.handlers), entry.propagate, entry.disabled, entry.parent)
             for name, entry in registry.items() if isinstance(entry, logging.Logger)}
    root = logging.getLogger()
    root_saved = (root.level, list(root.handlers))
    disable_saved = manager.disable
    # A deterministic starting point for the protected namespaces.
    for name, entry in registry.items():
        if isinstance(entry, logging.Logger) and name.split(".")[0] in SDK_LOGGER_NAMESPACES:
            entry.setLevel(logging.NOTSET)
    root.setLevel(logging.WARNING)
    logging.disable(logging.NOTSET)
    yield
    logging.disable(disable_saved)
    manager.loggerDict.clear()
    manager.loggerDict.update(registry)
    for name, (level, handlers, propagate, disabled, parent) in saved.items():
        entry = registry[name]
        entry.level = level
        entry.handlers[:] = handlers
        entry.propagate, entry.disabled, entry.parent = propagate, disabled, parent
    root.setLevel(root_saved[0])
    root.handlers[:] = root_saved[1]
    manager._clear_cache()


class _Transport:
    def __init__(self) -> None:
        self.requests: List[httpx2.Request] = []

    def __call__(self, request):
        self.requests.append(request)
        return httpx2.Response(200, json={
            "id": "m", "type": "message", "role": "assistant", "model": "claude-test-model",
            "content": [{"type": "text", "text": "done"}], "stop_reason": "end_turn", "stop_sequence": None,
            "usage": {"input_tokens": 1, "output_tokens": 1}})


def _config() -> ProviderConfig:
    return ProviderConfig(provider="anthropic", model="claude-test-model", api_key_env_var="K", timeout_seconds=5)


def _client(transport: _Transport) -> anthropic.Anthropic:
    return anthropic.Anthropic(api_key=API_KEY_MARKER, base_url="https://api.anthropic.com", max_retries=0,
                               http_client=httpx2.Client(trust_env=False, transport=httpx2.MockTransport(transport)))


def _provider(transport: _Transport) -> AnthropicProvider:
    return AnthropicProvider(_config(), API_KEY_MARKER, client=_client(transport))


def _context() -> AssembledContext:
    return AssembledContext(investigation_id="inv-p19", instructions=f"Investigate: {OBJECTIVE_MARKER}",
                            capability_catalog=(),
                            data=(UntrustedData("tool_result:tr-1", {"evidence": EVIDENCE_MARKER}),))


def _debug_with_handler(name: str) -> _Capture:
    capture = _Capture()
    logger = logging.getLogger(name)
    logger.setLevel(logging.DEBUG)
    logger.addHandler(capture)
    return capture


def _assert_clean(text: str) -> None:
    for marker in MARKERS:
        assert marker not in text, marker


def _refused(action) -> ProviderTransportError:
    with pytest.raises(ProviderTransportError) as info:
        action()
    assert info.value.code == "TRANSPORT_SDK_DEBUG_LOGGING"
    message = str(info.value)
    for leak in ("anthropic.", "httpx2.", "httpcore2.", *MARKERS):
        assert leak not in message
    return info.value


# ===========================================================================
# 1. The reproduced bypass and child coverage (TESTS 1-4, P19-INV-1)
# ===========================================================================


def test_the_phase19_reproduction_is_refused():
    """TEST 1: anthropic._base_client at DEBUG with a handler, parent left at
    its default. Refused at construction; nothing is sent or logged."""
    transport = _Transport()
    capture = _debug_with_handler("anthropic._base_client")
    assert not logging.getLogger("anthropic").isEnabledFor(logging.DEBUG)  # the Phase 18 check would pass
    _refused(lambda: _provider(transport))
    assert transport.requests == [] and capture.records == []


@pytest.mark.parametrize("name", [
    "anthropic._base_client",      # TEST 1
    "anthropic._response",         # TEST 2: another existing anthropic.* child
    "anthropic.lib.middleware",    # TEST 2: a deeper existing child
    "httpx2._client",              # TEST 3
    "httpcore2.http11",            # TEST 4
    "httpcore2.connection",        # TEST 4
])
def test_any_protected_child_at_debug_is_refused_at_construction_and_send(name):
    transport = _Transport()
    provider = _provider(transport)                       # safe at construction
    prepared = provider.prepare_turn(_context())
    capture = _debug_with_handler(name)                   # level changed after construction (§33)
    _refused(lambda: provider.send_turn(prepared))
    assert transport.requests == [] and capture.records == []
    _refused(lambda: _provider(_Transport()))             # and a new provider is refused too


def test_the_existing_sdk_logger_layout_is_pinned():
    """The SDK's request logger for the installed version (anthropic 1.7.0).
    If it moves, the namespace-wide check still covers it; this test flags
    the change for review."""
    import anthropic._base_client as base_client

    assert base_client.log.name == "anthropic._base_client"
    assert base_client.log.name.split(".")[0] in SDK_LOGGER_NAMESPACES


# ===========================================================================
# 2. Late loggers and send-time checking (TEST 5, §33, §34, P19-INV-2)
# ===========================================================================


def test_a_child_logger_created_after_construction_is_caught_at_send():
    """TEST 5: the late-child case the send-time check exists for. The
    request is prepared (and, on the Runtime path, its manifest recorded)
    while logging is safe; the child is created and set to DEBUG afterwards."""
    transport = _Transport()
    provider = _provider(transport)
    prepared = provider.prepare_turn(_context())
    assert "anthropic.p19_late_child" not in logging.Logger.manager.loggerDict
    capture = _debug_with_handler("anthropic.p19_late_child")
    _refused(lambda: provider.send_turn(prepared))
    assert transport.requests == [] and capture.records == []


def test_logging_changed_between_preparation_and_send_is_caught():
    """§34: preparation-time checking is not relied on."""
    transport = _Transport()
    provider = _provider(transport)
    prepared = provider.prepare_turn(_context())
    _debug_with_handler("anthropic._base_client")
    _refused(lambda: provider.send_turn(prepared))
    assert transport.requests == []


def test_unsafe_logging_refuses_preparation():
    provider = _provider(_Transport())
    _debug_with_handler("anthropic._base_client")
    _refused(lambda: provider.prepare_turn(_context()))


def test_the_final_logging_check_immediately_precedes_every_request(monkeypatch):
    """§12/§41: the last provider action before a request is the logging
    check (then pure transport verification); a request never goes out
    without one."""
    events: List[str] = []
    real_check = provider_module.check_sdk_logging

    def recording_check():
        events.append("check")
        return real_check()

    class Recording(_Transport):
        def __call__(self, request):
            events.append("request")
            return super().__call__(request)

    transport = Recording()
    monkeypatch.setattr(provider_module, "check_sdk_logging", recording_check)
    provider = _provider(transport)
    for _ in range(3):
        provider.next_turn(_context())
    requests = [i for i, event in enumerate(events) if event == "request"]
    assert len(requests) == 3
    assert all(events[i - 1] == "check" for i in requests)


# ===========================================================================
# 3. Root, inheritance, logging.disable, dictConfig (TESTS 6-8, P19-INV-3)
# ===========================================================================


def test_root_debug_is_refused_when_protected_loggers_inherit_it():
    """TEST 6: root DEBUG, namespace parents and children NOTSET."""
    logging.getLogger().setLevel(logging.DEBUG)
    _refused(lambda: _provider(_Transport()))


def test_parent_debug_reaches_a_notset_child():
    logging.getLogger("anthropic").setLevel(logging.DEBUG)
    assert logging.getLogger("anthropic._base_client").level == logging.NOTSET
    _refused(lambda: _provider(_Transport()))


def test_effective_semantics_allow_root_debug_when_every_namespace_is_explicitly_info():
    """Effective levels, not guesses: with each namespace explicitly at INFO,
    root DEBUG cannot make them emit DEBUG, so the provider proceeds, and a
    root capture handler sees no content."""
    root = logging.getLogger()
    root.setLevel(logging.DEBUG)
    capture = _Capture()
    root.addHandler(capture)
    for ns in SDK_LOGGER_NAMESPACES:
        logging.getLogger(ns).setLevel(logging.INFO)
    transport = _Transport()
    _provider(transport).next_turn(_context())
    assert len(transport.requests) == 1
    _assert_clean(capture.text)
    assert "HTTP Request" in capture.text  # INFO logging was genuinely active


def test_a_namespace_with_no_logger_yet_is_judged_by_root():
    """A logger created later in a namespace with no logger object inherits
    root; with root at DEBUG the provider refuses."""
    manager = logging.Logger.manager
    for name in [n for n in manager.loggerDict if n == "httpcore2" or n.startswith("httpcore2.")]:
        del manager.loggerDict[name]
    manager._clear_cache()
    for ns in ("anthropic", "httpx2"):
        logging.getLogger(ns).setLevel(logging.INFO)
    logging.getLogger().setLevel(logging.DEBUG)
    _refused(check_sdk_logging)


def test_logging_disable_is_honored_as_the_logging_module_does():
    """TEST 7: logging.disable(DEBUG) really suppresses DEBUG records, so the
    check permits it and nothing is logged; lifting it restores refusal."""
    capture = _debug_with_handler("anthropic._base_client")
    logging.disable(logging.DEBUG)
    transport = _Transport()
    _provider(transport).next_turn(_context())
    assert len(transport.requests) == 1 and capture.records == []
    logging.disable(logging.NOTSET)
    _refused(lambda: _provider(_Transport()))


def test_a_disabled_logger_flag_is_honored():
    logger = logging.getLogger("anthropic._base_client")
    logger.setLevel(logging.DEBUG)
    logger.disabled = True
    assert check_sdk_logging() is False
    logger.disabled = False
    _refused(check_sdk_logging)


def test_dictconfig_enabling_debug_is_refused():
    """TEST 8."""
    capture = _Capture()
    logging.config.dictConfig({
        "version": 1, "disable_existing_loggers": False,
        "loggers": {"anthropic._base_client": {"level": "DEBUG"}},
    })
    logging.getLogger("anthropic._base_client").addHandler(capture)
    transport = _Transport()
    _refused(lambda: _provider(transport))
    assert transport.requests == [] and capture.records == []


# ===========================================================================
# 4. Durable claim (TEST 9, §37, P19-INV-4)
# ===========================================================================


def test_unsafe_logging_before_a_turn_produces_no_manifest_and_no_request(tmp_path):
    """TEST 9: no turn is recorded with sdk_debug_logging=false while the SDK
    would log the body; the investigation fails with PROVIDER_FAILURE."""
    transport = _Transport()
    provider = _provider(transport)
    run = Run(tmp_path).start(f"Assess this host {OBJECTIVE_MARKER}")
    capture = _debug_with_handler("anthropic._base_client")
    result = run.runtime.controller.run_turn(run.inv, provider, capability_catalog=run.runtime.registry.catalog_view())
    assert result.outcome == TurnOutcome.FAILED and result.detail == "PROVIDER_FAILURE"
    assert transport.requests == [] and capture.records == []
    assert not [e for e in run.events() if e.event_type.value == "agent_turn_requested"]
    review = run.review()
    assert review.status.value == "failed" and "turn_transport_policy_invalid" not in codes(review)


def test_a_valid_turn_records_the_verified_logging_state(tmp_path):
    """§37: a recorded sdk_debug_logging=false belongs to a request that
    passed the check; Review sees a consistent stream."""
    transport = _Transport()
    run = Run(tmp_path).start()
    result = run.runtime.controller.run_turn(run.inv, _provider(transport),
                                             capability_catalog=run.runtime.registry.catalog_view())
    assert result.outcome == TurnOutcome.CONCLUDED and len(transport.requests) == 1
    (manifest,) = [e for e in run.events() if e.event_type.value == "agent_turn_requested"]
    assert manifest.details["provider"]["transport"]["sdk_debug_logging"] is False
    assert run.review().consistent


def test_the_recorded_value_is_the_verified_value(monkeypatch):
    """P19-INV-4: the policy's sdk_debug_logging comes from the check; a
    provider cannot be built (so no identity exists) when the check fails."""
    import chanakya.providers.transport as transport_module

    calls = []
    monkeypatch.setattr(transport_module, "check_sdk_logging", lambda: calls.append(1) or False)
    policy = _provider(_Transport()).provider_identity().transport
    assert policy.sdk_debug_logging is False and calls
    monkeypatch.undo()
    _debug_with_handler("anthropic._base_client")
    _refused(lambda: _provider(_Transport()))


# ===========================================================================
# 5. Data egress (TEST 10, §32, §35, §36, P19-INV-5)
# ===========================================================================


@pytest.mark.parametrize("configuration", ["default", "info_everywhere", "root_info_with_handlers"])
def test_permitted_logging_never_contains_request_content(configuration):
    """TEST 10: every configuration the check permits was run with capture
    handlers on the root and on every protected logger."""
    root = logging.getLogger()
    capture = _Capture()
    root.addHandler(capture)
    if configuration == "info_everywhere":
        for ns in SDK_LOGGER_NAMESPACES:
            logging.getLogger(ns).setLevel(logging.INFO)
        root.setLevel(logging.INFO)
    elif configuration == "root_info_with_handlers":
        root.setLevel(logging.INFO)
        for name in ("anthropic._base_client", "httpx2", "httpcore2.http11"):
            logging.getLogger(name).addHandler(capture)
    transport = _Transport()
    _provider(transport).next_turn(_context())
    body = transport.requests[0].content.decode()
    assert OBJECTIVE_MARKER in body and EVIDENCE_MARKER in body  # the content really was sent
    _assert_clean(capture.text)
    assert body not in capture.text


def test_a_malicious_handler_on_a_protected_logger_receives_nothing():
    """§32."""
    capture = _debug_with_handler("anthropic._base_client")
    logging.getLogger("httpx2").addHandler(capture)
    transport = _Transport()
    _refused(lambda: _provider(transport))
    assert capture.records == [] and transport.requests == []


def test_full_runtime_turn_under_permitted_logging_leaks_nothing(tmp_path):
    """P19-INV-5 on the production composition path."""
    root = logging.getLogger()
    root.setLevel(logging.INFO)
    capture = _Capture()
    root.addHandler(capture)
    transport = _Transport()
    run = Run(tmp_path).start(f"Assess this host {OBJECTIVE_MARKER}")
    result = run.runtime.controller.run_turn(run.inv, _provider(transport),
                                             capability_catalog=run.runtime.registry.catalog_view())
    assert result.outcome == TurnOutcome.CONCLUDED
    assert OBJECTIVE_MARKER in transport.requests[0].content.decode()
    _assert_clean(capture.text)


# ===========================================================================
# 6. Environment control preserved (TEST 13)
# ===========================================================================


def test_anthropic_log_is_still_refused_by_the_cli(tmp_path):
    out = io.StringIO()
    code = cli_main.main(["Assess", "--workdir", str(tmp_path / "wd")],
                         environ={"ANTHROPIC_LOG": "debug", "ANTHROPIC_API_KEY": API_KEY_MARKER}, output=out)
    assert code == cli_main.EXIT_CONFIG_ERROR and "ANTHROPIC_LOG" in out.getvalue()
    _assert_clean(out.getvalue())


# ===========================================================================
# 7. No authority (P19-INV-6)
# ===========================================================================

_AUTHORITY = [_CHANAKYA / "policy", _CHANAKYA / "approval", _CHANAKYA / "risk", _CHANAKYA / "registry",
              _CHANAKYA / "capability", _CHANAKYA / "targets", _CHANAKYA / "runtime" / "dispatch.py",
              _CHANAKYA / "runtime" / "tool_request_intake.py", _CHANAKYA / "runtime" / "retry_controller.py"]
_LOGGING_POLICY_NAMES = {"check_sdk_logging", "sdk_debug_logging", "SDK_LOGGER_NAMESPACES", "SDK_LOGGERS",
                         "ProviderTransportError", "TRANSPORT_SDK_DEBUG_LOGGING", "_protected_loggers"}


def test_logging_policy_carries_no_authority():
    offenders = set()
    for base in _AUTHORITY:
        for path in ([base] if base.is_file() else sorted(base.rglob("*.py"))):
            for node in ast.walk(ast.parse(path.read_text(encoding="utf-8"))):
                names = set()
                if isinstance(node, ast.Name):
                    names.add(node.id)
                elif isinstance(node, ast.Attribute):
                    names.add(node.attr)
                elif isinstance(node, ast.ImportFrom):
                    names |= {a.name for a in node.names} | {node.module or ""}
                if names & _LOGGING_POLICY_NAMES or any("providers" in n for n in names):
                    offenders.add(path.relative_to(_REPO).as_posix())
    assert offenders == set()


def test_a_logging_refusal_changes_no_policy_decision(gateway, authorized_context):
    from factories import make_request

    request = make_request("list_listening_ports", "target-local-host-01")
    before = gateway.evaluate(request, authorized_context)
    _debug_with_handler("anthropic._base_client")
    _refused(lambda: _provider(_Transport()))
    after = gateway.evaluate(request, authorized_context)
    assert (before.verdict, before.matched_rule) == (after.verdict, after.matched_rule)
