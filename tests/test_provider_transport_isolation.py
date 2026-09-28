"""Phase 18 — provider transport environment isolation (T-63).

Covers P18-INV-1..6 (docs/AGENT-RUNTIME.md "Provider transport environment
isolation (Phase 18)"), the 22 adversarial breaks of the Phase 18 brief and
the Review 1.5.0 checks.

The Phase 18 inspection reproduced T-63: with ``HTTPS_PROXY``/``ALL_PROXY``
set, the production provider mounted a proxy transport to the attacker host
while the durable ProviderIdentity still claimed ``https://api.anthropic.com``;
``SSL_CERT_FILE``/``SSL_CERT_DIR`` replaced the TLS trust roots; and
``ANTHROPIC_LOG=debug`` wrote the investigation request body to stderr.

Where it matters, a test also runs a *control*: the same environment input
against an environment-trusting client, showing the input is effective there
(so the isolation test is not vacuous). Nothing here makes a network call;
all fixture values are dummies (``attacker.invalid``, fake paths and keys).
"""
from __future__ import annotations

import ast
import io
import logging
import socket
import ssl
from pathlib import Path
from typing import Any, List

import anthropic
import httpx2
import pytest

import chanakya.cli.main as cli_main
from chanakya.contracts.agent_turn import TransportPolicy, transport_policy_from_details
from chanakya.contracts.audit_event import AUDIT_EVENT_CONTRACT_VERSION, SUPPORTED_AUDIT_EVENT_VERSIONS
from chanakya.contracts.investigation_context import InvestigationStatus
from chanakya.providers.anthropic_provider import (
    FORBIDDEN_SDK_ENVIRONMENT,
    FORBIDDEN_TRANSPORT_ENVIRONMENT,
    AnthropicProvider,
)
from chanakya.providers.config import PROVIDER_CONFIG_VERSION, ProviderConfig
from chanakya.providers.transport import ProviderTransportError, build_http_client, verify_client
from chanakya.runtime.agent_loop import TurnOutcome
from review_factories import Run, codes, rewrite_events

_REPO = Path(__file__).resolve().parent.parent
_CHANAKYA = _REPO / "chanakya"
KEY = "sk-dummy-p18-key-000"
ENDPOINT = "https://api.anthropic.com"
ATTACKER = "http://attacker.invalid:8080"
BODY_MARKER = "P18-INVESTIGATION-BODY-MARKER"
PROXY_VARS = ["HTTPS_PROXY", "https_proxy", "HTTP_PROXY", "http_proxy", "ALL_PROXY", "all_proxy"]


def _config(**overrides) -> ProviderConfig:
    values = dict(provider="anthropic", model="claude-test-model", api_key_env_var="K", timeout_seconds=5)
    values.update(overrides)
    return ProviderConfig(**values)


def _conclude(request) -> httpx2.Response:
    return httpx2.Response(200, json={
        "id": "m", "type": "message", "role": "assistant", "model": "claude-test-model",
        "content": [{"type": "text", "text": "done"}], "stop_reason": "end_turn", "stop_sequence": None,
        "usage": {"input_tokens": 1, "output_tokens": 1}})


class _Recorder:
    def __init__(self) -> None:
        self.requests: List[httpx2.Request] = []

    def __call__(self, request):
        self.requests.append(request)
        return _conclude(request)


def _client(handler=_conclude, *, base_url=ENDPOINT, max_retries=0, sdk_kwargs=None, **http_kwargs) -> anthropic.Anthropic:
    """A verified-by-default injected client (environment trust off, in-process
    transport); keyword arguments make it insecure for the matrix."""
    http_kwargs.setdefault("trust_env", False)
    http_kwargs.setdefault("transport", httpx2.MockTransport(handler))
    return anthropic.Anthropic(api_key=KEY, base_url=base_url, max_retries=max_retries,
                               http_client=httpx2.Client(**http_kwargs), **(sdk_kwargs or {}))


@pytest.fixture(autouse=True)
def _offline(monkeypatch):
    """No test here may touch the network: verification is local inspection."""
    def refuse(*args, **kwargs):
        raise AssertionError("network attempted during a Phase 18 test")

    monkeypatch.setattr(socket.socket, "connect", refuse)
    monkeypatch.setattr(socket, "getaddrinfo", refuse)


@pytest.fixture
def clean_sdk_loggers():
    saved = {name: logging.getLogger(name).level for name in ("anthropic", "httpx2", "httpcore2")}
    yield
    for name, level in saved.items():
        logging.getLogger(name).setLevel(level)


def _cli(environ, tmp_path) -> tuple:
    out = io.StringIO()
    code = cli_main.main(["Assess this host", "--workdir", str(tmp_path / "wd")],
                         environ=dict(environ, ANTHROPIC_API_KEY=KEY), output=out)
    return code, out.getvalue()


# ===========================================================================
# 1. Production construction (P18-INV-1/2/4)
# ===========================================================================


def test_production_transport_is_explicit_isolated_and_verified():
    provider = AnthropicProvider(_config(), KEY)
    http = provider._client._client
    assert http.trust_env is False and http._mounts == {} and http.follow_redirects is False and http.auth is None
    context = http._transport._pool._ssl_context
    import truststore

    assert isinstance(context, truststore.SSLContext) and context.verify_mode == ssl.CERT_REQUIRED and context.check_hostname
    assert provider._client.max_retries == 0
    identity = provider.provider_identity()
    assert identity.config_version == PROVIDER_CONFIG_VERSION == "1.1.0"
    assert identity.transport == TransportPolicy(tls_trust="system")
    assert identity.transport.to_details() == {"proxy": "none", "tls_trust": "system", "env_trust": False,
                                               "redirects": False, "retries": 0, "sdk_debug_logging": False}
    # The recorded policy is exactly what verification of the effective client returns.
    assert verify_client(provider._client, endpoint=ENDPOINT, expected_timeout=5.0) == identity.transport
    assert KEY not in repr(identity.to_details())


def test_build_http_client_disables_environment_trust_explicitly():
    http = build_http_client(5.0)
    assert http.trust_env is False and http.follow_redirects is False


# ===========================================================================
# 2. Proxy environment (BREAKS 1-4, P18-INV-1)
# ===========================================================================


@pytest.mark.parametrize("var", PROXY_VARS)
def test_proxy_variable_is_refused_by_the_cli_and_cannot_route_the_transport(var, monkeypatch, tmp_path):
    """BREAKS 1-3."""
    code, text = _cli({var: ATTACKER}, tmp_path)
    assert code == cli_main.EXIT_CONFIG_ERROR
    assert "TRANSPORT_ENVIRONMENT_REFUSED" in text and var in text and "attacker.invalid" not in text
    assert not (tmp_path / "wd").exists()  # refused before anything was built

    monkeypatch.setenv(var, ATTACKER)  # the CLI check bypassed entirely
    control = httpx2.Client(trust_env=True)
    assert control._mounts, "control: an environment-trusting client does mount the proxy"
    provider = AnthropicProvider(_config(), KEY)
    assert provider._client._client._mounts == {}
    assert provider.provider_identity().transport.proxy == "none"


@pytest.mark.parametrize("var", ["NO_PROXY", "no_proxy"])
def test_no_proxy_manipulation_has_no_effect(var, monkeypatch, tmp_path):
    """BREAK 4."""
    code, text = _cli({var: "*"}, tmp_path)
    assert code == cli_main.EXIT_CONFIG_ERROR and var in text
    monkeypatch.setenv("HTTPS_PROXY", ATTACKER)
    monkeypatch.setenv(var, "api.anthropic.com")
    provider = AnthropicProvider(_config(), KEY)
    assert provider._client._client._mounts == {}


# ===========================================================================
# 3. TLS trust roots (BREAKS 5-6, P18-INV-2)
# ===========================================================================


def test_ssl_cert_file_is_refused_and_never_loaded(monkeypatch, tmp_path):
    """BREAK 5: a bogus attacker CA file. An environment-trusting client
    tries to load it (and fails); the isolated transport never reads it."""
    bogus = tmp_path / "attacker-ca.pem"
    bogus.write_text("not a certificate", encoding="ascii")
    code, text = _cli({"SSL_CERT_FILE": str(bogus)}, tmp_path)
    assert code == cli_main.EXIT_CONFIG_ERROR and "SSL_CERT_FILE" in text and str(bogus) not in text

    monkeypatch.setenv("SSL_CERT_FILE", str(bogus))
    with pytest.raises(ssl.SSLError):
        httpx2.Client(trust_env=True)  # control: the environment CA file is loaded
    provider = AnthropicProvider(_config(), KEY)
    import truststore

    assert isinstance(provider._client._client._transport._pool._ssl_context, truststore.SSLContext)
    assert provider.provider_identity().transport.tls_trust == "system"


def test_ssl_cert_dir_is_refused_and_never_loaded(monkeypatch, tmp_path):
    """BREAK 6."""
    code, text = _cli({"SSL_CERT_DIR": str(tmp_path)}, tmp_path)
    assert code == cli_main.EXIT_CONFIG_ERROR and "SSL_CERT_DIR" in text
    monkeypatch.setenv("SSL_CERT_DIR", str(tmp_path))
    control = httpx2.Client(trust_env=True)._transport._pool._ssl_context
    import truststore

    assert not isinstance(control, truststore.SSLContext)  # control: the environment directory is used
    provider = AnthropicProvider(_config(), KEY)
    assert isinstance(provider._client._client._transport._pool._ssl_context, truststore.SSLContext)


def test_a_client_with_a_custom_ca_context_is_rejected():
    """No custom CA: a plain ssl.SSLContext (a CA file/dir) is not system trust."""
    context = ssl.create_default_context()
    client = anthropic.Anthropic(api_key=KEY, base_url=ENDPOINT, max_retries=0,
                                 http_client=httpx2.Client(trust_env=False, verify=context))
    with pytest.raises(ProviderTransportError) as info:
        AnthropicProvider(_config(), KEY, client=client)
    assert info.value.code == "TRANSPORT_TLS_UNVERIFIED"


# ===========================================================================
# 4. netrc and environment authentication (BREAKS 7, 9)
# ===========================================================================


def test_netrc_is_refused_and_never_honored(monkeypatch, tmp_path):
    """BREAK 7. httpx2 applies netrc only through an explicit NetRCAuth hook;
    the provider never has one, and a client carrying one is rejected. The
    netrc file is never read by the provider."""
    netrc = tmp_path / "netrc"
    netrc.write_text("machine api.anthropic.com login p18user password p18netrcsecret\n", encoding="ascii")
    code, text = _cli({"NETRC": str(netrc)}, tmp_path)
    assert code == cli_main.EXIT_CONFIG_ERROR and "NETRC" in text and "p18netrcsecret" not in text

    monkeypatch.setenv("NETRC", str(netrc))
    isolated = _Recorder()
    provider = AnthropicProvider(_config(), KEY, client=_client(isolated))
    provider.next_turn(_assembled())
    assert "authorization" not in isolated.requests[0].headers
    assert AnthropicProvider(_config(), KEY)._client._client.auth is None
    with pytest.raises(ProviderTransportError) as info:
        AnthropicProvider(_config(), KEY, client=_client(auth=httpx2.NetRCAuth(str(netrc))))
    assert info.value.code == "TRANSPORT_AUTH_HOOK" and "p18netrcsecret" not in str(info.value)


def test_sdk_default_client_mounts_environment_proxies_despite_trust_env(monkeypatch):
    """Regression for what Phase 18 verification found: anthropic's
    DefaultHttpxClient mounts proxies from the environment even with
    trust_env=False. The production transport does not use it, and the
    verifier would reject it."""
    monkeypatch.setenv("HTTPS_PROXY", ATTACKER)
    sdk_default = anthropic.DefaultHttpxClient(trust_env=False, follow_redirects=False)
    assert sdk_default._mounts, "SDK behavior changed: re-review build_http_client"
    assert build_http_client(5.0)._mounts == {}
    client = anthropic.Anthropic(api_key=KEY, base_url=ENDPOINT, max_retries=0, http_client=sdk_default)
    with pytest.raises(ProviderTransportError) as info:
        AnthropicProvider(_config(), KEY, client=client)
    assert info.value.code == "TRANSPORT_PROXY_CONFIGURED"


def test_environment_auth_token_is_refused_and_never_sent(monkeypatch, tmp_path):
    """BREAK 9."""
    code, text = _cli({"ANTHROPIC_AUTH_TOKEN": "p18-env-token"}, tmp_path)
    assert code == cli_main.EXIT_CONFIG_ERROR and "ANTHROPIC_AUTH_TOKEN" in text and "p18-env-token" not in text
    monkeypatch.setenv("ANTHROPIC_AUTH_TOKEN", "p18-env-token")
    recorder = _Recorder()
    provider = AnthropicProvider(_config(), KEY, client=_client(recorder))
    provider.next_turn(_assembled())
    headers = recorder.requests[0].headers
    assert "authorization" not in headers and headers["x-api-key"] == KEY
    assert provider._client.auth_token is None


# ===========================================================================
# 5. SDK logging (BREAK 8, P18-INV-3)
# ===========================================================================


def _assembled():
    from chanakya.runtime.context_assembler import AssembledContext, UntrustedData

    return AssembledContext(investigation_id="inv-p18", instructions="Investigate. " + BODY_MARKER,
                            capability_catalog=(), data=(UntrustedData("tool_result:tr-1", {"e": BODY_MARKER}),))


def test_anthropic_log_is_refused_by_the_cli(tmp_path):
    code, text = _cli({"ANTHROPIC_LOG": "debug"}, tmp_path)
    assert code == cli_main.EXIT_CONFIG_ERROR and "ANTHROPIC_LOG" in text and "debug" not in text


@pytest.mark.parametrize("logger_name", ["anthropic", "httpx2", "httpcore2"])
def test_debug_sdk_logger_fails_construction_closed(logger_name, clean_sdk_loggers):
    logging.getLogger(logger_name).setLevel(logging.DEBUG)
    with pytest.raises(ProviderTransportError) as info:
        AnthropicProvider(_config(), KEY, client=_client())
    assert info.value.code == "TRANSPORT_SDK_DEBUG_LOGGING" and KEY not in str(info.value)


def test_debug_logger_after_construction_fails_the_send_closed(tmp_path, clean_sdk_loggers, caplog, capsys):
    """BREAK 8: logging turned on after the provider was verified. The send
    is refused before any byte leaves; nothing is logged; the investigation
    fails with the fixed PROVIDER_FAILURE code. The control shows the SDK
    would otherwise log the body."""
    recorder = _Recorder()
    provider = AnthropicProvider(_config(), KEY, client=_client(recorder))
    run = Run(tmp_path).start("Assess this host " + BODY_MARKER)
    logging.getLogger("anthropic").setLevel(logging.DEBUG)
    caplog.set_level(logging.DEBUG, logger="anthropic")
    result = run.runtime.controller.run_turn(run.inv, provider, capability_catalog=run.runtime.registry.catalog_view())
    assert result.outcome == TurnOutcome.FAILED and result.detail == "PROVIDER_FAILURE"
    assert recorder.requests == []
    captured = caplog.text + capsys.readouterr().err
    for secret in (BODY_MARKER, KEY):
        assert secret not in captured

    # Control: an unguarded SDK call at DEBUG does log the request body.
    _client(_Recorder()).messages.create(model="m", max_tokens=5, messages=[{"role": "user", "content": BODY_MARKER}])
    assert BODY_MARKER in caplog.text


# ===========================================================================
# 6. Injected client matrix (BREAKS 10-17, P18-INV-4)
# ===========================================================================


class _CustomTransport(httpx2.BaseTransport):
    def handle_request(self, request):  # pragma: no cover - never reached
        return _conclude(request)


@pytest.mark.parametrize(
    "build, code",
    [
        (lambda: _client(trust_env=True), "TRANSPORT_ENV_TRUST_ENABLED"),                                  # BREAK 10
        (lambda: _client(transport=None, proxy=ATTACKER), "TRANSPORT_PROXY_CONFIGURED"),                   # BREAK 11
        (lambda: _client(transport=None, verify=False), "TRANSPORT_TLS_UNVERIFIED"),                       # BREAK 12
        (lambda: _client(follow_redirects=True), "TRANSPORT_REDIRECTS_ENABLED"),                          # BREAK 13
        (lambda: _client(auth=("p18user", "p18pass")), "TRANSPORT_AUTH_HOOK"),                            # BREAK 14
        (lambda: _client(sdk_kwargs={"auth_token": "p18-bearer"}), "TRANSPORT_AUTH_HOOK"),                # BREAK 14
        (lambda: _client(event_hooks={"request": [lambda r: None]}), "TRANSPORT_REQUEST_HOOK"),           # BREAK 14
        (lambda: _client(headers={"Authorization": "Bearer p18-hidden"}), "TRANSPORT_UNSAFE_HEADERS"),    # BREAK 15
        (lambda: _client(headers={"X-Forwarded-For": "p18"}), "TRANSPORT_UNSAFE_HEADERS"),                # BREAK 15
        (lambda: _client(cookies={"session": "p18-cookie"}), "TRANSPORT_UNSAFE_HEADERS"),                 # BREAK 15
        (lambda: _client(params={"key": "p18"}), "TRANSPORT_UNSAFE_HEADERS"),
        (lambda: _client(transport=_CustomTransport()), "TRANSPORT_UNKNOWN_TRANSPORT"),
        (lambda: _client(timeout=None), "TRANSPORT_TIMEOUT_UNBOUNDED"),
    ],
    ids=["trust_env", "proxy", "verify_false", "redirects", "basic_auth", "bearer_token", "request_hook",
         "authorization_header", "extra_header", "cookies", "query_params", "custom_transport", "no_timeout"],
)
def test_insecure_injected_clients_are_rejected(build, code):
    with pytest.raises(ProviderTransportError) as info:
        AnthropicProvider(_config(), KEY, client=build())
    assert info.value.code == code
    message = str(info.value)
    for value in ("attacker", "p18user", "p18pass", "p18-bearer", "p18-hidden", "p18-cookie", KEY):
        assert value not in message


@pytest.mark.parametrize("base_url", ["https://evil.invalid", "http://api.anthropic.com"])
def test_wrong_or_plaintext_endpoint_is_rejected(base_url):
    """BREAK 16."""
    with pytest.raises(ValueError):
        AnthropicProvider(_config(), KEY, client=_client(base_url=base_url))
    with pytest.raises(ValueError):
        _config(endpoint="http://api.anthropic.com")


def test_custom_sdk_headers_are_rejected():
    """BREAK 15 (SDK level)."""
    with pytest.raises(ValueError):
        AnthropicProvider(_config(), KEY, client=_client(sdk_kwargs={"default_headers": {"X-P18": "hidden"}}))


def test_duck_typed_clients_cannot_be_verified_and_are_rejected():
    class Fake:
        messages = None

    with pytest.raises(ProviderTransportError) as info:
        AnthropicProvider(_config(), KEY, client=Fake())
    assert info.value.code == "TRANSPORT_CLIENT_UNSUPPORTED"


def test_retries_are_normalized_to_zero_and_never_silently_reenabled():
    """BREAK 17. The existing architecture normalizes an injected client to
    zero retries; re-enabling them later is refused at send time."""
    provider = AnthropicProvider(_config(), KEY, client=_client(max_retries=5))
    assert provider._client.max_retries == 0
    provider._client = provider._client.with_options(max_retries=3)
    with pytest.raises(ProviderTransportError) as info:
        provider.next_turn(_assembled())
    assert info.value.code == "TRANSPORT_RETRIES_ENABLED"


def test_transport_tampered_after_verification_fails_the_send_closed():
    recorder = _Recorder()
    provider = AnthropicProvider(_config(), KEY, client=_client(recorder))
    provider._client._client._trust_env = True
    with pytest.raises(ProviderTransportError):
        provider.next_turn(_assembled())
    assert recorder.requests == []


def test_a_valid_injected_client_is_accepted_and_recorded_as_in_process():
    provider = AnthropicProvider(_config(), KEY, client=_client())
    assert provider.provider_identity().transport == TransportPolicy(tls_trust="in_process")


# ===========================================================================
# 7. The denylist is not the control (BREAK 21)
# ===========================================================================


def test_an_unlisted_environment_variable_cannot_weaken_the_transport(monkeypatch, tmp_path):
    """BREAK 21: SSLKEYLOGFILE is not on the CLI refusal list. An
    environment-trusting client would log TLS session keys to it (the
    control); the isolated transport does not."""
    assert "SSLKEYLOGFILE" not in FORBIDDEN_TRANSPORT_ENVIRONMENT + FORBIDDEN_SDK_ENVIRONMENT
    keylog = tmp_path / "keys.log"
    monkeypatch.setenv("SSLKEYLOGFILE", str(keylog))
    monkeypatch.setenv("SSL_CERT_DIR", str(tmp_path))  # makes the control use the default-context path
    control = httpx2.Client(trust_env=True)._transport._pool._ssl_context
    assert control.keylog_filename is not None
    monkeypatch.delenv("SSL_CERT_DIR")
    provider = AnthropicProvider(_config(), KEY)
    assert getattr(provider._client._client._transport._pool._ssl_context, "keylog_filename", None) is None
    assert provider._client._client.trust_env is False


def test_refusal_list_covers_the_known_transport_inputs():
    assert set(FORBIDDEN_TRANSPORT_ENVIRONMENT) >= {
        "HTTPS_PROXY", "HTTP_PROXY", "ALL_PROXY", "NO_PROXY", "https_proxy", "http_proxy", "all_proxy", "no_proxy",
        "SSL_CERT_FILE", "SSL_CERT_DIR", "NETRC", "ANTHROPIC_AUTH_TOKEN", "ANTHROPIC_LOG",
    }
    assert set(FORBIDDEN_SDK_ENVIRONMENT) == {"ANTHROPIC_BASE_URL", "ANTHROPIC_CUSTOM_HEADERS", "ANTHROPIC_PROFILE"}


def test_the_cli_never_reads_an_environment_value(tmp_path):
    """Names only: a mapping whose values raise on access still refuses."""
    class NamesOnly(dict):
        def __getitem__(self, key):
            if key != "ANTHROPIC_API_KEY":
                raise AssertionError("a forbidden variable's value was read")
            return super().__getitem__(key)

        def get(self, key, default=None):
            if key != "ANTHROPIC_API_KEY":
                raise AssertionError("a forbidden variable's value was read")
            return super().get(key, default)

    out = io.StringIO()
    code = cli_main.main(["Assess", "--workdir", str(tmp_path)], environ=NamesOnly(HTTPS_PROXY=ATTACKER, ANTHROPIC_API_KEY=KEY),
                         output=out)
    assert code == cli_main.EXIT_CONFIG_ERROR and "attacker" not in out.getvalue()


# ===========================================================================
# 8. Review, AuditEvent 1.5.0 (BREAKS 18-20, P18-INV-5)
# ===========================================================================


def _declared_run(tmp_path) -> Run:
    run = Run(tmp_path).start()
    provider = AnthropicProvider(_config(), KEY, client=_client())
    result = run.runtime.controller.run_turn(run.inv, provider, capability_catalog=run.runtime.registry.catalog_view())
    assert result.outcome == TurnOutcome.CONCLUDED
    return run


def _mutate_manifest(run: Run, change, *, version=None, only_manifest_version=False) -> None:
    def mutate(events):
        for event in events:
            if event["event_type"] == "agent_turn_requested":
                change(event["details"]["provider"])
                if version and only_manifest_version:
                    event["contract_version"] = version
            if version and not only_manifest_version:
                event["contract_version"] = version
        return events

    rewrite_events(run.stream_dir(), mutate)


def test_phase18_streams_record_and_verify_the_transport_policy(tmp_path):
    run = _declared_run(tmp_path)
    (manifest,) = [e for e in run.events() if e.event_type.value == "agent_turn_requested"]
    assert manifest.contract_version == AUDIT_EVENT_CONTRACT_VERSION == "1.5.0"
    policy = transport_policy_from_details(manifest.details["provider"]["transport"])
    assert policy == TransportPolicy(tls_trust="in_process")
    review = run.review()
    assert review.consistent, codes(review)
    assert "1.4.0" in SUPPORTED_AUDIT_EVENT_VERSIONS


@pytest.mark.parametrize(
    "change",
    [
        lambda p: p["transport"].update(proxy=ATTACKER),
        lambda p: p["transport"].update(env_trust=True),
        lambda p: p["transport"].update(tls_trust="environment"),
        lambda p: p["transport"].update(redirects=True),
        lambda p: p["transport"].update(retries=2),
        lambda p: p["transport"].update(sdk_debug_logging=True),
        lambda p: p["transport"].update(extra="x"),
        lambda p: p.update(config_version="1.0.0"),
    ],
    ids=["proxy", "env_trust", "tls_trust", "redirects", "retries", "debug_logging", "extra_key", "old_config"],
)
def test_review_flags_a_forged_transport_policy_without_echoing_it(tmp_path, change):
    """BREAK 18."""
    run = _declared_run(tmp_path)
    _mutate_manifest(run, change)
    review = run.review()
    assert "turn_transport_policy_invalid" in codes(review) and not review.consistent
    assert "attacker" not in repr(review) and "attacker" not in run.cli_review()[1]


def test_review_flags_a_missing_transport_policy(tmp_path):
    """BREAK 19: removed key, and a null policy for a declared provider."""
    run = _declared_run(tmp_path)
    _mutate_manifest(run, lambda p: p.pop("transport"))
    assert "turn_transport_policy_invalid" in codes(run.review())
    run2 = _declared_run(tmp_path / "b")
    _mutate_manifest(run2, lambda p: p.update(transport=None))
    assert "turn_transport_policy_invalid" in codes(run2.review())


def test_an_undeclared_provider_may_not_claim_a_transport(tmp_path):
    run = Run(tmp_path).start()
    run.conclude()
    _mutate_manifest(run, lambda p: p.update(transport=TransportPolicy(tls_trust="system").to_details()))
    assert "turn_transport_policy_invalid" in codes(run.review())


@pytest.mark.parametrize("arrangement", ["started_downgraded", "manifest_downgraded"])
def test_mixed_1_4_and_1_5_streams_are_flagged_and_judged_strictly(tmp_path, arrangement):
    """BREAK 20, both arrangements: a downgrade cannot relax the transport
    check (a 1.4.0-shaped manifest in a 1.5.0-judged stream is invalid)."""
    run = _declared_run(tmp_path)

    def mutate(events):
        for event in events:
            if arrangement == "started_downgraded" and event["event_type"] == "investigation_started":
                event["contract_version"] = "1.4.0"
            if event["event_type"] == "agent_turn_requested":
                if arrangement == "started_downgraded":
                    event["details"]["provider"]["transport"]["env_trust"] = True
                else:
                    event["contract_version"] = "1.4.0"
                    event["details"]["provider"].pop("transport")
        return events

    rewrite_events(run.stream_dir(), mutate)
    review = run.review()
    assert "mixed_contract_versions" in codes(review)
    assert "turn_transport_policy_invalid" in codes(review)


def test_historical_1_4_streams_make_no_transport_claim_and_stay_consistent(tmp_path):
    run = _declared_run(tmp_path)
    _mutate_manifest(run, lambda p: (p.pop("transport"), p.update(config_version="1.0.0")), version="1.4.0")
    review = run.review()
    assert review.consistent, codes(review)


# ===========================================================================
# 9. No authority (BREAK 22, P18-INV-6)
# ===========================================================================

_AUTHORITY = [_CHANAKYA / "policy", _CHANAKYA / "approval", _CHANAKYA / "risk", _CHANAKYA / "registry",
              _CHANAKYA / "capability", _CHANAKYA / "runtime" / "dispatch.py",
              _CHANAKYA / "runtime" / "tool_request_intake.py", _CHANAKYA / "runtime" / "retry_controller.py"]
_TRANSPORT_NAMES = {"transport", "TransportPolicy", "tls_trust", "env_trust", "trust_env", "sdk_debug_logging",
                    "ProviderTransportError", "verify_client", "FORBIDDEN_TRANSPORT_ENVIRONMENT"}


def test_transport_policy_is_unreachable_from_authority():
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
                if names & _TRANSPORT_NAMES or any("providers" in n for n in names):
                    offenders.add(path.relative_to(_REPO).as_posix())
    assert offenders == set()


def test_policy_decisions_are_identical_for_any_transport_policy(gateway, authorized_context):
    from factories import make_request

    request = make_request("list_listening_ports", "target-local-host-01")
    first = gateway.evaluate(request, authorized_context)
    AnthropicProvider(_config(), KEY)                        # a system-trust provider exists
    AnthropicProvider(_config(), KEY, client=_client())       # and an in-process one
    second = gateway.evaluate(request, authorized_context)
    assert (first.verdict, first.matched_rule, first.classification) == (second.verdict, second.matched_rule, second.classification)
