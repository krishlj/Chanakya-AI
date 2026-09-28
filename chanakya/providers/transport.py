"""Provider transport environment isolation — Phase 18 (docs/THREAT-MODEL.md T-63).

The provider transport is the only path by which the API key and model
context leave the host. Its behavior must come from trusted code and
configuration, never from the process environment. Before Phase 18 the SDK's
HTTP client ran with ``trust_env=True``, so ``HTTPS_PROXY``/``ALL_PROXY``
re-routed the connection, ``SSL_CERT_FILE``/``SSL_CERT_DIR`` replaced the TLS
trust roots, and ``ANTHROPIC_LOG=debug``
wrote the request body to stderr, while the durable turn record claimed the
explicit endpoint.

The control is structural, not a denylist:

1. ``build_http_client`` constructs the transport explicitly:
   ``trust_env=False`` (no proxy, CA or other environment input), TLS
   verification against the system trust store, redirects off, the
   configured timeout. It does not use ``anthropic.DefaultHttpxClient``,
   which mounts proxies from the environment regardless of ``trust_env``.
   (httpx2 applies netrc only through an explicit ``NetRCAuth``, which the
   verifier rejects as an auth hook.)
2. ``verify_client`` inspects the *effective* client (production-built or
   injected) and fails closed on anything it cannot confirm: environment
   trust, proxy mounts, a non-system or disabled TLS context, an unknown
   transport, redirects, auth hooks, request hooks, extra headers, cookies,
   query parameters, a bearer token, retries or an unbounded timeout. It
   returns the ``TransportPolicy`` that was verified, and only that is
   recorded.
3. ``check_sdk_logging`` fails closed if the SDK or transport loggers would
   emit DEBUG records (which include request bodies).

The CLI's environment refusal list is defense in depth and operator intent;
the transport stays isolated for variables it does not know about.

Every failure is ``ProviderTransportError`` with a fixed code. Nothing here
reads an environment value, and no client repr, header, proxy URL, path or
credential is ever part of an error.

Private-attribute use is confined to ``_http_client_of`` and
``_tls_context_of``: the Anthropic SDK (1.x) keeps its HTTP client at
``Anthropic._client`` and httpx2 (2.x) exposes proxy mounts and the TLS
context only through ``Client._mounts`` and ``HTTPTransport._pool``. When
those are not what this module expects, it fails closed. Verified against
anthropic 1.7.0 / httpx2 2.13.0 (``tests/test_provider_transport_isolation.py``).
"""
from __future__ import annotations

import logging
import math
import ssl
from typing import Any, Optional

import anthropic
import httpx2

from chanakya.contracts.agent_turn import (
    TLS_TRUST_IN_PROCESS,
    TLS_TRUST_SYSTEM,
    TransportPolicy,
)

#: Loggers that emit request content at DEBUG (``anthropic`` logs request
#: options including the body; ``httpx2``/``httpcore2`` log exchange details).
SDK_LOGGERS = ("anthropic", "httpx2", "httpcore2")

#: The only default headers a verified HTTP client may carry (httpx2's own).
#: Authentication is added per request by the SDK from the explicit API key.
_ALLOWED_HTTP_HEADERS = frozenset({"accept", "accept-encoding", "connection", "user-agent"})

#: An injected client's read timeout may not exceed this (the SDK default).
MAX_INJECTED_TIMEOUT_SECONDS = 600.0

# Fixed failure codes (never carry values).
TRANSPORT_CLIENT_UNSUPPORTED = "TRANSPORT_CLIENT_UNSUPPORTED"
TRANSPORT_ENV_TRUST_ENABLED = "TRANSPORT_ENV_TRUST_ENABLED"
TRANSPORT_PROXY_CONFIGURED = "TRANSPORT_PROXY_CONFIGURED"
TRANSPORT_TLS_UNVERIFIED = "TRANSPORT_TLS_UNVERIFIED"
TRANSPORT_UNKNOWN_TRANSPORT = "TRANSPORT_UNKNOWN_TRANSPORT"
TRANSPORT_REDIRECTS_ENABLED = "TRANSPORT_REDIRECTS_ENABLED"
TRANSPORT_AUTH_HOOK = "TRANSPORT_AUTH_HOOK"
TRANSPORT_REQUEST_HOOK = "TRANSPORT_REQUEST_HOOK"
TRANSPORT_UNSAFE_HEADERS = "TRANSPORT_UNSAFE_HEADERS"
TRANSPORT_ENDPOINT_MISMATCH = "TRANSPORT_ENDPOINT_MISMATCH"
TRANSPORT_RETRIES_ENABLED = "TRANSPORT_RETRIES_ENABLED"
TRANSPORT_TIMEOUT_UNBOUNDED = "TRANSPORT_TIMEOUT_UNBOUNDED"
TRANSPORT_SDK_DEBUG_LOGGING = "TRANSPORT_SDK_DEBUG_LOGGING"


class ProviderTransportError(ValueError):
    """The provider transport is not the verified, environment-isolated
    transport. ``code`` is fixed; the message never contains a value."""

    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(f"provider transport rejected: {code}")


def build_http_client(timeout_seconds: float) -> httpx2.Client:
    """The production transport: explicit and environment-isolated.

    Deliberately NOT ``anthropic.DefaultHttpxClient``: in anthropic 1.7.0 its
    constructor reads the proxy environment variables unconditionally
    (``get_environment_proxies()``) and mounts proxy transports even when
    ``trust_env=False`` is passed (found by ``verify_client`` during Phase
    18). The client and its transport are therefore built directly: one
    ``HTTPTransport`` with environment trust off and TLS verified against the
    system store, and no mounts."""
    transport = httpx2.HTTPTransport(verify=True, trust_env=False)
    return httpx2.Client(
        transport=transport,
        trust_env=False,
        follow_redirects=False,
        timeout=timeout_seconds,
    )


def check_sdk_logging() -> None:
    """Fails closed if an SDK/transport logger would emit DEBUG records
    (``ANTHROPIC_LOG=debug`` or an application setting DEBUG globally)."""
    for name in SDK_LOGGERS:
        if logging.getLogger(name).isEnabledFor(logging.DEBUG):
            raise ProviderTransportError(TRANSPORT_SDK_DEBUG_LOGGING)


def _http_client_of(client: Any) -> httpx2.Client:
    http = getattr(client, "_client", None)
    if not isinstance(http, httpx2.Client):
        raise ProviderTransportError(TRANSPORT_CLIENT_UNSUPPORTED)
    return http


def _tls_context_of(transport: Any) -> Optional[ssl.SSLContext]:
    pool = getattr(transport, "_pool", None)
    if pool is None or getattr(pool, "_proxy", None) is not None:
        raise ProviderTransportError(TRANSPORT_PROXY_CONFIGURED if pool is not None else TRANSPORT_UNKNOWN_TRANSPORT)
    context = getattr(pool, "_ssl_context", None)
    return context if isinstance(context, ssl.SSLContext) else None


def _tls_trust(http: httpx2.Client) -> str:
    transport = getattr(http, "_transport", None)
    if type(transport) is httpx2.MockTransport:
        # An in-process handler: no network I/O, so no TLS and no route.
        return TLS_TRUST_IN_PROCESS
    if type(transport) is not httpx2.HTTPTransport:
        raise ProviderTransportError(TRANSPORT_UNKNOWN_TRANSPORT)
    context = _tls_context_of(transport)
    if context is None or context.verify_mode != ssl.CERT_REQUIRED or not context.check_hostname:
        raise ProviderTransportError(TRANSPORT_TLS_UNVERIFIED)
    # With trust_env=False and verify=True, httpx2 uses the system trust
    # store through truststore; a plain ssl.SSLContext means a CA file or
    # directory was loaded instead.
    import truststore

    if not isinstance(context, truststore.SSLContext):
        raise ProviderTransportError(TRANSPORT_TLS_UNVERIFIED)
    return TLS_TRUST_SYSTEM


def _timeout_bounded(timeout: Any, expected: Optional[float]) -> bool:
    if isinstance(timeout, (int, float)) and not isinstance(timeout, bool):
        values = [float(timeout)]
    elif isinstance(timeout, httpx2.Timeout):
        values = [timeout.connect, timeout.read, timeout.write, timeout.pool]
    else:
        return False
    if any(v is None or not math.isfinite(v) or v <= 0 for v in values):
        return False
    if expected is not None:
        return all(v == float(expected) for v in values)
    return all(v <= MAX_INJECTED_TIMEOUT_SECONDS for v in values)


def verify_client(client: Any, *, endpoint: str, expected_timeout: Optional[float]) -> TransportPolicy:
    """Verifies the effective client and returns the policy it enforces.
    ``expected_timeout`` is the configured timeout for a client this module
    built; an injected client needs only a bounded one."""
    if not isinstance(client, anthropic.Anthropic):
        raise ProviderTransportError(TRANSPORT_CLIENT_UNSUPPORTED)
    # -- SDK level ---------------------------------------------------------
    if str(client.base_url).rstrip("/") != endpoint.rstrip("/") or not endpoint.startswith("https://"):
        raise ProviderTransportError(TRANSPORT_ENDPOINT_MISMATCH)
    if client.max_retries != 0:
        raise ProviderTransportError(TRANSPORT_RETRIES_ENABLED)
    if getattr(client, "auth_token", None) is not None or set(client.auth_headers) != {"X-Api-Key"}:
        raise ProviderTransportError(TRANSPORT_AUTH_HOOK)
    if dict(getattr(client, "_custom_headers", None) or {}) or dict(getattr(client, "_custom_query", None) or {}):
        raise ProviderTransportError(TRANSPORT_UNSAFE_HEADERS)
    if not _timeout_bounded(client.timeout, expected_timeout):
        raise ProviderTransportError(TRANSPORT_TIMEOUT_UNBOUNDED)
    # -- HTTP level --------------------------------------------------------
    http = _http_client_of(client)
    if http.trust_env is not False:
        raise ProviderTransportError(TRANSPORT_ENV_TRUST_ENABLED)
    if getattr(http, "_mounts", None) != {}:
        raise ProviderTransportError(TRANSPORT_PROXY_CONFIGURED)
    if http.follow_redirects is not False:
        raise ProviderTransportError(TRANSPORT_REDIRECTS_ENABLED)
    if http.auth is not None:
        raise ProviderTransportError(TRANSPORT_AUTH_HOOK)
    if any(http.event_hooks.get(kind) for kind in ("request", "response")) or set(http.event_hooks) - {"request", "response"}:
        raise ProviderTransportError(TRANSPORT_REQUEST_HOOK)
    if {name.lower() for name in http.headers} - _ALLOWED_HTTP_HEADERS or len(http.cookies) or len(http.params):
        raise ProviderTransportError(TRANSPORT_UNSAFE_HEADERS)
    tls_trust = _tls_trust(http)
    return TransportPolicy(tls_trust=tls_trust)


__all__ = [
    "MAX_INJECTED_TIMEOUT_SECONDS",
    "ProviderTransportError",
    "SDK_LOGGERS",
    "build_http_client",
    "check_sdk_logging",
    "verify_client",
]
