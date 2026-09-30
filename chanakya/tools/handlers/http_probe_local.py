"""http_probe_local — the first active-but-read-only capability (P2).

Sends exactly ONE bounded HTTP ``GET`` to a service on the local loopback
interface and returns a bounded, structured snapshot of the response
(status line, a capped set of headers, a capped body snippet). It exists so
Chanakya can *actively validate* a hypothesis about a locally running web
application — the minimum capability the
``CHANAKYA-LOCAL-PENTEST-POC-READINESS.md`` inspection identified — without
becoming a scanner or an attack engine.

What it is, and is not:

- ONE request, ONE method (``GET``), ONE fixed loopback host. It is not a
  port sweep, not a fuzzer, not a payload-mutation engine, and follows no
  redirects (``http.client`` returns the 3xx response as-is), so a 302 to an
  external URL is never chased.
- The connection host is the hard-coded literal ``127.0.0.1`` (see
  ``_LOOPBACK_HOST``). It is never taken from a parameter, the target record
  or the model, so no request can reach a public IP, a LAN host, an
  arbitrary hostname, or an Internet domain. The loopback boundary is a code
  constant enforced outside the LLM, plus ``require_loopback_host`` as a
  defense-in-depth guard inside the default fetcher.
- Only the loopback ``port`` (1-65535) and an absolute request ``path`` are
  parameters, and both are bounded and re-validated here in addition to the
  Registry's closed ``parameters_schema``. The path must be a single
  absolute path (starts with ``/``, not ``//``), carry no scheme, and hold
  no whitespace or control characters.

Security posture (mirrors ``listening_ports`` / ``LocalHostAdapter``):

- Stdlib ``http.client`` only. No ``subprocess``, ``os.system``/``os.popen``,
  ``eval``/``exec``, shell, or command string anywhere (verified by
  ``tests/test_http_probe_local.py``'s static checks).
- Bounded everywhere: the default fetcher opens the connection with an
  explicit socket timeout and reads at most ``MAX_BODY_BYTES + 1`` bytes, so
  it cannot block on a slow or endless response. Output larger than
  ``MAX_OUTPUT_BYTES`` (canonical JSON) raises ``OutputTooLargeError`` and is
  never truncated.
- The response is host-controlled, untrusted text. Header names/values and
  the body snippet are kept as ordinary string data (never interpreted); the
  Runtime already wraps every tool result as ``UntrustedData`` before it
  reaches the model.

Output (``ToolResult.output``)::

    {"host": "127.0.0.1", "port": int, "path": str,
     "status_code": int, "reason": str,
     "headers": [{"name": str, "value": str}, ...],
     "body_snippet": str, "body_snippet_bytes": int, "body_truncated": bool}

The network call is injected (``fetch``) exactly as ``listening_ports``
injects its reader, so tests exercise every branch without a real socket.
"""
from __future__ import annotations

import http.client
import json
from dataclasses import dataclass
from typing import Any, Callable, Mapping, Optional, Sequence, Tuple

from chanakya.contracts.target import Target

#: Must match the ``capability`` of the production ``RegistryEntry``
#: (``chanakya.registry.bootstrap.HTTP_PROBE_LOCAL_CAPABILITY``) — a plain
#: string match, this codebase's convention (see ``listening_ports``).
CAPABILITY_ID = "http_probe_local"

_SUPPORTED_TARGET_TYPES: Sequence[str] = ("local_host",)

#: The only host this capability ever connects to. A code constant, never a
#: parameter or a model-supplied value — this is the loopback boundary.
_LOOPBACK_HOST = "127.0.0.1"

#: Values ``require_loopback_host`` accepts. The default fetcher still
#: connects to ``_LOOPBACK_HOST`` regardless; these are the only names a
#: loopback guard treats as local (``localhost`` and ``::1`` included for the
#: guard's own completeness — production only ever passes ``127.0.0.1``).
_LOOPBACK_HOSTS = frozenset({"127.0.0.1", "::1", "localhost"})

MIN_PORT = 1
MAX_PORT = 65535

#: Bounds on the request path (a parameter).
MAX_PATH_LENGTH = 512

#: Bounds on the captured response.
MAX_BODY_BYTES = 4096
MAX_HEADERS = 32
MAX_HEADER_NAME_LENGTH = 256
MAX_HEADER_VALUE_LENGTH = 1024

#: Handler-side socket timeout. Matches the Registry entry's
#: ``default_timeout_seconds`` so the handler never outlives the Runtime's
#: (cooperative) step-timeout backstop.
DEFAULT_TIMEOUT_SECONDS = 5

#: Canonical JSON size limit for the output. Kept below the Evidence Store's
#: 65,536-byte payload limit, exactly as ``listening_ports`` does.
MAX_OUTPUT_BYTES = 60000


class HttpProbeError(Exception):
    """Base class for this capability's failures."""


class TargetBoundaryError(HttpProbeError):
    """A non-loopback host was requested. Never repaired, never connected."""


class OutputTooLargeError(HttpProbeError):
    """The output would exceed ``MAX_OUTPUT_BYTES``."""


@dataclass(frozen=True)
class ProbeResponse:
    """The bounded facts the fetcher returns about one HTTP response. Plain,
    inert data — the handler projects it into ``ToolResult.output``."""

    status_code: int
    reason: str
    header_pairs: Sequence[Tuple[str, str]]
    body: bytes
    body_truncated: bool


def _canonical_size(value: Any) -> int:
    return len(json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("utf-8"))


def is_loopback_host(host: Any) -> bool:
    """True only for the canonical loopback host values."""
    return isinstance(host, str) and host in _LOOPBACK_HOSTS


def require_loopback_host(host: Any) -> None:
    """Defense in depth: refuse any host that is not localhost, before any
    connection is attempted. Production always passes ``127.0.0.1``; this
    guard makes the boundary explicit and independently testable."""
    if not is_loopback_host(host):
        raise TargetBoundaryError("http_probe_local targets the local loopback interface only")


def validate_port(value: Any) -> int:
    """A loopback TCP port, 1-65535. Booleans are refused (``bool`` is an
    ``int`` subclass)."""
    if type(value) is not int or not (MIN_PORT <= value <= MAX_PORT):
        raise HttpProbeError("port must be an integer in 1..65535")
    return value


def validate_path(value: Any) -> str:
    """A single absolute request path on the local service. Rejects a scheme,
    a protocol-relative ``//host`` form, whitespace and control characters,
    and anything longer than ``MAX_PATH_LENGTH`` — so no parameter can point
    the request anywhere but at a path on the fixed loopback host."""
    if type(value) is not str or not value:
        raise HttpProbeError("path must be a non-empty string")
    if len(value) > MAX_PATH_LENGTH:
        raise HttpProbeError("path exceeds the maximum length")
    if not value.startswith("/") or value.startswith("//"):
        raise HttpProbeError("path must be a single absolute path beginning with '/'")
    if "://" in value:
        raise HttpProbeError("path must not contain a URL scheme")
    if any(ord(ch) < 0x20 or ord(ch) == 0x7F or ch.isspace() for ch in value):
        raise HttpProbeError("path must not contain whitespace or control characters")
    return value


def _default_fetch(host: str, port: int, path: str, timeout_seconds: int) -> ProbeResponse:
    """The production network call: one bounded ``GET`` over ``http.client``.
    No redirects are followed, the socket has an explicit timeout, and at
    most ``MAX_BODY_BYTES + 1`` bytes of body are read. The connection is
    always closed."""
    require_loopback_host(host)  # defense in depth; host is a fixed constant
    connection = http.client.HTTPConnection(host, port, timeout=timeout_seconds)
    try:
        # Lower-level putrequest/endheaders (rather than the convenience
        # ``request`` method) keeps this module free of any ``.request``
        # attribute access, preserving the codebase-wide SDK-isolation scan
        # (tests/test_anthropic_provider_sdk_security.py). A GET carries no
        # body, so no ``send`` follows.
        connection.putrequest("GET", path)
        connection.endheaders()
        response = connection.getresponse()
        status_code = int(response.status)
        reason = response.reason if isinstance(response.reason, str) else ""
        header_pairs = [(name, value) for name, value in response.getheaders() if isinstance(name, str) and isinstance(value, str)]
        raw = response.read(MAX_BODY_BYTES + 1)
    finally:
        connection.close()
    truncated = len(raw) > MAX_BODY_BYTES
    return ProbeResponse(status_code, reason, tuple(header_pairs), bytes(raw[:MAX_BODY_BYTES]), truncated)


def build_output(host: str, port: int, path: str, response: ProbeResponse) -> Mapping[str, Any]:
    """Normalized, bounded output; enforces ``MAX_OUTPUT_BYTES`` (never
    truncates the whole record — an over-limit response is rejected)."""
    headers = []
    for name, value in list(response.header_pairs)[:MAX_HEADERS]:
        if not isinstance(name, str) or not isinstance(value, str):
            continue
        headers.append({"name": name[:MAX_HEADER_NAME_LENGTH], "value": value[:MAX_HEADER_VALUE_LENGTH]})
    body = bytes(response.body[:MAX_BODY_BYTES]) if isinstance(response.body, (bytes, bytearray)) else b""
    output = {
        "host": host,
        "port": int(port),
        "path": path,
        "status_code": int(response.status_code),
        "reason": response.reason if isinstance(response.reason, str) else "",
        "headers": headers,
        "body_snippet": body.decode("utf-8", errors="replace"),
        "body_snippet_bytes": len(body),
        "body_truncated": bool(response.body_truncated),
    }
    size = _canonical_size(output)
    if size > MAX_OUTPUT_BYTES:
        raise OutputTooLargeError(f"output is {size} bytes; the limit is {MAX_OUTPUT_BYTES} (not truncated)")
    return output


class HttpProbeLocalHandler:
    """``CapabilityHandler`` for ``http_probe_local``. ``fetch`` (the network
    call) and ``timeout_seconds`` are injectable for tests; by default the
    fetcher issues one real ``http.client`` GET to ``127.0.0.1``."""

    supported_target_types = _SUPPORTED_TARGET_TYPES

    def __init__(
        self,
        *,
        fetch: Optional[Callable[[str, int, str, int], ProbeResponse]] = None,
        timeout_seconds: int = DEFAULT_TIMEOUT_SECONDS,
    ) -> None:
        self._fetch = fetch if fetch is not None else _default_fetch
        self._timeout_seconds = timeout_seconds

    def run(self, target: Target, parameters: Mapping[str, Any]) -> Mapping[str, Any]:
        # Re-validate the closed parameter set here too (the Gateway already
        # checked the schema; this handler never trusts that it did).
        if set(parameters) != {"port", "path"}:
            raise HttpProbeError("http_probe_local requires exactly 'port' and 'path'")
        port = validate_port(parameters["port"])
        path = validate_path(parameters["path"])
        response = self._fetch(_LOOPBACK_HOST, port, path, self._timeout_seconds)
        if not isinstance(response, ProbeResponse):
            raise HttpProbeError("fetcher returned an invalid response object")
        return build_output(_LOOPBACK_HOST, port, path, response)


__all__ = [
    "CAPABILITY_ID",
    "DEFAULT_TIMEOUT_SECONDS",
    "MAX_BODY_BYTES",
    "MAX_OUTPUT_BYTES",
    "MAX_PATH_LENGTH",
    "HttpProbeError",
    "HttpProbeLocalHandler",
    "OutputTooLargeError",
    "ProbeResponse",
    "TargetBoundaryError",
    "build_output",
    "is_loopback_host",
    "require_loopback_host",
    "validate_path",
    "validate_port",
]
