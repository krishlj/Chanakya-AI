"""AnthropicProvider — Phase 5.6.3.

Adapts the official Anthropic Python SDK (``anthropic>=1.7.0,<2.0``,
already pinned in ``pyproject.toml`` since Phase 5.6.2) to the existing
``chanakya.runtime.agent_loop.AgentProvider`` Protocol:

    def next_turn(self, assembled_context: AssembledContext) -> Mapping[str, Any]: ...

This class is an adapter ONLY. It is not a policy engine, a security
gateway, a tool executor, an approval system, an evidence writer, an
audit writer, an agent runtime, or an authorization authority — the
existing ``AgentLoopController`` remains responsible for orchestration
and ``PolicyGateway`` remains the sole policy-enforcement authority.
Nothing in this module imports ``chanakya.policy``, ``chanakya.runtime.
dispatch``, ``chanakya.evidence``, or ``chanakya.runtime.audit`` — there
is no path from here to authorization, execution, or persistence.

Request/response translation itself lives in ``mapping.py`` — this class
is deliberately thin: resolve configuration into an SDK client, call it
once, hand the result to the mapping module, return a plain
``Mapping[str, Any]``.

Security invariants (LLM-INV-1..11, Phase 5.6.3 checkpoint) and how this
module satisfies each:

- **LLM-INV-1** (never authorizes anything): this class has no
  allow/deny/require_approval logic and returns only a proposal shape;
  the Policy Gateway is never imported or referenced.
- **LLM-INV-2** (cannot execute tools or dispatch capabilities): no
  import of ``chanakya.runtime.dispatch``/``ToolExecutor``; the only
  network call this class ever makes is ``self._client.messages.create``
  (the Anthropic API itself), never a capability invocation.
- **LLM-INV-3** (credentials never enter context/turn/request/evidence/
  audit/output): ``api_key`` is passed straight through to the SDK
  client constructor in ``__init__`` and is never assigned to an
  instance attribute, never interpolated into a log message or
  exception string this module constructs, and never appears in the
  mapping this class returns (``mapping.py`` never reads or forwards
  it — it has no reference to it at all).
- **LLM-INV-4** (SDK types never cross into Runtime contracts):
  ``next_turn`` returns exactly ``mapping.response_to_turn_mapping(...)``
  — a plain dict of ``str``/``dict``/``None`` values; the ``anthropic.
  types.Message`` object itself, and every content-block object it
  contains, stay local to this call and are never returned.
- **LLM-INV-5** (UntrustedData never becomes trusted system
  instructions): ``mapping.build_request_kwargs`` sends
  ``assembled_context.instructions`` as the Anthropic ``system``
  parameter alone, and ``assembled_context.data`` only ever as
  structured JSON inside the ``user`` message — see ``mapping.py`` for
  the detailed boundary handling.
- **LLM-INV-6** (provider output stays subject to AgentTurnOutput
  validation): this class does not call ``AgentTurnOutput.from_dict``
  itself — it returns a plain mapping and lets the existing
  ``AgentLoopController`` do that validation, exactly like every other
  ``AgentProvider`` implementation (real or test double).
- **LLM-INV-7** (provider output stays subject to Runtime resource
  governance): same reasoning as LLM-INV-6 — the Resource Governor's
  ``check_provider_output_size`` call in ``agent_loop.py`` runs on
  whatever this method returns, unmodified by anything in this module.
- **LLM-INV-8** (provider cannot modify RuntimeExecutionLimits): this
  module has no import of, or reference to,
  ``chanakya.runtime.limits.RuntimeExecutionLimits`` at all.
- **LLM-INV-9** (provider failure cannot implicitly authorize/conclude/
  bypass policy): an SDK exception from ``messages.create`` propagates
  unmodified out of ``next_turn`` — there is no ``try/except`` here that
  could convert it into a successful ``conclude`` or any other outcome;
  the existing ``AgentLoopController.run_turn`` outer fail-closed
  backstop (already covering ``RaisingAgentProvider`` in
  ``tests/test_agent_provider_boundary.py``) handles it exactly as it
  already handles any other provider exception.
- **LLM-INV-10** (no EvidenceStore/AuditEvent write capability): no
  import of ``chanakya.evidence`` or ``chanakya.runtime.audit``.
- **LLM-INV-11** (ToolRequest reaches execution only through Runtime /
  ToolRequestIntake / PolicyGateway): a mapped ``tool_request`` is
  returned as plain untrusted data inside the turn mapping — the same
  ``AgentTurnOutput.tool_request`` shape ``ScriptedAgentProvider``
  already returns in existing tests — and is handled by the identical,
  unmodified ``_handle_tool_request_turn`` -> ``ToolRequestIntake`` ->
  ``PolicyGateway`` pipeline; this class has no other path by which a
  tool request could reach execution.
"""
from __future__ import annotations

import copy
from typing import Any, Mapping, Optional

import anthropic

from chanakya.contracts.agent_turn import (
    PreparedProviderRequest,
    ProviderIdentity,
    ProviderResponse,
    hash_value,
)
from chanakya.runtime.context_assembler import AssembledContext

from . import mapping
from .config import ProviderConfig
from .transport import build_http_client, check_sdk_logging, verify_client

#: Phase 14 (T-59): environment variables through which the Anthropic SDK
#: would take a security-sensitive setting (destination, extra headers, a
#: profile that can carry a base URL) from the process environment. The CLI
#: composition root (the one place that reads the environment) refuses to
#: start while any is set; only the names are checked, never the values.
#: This module reads no environment: it passes an explicit ``base_url`` and
#: then verifies the built client's actual endpoint and headers.
FORBIDDEN_SDK_ENVIRONMENT = ("ANTHROPIC_BASE_URL", "ANTHROPIC_CUSTOM_HEADERS", "ANTHROPIC_PROFILE")

#: Phase 18 (T-63): environment variables that would influence the provider
#: transport (route, TLS trust roots, credentials, SDK logging) if the
#: transport trusted the environment. It does not (``trust_env=False`` and
#: post-construction verification, ``chanakya.providers.transport``); the CLI
#: still refuses to start while any is present, as defense in depth and to
#: make operator intent explicit. Names only: values are never read.
FORBIDDEN_TRANSPORT_ENVIRONMENT = (
    "HTTPS_PROXY", "HTTP_PROXY", "ALL_PROXY", "NO_PROXY",
    "https_proxy", "http_proxy", "all_proxy", "no_proxy",
    "SSL_CERT_FILE", "SSL_CERT_DIR", "NETRC",
    "ANTHROPIC_AUTH_TOKEN", "ANTHROPIC_LOG",
)


def _normalized_endpoint(value: Any) -> str:
    return str(value).rstrip("/")


class AnthropicProvider:
    """Adapts the Anthropic SDK to ``chanakya.runtime.agent_loop.AgentProvider``.

    ``api_key`` is accepted via constructor injection only (per the
    Phase 5.6.3 checkpoint) — this class never reads ``os.environ`` or
    any other secret store itself; resolving ``ProviderConfig.
    api_key_env_var`` into a raw value is a composition/bootstrap-layer
    concern, out of scope here.
    """

    def __init__(
        self,
        config: ProviderConfig,
        api_key: str,
        *,
        client: Optional[anthropic.Anthropic] = None,
    ) -> None:
        if not isinstance(api_key, str) or not api_key:
            raise ValueError("AnthropicProvider requires a non-empty api_key")

        self._config = config
        # `api_key` is deliberately not assigned to `self` anywhere in
        # this class (LLM-INV-3) — it is handed directly to the SDK
        # client constructor and nowhere else. `client` lets a caller
        # (tests; a future composition root) supply a pre-configured
        # `anthropic.Anthropic` instance instead — e.g. one built with a
        # mock HTTP transport in tests, so no real network call is ever
        # made without one being explicitly injected.
        #
        # Phase 5.6.6 remediation (LLM-INV-3): the SDK's default HTTP
        # client follows redirects, and on a cross-origin redirect the
        # transport strips only `Authorization` — not the `X-Api-Key`
        # header this SDK authenticates with — and a 307 also re-sends
        # the request body (investigation data). Redirects are therefore
        # never followed: a 3xx surfaces as an SDK status error and takes
        # the Runtime's existing fail-closed provider-failure path.
        #
        # Phase 14 (T-59, CT-INV-4): the destination is explicit. The SDK is
        # always given ``config.effective_endpoint`` as ``base_url`` (so
        # ANTHROPIC_BASE_URL and profile base URLs are never consulted), and
        # a real SDK client is checked to target exactly that endpoint with
        # no custom headers (ANTHROPIC_CUSTOM_HEADERS would add some), or
        # construction fails closed.
        #
        # Phase 18 (T-63, P18-INV-1..4): the transport is built explicitly
        # with environment trust disabled (no proxy, CA, netrc or other
        # environment input), then the *effective* client, built here or
        # injected, is verified; anything unverifiable fails closed with
        # ``ProviderTransportError``. Only the verified policy is recorded.
        check_sdk_logging()
        built_here = client is None
        if built_here:
            client = anthropic.Anthropic(
                api_key=api_key,
                base_url=config.effective_endpoint,
                timeout=config.timeout_seconds,
                max_retries=0,
                http_client=build_http_client(config.timeout_seconds),
            )
        if isinstance(client, anthropic.Anthropic):
            if _normalized_endpoint(client.base_url) != _normalized_endpoint(config.effective_endpoint):
                raise ValueError("provider client does not target the configured endpoint")
            if dict(getattr(client, "_custom_headers", None) or {}):
                raise ValueError("provider client carries custom headers; refusing to send investigation data")
            # Phase 15: one recorded turn = one provider send. The SDK's own
            # retries (default 2) would re-send a recorded request unseen by
            # the turn record; the Runtime already fails closed on provider
            # errors, so no retry is needed here. Applied to injected clients
            # too (same transport, retries off).
            client = client.with_options(max_retries=0)
        self._endpoint = _normalized_endpoint(config.effective_endpoint)
        self._expected_timeout = float(config.timeout_seconds) if built_here else None
        transport = verify_client(client, endpoint=self._endpoint, expected_timeout=self._expected_timeout)
        self._client = client
        self._identity = ProviderIdentity(
            provider=config.provider,
            model=config.model,
            endpoint=_normalized_endpoint(config.effective_endpoint),
            config_version=config.provider_config_version,
            timeout_seconds=float(config.timeout_seconds),
            max_tokens=mapping.effective_max_tokens(config),
            transport=transport,
        )

    # -- Phase 14: declared identity and a two-phase, recordable call ----------

    def provider_identity(self) -> ProviderIdentity:
        """Provider, model, explicit endpoint, configuration version,
        timeout and max tokens. Never the credential or any header."""
        return self._identity

    def prepare_turn(self, assembled_context: AssembledContext) -> PreparedProviderRequest:
        """Builds the exact request ``send_turn`` will send, and its
        canonical hash. The Runtime records the hash before sending."""
        payload = copy.deepcopy(dict(mapping.build_request_kwargs(assembled_context, self._config)))
        return PreparedProviderRequest(
            payload=payload, request_hash=hash_value(payload), investigation_id=assembled_context.investigation_id
        )

    def send_turn(self, prepared: PreparedProviderRequest) -> ProviderResponse:
        """Sends exactly the prepared request (re-verified against its hash)
        and returns the turn mapping plus the stop reason and tool-block
        count. Raises whatever the SDK raises (LLM-INV-9)."""
        request_kwargs = copy.deepcopy(dict(prepared.payload))
        if hash_value(request_kwargs) != prepared.request_hash:
            raise ValueError("prepared provider request does not match its recorded hash")
        # Phase 18: re-checked at every send, before any byte leaves: SDK
        # debug logging (which would copy the body) and the transport the
        # recorded policy describes.
        check_sdk_logging()
        verified = verify_client(self._client, endpoint=self._endpoint, expected_timeout=self._expected_timeout)
        if verified != self._identity.transport:
            raise ValueError("provider transport changed after verification")
        response = self._client.messages.create(**request_kwargs)
        convert = (
            mapping.response_to_turn_mapping_with_findings
            if self._config.findings_channel
            else mapping.response_to_turn_mapping
        )
        stop_reason, tool_use_blocks = mapping.response_metadata(response)
        turn = convert(response, investigation_id=prepared.investigation_id)
        return ProviderResponse(turn=turn, stop_reason=stop_reason, tool_use_blocks=tool_use_blocks)

    def next_turn(self, assembled_context: AssembledContext) -> Mapping[str, Any]:
        """Implements ``AgentProvider.next_turn`` as one call. The Runtime
        uses ``prepare_turn``/``send_turn`` so the request is recorded
        first. Raises whatever the SDK call raises (LLM-INV-9)."""
        return self.send_turn(self.prepare_turn(assembled_context)).turn

__all__ = ["AnthropicProvider", "FORBIDDEN_SDK_ENVIRONMENT", "FORBIDDEN_TRANSPORT_ENVIRONMENT"]
