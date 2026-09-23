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

from typing import Any, Mapping, Optional

import anthropic

from chanakya.runtime.context_assembler import AssembledContext

from . import mapping
from .config import ProviderConfig


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
        self._client = (
            client
            if client is not None
            else anthropic.Anthropic(
                api_key=api_key,
                base_url=config.endpoint,
                timeout=config.timeout_seconds,
            )
        )

    def next_turn(self, assembled_context: AssembledContext) -> Mapping[str, Any]:
        """Implements ``AgentProvider.next_turn``. Raises whatever the
        underlying SDK call raises (timeout, auth failure, rate limit,
        connection error, ...) — never caught or converted into a
        turn-shaped result here (LLM-INV-9)."""
        request_kwargs = mapping.build_request_kwargs(assembled_context, self._config)
        response = self._client.messages.create(**request_kwargs)
        return mapping.response_to_turn_mapping(response, investigation_id=assembled_context.investigation_id)


__all__ = ["AnthropicProvider"]
