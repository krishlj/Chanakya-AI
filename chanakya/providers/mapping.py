"""Phase 5.6.3 — AnthropicProvider request/response mapping.

Pure functions only: build the Anthropic Messages API request from an
``AssembledContext``, and convert an Anthropic ``Message`` response back
into the plain ``Mapping[str, Any]`` shape ``AgentTurnOutput.from_dict``
expects. Nothing here calls the network, holds state, evaluates policy,
or touches the Tool Layer/Evidence/Audit — this module is a translation
layer only, kept separate from ``AnthropicProvider`` so the SDK-shape
concerns (tool schemas, content-block parsing) don't crowd the thin
adapter class itself.

Security-relevant properties this module is responsible for (see
``anthropic_provider.py`` module docstring for the full LLM-INV list):

- ``AssembledContext.instructions`` (Runtime-authored, trusted) becomes
  the Anthropic ``system`` parameter — never mixed with untrusted data.
- ``AssembledContext.data`` (each entry already wrapped as
  ``UntrustedData`` by the Context Assembler) is serialized into the
  ``user`` message, each item keeping its own ``source``/``content``
  pair distinct — never flattened into the system/instruction text and
  never itself treated as a system or control message.
- The response is walked for content blocks by structural type only
  (``TextBlock``/``ToolUseBlock``); no Anthropic SDK object is ever
  returned from a public function here — only plain ``dict``/``str``/
  ``None`` values that already satisfy ``AgentTurnOutput.from_dict``'s
  and (once past intake) ``ToolRequest.from_dict``'s own contracts.
"""
from __future__ import annotations

import json
import uuid
from typing import Any, Mapping, MutableMapping, Optional

from chanakya.contracts.enums import SUPPORTED_CONTRACT_VERSIONS
from chanakya.runtime.clock import utcnow_iso
from chanakya.runtime.context_assembler import AssembledContext

from .config import ProviderConfig

#: The most recent contract version this mapping module produces.
#: ``SUPPORTED_CONTRACT_VERSIONS`` is the authoritative set this must
#: always be a member of — asserted once at import time so a future
#: contract-version bump that drops "1.0.0" fails loudly here rather
#: than silently emitting an unsupported version.
_CONTRACT_VERSION = "1.0.0"
assert _CONTRACT_VERSION in SUPPORTED_CONTRACT_VERSIONS

#: Used only when ``ProviderConfig.max_output_tokens`` is not configured
#: (``None``). The Anthropic Messages API requires a ``max_tokens``
#: value on every request — this is a provider request-parameter
#: default, not a Runtime governance ceiling; RuntimeExecutionLimits'
#: ``max_provider_output_bytes`` (enforced by the Resource Governor,
#: independently of this value) remains the sole authoritative byte-size
#: control on provider output (LLM-INV-7).
_DEFAULT_MAX_TOKENS = 4096

#: The synthetic parameter name added to every tool's ``input_schema`` so
#: the model has a structured place to supply the target a capability
#: should run against. ``AssembledContext`` (deliberately) carries no
#: target information of its own for the provider to fall back on, and
#: ``ToolRequest.target_ref`` is a required field this mapping cannot
#: invent on the model's behalf — so it is requested from the model the
#: same way any other capability parameter is, and then split back out
#: of ``parameters`` before the raw tool_request dict is built. See the
#: Phase 5.6.3 report's "Limitations" section.
_TARGET_REF_PARAM = "target_ref"


def build_request_kwargs(assembled_context: AssembledContext, config: ProviderConfig) -> MutableMapping[str, Any]:
    """Builds the keyword arguments for ``anthropic.Anthropic().messages.create``.

    ``assembled_context.instructions`` (trusted, Runtime-authored) is
    sent as the ``system`` parameter, unmodified and alone. Everything
    in ``assembled_context.data`` (untrusted, tool/target-originated) is
    serialized into the single ``user`` message as a structured JSON
    object that preserves each entry's ``source``, and never appears in
    ``system``. The capability catalog is passed as native Anthropic
    ``tools``, not embedded in prompt text.
    """
    user_payload = {
        "investigation_id": assembled_context.investigation_id,
        "untrusted_data": [
            {"source": entry.source, "content": entry.content} for entry in assembled_context.data
        ],
    }
    user_text = json.dumps(user_payload, default=str)

    kwargs: MutableMapping[str, Any] = {
        "model": config.model,
        "system": assembled_context.instructions,
        "messages": [{"role": "user", "content": user_text}],
        "max_tokens": config.max_output_tokens if config.max_output_tokens is not None else _DEFAULT_MAX_TOKENS,
    }
    if config.temperature is not None:
        # The installed SDK's `Messages.create` (inspected before writing
        # this module) has no typed `temperature` parameter in this
        # version's signature — its sampling controls are expressed
        # through `output_config.effort` instead. `extra_body` is the
        # SDK's own documented, public escape hatch for forwarding an
        # additional raw JSON field the typed signature doesn't model;
        # using it here (rather than guessing at an undocumented method
        # or silently dropping a configured value) is what lets
        # `ProviderConfig.temperature` still reach the request body.
        kwargs["extra_body"] = {"temperature": config.temperature}

    tools = [_build_tool_param(entry) for entry in assembled_context.capability_catalog]
    if tools:
        kwargs["tools"] = tools

    return kwargs


def _build_tool_param(entry: Mapping[str, Any]) -> Mapping[str, Any]:
    """Maps one Capability Catalog View entry (docs/TOOL-REGISTRY.md §4)
    into an Anthropic ``ToolParam``. Only the catalog's own Agent-visible
    fields are read — no privileged/registry-internal field ever reaches
    this function because the Runtime never put one in
    ``capability_catalog`` to begin with (this module trusts, but does
    not re-derive, that existing filtering).
    """
    raw_schema = entry.get("parameters_schema")
    schema: MutableMapping[str, Any] = dict(raw_schema) if isinstance(raw_schema, Mapping) else {"type": "object"}
    schema.setdefault("type", "object")

    properties = dict(schema.get("properties") or {})
    properties[_TARGET_REF_PARAM] = {
        "type": "string",
        "description": "The target identifier this action applies to.",
    }
    schema["properties"] = properties

    required = list(schema.get("required") or [])
    if _TARGET_REF_PARAM not in required:
        required.append(_TARGET_REF_PARAM)
    schema["required"] = required

    return {
        "name": entry["capability"],
        "description": entry.get("description") or "",
        "input_schema": schema,
    }


def response_to_turn_mapping(response: Any, *, investigation_id: str) -> Mapping[str, Any]:
    """Converts an Anthropic ``Message`` response into a plain dict
    matching ``AgentTurnOutput.from_dict``'s expected shape. Returns only
    JSON-plain values (``str``/``dict``/``None``) — no SDK type (a
    ``TextBlock``, ``ToolUseBlock``, or the ``Message`` itself) is ever
    reachable from the returned mapping (LLM-INV-4).

    Never invents a tool_request the model didn't actually produce
    (LLM-INV-9's malformed-output backstop still applies downstream):
    only a genuine ``tool_use`` content block turns into
    ``next_action: propose_tool_request``. Everything else concludes.
    """
    content = list(getattr(response, "content", None) or [])

    tool_use_block = next((block for block in content if _block_type(block) == "tool_use"), None)
    text_parts = [block.text for block in content if _block_type(block) == "text" and getattr(block, "text", None)]
    explanation: Optional[str] = "\n".join(text_parts) if text_parts else None

    turn: MutableMapping[str, Any] = {
        "turn_id": str(uuid.uuid4()),
        "contract_version": _CONTRACT_VERSION,
        "investigation_id": investigation_id,
        "produced_at": utcnow_iso(),
    }

    if tool_use_block is not None:
        turn["next_action"] = "propose_tool_request"
        turn["tool_request"] = _build_tool_request(tool_use_block, investigation_id=investigation_id)
        if explanation:
            turn["explanation"] = explanation
    else:
        turn["next_action"] = "conclude"
        if explanation:
            turn["explanation"] = explanation

    return turn


def _block_type(block: Any) -> Optional[str]:
    return getattr(block, "type", None)


def _build_tool_request(tool_use_block: Any, *, investigation_id: str) -> Mapping[str, Any]:
    """Maps one ``ToolUseBlock`` into a raw ``tool_request`` payload.

    This is a *proposal only* — the returned mapping still has to pass
    both ``AgentTurnOutput.from_dict`` (structural) and, separately,
    ``ToolRequestIntake``/``ToolRequest.from_dict`` (contract-level) in
    the Runtime before it is ever handed to the Policy Gateway
    (LLM-INV-6, LLM-INV-11). No trusted registry metadata (permission
    level, classification, approval/authorization status) is read from,
    or written into, the model's input here — there is nothing in
    ``ToolUseBlock`` that could carry one, by construction of the tool
    schema this provider itself declared (``_build_tool_param``).
    """
    raw_input = getattr(tool_use_block, "input", None)
    parameters: MutableMapping[str, Any] = dict(raw_input) if isinstance(raw_input, Mapping) else {}
    target_ref = parameters.pop(_TARGET_REF_PARAM, None)

    tool_request: MutableMapping[str, Any] = {
        "tool_request_id": str(uuid.uuid4()),
        "contract_version": _CONTRACT_VERSION,
        "investigation_id": investigation_id,
        "step_id": str(uuid.uuid4()),
        "capability": getattr(tool_use_block, "name", None),
        "parameters": parameters,
        "proposed_by": "agent",
        "proposed_at": utcnow_iso(),
    }
    # Deliberately omitted (never set to a placeholder/guessed value) if
    # the model didn't supply one — ToolRequest.from_dict rejects a
    # missing 'target_ref' on its own; this mapping never repairs or
    # invents it on the model's behalf (RT-INV-5, restated for providers
    # by the Phase 5.6.3 checkpoint).
    if isinstance(target_ref, str) and target_ref:
        tool_request["target_ref"] = target_ref

    return tool_request


__all__ = ["build_request_kwargs", "response_to_turn_mapping"]
