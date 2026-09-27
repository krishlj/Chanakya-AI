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
- ``AssembledContext.target_context`` (Phase 5.7.4 — descriptive,
  investigation-scoped ``TargetContextView`` entries) is serialized into
  that same ``user`` message as its own ``investigation_targets`` section,
  built only from ``TargetContextView.as_model_mapping()`` — never placed
  in ``system``, never in a tool schema, never merged with
  ``untrusted_data``, and never used to fill a ``target_ref``. Omitted
  entirely when there is no target context, so such requests are
  byte-identical to pre-5.7.4 requests.
- ``AssembledContext.environment_context`` (Phase 5.7.6 — observational,
  untrusted, investigation-bound ``EnvironmentContextView`` entries) is
  serialized into that same ``user`` message as its own
  ``untrusted_environment_observations`` section, built only from
  ``EnvironmentContextView.as_model_mapping()`` — never in ``system``,
  never in a tool name/description/schema, never merged with
  ``investigation_targets`` or ``untrusted_data``, and never used to fill
  a ``target_ref``. Omitted entirely when empty (byte-identical to
  pre-5.7.6 requests). This module never discovers environment data: it
  renders only what the Runtime already assembled.
- The response is walked for content blocks by structural type only
  (``TextBlock``/``ToolUseBlock``); no Anthropic SDK object is ever
  returned from a public function here — only plain ``dict``/``str``/
  ``None`` values that already satisfy ``AgentTurnOutput.from_dict``'s
  and (once past intake) ``ToolRequest.from_dict``'s own contracts.
"""
from __future__ import annotations

import copy
import json
import uuid
from typing import Any, Mapping, MutableMapping, Optional

from chanakya.capability.reserved import (
    RESERVED_FINDING_TOOL,
    RESERVED_TARGET_PARAMETER,
    find_reserved_parameter_declarations,
    is_reserved_capability_name,
)
from chanakya.contracts.enums import SUPPORTED_CONTRACT_VERSIONS
from chanakya.contracts import risk_taxonomy
from chanakya.runtime.clock import utcnow_iso
from chanakya.runtime.context_assembler import AssembledContext
from chanakya.targets.context import TargetContextView
from chanakya.targets.environment_view import EnvironmentContextView

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
#: Phase 5.6.3 report's "Limitations" section. Phase 5.7.4: the model now
#: also receives the investigation's targets (``investigation_targets``
#: in the user message) to choose from — but the value is still only its
#: proposal, never filled in here, and still validated by
#: ToolRequestIntake and the Policy Gateway. Phase 5.7.5: the name is the
#: provider-neutral, Runtime-reserved ``RESERVED_TARGET_PARAMETER``
#: (``chanakya.capability.reserved``); the Registry refuses to admit a
#: capability that declares it, and this module refuses to build a tool
#: from a catalog entry that declares it (the catalog is caller-supplied,
#: so the Registry check alone does not cover every path here).
_TARGET_REF_PARAM = RESERVED_TARGET_PARAMETER

#: Phase 5.7.5 — fixed, provider-authored description of the reserved
#: parameter. Deterministic (never interpolates target ids or any other
#: per-investigation value; no ``enum``), and deliberately worded as a
#: proposal: it names ``investigation_targets`` as where target ids come
#: from, and states that being listed there does not mean an action will
#: be allowed. Carries no Agent-authored or target-authored text.
_TARGET_REF_DESCRIPTION = (
    "Required. The target this proposed action applies to: the target_id of one entry in "
    "investigation_targets. This value is only a proposal. Chanakya validates it and the Policy "
    "Gateway decides whether the action may run against that target; being listed in "
    "investigation_targets does not mean an action against that target will be allowed."
)

#: Phase 9: fixed description of the reserved finding channel. It names
#: what the channel is for and states that it runs nothing.
_FINDING_TOOL_DESCRIPTION = (
    "Call this only when you are finished, to end the investigation and report findings. It is not "
    "an action: it runs nothing, changes nothing and grants nothing. Each finding must cite, in "
    "evidence_refs, the tool_result ids (the part after 'tool_result:' in an untrusted_data source) "
    "of the results that support it. Findings are recorded as opinions grounded in that evidence."
)

#: Phase 10: fixed description of the finding ``category``. The enum is the
#: provider-neutral rule-set taxonomy (``chanakya.contracts.risk_taxonomy``);
#: it is a hint only. The Runtime does not trust schema conformance: a
#: category outside it is simply not assessed, and the model supplies no
#: risk field of any kind.
_FINDING_CATEGORY_DESCRIPTION = (
    "Optional. The kind of finding. Chanakya's fixed, rule-based risk assessment uses this category "
    "together with the provenance of the cited evidence; a finding without a listed category is "
    "recorded but not risk-assessed. You do not rate severity or risk."
)

def _finding_tool_schema() -> Mapping[str, Any]:
    """Phase 13: the finding channel schema with its ``category`` enum taken,
    at request time, from the one active risk rule set, so the model-facing
    vocabulary cannot drift from the rules that rate it. A fresh copy is
    returned; the template is never mutated."""
    schema = copy.deepcopy(_FINDING_TOOL_SCHEMA)
    category = schema["properties"]["findings"]["items"]["properties"]["category"]
    category["enum"] = list(risk_taxonomy.active_rule_set().category_ids)
    return schema


_FINDING_TOOL_SCHEMA = {
    "type": "object",
    "properties": {
        "findings": {
            "type": "array",
            "maxItems": 20,
            "items": {
                "type": "object",
                "properties": {
                    "title": {"type": "string", "maxLength": 200},
                    "description": {"type": "string", "maxLength": 4000},
                    "evidence_refs": {"type": "array", "items": {"type": "string"}, "minItems": 1, "maxItems": 20},
                    "category": {
                        "type": "string",
                        "enum": [],  # filled per request from the active rule set
                        "description": _FINDING_CATEGORY_DESCRIPTION,
                    },
                    "confidence": {"type": "string", "enum": ["low", "medium", "high"]},
                },
                "required": ["title", "description", "evidence_refs"],
                "additionalProperties": False,
            },
        }
    },
    "required": ["findings"],
    "additionalProperties": False,
}

#: Returned instead of a usable turn when the model misuses the reserved
#: channel; ``AgentTurnOutput.from_dict`` rejects it (MALFORMED_TURN).
_INVALID_RESERVED_USE = "invalid_reserved_tool_use"

#: Phase 5.7.4 — user-message key for the target-context section
#: (docs/TARGET-AWARE-AGENT-CONTEXT.md §14). A sibling of, never nested
#: in or merged with, ``untrusted_data``.
_TARGET_CONTEXT_KEY = "investigation_targets"

#: Phase 5.7.6 — user-message key for the environment section
#: (docs/TARGET-AWARE-AGENT-CONTEXT.md §13a). Self-describing as untrusted
#: so the model can tell it apart from both target identity
#: (``investigation_targets``) and tool output (``untrusted_data``) without
#: any change to the Runtime-authored system text.
_ENVIRONMENT_CONTEXT_KEY = "untrusted_environment_observations"


def build_request_kwargs(assembled_context: AssembledContext, config: ProviderConfig) -> MutableMapping[str, Any]:
    """Builds the keyword arguments for ``anthropic.Anthropic().messages.create``.

    ``assembled_context.instructions`` (trusted, Runtime-authored) is
    sent as the ``system`` parameter, unmodified and alone. Everything
    in ``assembled_context.data`` (untrusted, tool/target-originated) is
    serialized into the single ``user`` message as a structured JSON
    object that preserves each entry's ``source``, and never appears in
    ``system``. The capability catalog is passed as native Anthropic
    ``tools``, not embedded in prompt text.

    ``assembled_context.target_context`` (descriptive, investigation-scoped)
    is rendered as a separate ``investigation_targets`` section of the same
    user message, in the order given — see ``_target_context_section``.
    """
    user_payload: MutableMapping[str, Any] = {"investigation_id": assembled_context.investigation_id}
    targets = _target_context_section(assembled_context.target_context)
    if targets:
        user_payload[_TARGET_CONTEXT_KEY] = targets
    environment = _environment_context_section(getattr(assembled_context, "environment_context", ()))
    if environment:
        user_payload[_ENVIRONMENT_CONTEXT_KEY] = environment
    user_payload["untrusted_data"] = [
        {"source": entry.source, "content": entry.content} for entry in assembled_context.data
    ]
    user_text = json.dumps(user_payload, default=str)

    kwargs: MutableMapping[str, Any] = {
        "model": config.model,
        "system": assembled_context.instructions,
        "messages": [{"role": "user", "content": user_text}],
        "max_tokens": effective_max_tokens(config),
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
    if getattr(config, "findings_channel", False):
        tools.append(
            {"name": RESERVED_FINDING_TOOL, "description": _FINDING_TOOL_DESCRIPTION, "input_schema": _finding_tool_schema()}
        )
    if tools:
        kwargs["tools"] = tools

    return kwargs


def effective_max_tokens(config: ProviderConfig) -> int:
    """The ``max_tokens`` every request carries (Phase 14: recorded)."""
    return config.max_output_tokens if config.max_output_tokens is not None else _DEFAULT_MAX_TOKENS


def response_metadata(response: Any):
    """Phase 14: ``(stop_reason, tool_use_block_count)`` of a response, so
    the Runtime can record them and reject a cut-off or multi-tool turn
    instead of silently using the first block. Plain values only."""
    content = list(getattr(response, "content", None) or [])
    stop_reason = getattr(response, "stop_reason", None)
    tool_use_blocks = sum(1 for block in content if _block_type(block) == "tool_use")
    return (stop_reason if isinstance(stop_reason, str) else None), tool_use_blocks


def _target_context_section(target_context: Any) -> list:
    """Serializes target context through the approved, provider-neutral
    representation only: ``TargetContextView.as_model_mapping()`` (fixed
    keys, ``str``/``None`` values). Order is preserved exactly as the
    Runtime assembled it — no re-sorting, no de-duplication, no filtering
    (all of that is the Runtime's job, already done and scope-checked).

    Fails closed with ``TypeError`` on any entry that is not a
    ``TargetContextView`` (e.g. a raw ``Target``, a dict, an
    ``EnvironmentContext``) rather than serializing it by some other route
    (TC-INV-9). The provider raising means no request is sent; the
    Runtime's existing fail-closed backstop handles it.
    """
    section = []
    for view in target_context or ():
        if not isinstance(view, TargetContextView):
            raise TypeError(
                f"AssembledContext.target_context entries must be TargetContextView, got {type(view).__name__}"
            )
        section.append(view.as_model_mapping())
    return section


def _environment_context_section(environment_context: Any) -> list:
    """Serializes environment context through the approved,
    provider-neutral representation only:
    ``EnvironmentContextView.as_model_mapping()``. Order is preserved
    exactly as the Runtime assembled it; binding/projection were already
    enforced there. Fails closed with ``TypeError`` on any entry that is not
    an ``EnvironmentContextView`` (e.g. a raw ``EnvironmentContext``, a
    dict, a ``TargetContextView``), so no request is sent."""
    section = []
    for view in environment_context or ():
        if not isinstance(view, EnvironmentContextView):
            raise TypeError(
                "AssembledContext.environment_context entries must be EnvironmentContextView, "
                f"got {type(view).__name__}"
            )
        section.append(view.as_model_mapping())
    return section


def _build_tool_param(entry: Mapping[str, Any]) -> Mapping[str, Any]:
    """Maps one Capability Catalog View entry (docs/TOOL-REGISTRY.md §4)
    into an Anthropic ``ToolParam``. Only the catalog's own Agent-visible
    fields are read — no privileged/registry-internal field ever reaches
    this function because the Runtime never put one in
    ``capability_catalog`` to begin with (this module trusts, but does
    not re-derive, that existing filtering).
    """
    # Phase 9: a caller-supplied catalog must not shadow the reserved
    # finding channel.
    if is_reserved_capability_name(entry.get("capability")):
        raise ValueError(
            f"capability name {entry.get('capability')!r} is reserved for the finding channel; "
            "refusing to build its tool definition"
        )
    raw_schema = entry.get("parameters_schema")
    # Phase 5.7.5 (F-4): never silently shadow a capability's own
    # declaration of the reserved name — fail closed (no request is sent;
    # the Runtime's existing fail-closed path handles the raised error).
    reserved = find_reserved_parameter_declarations(raw_schema)
    if reserved:
        raise ValueError(
            f"capability {entry.get('capability')!r} declares Runtime-reserved parameter "
            f"{_TARGET_REF_PARAM!r} at {reserved!r}; refusing to build its tool definition"
        )
    schema: MutableMapping[str, Any] = dict(raw_schema) if isinstance(raw_schema, Mapping) else {"type": "object"}
    schema.setdefault("type", "object")

    properties = dict(schema.get("properties") or {})
    properties[_TARGET_REF_PARAM] = {
        "type": "string",
        "description": _TARGET_REF_DESCRIPTION,
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
    """Converts a response with the finding channel disabled. A call to the
    reserved ``report_findings`` name is never turned into a tool_request;
    it yields a malformed turn. See ``_response_to_turn`` for the rest."""
    return _response_to_turn(response, investigation_id=investigation_id, findings_channel=False)


def response_to_turn_mapping_with_findings(response: Any, *, investigation_id: str) -> Mapping[str, Any]:
    """Phase 9. As ``response_to_turn_mapping``, but a lone, well-formed
    ``report_findings`` call becomes ``next_action: conclude`` with its
    raw ``findings``. Same inputs: it cannot see the assembled context."""
    return _response_to_turn(response, investigation_id=investigation_id, findings_channel=True)


def _response_to_turn(response: Any, *, investigation_id: str, findings_channel: bool) -> Mapping[str, Any]:
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

    tool_use_blocks = [block for block in content if _block_type(block) == "tool_use"]
    reserved_blocks = [b for b in tool_use_blocks if is_reserved_capability_name(getattr(b, "name", None))]
    tool_use_block = tool_use_blocks[0] if tool_use_blocks else None
    text_parts = [block.text for block in content if _block_type(block) == "text" and getattr(block, "text", None)]
    explanation: Optional[str] = "\n".join(text_parts) if text_parts else None

    turn: MutableMapping[str, Any] = {
        "turn_id": str(uuid.uuid4()),
        "contract_version": _CONTRACT_VERSION,
        "investigation_id": investigation_id,
        "produced_at": utcnow_iso(),
    }

    if reserved_blocks:
        # Phase 9: the finding channel never becomes a tool_request. It is
        # accepted only when enabled and when it is the one tool call in
        # the response; any other use is made malformed on purpose.
        block = reserved_blocks[0]
        raw_input = getattr(block, "input", None)
        if (
            not findings_channel
            or len(tool_use_blocks) != 1
            or getattr(block, "name", None) != RESERVED_FINDING_TOOL
            or not isinstance(raw_input, Mapping)
            or set(raw_input) != {"findings"}
        ):
            turn["next_action"] = _INVALID_RESERVED_USE
            return turn
        turn["next_action"] = "conclude"
        turn["findings"] = raw_input["findings"]
        if explanation:
            turn["explanation"] = explanation
        return turn

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


__all__ = [
    "build_request_kwargs",
    "effective_max_tokens",
    "response_metadata",
    "response_to_turn_mapping",
    "response_to_turn_mapping_with_findings",
]
