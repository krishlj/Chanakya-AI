"""Chanakya AI — LLM provider adapters (Phase 5.6+).

Phase 5.6.1 added the configuration boundary (`ProviderConfig`). Phase
5.6.3 adds the first real adapter, `AnthropicProvider`, implementing
`chanakya.runtime.agent_loop.AgentProvider` against the official
Anthropic SDK — see `anthropic_provider.py`'s module docstring for the
full security-invariant accounting.

The API key is resolved only by the CLI composition root
(`chanakya.cli.main.main`). Not implemented: a multi-provider registry,
streaming, and SDK retries (`max_retries` is always 0). Each request asks for
at most one tool call per turn (`mapping._TOOL_CHOICE`); the Runtime still
rejects a reply with more than one `tool_use` block (CT-INV-3).
"""
from .anthropic_provider import AnthropicProvider
from .config import MAX_TEMPERATURE, MIN_TEMPERATURE, ProviderConfig

__all__ = ["ProviderConfig", "MIN_TEMPERATURE", "MAX_TEMPERATURE", "AnthropicProvider"]
