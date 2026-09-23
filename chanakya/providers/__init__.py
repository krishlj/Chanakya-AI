"""Chanakya AI — LLM provider adapters (Phase 5.6+).

Phase 5.6.1 added the configuration boundary (`ProviderConfig`). Phase
5.6.3 adds the first real adapter, `AnthropicProvider`, implementing
`chanakya.runtime.agent_loop.AgentProvider` against the official
Anthropic SDK — see `anthropic_provider.py`'s module docstring for the
full security-invariant accounting.

Deliberately NOT implemented yet: any composition/bootstrap module
(`bootstrap.py`) that resolves `ProviderConfig.api_key_env_var` into a
raw credential, a multi-provider registry, streaming, or retries. Each
of those is a later, separately-approved step.
"""
from .anthropic_provider import AnthropicProvider
from .config import MAX_TEMPERATURE, MIN_TEMPERATURE, ProviderConfig

__all__ = ["ProviderConfig", "MIN_TEMPERATURE", "MAX_TEMPERATURE", "AnthropicProvider"]
