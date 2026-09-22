"""Chanakya AI — Phase 5.6.1 Provider Configuration.

Home for real LLM provider adapters (Phase 5.6+). This step (5.6.1)
implements only the configuration boundary a future provider adapter
(e.g. an `AnthropicAgentProvider` implementing
`chanakya.runtime.agent_loop.AgentProvider`) will be constructed from.

Deliberately NOT implemented yet: any concrete provider adapter, any LLM
SDK dependency, any network call, any context/response mapping logic
(`mapping.py`), and any composition/bootstrap module (`bootstrap.py`).
Each of those is a later, separately-approved Phase 5.6.x step.
"""
from .config import MAX_TEMPERATURE, MIN_TEMPERATURE, ProviderConfig

__all__ = ["ProviderConfig", "MIN_TEMPERATURE", "MAX_TEMPERATURE"]
