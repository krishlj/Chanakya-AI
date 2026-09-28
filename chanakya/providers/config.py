"""ProviderConfig — Phase 5.6.1 (Provider Configuration Contract).

Provider-specific configuration only: which vendor, which model, where to
reach it, how long to wait, and how to *find* (never hold) its credential.
This is deliberately a narrow, single-provider-shaped boundary — not a
generic configuration framework, not a secret manager, not a multi-provider
registry (see the Phase 5.6 design report's "no premature features" list).

Explicit non-goal, restated from `docs/AGENT-RUNTIME.md` RT-INV-11 and
`ARCHITECTURE.md` §15: this object never holds a raw credential. It holds
only a *reference* to where one can later be found (e.g. an environment
variable name) — the composition/bootstrap layer (a later phase) resolves
that reference and hands the raw value directly to the provider adapter's
constructor. Nothing in this module ever reads `os.environ` or any other
secret store; doing so here would make credential resolution implicit and
untestable, instead of an explicit, auditable step owned by one composition
root (Phase 5.6 design report, Task 11).

Explicit non-goal, restated from the Phase 5.6 design report §2.E: this
object never holds a Runtime security/governance control (resource
ceilings, retry budgets, target scope, capability permissions, policy
rules). `chanakya.runtime.limits.RuntimeExecutionLimits` remains the sole
authority for all of those — this class does not duplicate, shadow, or
override any of its fields.

Follows `RuntimeExecutionLimits`'s own conventions
(`chanakya/runtime/limits.py`): a frozen dataclass, fail-closed
`__post_init__` validation, no `None`-as-"unlimited" sentinel for a
governance ceiling. The three fields below that *are* allowed to be `None`
(`endpoint`, `max_output_tokens`, `temperature`) do not carry that meaning
here: `None` means "not configured — the provider adapter must supply an
explicit value, or rely on the vendor SDK's own built-in default, at call
time." `ProviderConfig` itself never interprets `None` as "unlimited";
it simply declines to constrain that particular request-time detail.
"""
from __future__ import annotations

import math
from dataclasses import dataclass
from typing import Optional

#: The sampling-temperature range this configuration accepts. Chosen to
#: match Anthropic's documented valid range for its Messages API — the
#: first (and, per the Phase 5.6 design report, currently only) provider
#: this configuration is built for — rather than an arbitrary
#: application-invented bound. A future provider with a genuinely wider
#: or differently-scaled range would need its own configuration type;
#: this phase does not attempt a provider-agnostic range (no
#: multi-provider abstraction, per the design report's constraints).
MIN_TEMPERATURE = 0.0
MAX_TEMPERATURE = 1.0

#: Phase 14 (T-59): the trusted default endpoint. ``endpoint=None`` means
#: exactly this URL, never "whatever the vendor SDK resolves from the
#: environment or a profile".
DEFAULT_ANTHROPIC_ENDPOINT = "https://api.anthropic.com"

#: Phase 14: the version of this provider configuration, recorded in every
#: agent turn record so the configuration a turn ran under is identifiable.
#: 1.1.0 (Phase 18): the transport is environment-isolated and verified
#: (``chanakya.providers.transport``); the identity records its policy.
PROVIDER_CONFIG_VERSION = "1.1.0"


@dataclass(frozen=True)
class ProviderConfig:
    """Provider-specific configuration for a (future) `AgentProvider`
    adapter. Every field here is either a non-secret operational setting
    or a *reference* to a secret, never the secret itself.

    Fields:
        provider: Vendor/provider identifier (e.g. ``"anthropic"``).
            Free text at this layer — no registry validates it against a
            known set (no provider registry exists yet, by design).
        model: The vendor's model identifier (e.g. a Claude model name).
        api_key_env_var: The name of the environment variable a later
            composition/bootstrap layer will read to obtain the raw
            credential. This field itself is never a raw secret and is
            never resolved by this class.
        timeout_seconds: The provider call's own request timeout, in
            seconds. Distinct from — and never a substitute for —
            `RuntimeExecutionLimits.default_step_timeout_seconds`, which
            governs tool dispatch, not the LLM call.
        endpoint: Optional API base URL override (``https://`` only, Phase
            14). ``None`` means ``DEFAULT_ANTHROPIC_ENDPOINT``, never an
            SDK default resolved from the environment or a profile.
        max_output_tokens: Optional cap on the model's output length, as
            a request-time sampling parameter passed to the vendor.
            ``None`` means "not configured here — the adapter decides,
            or the vendor's own default applies." This is unrelated to,
            and never a substitute for,
            `RuntimeExecutionLimits.max_provider_output_bytes`, which
            remains the Runtime's own authoritative, always-enforced
            byte-size ceiling on provider output regardless of what
            value (if any) is configured here.
        temperature: Optional sampling temperature, constrained to
            ``[MIN_TEMPERATURE, MAX_TEMPERATURE]`` when present. ``None``
            means "use the vendor's own default," not "unconstrained."
    """

    provider: str
    model: str
    api_key_env_var: str
    timeout_seconds: float
    endpoint: Optional[str] = None
    max_output_tokens: Optional[int] = None
    temperature: Optional[float] = None
    #: Phase 9: offer the Agent the reserved, non-dispatchable
    #: ``report_findings`` channel. Off by default, so requests are
    #: unchanged unless a composition root enables it.
    findings_channel: bool = False
    #: Phase 14: recorded in every agent turn record (as ``config_version``).
    provider_config_version: str = PROVIDER_CONFIG_VERSION

    @property
    def effective_endpoint(self) -> str:
        """The endpoint requests go to: explicit, never implicit (T-59)."""
        return self.endpoint if self.endpoint is not None else DEFAULT_ANTHROPIC_ENDPOINT

    def __post_init__(self) -> None:
        for field_name in ("provider", "model", "api_key_env_var", "provider_config_version"):
            value = getattr(self, field_name)
            if not isinstance(value, str) or not value:
                raise ValueError(f"ProviderConfig.{field_name} must be a non-empty string")

        if isinstance(self.timeout_seconds, bool) or not isinstance(self.timeout_seconds, (int, float)):
            raise ValueError("ProviderConfig.timeout_seconds must be a positive, finite number")
        if not math.isfinite(self.timeout_seconds) or self.timeout_seconds <= 0:
            raise ValueError("ProviderConfig.timeout_seconds must be a positive, finite number")

        if self.endpoint is not None:
            if not isinstance(self.endpoint, str) or not self.endpoint:
                raise ValueError("ProviderConfig.endpoint must be a non-empty string if present")
            # Deliberately minimal — a scheme check only, not a full URL
            # grammar/RFC validation (Phase 5.6 design report: "do not
            # over-engineer URL validation"). Phase 14 (T-59): https only;
            # a plaintext endpoint would send the API key in cleartext.
            if not self.endpoint.startswith("https://") or len(self.endpoint) == len("https://"):
                raise ValueError("ProviderConfig.endpoint must start with 'https://' if present")
            if any(ch.isspace() or ch == "@" for ch in self.endpoint):
                raise ValueError("ProviderConfig.endpoint must not contain whitespace or userinfo")

        if self.max_output_tokens is not None:
            if (
                isinstance(self.max_output_tokens, bool)
                or not isinstance(self.max_output_tokens, int)
                or self.max_output_tokens <= 0
            ):
                raise ValueError("ProviderConfig.max_output_tokens must be a positive integer if present")

        if not isinstance(self.findings_channel, bool):
            raise ValueError("ProviderConfig.findings_channel must be a bool")

        if self.temperature is not None:
            if isinstance(self.temperature, bool) or not isinstance(self.temperature, (int, float)):
                raise ValueError("ProviderConfig.temperature must be a number if present")
            if not (MIN_TEMPERATURE <= self.temperature <= MAX_TEMPERATURE):
                raise ValueError(
                    f"ProviderConfig.temperature must be between {MIN_TEMPERATURE} and "
                    f"{MAX_TEMPERATURE} if present"
                )
