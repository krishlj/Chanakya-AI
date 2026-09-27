"""Phase 5.6.1 — Provider Configuration Contract.

Covers the 13 security requirements from the approved Phase 5.6.1
implementation task: no raw-secret storage, no environment-variable
reads, immutability, fail-closed validation, and no overlap with
`RuntimeExecutionLimits`'s governance fields.

Does not exercise any provider adapter, SDK, or network call — none
exist yet (Phase 5.6.2+).
"""
from __future__ import annotations

import dataclasses
import math

import pytest

from chanakya.providers import MAX_TEMPERATURE, MIN_TEMPERATURE, ProviderConfig
from chanakya.runtime.limits import RuntimeExecutionLimits


def _config(**overrides) -> ProviderConfig:
    fields = dict(
        provider="anthropic",
        model="claude-sonnet-5",
        api_key_env_var="ANTHROPIC_API_KEY",
        timeout_seconds=30.0,
    )
    fields.update(overrides)
    return ProviderConfig(**fields)


# ===========================================================================
# Construction — happy path
# ===========================================================================


def test_valid_config_constructs():
    config = _config()
    assert config.provider == "anthropic"
    assert config.model == "claude-sonnet-5"
    assert config.api_key_env_var == "ANTHROPIC_API_KEY"
    assert config.timeout_seconds == 30.0
    assert config.endpoint is None
    assert config.max_output_tokens is None
    assert config.temperature is None


def test_valid_config_with_all_optional_fields_constructs():
    config = _config(
        endpoint="https://api.anthropic.com",
        max_output_tokens=4096,
        temperature=0.7,
    )
    assert config.endpoint == "https://api.anthropic.com"
    assert config.max_output_tokens == 4096
    assert config.temperature == 0.7


# ===========================================================================
# 4/5. provider / model — required, non-empty
# ===========================================================================


def test_empty_provider_rejected():
    with pytest.raises(ValueError, match="provider"):
        _config(provider="")


def test_non_string_provider_rejected():
    with pytest.raises(ValueError, match="provider"):
        _config(provider=123)


def test_empty_model_rejected():
    with pytest.raises(ValueError, match="model"):
        _config(model="")


def test_non_string_model_rejected():
    with pytest.raises(ValueError, match="model"):
        _config(model=None)


# ===========================================================================
# 2/3. credential reference — accepted / rejected
# ===========================================================================


def test_credential_reference_is_accepted():
    config = _config(api_key_env_var="MY_VENDOR_API_KEY")
    assert config.api_key_env_var == "MY_VENDOR_API_KEY"


def test_empty_credential_reference_rejected():
    with pytest.raises(ValueError, match="api_key_env_var"):
        _config(api_key_env_var="")


def test_non_string_credential_reference_rejected():
    with pytest.raises(ValueError, match="api_key_env_var"):
        _config(api_key_env_var=None)


# ===========================================================================
# 1/11. raw credential is never an accepted field / never stored
# ===========================================================================


def test_raw_credential_field_is_not_accepted():
    """There is no ``api_key`` (or similarly-named raw-secret) field on
    ProviderConfig at all — passing one is a TypeError (unexpected
    keyword argument), not a value that gets silently stored."""
    with pytest.raises(TypeError):
        ProviderConfig(
            provider="anthropic",
            model="claude-sonnet-5",
            api_key_env_var="ANTHROPIC_API_KEY",
            timeout_seconds=30.0,
            api_key="sk-this-should-not-be-a-field",  # type: ignore[call-arg]
        )


def test_config_declares_no_raw_secret_field():
    field_names = {f.name for f in dataclasses.fields(ProviderConfig)}
    for forbidden in ("api_key", "apikey", "secret", "token", "password", "credential"):
        assert forbidden not in field_names


def test_config_has_no_method_that_returns_a_secret():
    forbidden_names = ("get_api_key", "resolve_secret", "get_secret", "resolve_credential", "api_key")
    config = _config()
    for name in forbidden_names:
        assert not hasattr(config, name)


# ===========================================================================
# 6. timeout_seconds — positive, finite
# ===========================================================================


def test_zero_timeout_rejected():
    with pytest.raises(ValueError, match="timeout_seconds"):
        _config(timeout_seconds=0)


def test_negative_timeout_rejected():
    with pytest.raises(ValueError, match="timeout_seconds"):
        _config(timeout_seconds=-1.0)


def test_infinite_timeout_rejected():
    with pytest.raises(ValueError, match="timeout_seconds"):
        _config(timeout_seconds=math.inf)


def test_nan_timeout_rejected():
    with pytest.raises(ValueError, match="timeout_seconds"):
        _config(timeout_seconds=math.nan)


def test_non_numeric_timeout_rejected():
    with pytest.raises(ValueError, match="timeout_seconds"):
        _config(timeout_seconds="30")


def test_boolean_timeout_rejected():
    with pytest.raises(ValueError, match="timeout_seconds"):
        _config(timeout_seconds=True)


def test_positive_integer_timeout_accepted():
    config = _config(timeout_seconds=15)
    assert config.timeout_seconds == 15


# ===========================================================================
# endpoint — optional, minimally validated
# ===========================================================================


def test_endpoint_defaults_to_none():
    assert _config().endpoint is None


def test_empty_endpoint_rejected():
    with pytest.raises(ValueError, match="endpoint"):
        _config(endpoint="")


def test_endpoint_without_scheme_rejected():
    with pytest.raises(ValueError, match="endpoint"):
        _config(endpoint="api.anthropic.com")


def test_valid_https_endpoint_accepted():
    config = _config(endpoint="https://api.anthropic.com")
    assert config.endpoint == "https://api.anthropic.com"


def test_http_endpoint_rejected():
    """Phase 14 (T-59): plaintext endpoints would carry the API key in
    cleartext; only https is accepted."""
    with pytest.raises(ValueError, match="https"):
        _config(endpoint="http://localhost:8080")


def test_endpoint_none_means_the_explicit_trusted_default():
    from chanakya.providers.config import DEFAULT_ANTHROPIC_ENDPOINT

    assert _config().effective_endpoint == DEFAULT_ANTHROPIC_ENDPOINT == "https://api.anthropic.com"
    assert _config(endpoint="https://gateway.example.test").effective_endpoint == "https://gateway.example.test"


# ===========================================================================
# 7. max_output_tokens — optional, positive integer if present
# ===========================================================================


def test_max_output_tokens_defaults_to_none():
    assert _config().max_output_tokens is None


def test_zero_max_output_tokens_rejected():
    with pytest.raises(ValueError, match="max_output_tokens"):
        _config(max_output_tokens=0)


def test_negative_max_output_tokens_rejected():
    with pytest.raises(ValueError, match="max_output_tokens"):
        _config(max_output_tokens=-100)


def test_non_integer_max_output_tokens_rejected():
    with pytest.raises(ValueError, match="max_output_tokens"):
        _config(max_output_tokens=1024.5)


def test_boolean_max_output_tokens_rejected():
    with pytest.raises(ValueError, match="max_output_tokens"):
        _config(max_output_tokens=True)


def test_positive_max_output_tokens_accepted():
    config = _config(max_output_tokens=4096)
    assert config.max_output_tokens == 4096


# ===========================================================================
# 8. temperature — optional, within the documented range if present
# ===========================================================================


def test_temperature_defaults_to_none():
    assert _config().temperature is None


def test_temperature_below_range_rejected():
    with pytest.raises(ValueError, match="temperature"):
        _config(temperature=MIN_TEMPERATURE - 0.01)


def test_temperature_above_range_rejected():
    with pytest.raises(ValueError, match="temperature"):
        _config(temperature=MAX_TEMPERATURE + 0.01)


def test_temperature_boundary_values_accepted():
    assert _config(temperature=MIN_TEMPERATURE).temperature == MIN_TEMPERATURE
    assert _config(temperature=MAX_TEMPERATURE).temperature == MAX_TEMPERATURE


def test_non_numeric_temperature_rejected():
    with pytest.raises(ValueError, match="temperature"):
        _config(temperature="hot")


def test_boolean_temperature_rejected():
    with pytest.raises(ValueError, match="temperature"):
        _config(temperature=True)


def test_documented_temperature_range_is_zero_to_one():
    """Pins the documented range (module docstring / config.py comments)
    so a silent range change would fail this test rather than only the
    prose going stale."""
    assert MIN_TEMPERATURE == 0.0
    assert MAX_TEMPERATURE == 1.0


# ===========================================================================
# 9. Immutability
# ===========================================================================


def test_config_is_immutable():
    config = _config()
    with pytest.raises(dataclasses.FrozenInstanceError):
        config.model = "a-different-model"  # type: ignore[misc]


# ===========================================================================
# 10. No environment-variable access
# ===========================================================================


def test_config_does_not_read_environment_variables(monkeypatch):
    """Constructing with an env-var NAME that does not exist in the
    environment at all must not raise or otherwise behave differently —
    proving the value is stored purely as an opaque reference, never
    resolved (os.environ is never consulted by this class)."""
    monkeypatch.delenv("DEFINITELY_UNSET_PROVIDER_KEY", raising=False)
    config = _config(api_key_env_var="DEFINITELY_UNSET_PROVIDER_KEY")
    assert config.api_key_env_var == "DEFINITELY_UNSET_PROVIDER_KEY"


def test_config_module_does_not_import_os():
    """Structural: chanakya/providers/config.py has no `import os` (or
    `from os import ...`) statement at all — checked via the AST, not a
    raw substring match, since the module's own docstring legitimately
    *discusses* os.environ (to say it is never read). No such import
    existing means there is no code path by which the module could read
    os.environ even by accident."""
    import ast
    import inspect

    import chanakya.providers.config as config_module

    tree = ast.parse(inspect.getsource(config_module))
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            assert not any(alias.name == "os" for alias in node.names)
        if isinstance(node, ast.ImportFrom):
            assert node.module != "os"


# ===========================================================================
# 12. No overlap with RuntimeExecutionLimits governance fields
# ===========================================================================


def test_config_contains_no_runtime_execution_limits_fields():
    provider_config_fields = {f.name for f in dataclasses.fields(ProviderConfig)}
    runtime_limit_fields = {f.name for f in dataclasses.fields(RuntimeExecutionLimits)}
    assert provider_config_fields.isdisjoint(runtime_limit_fields)


def test_config_has_no_governance_shaped_fields():
    provider_config_fields = {f.name for f in dataclasses.fields(ProviderConfig)}
    forbidden_substrings = (
        "max_context_bytes",
        "max_provider_output_bytes",
        "max_steps",
        "max_tool_calls",
        "max_retries",
        "max_investigation_duration",
        "max_concurrent",
        "target_ref",
        "target_scope",
        "capability",
        "approval",
        "policy",
    )
    for field_name in provider_config_fields:
        for forbidden in forbidden_substrings:
            assert forbidden not in field_name


# ===========================================================================
# Full regression is exercised by the outer test suite run, not here.
# ===========================================================================
