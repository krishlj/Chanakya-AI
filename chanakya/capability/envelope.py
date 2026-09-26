"""Capability execution envelope — Phase 11 (docs/TOOL-REGISTRY.md §8, §13-14).

A ``CapabilityEnvelope`` is the immutable, provider-neutral snapshot of the
execution constraints a Registry entry declares for one capability:

- ``output_schema``: the shape a successful output must match;
- ``max_output_bytes``: the ceiling on the output's canonical JSON size;
- ``timeout_seconds``: the capability's declared step timeout.

It carries no authority. The Policy Gateway builds exactly one per
decision, with ``envelope_from_registry_entry``, from the same
``RegistryEntry`` it used to decide, and attaches it to the
``PolicyDecision``. The Runtime copies it into the ``DispatchInstruction``
(tightening the timeout to its own ceiling, never loosening it) and the
Tool Layer enforces it on the handler's output with ``check_output``. The
model, the target, the handler and ``ToolRequest.parameters`` have no way
to supply or change it.

``resource_limits.max_cpu_seconds``, ``max_memory_mb`` and
``max_concurrent_invocations`` are NOT part of the envelope: enforcing
them honestly needs process isolation, which Chanakya does not have. They
stay declarative Registry metadata.

Validation fails closed. The schema must use only constructs
``chanakya.capability.schema`` supports; it is deep-copied into read-only
mappings and tuples so nothing holding the envelope can change it. Limits
must be positive integers (booleans are refused).

``check_output`` returns a fixed reason code, never the offending value:
serialization is checked first (JSON types only, string keys, finite
numbers, bounded depth), then the canonical size (``chanakya.evidence.
hashing.canonical_bytes``, the bytes Evidence hashes), then the schema.
Nothing is truncated, repaired, coerced or stripped.
"""
from __future__ import annotations

import math
from dataclasses import dataclass
from types import MappingProxyType
from typing import Any, Dict, Mapping, Optional

from chanakya.evidence.hashing import canonical_bytes

from .reserved import is_reserved_capability_name
from .schema import (
    MAX_SCHEMA_DEPTH,
    SCHEMA_REASON_CODES,
    SchemaValidationError,
    find_unsupported_schema_constructs,
    validate,
)

#: Error-message prefix of every envelope violation ToolResult. The Runtime
#: uses ``is_envelope_violation`` to recognize them (they are deterministic
#: and are not retried).
ENVELOPE_VIOLATION_PREFIX = "capability_envelope_violation"

ENVELOPE_MISSING = "ENVELOPE_MISSING"
ENVELOPE_MISMATCH = "ENVELOPE_MISMATCH"
OUTPUT_NOT_A_MAPPING = "OUTPUT_NOT_A_MAPPING"
OUTPUT_NOT_SERIALIZABLE = "OUTPUT_NOT_SERIALIZABLE"
OUTPUT_TOO_LARGE = "OUTPUT_TOO_LARGE"

ENVELOPE_REASON_CODES = frozenset(
    {ENVELOPE_MISSING, ENVELOPE_MISMATCH, OUTPUT_NOT_A_MAPPING, OUTPUT_NOT_SERIALIZABLE, OUTPUT_TOO_LARGE}
)
_ALL_REASON_CODES = ENVELOPE_REASON_CODES | SCHEMA_REASON_CODES

_DICT_KEYS = frozenset({"capability", "output_schema", "max_output_bytes", "timeout_seconds"})


class CapabilityEnvelopeError(ValueError):
    """An envelope cannot be built. Never repaired."""


def _freeze(value: Any) -> Any:
    if isinstance(value, Mapping):
        return MappingProxyType({key: _freeze(item) for key, item in value.items()})
    if isinstance(value, (list, tuple)):
        return tuple(_freeze(item) for item in value)
    return value


def _thaw(value: Any) -> Any:
    if isinstance(value, Mapping):
        return {key: _thaw(item) for key, item in value.items()}
    if isinstance(value, tuple):
        return [_thaw(item) for item in value]
    return value


def _positive_int(field_name: str, value: Any) -> None:
    if type(value) is not int or value <= 0:
        raise CapabilityEnvelopeError(f"CapabilityEnvelope.{field_name} must be a positive integer")


@dataclass(frozen=True)
class CapabilityEnvelope:
    capability: str
    output_schema: Mapping[str, Any]
    max_output_bytes: int
    timeout_seconds: int

    def __post_init__(self) -> None:
        if type(self.capability) is not str or not self.capability:
            raise CapabilityEnvelopeError("CapabilityEnvelope.capability must be a non-empty string")
        if is_reserved_capability_name(self.capability):
            raise CapabilityEnvelopeError("CapabilityEnvelope.capability is a Runtime-reserved name")
        if not isinstance(self.output_schema, Mapping):
            raise CapabilityEnvelopeError("CapabilityEnvelope.output_schema must be a mapping")
        if find_unsupported_schema_constructs(self.output_schema):
            raise CapabilityEnvelopeError("CapabilityEnvelope.output_schema uses unsupported schema constructs")
        _positive_int("max_output_bytes", self.max_output_bytes)
        _positive_int("timeout_seconds", self.timeout_seconds)
        object.__setattr__(self, "output_schema", _freeze(self.output_schema))

    def to_dict(self) -> Dict[str, Any]:
        return {
            "capability": self.capability,
            "output_schema": _thaw(self.output_schema),
            "max_output_bytes": self.max_output_bytes,
            "timeout_seconds": self.timeout_seconds,
        }

    @staticmethod
    def from_dict(data: Any) -> "CapabilityEnvelope":
        if not isinstance(data, Mapping) or set(data) != _DICT_KEYS:
            raise CapabilityEnvelopeError("record does not have the CapabilityEnvelope shape")
        return CapabilityEnvelope(**dict(data))


def envelope_from_registry_entry(entry: Any) -> CapabilityEnvelope:
    """The single RegistryEntry → CapabilityEnvelope conversion. Only an
    enabled entry yields an envelope. Reads the entry's declared
    ``output_schema``, ``resource_limits.max_output_bytes`` and
    ``default_timeout_seconds``; nothing else is consulted."""
    status = getattr(getattr(entry, "status", None), "value", None)
    if status != "enabled":
        raise CapabilityEnvelopeError("only an enabled Registry entry has an execution envelope")
    return CapabilityEnvelope(
        capability=entry.capability,
        output_schema=entry.output_schema,
        max_output_bytes=entry.resource_limits.max_output_bytes,
        timeout_seconds=entry.default_timeout_seconds,
    )


def violation_message(code: str) -> str:
    """The fixed ``ToolResult.error_message`` for an envelope violation."""
    if code not in _ALL_REASON_CODES:
        raise ValueError("unknown envelope reason code")
    return f"{ENVELOPE_VIOLATION_PREFIX}: {code}"


def is_envelope_violation(error_message: Optional[str]) -> bool:
    """True for exactly the messages ``violation_message`` produces."""
    if not isinstance(error_message, str):
        return False
    prefix = f"{ENVELOPE_VIOLATION_PREFIX}: "
    if not error_message.startswith(prefix):
        return False
    return error_message[len(prefix):] in _ALL_REASON_CODES


def is_json_compatible(value: Any) -> bool:
    """Iterative strict-JSON check: dict/list/str/int/float/bool/None only,
    string keys, finite numbers, depth ≤ MAX_SCHEMA_DEPTH."""
    stack = [(value, 0)]
    while stack:
        item, depth = stack.pop()
        if depth > MAX_SCHEMA_DEPTH:
            return False
        if item is None or isinstance(item, (str, bool, int)):
            continue
        if isinstance(item, float):
            if not math.isfinite(item):
                return False
            continue
        if isinstance(item, Mapping):
            if not all(type(key) is str for key in item):
                return False
            stack.extend((child, depth + 1) for child in item.values())
            continue
        if isinstance(item, list):
            stack.extend((child, depth + 1) for child in item)
            continue
        return False
    return True


def check_output(envelope: CapabilityEnvelope, output: Any) -> Optional[str]:
    """``None`` if ``output`` satisfies ``envelope``, otherwise a fixed
    reason code. Never raises for a bad ``output``; never returns content."""
    if not isinstance(output, Mapping):
        return OUTPUT_NOT_A_MAPPING
    try:
        if not is_json_compatible(output):
            return OUTPUT_NOT_SERIALIZABLE
        size = len(canonical_bytes(output))
    except (TypeError, ValueError, RecursionError):
        return OUTPUT_NOT_SERIALIZABLE
    if size > envelope.max_output_bytes:
        return OUTPUT_TOO_LARGE
    try:
        validate(envelope.output_schema, output)
    except SchemaValidationError as exc:
        return exc.code
    except (TypeError, ValueError, RecursionError):
        return OUTPUT_NOT_SERIALIZABLE
    return None


__all__ = [
    "ENVELOPE_MISMATCH",
    "ENVELOPE_MISSING",
    "ENVELOPE_REASON_CODES",
    "ENVELOPE_VIOLATION_PREFIX",
    "OUTPUT_NOT_A_MAPPING",
    "OUTPUT_NOT_SERIALIZABLE",
    "OUTPUT_TOO_LARGE",
    "CapabilityEnvelope",
    "CapabilityEnvelopeError",
    "check_output",
    "envelope_from_registry_entry",
    "is_json_compatible",
    "is_envelope_violation",
    "violation_message",
]
