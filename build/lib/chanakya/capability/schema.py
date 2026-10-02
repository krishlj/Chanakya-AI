"""A minimal, dependency-free JSON-Schema-like validator — Phase 11.

Moved here from ``chanakya.policy.schema`` (which re-exports it unchanged
for the Policy Gateway) so the Tool Layer can validate capability output
without importing ``chanakya.policy``. Provider-neutral and authority-free:
it answers "does this value match this schema", nothing more.

Supported keywords: ``type`` (one name, or a list of names), ``properties``,
``required``, ``additionalProperties`` (boolean only), ``items``, ``enum``,
``minimum``, plus the annotations ``description`` and ``title``. Type names:
``object``, ``string``, ``integer``, ``number``, ``boolean``, ``array``,
``null``. This is NOT a general-purpose JSON Schema implementation.

``validate`` ignores keywords it does not know, exactly as the Phase 2
validator did, so parameter validation behaves as before. Capability
*output* schemas are stricter: ``find_unsupported_schema_constructs``
rejects any unknown keyword or malformed construct, and a
``chanakya.capability.envelope.CapabilityEnvelope`` cannot be built from
a schema that has one. ``find_open_schema_violations`` implements the
Phase 11 D-2 rule for production output schemas: every object is closed
and every array declares its items.

Error messages never contain the rejected value, and never contain an
object key taken from the value. They carry a fixed reason code and a
bounded path built only from schema property names and array indices.
``integer`` and ``number`` reject booleans, and ``enum`` compares type as
well as value, so ``True`` never matches ``1``.
"""
from __future__ import annotations

from typing import Any, List, Mapping, Sequence

SCHEMA_TYPE_MISMATCH = "SCHEMA_TYPE_MISMATCH"
SCHEMA_REQUIRED_FIELD_MISSING = "SCHEMA_REQUIRED_FIELD_MISSING"
SCHEMA_UNEXPECTED_FIELD = "SCHEMA_UNEXPECTED_FIELD"
SCHEMA_ENUM_INVALID = "SCHEMA_ENUM_INVALID"
SCHEMA_MINIMUM_VIOLATION = "SCHEMA_MINIMUM_VIOLATION"
SCHEMA_UNSUPPORTED = "SCHEMA_UNSUPPORTED"

SCHEMA_REASON_CODES = frozenset(
    {
        SCHEMA_TYPE_MISMATCH,
        SCHEMA_REQUIRED_FIELD_MISSING,
        SCHEMA_UNEXPECTED_FIELD,
        SCHEMA_ENUM_INVALID,
        SCHEMA_MINIMUM_VIOLATION,
        SCHEMA_UNSUPPORTED,
    }
)

#: Keywords an output schema may use. Anything else is unsupported.
SUPPORTED_SCHEMA_KEYWORDS = frozenset(
    {"type", "properties", "required", "additionalProperties", "items", "enum", "minimum", "description", "title"}
)

#: Deepest nesting a schema (or a validated value) may reach.
MAX_SCHEMA_DEPTH = 32
_MAX_PATH_LENGTH = 200

_TYPE_MAP: Mapping[str, Any] = {
    "object": Mapping,
    "string": str,
    "integer": int,
    "number": (int, float),
    "boolean": bool,
    "array": list,
    "null": type(None),
}


class SchemaValidationError(ValueError):
    """A value does not conform to a schema. ``code`` is one of
    ``SCHEMA_REASON_CODES``; the message is ``"<code> at <path>"``."""

    def __init__(self, code: str, path: str) -> None:
        self.code = code
        self.path = path if len(path) <= _MAX_PATH_LENGTH else path[:_MAX_PATH_LENGTH] + "..."
        super().__init__(f"{code} at {self.path}")


def _type_names(schema: Mapping[str, Any], path: str) -> Sequence[str]:
    declared = schema.get("type")
    names = [declared] if isinstance(declared, str) else declared
    if not isinstance(names, (list, tuple)) or not names or any(n not in _TYPE_MAP for n in names):
        raise SchemaValidationError(SCHEMA_UNSUPPORTED, path)
    return names


def _matches_type(name: str, value: Any) -> bool:
    if name in ("integer", "number") and isinstance(value, bool):
        return False
    return isinstance(value, _TYPE_MAP[name])


def _in_enum(value: Any, allowed: Any) -> bool:
    return any(type(value) is type(option) and value == option for option in allowed)


def validate(schema: Mapping[str, Any], value: Any, *, path: str = "$", _depth: int = 0) -> None:
    """Raises ``SchemaValidationError`` if ``value`` does not match ``schema``."""
    if _depth > MAX_SCHEMA_DEPTH:
        raise SchemaValidationError(SCHEMA_UNSUPPORTED, path)
    if not schema:
        return

    names = _type_names(schema, path) if schema.get("type") is not None else ()
    if names and not any(_matches_type(name, value) for name in names):
        raise SchemaValidationError(SCHEMA_TYPE_MISMATCH, path)

    if "enum" in schema and not _in_enum(value, schema["enum"]):
        raise SchemaValidationError(SCHEMA_ENUM_INVALID, path)

    if "minimum" in schema and isinstance(value, (int, float)) and not isinstance(value, bool):
        if value < schema["minimum"]:
            raise SchemaValidationError(SCHEMA_MINIMUM_VIOLATION, path)

    if "object" in names and isinstance(value, Mapping):
        properties = schema.get("properties", {})
        for key in schema.get("required", []):
            if key not in value:
                raise SchemaValidationError(SCHEMA_REQUIRED_FIELD_MISSING, f"{path}.{key}")
        if schema.get("additionalProperties") is False:
            # Never name the unexpected key: it comes from the value.
            if any(key not in properties for key in value):
                raise SchemaValidationError(SCHEMA_UNEXPECTED_FIELD, path)
        for key, subschema in properties.items():
            if key in value:
                validate(subschema, value[key], path=f"{path}.{key}", _depth=_depth + 1)

    if "array" in names and isinstance(value, list):
        item_schema = schema.get("items")
        if item_schema:
            for index, item in enumerate(value):
                validate(item_schema, item, path=f"{path}[{index}]", _depth=_depth + 1)


def find_unsupported_schema_constructs(schema: Any) -> List[str]:
    """Paths at which ``schema`` uses a keyword or construct this validator
    does not support. Empty means fully supported. Pure; never raises."""
    problems: List[str] = []
    _walk_supported(schema, "$", 0, problems)
    return problems


def _walk_supported(schema: Any, path: str, depth: int, problems: List[str]) -> None:
    if depth > MAX_SCHEMA_DEPTH or not isinstance(schema, Mapping):
        problems.append(path)
        return
    for key in schema:
        if key not in SUPPORTED_SCHEMA_KEYWORDS:
            problems.append(f"{path}.{key}" if isinstance(key, str) else path)
    if "type" in schema:
        declared = schema["type"]
        names = [declared] if isinstance(declared, str) else declared
        if not isinstance(names, (list, tuple)) or not names or any(
            not isinstance(n, str) or n not in _TYPE_MAP for n in names
        ):
            problems.append(f"{path}.type")
    if "additionalProperties" in schema and not isinstance(schema["additionalProperties"], bool):
        problems.append(f"{path}.additionalProperties")
    if "required" in schema:
        required = schema["required"]
        if not isinstance(required, (list, tuple)) or not all(isinstance(k, str) for k in required):
            problems.append(f"{path}.required")
    if "enum" in schema and (not isinstance(schema["enum"], (list, tuple)) or not schema["enum"]):
        problems.append(f"{path}.enum")
    if "minimum" in schema and (isinstance(schema["minimum"], bool) or not isinstance(schema["minimum"], (int, float))):
        problems.append(f"{path}.minimum")
    for key in ("description", "title"):
        if key in schema and not isinstance(schema[key], str):
            problems.append(f"{path}.{key}")
    if "properties" in schema:
        properties = schema["properties"]
        if not isinstance(properties, Mapping):
            problems.append(f"{path}.properties")
        else:
            for name, subschema in properties.items():
                if not isinstance(name, str):
                    problems.append(f"{path}.properties")
                    continue
                _walk_supported(subschema, f"{path}.{name}", depth + 1, problems)
    if "items" in schema:
        _walk_supported(schema["items"], f"{path}[]", depth + 1, problems)


def find_open_schema_violations(schema: Any) -> List[str]:
    """Phase 11 D-2: paths at which an output schema is not closed.

    The root must be ``type: object``. Every object subschema must declare
    ``properties``, a ``required`` list naming only declared properties,
    and ``additionalProperties: false``. Every array subschema must declare
    ``items``. Unsupported constructs are reported too. Empty means
    closed."""
    problems = [f"unsupported:{p}" for p in find_unsupported_schema_constructs(schema)]
    if problems:
        return problems
    if schema.get("type") != "object":
        problems.append("$.type")
    _walk_closed(schema, "$", problems)
    return problems


def _walk_closed(schema: Mapping[str, Any], path: str, problems: List[str]) -> None:
    declared = schema.get("type")
    names = [declared] if isinstance(declared, str) else list(declared or ())
    if not names:
        problems.append(f"{path}.type")
    if "object" in names:
        properties = schema.get("properties")
        if not isinstance(properties, Mapping):
            problems.append(f"{path}.properties")
            properties = {}
        if schema.get("additionalProperties") is not False:
            problems.append(f"{path}.additionalProperties")
        required = schema.get("required")
        if not isinstance(required, (list, tuple)) or any(k not in properties for k in required):
            problems.append(f"{path}.required")
        for name, subschema in properties.items():
            _walk_closed(subschema, f"{path}.{name}", problems)
    if "array" in names:
        items = schema.get("items")
        if not isinstance(items, Mapping) or not items:
            problems.append(f"{path}.items")
        else:
            _walk_closed(items, f"{path}[]", problems)


__all__ = [
    "MAX_SCHEMA_DEPTH",
    "SCHEMA_ENUM_INVALID",
    "SCHEMA_MINIMUM_VIOLATION",
    "SCHEMA_REASON_CODES",
    "SCHEMA_REQUIRED_FIELD_MISSING",
    "SCHEMA_TYPE_MISMATCH",
    "SCHEMA_UNEXPECTED_FIELD",
    "SCHEMA_UNSUPPORTED",
    "SUPPORTED_SCHEMA_KEYWORDS",
    "SchemaValidationError",
    "find_open_schema_violations",
    "find_unsupported_schema_constructs",
    "validate",
]
