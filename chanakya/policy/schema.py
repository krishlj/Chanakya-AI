"""A minimal, deliberately small JSON-Schema-like validator.

Covers only what the ``parameters_schema``/``output_schema`` examples in
docs/TOOL-REGISTRY.md actually use: ``type``, ``properties``, ``required``,
``additionalProperties``, ``items``, ``enum``, ``minimum``. This is NOT a
general-purpose JSON Schema implementation — see the Phase 2 implementation
notes' "known limitations." No external dependency is introduced on
purpose, to keep this phase's footprint minimal (SR-22/T-23 — smaller
dependency surface).
"""
from __future__ import annotations

from typing import Any, Mapping


class SchemaValidationError(ValueError):
    """Raised when a value does not conform to a capability's declared schema."""


_TYPE_MAP: Mapping[str, Any] = {
    "object": dict,
    "string": str,
    "integer": int,
    "number": (int, float),
    "boolean": bool,
    "array": list,
}


def validate(schema: Mapping[str, Any], value: Any, *, path: str = "$") -> None:
    if not schema:
        return

    expected_type = schema.get("type")
    if expected_type is not None:
        py_type = _TYPE_MAP.get(expected_type)
        if py_type is None:
            raise SchemaValidationError(f"{path}: unsupported schema type {expected_type!r}")
        # bool is a subclass of int in Python — reject it explicitly for "integer".
        if expected_type == "integer" and isinstance(value, bool):
            raise SchemaValidationError(f"{path}: expected integer, got boolean")
        if not isinstance(value, py_type):
            raise SchemaValidationError(f"{path}: expected {expected_type}, got {type(value).__name__}")

    if "enum" in schema and value not in schema["enum"]:
        raise SchemaValidationError(f"{path}: value {value!r} not in enum {schema['enum']!r}")

    if expected_type == "integer" and "minimum" in schema and value < schema["minimum"]:
        raise SchemaValidationError(f"{path}: {value} is below minimum {schema['minimum']}")

    if expected_type == "object" and isinstance(value, Mapping):
        properties = schema.get("properties", {})
        for key in schema.get("required", []):
            if key not in value:
                raise SchemaValidationError(f"{path}: missing required property {key!r}")
        if schema.get("additionalProperties") is False:
            extra = set(value.keys()) - set(properties.keys())
            if extra:
                raise SchemaValidationError(f"{path}: unexpected propert{'y' if len(extra) == 1 else 'ies'} {sorted(extra)!r}")
        for key, subschema in properties.items():
            if key in value:
                validate(subschema, value[key], path=f"{path}.{key}")

    if expected_type == "array" and isinstance(value, list):
        item_schema = schema.get("items")
        if item_schema:
            for index, item in enumerate(value):
                validate(item_schema, item, path=f"{path}[{index}]")
