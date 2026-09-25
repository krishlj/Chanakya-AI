"""Reserved capability-parameter names — docs/TARGET-AWARE-AGENT-CONTEXT.md
§15 (Phase 5.7.5, finding F-4).

``target_ref`` is owned by the Chanakya Runtime: it is the
``ToolRequest.target_ref`` contract field (docs/CONTRACTS.md §3) through
which the Agent *proposes* which investigation target an action applies to.
A provider presents it to the model as a top-level tool-call argument and
splits it back out of the model's input before building the raw
``tool_request``; ToolRequestIntake and the Policy Gateway then validate and
authorize it. No capability may therefore declare its own parameter of that
name — doing so would either be shadowed by the Runtime's definition or
introduce a second, Gateway-unchecked "target" selector inside
``parameters``.

Provider-neutral and authority-free: this module only names the reserved
field and finds declarations of it in a JSON-Schema-like mapping. It makes
no authorization decision and imports nothing from ``chanakya.policy``,
``chanakya.runtime``, ``chanakya.providers``, or ``chanakya.registry``.

Nested-schema decision: the name is reserved **anywhere** in a capability's
``parameters_schema`` — top-level or nested (``properties`` of nested
objects, ``items``, combinators, definitions) — not only at the top level.
Top-level is where the mechanical collision with the provider's extraction
happens; nested declarations are rejected too because they would give the
model a second field *named* like the authoritative target selector but
never scope-checked by the Gateway (which reads only
``ToolRequest.target_ref``). Fail closed; nothing is renamed, removed, or
overridden.
"""
from __future__ import annotations

from typing import Any, Iterator, List, Mapping

#: The Runtime-reserved parameter name. Must equal the ``ToolRequest``
#: contract field name (asserted in tests).
RESERVED_TARGET_PARAMETER = "target_ref"

#: All names no capability ``parameters_schema`` may declare.
RESERVED_PARAMETER_NAMES = frozenset({RESERVED_TARGET_PARAMETER})

#: Phase 9: name of the Runtime-reserved, non-dispatchable channel through
#: which the Agent reports Findings when it concludes. It is not a
#: capability: a provider maps it to a conclude turn, so it never reaches
#: Intake, the Policy Gateway, dispatch or a ToolExecutor.
RESERVED_FINDING_TOOL = "report_findings"

#: Names no capability may be registered under (compared case-insensitively).
RESERVED_CAPABILITY_NAMES = frozenset({RESERVED_FINDING_TOOL})


def is_reserved_capability_name(name: Any) -> bool:
    """True if ``name`` equals a reserved capability name, ignoring case."""
    return isinstance(name, str) and name.casefold() in {n.casefold() for n in RESERVED_CAPABILITY_NAMES}


def _walk(node: Any, path: str) -> Iterator[str]:
    if isinstance(node, Mapping):
        properties = node.get("properties")
        if isinstance(properties, Mapping):
            for name in properties:
                if name in RESERVED_PARAMETER_NAMES:
                    yield f"{path}.properties.{name}"
        required = node.get("required")
        if isinstance(required, (list, tuple)):
            for name in required:
                if name in RESERVED_PARAMETER_NAMES:
                    yield f"{path}.required[{name}]"
        for key, value in node.items():
            yield from _walk(value, f"{path}.{key}")
    elif isinstance(node, (list, tuple)):
        for index, value in enumerate(node):
            yield from _walk(value, f"{path}[{index}]")


def find_reserved_parameter_declarations(schema: Any) -> List[str]:
    """Returns the schema paths (e.g. ``$.properties.target_ref``,
    ``$.required[target_ref]``, ``$.properties.filter.properties.target_ref``)
    at which a reserved name is declared as a property or listed as
    required, anywhere in ``schema``. Empty list means no reservation
    conflict. Pure; never mutates ``schema``."""
    return sorted(set(_walk(schema, "$")))


#: Phase 5.7.7 F-9 — the only keywords a capability's ROOT
#: ``parameters_schema`` may use. ``target_ref`` is presented as a member of
#: the root tool-input object, and JSON Schema applies subschemas to that
#: object only through the root schema and its in-place applicators
#: (``allOf``/``anyOf``/``oneOf``/``not``/``if``/``then``/``else``/``$ref``/
#: ``dependentSchemas``); no keyword reaches upward from a nested location.
#: Keywords such as ``patternProperties``, ``unevaluatedProperties``,
#: ``const``/``enum`` on the object, ``propertyNames`` or ``maxProperties``
#: could otherwise constrain, force, or block ``target_ref`` without ever
#: *naming* it as a property. ``additionalProperties`` is safe here: a
#: sibling ``properties.target_ref`` puts the reserved member outside its
#: reach. Nested property subschemas are not restricted by this list (they
#: apply only to their own values); the name scan above still covers them.
ROOT_SCHEMA_ALLOWED_KEYWORDS = frozenset(
    {"type", "properties", "required", "additionalProperties", "description", "title"}
)


def find_root_schema_violations(schema: Any) -> List[str]:
    """Returns why ``schema`` is not an admissible ROOT capability
    ``parameters_schema`` under ``ROOT_SCHEMA_ALLOWED_KEYWORDS``: each
    disallowed root keyword as ``$.<keyword>``, ``$.type`` if ``type`` is
    present and not exactly ``"object"``, or ``$`` if ``schema`` is not a
    mapping at all. Empty list means admissible. Root level only — this
    complements, and never replaces, ``find_reserved_parameter_declarations``.
    Pure; never mutates ``schema``."""
    if not isinstance(schema, Mapping):
        return ["$"]
    violations = sorted(f"$.{key}" for key in (str(k) for k in schema) if key not in ROOT_SCHEMA_ALLOWED_KEYWORDS)
    if "type" in schema and schema["type"] != "object":
        violations.append("$.type")
    return violations


__all__ = [
    "RESERVED_TARGET_PARAMETER",
    "RESERVED_PARAMETER_NAMES",
    "RESERVED_FINDING_TOOL",
    "RESERVED_CAPABILITY_NAMES",
    "is_reserved_capability_name",
    "ROOT_SCHEMA_ALLOWED_KEYWORDS",
    "find_reserved_parameter_declarations",
    "find_root_schema_violations",
]
