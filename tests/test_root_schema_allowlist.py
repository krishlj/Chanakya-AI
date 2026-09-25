"""Phase 5.7.7 F-9 — root capability ``parameters_schema`` allowlist
(docs/TARGET-AWARE-AGENT-CONTEXT.md, "As implemented in 5.7.7").

The recursive ``target_ref`` name scan only finds a *declaration* of the
reserved name. Root-level applicators and object assertions can constrain,
force, or block ``target_ref`` without naming it (``patternProperties``,
``allOf`` + ``additionalProperties``, ``$ref``, object ``const``/``enum``,
``propertyNames``, ...). ``SecurityToolRegistry.register`` therefore also
limits the ROOT schema to ``ROOT_SCHEMA_ALLOWED_KEYWORDS``. Nested property
subschemas are unrestricted apart from the unchanged name scan.

Provider behavior is deliberately unchanged: a caller-supplied catalog that
bypasses the Registry is not checked here (F-8 residual).
"""
from __future__ import annotations

import ast
import copy
import dataclasses
from pathlib import Path
from typing import Any

import pytest

from chanakya.capability.reserved import (
    ROOT_SCHEMA_ALLOWED_KEYWORDS,
    find_reserved_parameter_declarations,
    find_root_schema_violations,
)
from chanakya.providers import mapping
from chanakya.registry.bootstrap import make_observe_local_host_environment_entry
from chanakya.registry.exceptions import RegistryAdmissionError
from chanakya.registry.models import Status
from chanakya.registry.registry import SecurityToolRegistry

from test_target_ref_reservation import entry_with_schema, obj

_REPO_ROOT = Path(__file__).resolve().parent.parent
_X = {"const": "target-X"}


def assert_rejected(schema: Any, match: str = "allowlist") -> None:
    registry = SecurityToolRegistry()
    with pytest.raises(RegistryAdmissionError, match=match):
        registry.register(entry_with_schema(schema))
    assert registry.get("probe_capability") is None
    assert registry.get_enabled("probe_capability") is None
    assert registry.catalog_view() == []


def assert_admitted(schema: Any) -> None:
    registry = SecurityToolRegistry([entry_with_schema(schema)])
    assert registry.get_enabled("probe_capability") is not None


# ===========================================================================
# The allowlist itself
# ===========================================================================


def test_allowlist_is_exactly_the_approved_keywords():
    assert ROOT_SCHEMA_ALLOWED_KEYWORDS == frozenset(
        {"type", "properties", "required", "additionalProperties", "description", "title"}
    )


def test_checker_reports_paths_and_is_pure():
    schema = {"type": "string", "allOf": [], "patternProperties": {}, "properties": {}}
    before = copy.deepcopy(schema)
    assert find_root_schema_violations(schema) == ["$.allOf", "$.patternProperties", "$.type"]
    assert schema == before
    assert find_root_schema_violations(obj(port={"type": "integer"})) == []
    assert find_root_schema_violations(None) == ["$"]
    assert find_root_schema_violations(["type"]) == ["$"]


# ===========================================================================
# Every root keyword outside the allowlist is refused
# ===========================================================================


_DISALLOWED_ROOT = {
    "patternProperties": {"^x-": {"type": "string"}},
    "unevaluatedProperties": False,
    "dependentSchemas": {"port": {"required": ["host"]}},
    "dependentRequired": {"port": ["host"]},
    "dependencies": {"port": ["host"]},
    "allOf": [{"required": []}],
    "anyOf": [{"required": []}],
    "oneOf": [{"required": []}],
    "not": {"required": ["nothing"]},
    "if": {"required": ["port"]},
    "then": {"required": ["port"]},
    "else": {"required": []},
    "$ref": "#/$defs/p",
    "$defs": {"p": {"type": "object"}},
    "definitions": {"p": {"type": "object"}},
    "const": {"port": 1},
    "enum": [{"port": 1}],
    "propertyNames": {"maxLength": 32},
    "maxProperties": 5,
    "minProperties": 1,
    "default": {"port": 1},
    "examples": [{"port": 1}],
    "$schema": "https://json-schema.org/draft/2020-12/schema",
    "$id": "urn:probe",
    "format": "anything",
    "x-vendor-extension": True,
}


@pytest.mark.parametrize("keyword", sorted(_DISALLOWED_ROOT))
def test_registry_rejects_root_keyword_outside_allowlist(keyword):
    schema = dict(obj(port={"type": "integer"}), **{keyword: _DISALLOWED_ROOT[keyword]})
    assert find_reserved_parameter_declarations(schema) == []  # the name scan alone would admit it
    assert_rejected(schema)


@pytest.mark.parametrize("keyword", sorted(_DISALLOWED_ROOT))
def test_disallowed_root_keyword_is_rejected_in_every_status(keyword):
    schema = dict(obj(), **{keyword: _DISALLOWED_ROOT[keyword]})
    for status in Status:
        registry = SecurityToolRegistry()
        with pytest.raises(RegistryAdmissionError):
            registry.register(entry_with_schema(schema, status=status))
        assert registry.get("probe_capability") is None


# ===========================================================================
# The exact F-9 examples from the design review
# ===========================================================================


_F9_REJECTED = {
    "V1 patternProperties ^target_ref$": {"type": "object", "patternProperties": {"^target_ref$": _X}},
    "V2 patternProperties catch-all": {"type": "object", "patternProperties": {".": _X}},
    "V3 patternProperties _ref$": {"type": "object", "patternProperties": {"_ref$": _X}},
    "V3b allOf patternProperties": {"type": "object", "allOf": [{"patternProperties": {"^target": _X}}]},
    "V4 allOf additionalProperties": {"type": "object", "allOf": [{"additionalProperties": _X}]},
    "V5 anyOf additionalProperties": {"type": "object", "anyOf": [{"additionalProperties": _X}]},
    "V6 $defs + $ref": {"type": "object", "$defs": {"d": {"additionalProperties": _X}}, "allOf": [{"$ref": "#/$defs/d"}]},
    "V7 allOf unevaluatedProperties": {"type": "object", "allOf": [{"unevaluatedProperties": _X}]},
    "V8 dependentSchemas keyed target_ref": {"type": "object", "dependentSchemas": {"target_ref": {"additionalProperties": _X}}},
    "V9 not additionalProperties": {"type": "object", "not": {"additionalProperties": {"not": _X}}},
    "V10 object const": {"type": "object", "const": {"target_ref": "target-X"}},
    "V11 object enum": {"type": "object", "enum": [{"target_ref": "target-X"}]},
    "V12 propertyNames": {"type": "object", "propertyNames": {"not": {"const": "target_ref"}}},
    "V13 maxProperties 0": {"type": "object", "maxProperties": 0},
    "V14 object default": {"type": "object", "default": {"target_ref": "target-X"}},
    "V15 object examples": {"type": "object", "examples": [{"target_ref": "target-X"}]},
    "C2 root unevaluatedProperties": {"type": "object", "unevaluatedProperties": _X},
    "L3 root patternProperties ^x-": {"type": "object", "patternProperties": {"^x-": {"type": "string"}}},
}


@pytest.mark.parametrize("schema", list(_F9_REJECTED.values()), ids=list(_F9_REJECTED))
def test_f9_design_review_constructs_are_rejected(schema):
    assert find_reserved_parameter_declarations(schema) == []  # F-9: invisible to the name scan
    assert_rejected(schema)


_F9_ADMITTED = {
    "C1 root additionalProperties schema": {"type": "object", "additionalProperties": _X},
    "L1 repo style": {
        "type": "object", "properties": {"pid": {"type": "integer", "minimum": 1}}, "required": ["pid"],
        "additionalProperties": False,
    },
    "L2 enum on string": {"type": "object", "properties": {"protocol": {"type": "string", "enum": ["tcp", "udp"]}}},
    "L4 nested additionalProperties schema": {
        "type": "object", "properties": {"labels": {"type": "object", "additionalProperties": {"type": "string"}}},
    },
    "L5 nested maxLength/pattern": {
        "type": "object", "properties": {"path": {"type": "string", "maxLength": 256, "pattern": "^/"}},
    },
    "L6 nested patternProperties": {"type": "object", "properties": {"labels": {"type": "object", "patternProperties": {".": _X}}}},
    "L7 nested $ref to root": {"type": "object", "properties": {"child": {"$ref": "#"}}},
    "L8 nested allOf/const": {"type": "object", "properties": {"mode": {"allOf": [{"const": "fast"}]}}},
}


@pytest.mark.parametrize("schema", list(_F9_ADMITTED.values()), ids=list(_F9_ADMITTED))
def test_f9_design_review_safe_schemas_are_admitted(schema):
    assert_admitted(schema)


# ===========================================================================
# Allowed root keywords and `type`
# ===========================================================================


def test_every_allowed_root_keyword_together_registers():
    assert_admitted(
        {
            "type": "object",
            "title": "Probe",
            "description": "Probe parameters.",
            "properties": {"port": {"type": "integer"}},
            "required": ["port"],
            "additionalProperties": False,
        }
    )


@pytest.mark.parametrize("keyword", sorted(ROOT_SCHEMA_ALLOWED_KEYWORDS))
def test_each_allowed_root_keyword_registers_on_its_own(keyword):
    value = {
        "type": "object",
        "properties": {"port": {"type": "integer"}},
        "required": [],
        "additionalProperties": False,
        "description": "d",
        "title": "t",
    }[keyword]
    assert_admitted({keyword: value})


def test_type_object_registers():
    assert_admitted({"type": "object"})


def test_absent_type_registers():
    assert_admitted({"properties": {"port": {"type": "integer"}}, "required": ["port"]})


def test_empty_root_schema_registers():
    assert_admitted({})


@pytest.mark.parametrize("bad_type", ["string", "array", "integer", "null", "Object", ["object"], ["object", "null"], None])
def test_type_other_than_object_is_rejected(bad_type):
    assert_rejected({"type": bad_type, "properties": {}})


# ===========================================================================
# Nested schemas; interaction with the unchanged name scan
# ===========================================================================


def test_nested_schemas_may_use_normal_schema_keywords():
    assert_admitted(
        obj(
            options={
                "type": "object",
                "properties": {
                    "mode": {"type": "string", "enum": ["a", "b"], "default": "a", "examples": ["a"]},
                    "count": {"type": "integer", "minimum": 0, "maximum": 10},
                    "tags": {"type": "array", "items": {"type": "string"}, "minItems": 1, "uniqueItems": True},
                    "either": {"anyOf": [{"type": "string"}, {"type": "integer"}]},
                },
                "patternProperties": {"^x-": {"type": "string"}},
                "additionalProperties": False,
            }
        )
    )


@pytest.mark.parametrize(
    "schema",
    [
        obj(filter=obj(target_ref={"type": "string"})),
        obj(hosts={"type": "array", "items": obj(target_ref={"type": "string"})}),
        obj(options={"type": "object", "anyOf": [obj(target_ref={"type": "integer"})]}),
        obj(options={"type": "object", "required": ["target_ref"]}),
    ],
    ids=["nested_object", "array_items", "nested_combinator", "nested_required"],
)
def test_nested_target_ref_declarations_are_still_rejected_by_the_name_scan(schema):
    assert find_root_schema_violations(schema) == []  # root is clean; the name scan must catch it
    assert_rejected(schema, match="target_ref")


def test_name_scan_runs_first_and_keeps_its_message():
    # Both checks fail: the existing target_ref message is what the caller sees.
    schema = dict(obj(target_ref={"type": "string"}), allOf=[{}])
    with pytest.raises(RegistryAdmissionError, match="Runtime-reserved parameter name"):
        SecurityToolRegistry().register(entry_with_schema(schema))


def test_rejection_message_names_the_keyword_and_the_reason():
    with pytest.raises(RegistryAdmissionError) as excinfo:
        SecurityToolRegistry().register(entry_with_schema(dict(obj(), patternProperties={"^target_ref$": _X})))
    message = str(excinfo.value)
    assert "$.patternProperties" in message and "target_ref" in message and "probe_capability" in message


# ===========================================================================
# Registry state around a rejection
# ===========================================================================


def test_corrected_capability_can_register_after_a_rejected_attempt():
    good = entry_with_schema(obj(port={"type": "integer"}), capability="good_capability")
    registry = SecurityToolRegistry([good])
    bad = entry_with_schema(dict(obj(port={"type": "integer"}), allOf=[{"additionalProperties": _X}]), capability="bad_capability")
    with pytest.raises(RegistryAdmissionError):
        registry.register(bad)
    assert [e.capability for e in registry.list_enabled()] == ["good_capability"]
    assert registry.get_by_tool_id(bad.tool_id) is None
    registry.register(dataclasses.replace(bad, parameters_schema=obj(port={"type": "integer"})))
    assert registry.get_enabled("bad_capability") is not None


def test_disabled_rejected_entry_is_not_stored_and_can_never_be_enabled():
    registry = SecurityToolRegistry()
    with pytest.raises(RegistryAdmissionError):
        registry.register(entry_with_schema(dict(obj(), const={}), status=Status.DISABLED))
    assert registry.get("probe_capability") is None
    with pytest.raises(RegistryAdmissionError, match="unknown capability"):
        registry.set_status("probe_capability", Status.ENABLED, actor="admin")
    assert registry.catalog_view() == []


def test_constructor_rejects_a_batch_containing_a_root_violation():
    with pytest.raises(RegistryAdmissionError):
        SecurityToolRegistry(
            [
                entry_with_schema(obj(port={"type": "integer"}), capability="ok_one"),
                entry_with_schema(dict(obj(), patternProperties={".": _X}), capability="bad_one"),
            ]
        )


def test_existing_capabilities_pass_the_root_allowlist(registry):
    production = make_observe_local_host_environment_entry()
    assert find_root_schema_violations(production.parameters_schema) == []
    SecurityToolRegistry([production])
    for entry in registry.list_enabled():
        assert find_root_schema_violations(entry.parameters_schema) == []


# ===========================================================================
# Boundaries: provider-neutral, Registry-only, provider unchanged (F-8)
# ===========================================================================


def test_root_check_is_called_only_by_the_registry():
    callers = set()
    for path in (_REPO_ROOT / "chanakya").rglob("*.py"):
        if "find_root_schema_violations" in path.read_text(encoding="utf-8"):
            callers.add(path.relative_to(_REPO_ROOT).as_posix())
    assert callers == {"chanakya/capability/reserved.py", "chanakya/registry/registry.py"}


def test_name_scanner_itself_is_unchanged_by_f9():
    # find_reserved_parameter_declarations keeps its exact 5.7.5 semantics:
    # it does not report root keywords, so the provider (its other caller)
    # behaves exactly as before.
    assert find_reserved_parameter_declarations({"type": "object", "patternProperties": {"^target_ref$": _X}}) == []
    assert find_reserved_parameter_declarations(obj(target_ref={})) == ["$.properties.target_ref"]


def test_provider_behavior_is_unchanged_for_caller_supplied_catalogs():
    """F-8 residual, recorded deliberately: a catalog entry that never went
    through the Registry is still built by the provider as before."""
    schema = {"type": "object", "patternProperties": {"^target_ref$": _X}}
    tool = mapping._build_tool_param({"capability": "c", "parameters_schema": schema})
    assert tool["input_schema"]["patternProperties"] == {"^target_ref$": _X}
    assert tool["input_schema"]["properties"]["target_ref"]["description"] == mapping._TARGET_REF_DESCRIPTION


def test_reserved_module_stays_provider_neutral_and_authority_free():
    tree = ast.parse((_REPO_ROOT / "chanakya" / "capability" / "reserved.py").read_text(encoding="utf-8"))
    for node in ast.walk(tree):
        modules = [node.module] if isinstance(node, ast.ImportFrom) and node.module else []
        if isinstance(node, ast.Import):
            modules = [alias.name for alias in node.names]
        for module in modules:
            assert not module.startswith(
                ("chanakya.policy", "chanakya.runtime", "chanakya.providers", "chanakya.registry", "anthropic", "httpx")
            ), module
