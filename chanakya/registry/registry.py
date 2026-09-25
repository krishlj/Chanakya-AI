"""SecurityToolRegistry — docs/TOOL-REGISTRY.md.

The closed catalog of every capability the system knows how to run. No
capability can be invoked unless it is registered here (SR-3), and nothing
here ever executes anything — this class only stores, looks up, and
projects entries.
"""
from __future__ import annotations

import dataclasses
from datetime import datetime, timezone
from typing import Dict, Iterable, List, Optional

from chanakya.capability.reserved import (
    ROOT_SCHEMA_ALLOWED_KEYWORDS,
    find_reserved_parameter_declarations,
    find_root_schema_violations,
    is_reserved_capability_name,
)

from .exceptions import RegistryAdmissionError
from .models import ALLOWED_STATUS_TRANSITIONS, RegistryEntry, Status

#: docs/TOOL-REGISTRY.md §4 — the ONLY fields that may reach the Capability
#: Catalog View (and, transitively, the Agent/LLM). Every other field
#: (privileges, resource limits, provenance, trust level, owner, risk
#: category, approval requirement, operations) stays server-side.
_AGENT_VISIBLE_FIELDS = (
    "capability",
    "display_name",
    "description",
    "parameters_schema",
    "classification",
    "supported_target_types",
)


def _utcnow_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


class SecurityToolRegistry:
    def __init__(self, entries: Iterable[RegistryEntry] = ()) -> None:
        self._by_capability: Dict[str, RegistryEntry] = {}
        self._by_tool_id: Dict[str, RegistryEntry] = {}
        for entry in entries:
            self.register(entry)

    def register(self, entry: RegistryEntry) -> None:
        # Phase 9: the finding channel's name is Runtime-reserved; no
        # capability may take it, in any status or letter case.
        if is_reserved_capability_name(entry.capability):
            raise RegistryAdmissionError(
                f"capability name {entry.capability!r} is reserved by the Runtime for reporting findings"
            )
        # Phase 5.7.5 (docs/TARGET-AWARE-AGENT-CONTEXT.md §15, F-4):
        # ``target_ref`` is Runtime-reserved — it is how the Agent proposes a
        # target, validated by Intake and authorized only by the Policy
        # Gateway. A capability declaring it anywhere in its parameter schema
        # is never admitted, in any status, so it can never be enabled or
        # looked up. Nothing is renamed, removed, or overridden. This only
        # protects the parameter namespace; it is not an authorization check.
        reserved = find_reserved_parameter_declarations(entry.parameters_schema)
        if reserved:
            raise RegistryAdmissionError(
                f"capability {entry.capability!r} declares Runtime-reserved parameter name(s) "
                f"at {reserved!r}; 'target_ref' is owned by the Runtime for target selection"
            )
        # Phase 5.7.7 F-9: the root schema is limited to a keyword allowlist,
        # because root-level applicators and object assertions
        # (patternProperties, allOf, $ref, const, ...) can constrain or block
        # 'target_ref' without declaring it by name. In addition to, never
        # instead of, the recursive check above.
        root_violations = find_root_schema_violations(entry.parameters_schema)
        if root_violations:
            raise RegistryAdmissionError(
                f"capability {entry.capability!r} parameters_schema uses root keyword(s) outside the allowlist "
                f"{sorted(ROOT_SCHEMA_ALLOWED_KEYWORDS)!r} at {root_violations!r}; root keywords could "
                f"constrain the Runtime-reserved 'target_ref'"
            )
        if entry.capability in self._by_capability:
            raise RegistryAdmissionError(f"capability already registered: {entry.capability!r}")
        if entry.tool_id in self._by_tool_id:
            raise RegistryAdmissionError(f"tool_id already registered: {entry.tool_id!r}")
        self._by_capability[entry.capability] = entry
        self._by_tool_id[entry.tool_id] = entry

    def get(self, capability: str) -> Optional[RegistryEntry]:
        """Raw lookup regardless of ``status``. Admin tooling needs to be
        able to see disabled/quarantined entries; the Policy Gateway must
        NOT use this method directly — see ``get_enabled``."""
        return self._by_capability.get(capability)

    def get_enabled(self, capability: str) -> Optional[RegistryEntry]:
        """The Gateway-facing lookup. Returns ``None`` for a capability that
        is unknown *or* not ``enabled`` — deliberately indistinguishable
        (REG-INV-3, docs/TOOL-REGISTRY.md §"Security model")."""
        entry = self._by_capability.get(capability)
        if entry is None or entry.status != Status.ENABLED:
            return None
        return entry

    def get_by_tool_id(self, tool_id: str) -> Optional[RegistryEntry]:
        return self._by_tool_id.get(tool_id)

    def list_enabled(self) -> List[RegistryEntry]:
        return [e for e in self._by_capability.values() if e.status == Status.ENABLED]

    def set_status(self, capability: str, new_status: Status, *, actor: str) -> RegistryEntry:
        """docs/TOOL-REGISTRY.md §6 — enforces the lifecycle state machine.
        ``RegistryEntry`` is immutable, so this replaces the stored entry
        with an updated copy and returns it."""
        entry = self._by_capability.get(capability)
        if entry is None:
            raise RegistryAdmissionError(f"unknown capability: {capability!r}")
        allowed = ALLOWED_STATUS_TRANSITIONS.get(entry.status, frozenset())
        if new_status not in allowed:
            raise RegistryAdmissionError(
                f"illegal status transition for {capability!r}: "
                f"{entry.status.value} -> {new_status.value} (actor={actor!r})"
            )
        updated = dataclasses.replace(entry, status=new_status, updated_at=_utcnow_iso())
        self._by_capability[capability] = updated
        self._by_tool_id[entry.tool_id] = updated
        return updated

    def catalog_view(self, *, authorized_target_types: Optional[Iterable[str]] = None) -> List[dict]:
        """docs/TOOL-REGISTRY.md §4 — the Capability Catalog View: the ONLY
        Registry-derived structure that may reach the LLM Abstraction/Agent.
        Filters to ``enabled``, non-``quarantined`` entries whose
        ``supported_target_types`` intersect the caller's authorized target
        types (REG-INV-3), and reduces each entry to
        ``_AGENT_VISIBLE_FIELDS`` only.
        """
        allowed_types = set(authorized_target_types) if authorized_target_types is not None else None
        view: List[dict] = []
        for entry in self.list_enabled():
            if entry.trust_level.value == "quarantined":
                continue
            if allowed_types is not None and not (set(entry.supported_target_types) & allowed_types):
                continue
            view.append(self._project(entry))
        return view

    @staticmethod
    def _project(entry: RegistryEntry) -> dict:
        return {
            "capability": entry.capability,
            "display_name": entry.display_name,
            "description": entry.description,
            "parameters_schema": entry.parameters_schema,
            "classification": entry.classification.value,
            "supported_target_types": list(entry.supported_target_types),
        }
