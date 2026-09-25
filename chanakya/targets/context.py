"""Target Context Projection — docs/TARGET-AWARE-AGENT-CONTEXT.md §7-§9 (Phase 5.7.2).

The single, explicit boundary where an internal ``Target`` becomes a
model-visible representation. ``project_target`` reads a fixed allowlist
of named fields and builds a new ``TargetContextView``; it never
serializes, copies, or wraps the ``Target`` itself (TC-INV-9), so a field
added to ``Target`` later is invisible to the model until this module is
deliberately changed.

Exposed (all ``str`` or ``None``): ``target_id``, ``target_type``,
``display_name``, ``provenance_source``, ``last_verified_at``.

Deliberately NOT exposed (docs/TARGET-AWARE-AGENT-CONTEXT.md §8):
``status`` (its ``"authorized"`` value reads as a grant, and the Policy
Gateway re-reads the live value on every evaluation anyway),
``authorized_scope`` (authorization-state vocabulary), ``locator``
(docs/TARGET-MANAGER.md §5: nothing outside the matching adapter
interprets it), ``metadata`` (arbitrary, unbounded, not
credential-screened), ``owner_contact`` and ``provenance.registered_by``
(personal data), ``provenance.observed_at``, ``registered_at``,
``contract_version``.

``TargetContextView`` is descriptive only. It is never an authorization
input: nothing in ``chanakya.policy`` reads it, and this module imports
nothing from ``chanakya.policy``, ``chanakya.runtime``, or
``chanakya.providers`` (TC-INV-1). It is not ``EnvironmentContext``:
adapter observations never populate its fields — ``project_target``
accepts only a ``Target`` (TC-INV-10).

Not wired into ``AssembledContext``/``ContextAssembler``/any provider in
this phase (5.7.3/5.7.4). ``as_model_mapping()`` is the one canonical,
provider-independent serialization those later phases (and the Runtime's
existing context-size measurement) are expected to use.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, Optional

from chanakya.contracts.target import (
    _CREDENTIAL_PARAM_PATTERN,
    _URL_USERINFO_PATTERN,
    Target,
)

#: docs/TARGET-AWARE-AGENT-CONTEXT.md §9 / Q-2 — upper bound on
#: ``display_name``, in characters. Over-bound values are rejected, never
#: truncated (the Runtime's "never repair" posture, RT-INV-5).
MAX_DISPLAY_NAME_LENGTH = 256


class TargetContextProjectionError(ValueError):
    """Raised when a ``Target`` cannot be safely projected into a
    ``TargetContextView``. Fails closed: the caller receives no view at
    all, never a partially-populated or repaired one. Messages name the
    offending field only — they never echo its value, so a
    credential-shaped value is not copied into an exception string."""


def _require_non_empty_str(field_name: str, value: object) -> None:
    # Exact ``str`` only (Phase 5.7.7): a ``str`` subclass can override
    # ``__eq__``/``__hash__`` and so pass the Runtime's scope checks as one
    # target id while serializing as another.
    if type(value) is not str or not value.strip():
        raise TargetContextProjectionError(f"TargetContextView.{field_name} must be a non-empty string")


def _require_optional_str(field_name: str, value: object) -> None:
    if value is not None and type(value) is not str:
        raise TargetContextProjectionError(f"TargetContextView.{field_name} must be a string or None")


def _validate_display_name(value: object) -> None:
    _require_non_empty_str("display_name", value)
    if len(value) > MAX_DISPLAY_NAME_LENGTH:  # type: ignore[arg-type]
        raise TargetContextProjectionError(
            f"TargetContextView.display_name exceeds {MAX_DISPLAY_NAME_LENGTH} characters"
        )
    # Same best-effort credential-shape screen TargetLocator.value uses
    # (chanakya/contracts/target.py, docs/TARGET-MANAGER.md §5 F-6) —
    # reused, not re-implemented. A backstop, not a guarantee
    # (docs/THREAT-MODEL.md T-20 residual risk).
    if _URL_USERINFO_PATTERN.search(value) or _CREDENTIAL_PARAM_PATTERN.search(value):  # type: ignore[arg-type]
        raise TargetContextProjectionError(
            "TargetContextView.display_name must not contain credential-shaped content"
        )


@dataclass(frozen=True)
class TargetContextView:
    """The model-visible description of one investigation target.
    Primitive-only fields (``str``/``None``) — structurally incapable of
    carrying a handle, client, callable, nested ``Target``, or SDK object
    (TC-INV-2). Validated on construction, so a view built directly
    (rather than via ``project_target``) is held to the same rules."""

    target_id: str
    target_type: str
    display_name: str
    provenance_source: Optional[str] = None
    last_verified_at: Optional[str] = None

    def __init_subclass__(cls, **kwargs: object) -> None:
        # Phase 5.7.7: a subclass could override ``as_model_mapping`` (or
        # validation) and still pass every ``isinstance`` check downstream.
        raise TypeError("TargetContextView cannot be subclassed")

    def __post_init__(self) -> None:
        _require_non_empty_str("target_id", self.target_id)
        _require_non_empty_str("target_type", self.target_type)
        _validate_display_name(self.display_name)
        _require_optional_str("provenance_source", self.provenance_source)
        _require_optional_str("last_verified_at", self.last_verified_at)

    def as_model_mapping(self) -> Dict[str, Optional[str]]:
        """Canonical provider-independent serialization: always exactly
        these five keys, in this order, each ``str`` or ``None``. Returns
        a new dict on every call."""
        return {
            "target_id": self.target_id,
            "target_type": self.target_type,
            "display_name": self.display_name,
            "provenance_source": self.provenance_source,
            "last_verified_at": self.last_verified_at,
        }


def project_target(target: Target) -> TargetContextView:
    """The only approved path from an internal ``Target`` to model-visible
    target context. Reads exactly the allowlisted fields by name; reads
    nothing else from the ``Target`` (TC-INV-9). Pure: no registry access,
    no adapter call, no clock, no mutation of ``target``.

    Raises ``TypeError`` for anything that is not a ``Target`` (e.g. an
    ``EnvironmentContext`` or a duck-typed look-alike — TC-INV-10), and
    ``TargetContextProjectionError`` for a ``Target`` whose allowlisted
    values fail validation.
    """
    if not isinstance(target, Target):
        raise TypeError("project_target requires a Target instance")

    provenance = target.provenance
    provenance_source = provenance.source.value if provenance is not None else None

    return TargetContextView(
        target_id=target.target_id,
        target_type=target.target_type,
        display_name=target.display_name,
        provenance_source=provenance_source,
        last_verified_at=target.last_verified_at,
    )


__all__ = [
    "MAX_DISPLAY_NAME_LENGTH",
    "TargetContextProjectionError",
    "TargetContextView",
    "project_target",
]
