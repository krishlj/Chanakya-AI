"""EnvironmentContext model-facing projection — docs/TARGET-AWARE-AGENT-CONTEXT.md
§13a (Phase 5.7.6).

The single, explicit boundary where an adapter-collected
``EnvironmentContext`` becomes model-visible. ``project_environment_context``
reads a fixed allowlist of named fields and builds a new
``EnvironmentContextView``; it never serializes, copies, or wraps the
``EnvironmentContext`` itself (no ``vars()``/``__dict__``/``asdict()``), so
a field added to ``EnvironmentContext`` later is invisible to the model
until this module is deliberately changed.

Exposed: ``target_id``, ``source``, ``collected_at``,
``overall_confidence``, and per observation ``key``, ``value``,
``confidence``, ``notes``.

Deliberately NOT exposed: ``environment_context_id`` and
``contract_version`` (internal bookkeeping), ``collected_by`` (adapter
identifier — adapter internals).

The view is observational and untrusted (docs/TARGET-MANAGER.md §12): it
is never an authorization input, and it is a different type from
``TargetContextView`` — nothing here can populate, replace, or override a
target-context identity field (TC-INV-10, EC-INV-3). This module imports
nothing from ``chanakya.policy``, ``chanakya.runtime``, or
``chanakya.providers``.

Every check fails closed: an ``EnvironmentContext`` that cannot be
projected safely produces no view at all, never a partial, truncated, or
repaired one. Error messages name the offending field/position only and
never echo a value.
"""
from __future__ import annotations

import math
import re
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Tuple, Union

from chanakya.contracts.target import _CREDENTIAL_PARAM_PATTERN, _URL_USERINFO_PATTERN

from .environment import EnvironmentContext, EnvironmentSource, ObservationConfidence

#: Upper bounds. Over-bound input is rejected, never truncated (RT-INV-5).
#: Total size is additionally governed by ``max_context_bytes``.
MAX_OBSERVATIONS_PER_CONTEXT = 64
MAX_OBSERVATION_KEY_LENGTH = 128
MAX_OBSERVATION_TEXT_LENGTH = 4096
MAX_OBSERVATION_LIST_ITEMS = 64

#: Observation keys are identifiers, not prose: this keeps free text (and
#: therefore injected instructions) out of the key position entirely.
_KEY_PATTERN = re.compile(r"^[A-Za-z0-9_.\-]+$")

#: Best-effort backstop against an adapter reporting a credential as an
#: observation: a key whose final segment names a credential is refused.
#: Suffix-anchored so descriptive keys such as ``secret_marker`` are not
#: caught, while ``password``, ``db_password``, ``api_key``,
#: ``aws_secret_access_key``, ``auth_token`` are.
_CREDENTIAL_KEY_PATTERN = re.compile(
    r"(?i)(?:^|[_.\-])(password|passwd|pwd|secret|token|api[_\-]?key|apikey|access[_\-]?key|"
    r"private[_\-]?key|client[_\-]?secret|credentials?|cookie|bearer)$"
)

_ALLOWED_SOURCES = frozenset(source.value for source in EnvironmentSource)
_ALLOWED_CONFIDENCES = frozenset(confidence.value for confidence in ObservationConfidence)

ObservationScalar = Union[str, int, float, bool, None]
ObservationValue = Union[ObservationScalar, Tuple[ObservationScalar, ...]]


class EnvironmentContextProjectionError(ValueError):
    """Raised when an ``EnvironmentContext`` cannot be safely projected
    into an ``EnvironmentContextView``. Messages never echo values."""


def _require_non_empty_str(field_name: str, value: object) -> None:
    # Exact ``str`` only (Phase 5.7.7): a ``str`` subclass can lie through
    # ``__eq__``/``__hash__``/``__len__`` and pass scope/bound checks while
    # serializing as something else. The same rule applies to every string
    # checked in this module.
    if type(value) is not str or not value.strip():
        raise EnvironmentContextProjectionError(f"EnvironmentContextView.{field_name} must be a non-empty string")


def _check_text(field_name: str, value: str) -> None:
    if len(value) > MAX_OBSERVATION_TEXT_LENGTH:
        raise EnvironmentContextProjectionError(
            f"{field_name} exceeds {MAX_OBSERVATION_TEXT_LENGTH} characters"
        )
    if _URL_USERINFO_PATTERN.search(value) or _CREDENTIAL_PARAM_PATTERN.search(value):
        raise EnvironmentContextProjectionError(f"{field_name} must not contain credential-shaped content")


def _check_scalar(field_name: str, value: object) -> None:
    # bool is an int subclass; both are fine. Anything else — objects,
    # callables, SDK/adapter handles, bytes, mappings — is refused.
    if value is None or isinstance(value, (bool, int)):
        return
    if isinstance(value, float):
        if not math.isfinite(value):
            raise EnvironmentContextProjectionError(f"{field_name} must be a finite number")
        return
    if type(value) is str:
        _check_text(field_name, value)
        return
    raise EnvironmentContextProjectionError(
        f"{field_name} must be a str, int, float, bool or None, got {type(value).__name__}"
    )


def _check_confidence(field_name: str, value: object) -> None:
    if value is not None and (type(value) is not str or value not in _ALLOWED_CONFIDENCES):
        raise EnvironmentContextProjectionError(f"{field_name} must be one of {sorted(_ALLOWED_CONFIDENCES)} or None")


@dataclass(frozen=True)
class EnvironmentObservationView:
    """One model-visible observation. ``value`` is a JSON scalar or a
    flat tuple of JSON scalars — structurally incapable of carrying a
    handle, client, callable, or nested object."""

    key: str
    value: ObservationValue
    confidence: Optional[str] = None
    notes: Optional[str] = None

    def __init_subclass__(cls, **kwargs: object) -> None:
        raise TypeError("EnvironmentObservationView cannot be subclassed")

    def __post_init__(self) -> None:
        if type(self.key) is not str or not self.key:
            raise EnvironmentContextProjectionError("observation key must be a non-empty string")
        if len(self.key) > MAX_OBSERVATION_KEY_LENGTH:
            raise EnvironmentContextProjectionError(
                f"observation key exceeds {MAX_OBSERVATION_KEY_LENGTH} characters"
            )
        if not _KEY_PATTERN.match(self.key):
            raise EnvironmentContextProjectionError("observation key must contain only [A-Za-z0-9_.-]")
        if _CREDENTIAL_KEY_PATTERN.search(self.key):
            raise EnvironmentContextProjectionError("observation key names a credential; refusing to project it")
        if isinstance(self.value, tuple) and type(self.value) is not tuple:
            raise EnvironmentContextProjectionError("observation value list must be a plain tuple")
        if type(self.value) is tuple:
            if len(self.value) > MAX_OBSERVATION_LIST_ITEMS:
                raise EnvironmentContextProjectionError(
                    f"observation value list exceeds {MAX_OBSERVATION_LIST_ITEMS} items"
                )
            for item in self.value:
                _check_scalar("observation value item", item)
        else:
            _check_scalar("observation value", self.value)
        _check_confidence("observation confidence", self.confidence)
        if self.notes is not None:
            if type(self.notes) is not str:
                raise EnvironmentContextProjectionError("observation notes must be a string or None")
            _check_text("observation notes", self.notes)

    def as_model_mapping(self) -> Dict[str, Any]:
        value = list(self.value) if isinstance(self.value, tuple) else self.value
        return {"key": self.key, "value": value, "confidence": self.confidence, "notes": self.notes}


@dataclass(frozen=True)
class EnvironmentContextView:
    """The model-visible, observational description of one environment
    collection for one target. Distinct type from ``TargetContextView``;
    ``target_id`` is a join key only, never an identity override."""

    target_id: str
    source: str
    collected_at: str
    observations: Tuple[EnvironmentObservationView, ...]
    overall_confidence: Optional[str] = None

    def __init_subclass__(cls, **kwargs: object) -> None:
        # Phase 5.7.7: a subclass could override ``as_model_mapping`` and
        # still pass every ``isinstance`` check downstream.
        raise TypeError("EnvironmentContextView cannot be subclassed")

    def __post_init__(self) -> None:
        _require_non_empty_str("target_id", self.target_id)
        _require_non_empty_str("collected_at", self.collected_at)
        if len(self.collected_at) > MAX_OBSERVATION_KEY_LENGTH:
            raise EnvironmentContextProjectionError(
                f"EnvironmentContextView.collected_at exceeds {MAX_OBSERVATION_KEY_LENGTH} characters"
            )
        if type(self.source) is not str or self.source not in _ALLOWED_SOURCES:
            raise EnvironmentContextProjectionError(
                f"EnvironmentContextView.source must be one of {sorted(_ALLOWED_SOURCES)}"
            )
        _check_confidence("EnvironmentContextView.overall_confidence", self.overall_confidence)
        # Exact tuple: a tuple subclass could yield different entries on the
        # validation pass and the serialization pass.
        if type(self.observations) is not tuple:
            raise EnvironmentContextProjectionError("EnvironmentContextView.observations must be a tuple")
        if len(self.observations) > MAX_OBSERVATIONS_PER_CONTEXT:
            raise EnvironmentContextProjectionError(
                f"EnvironmentContextView.observations exceeds {MAX_OBSERVATIONS_PER_CONTEXT} entries"
            )
        for observation in self.observations:
            if type(observation) is not EnvironmentObservationView:
                raise EnvironmentContextProjectionError(
                    "EnvironmentContextView.observations entries must be EnvironmentObservationView"
                )

    def as_model_mapping(self) -> Dict[str, Any]:
        """Canonical provider-independent serialization: always exactly
        these five keys, in this order. Returns a new dict on every call."""
        observations: List[Dict[str, Any]] = [obs.as_model_mapping() for obs in self.observations]
        return {
            "target_id": self.target_id,
            "source": self.source,
            "collected_at": self.collected_at,
            "overall_confidence": self.overall_confidence,
            "observations": observations,
        }


def _project_value(value: Any) -> ObservationValue:
    if isinstance(value, (list, tuple)):
        return tuple(value)
    return value


def project_environment_context(environment_context: EnvironmentContext) -> EnvironmentContextView:
    """The only approved path from an ``EnvironmentContext`` to
    model-visible environment data. Reads exactly the allowlisted fields
    by name. Pure: no adapter call, no registry access, no clock, no
    mutation.

    Raises ``TypeError`` for anything that is not an ``EnvironmentContext``
    and ``EnvironmentContextProjectionError`` for one whose allowlisted
    values fail validation.
    """
    if not isinstance(environment_context, EnvironmentContext):
        raise TypeError("project_environment_context requires an EnvironmentContext instance")

    observations = environment_context.observations
    if not isinstance(observations, (tuple, list)):
        raise EnvironmentContextProjectionError("EnvironmentContext.observations must be a sequence")
    if len(observations) > MAX_OBSERVATIONS_PER_CONTEXT:
        raise EnvironmentContextProjectionError(
            f"EnvironmentContext.observations exceeds {MAX_OBSERVATIONS_PER_CONTEXT} entries"
        )

    projected = []
    for observation in observations:
        confidence = observation.confidence
        projected.append(
            EnvironmentObservationView(
                key=observation.key,
                value=_project_value(observation.value),
                confidence=confidence.value if isinstance(confidence, ObservationConfidence) else confidence,
                notes=observation.notes,
            )
        )

    source = environment_context.source
    overall = environment_context.overall_confidence
    return EnvironmentContextView(
        target_id=environment_context.target_id,
        source=source.value if isinstance(source, EnvironmentSource) else source,
        collected_at=environment_context.collected_at,
        observations=tuple(projected),
        overall_confidence=overall.value if isinstance(overall, ObservationConfidence) else overall,
    )


__all__ = [
    "MAX_OBSERVATIONS_PER_CONTEXT",
    "MAX_OBSERVATION_KEY_LENGTH",
    "MAX_OBSERVATION_LIST_ITEMS",
    "MAX_OBSERVATION_TEXT_LENGTH",
    "EnvironmentContextProjectionError",
    "EnvironmentContextView",
    "EnvironmentObservationView",
    "project_environment_context",
]
