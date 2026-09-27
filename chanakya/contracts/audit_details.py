"""Durable authorization facts in ``AuditEvent.details`` — Phase 12.

Phase 12 makes an investigation reconstructable from its audit stream
without new event types: existing events carry additive, bounded,
credential-screened ``details``. This module is the single definition of
those facts. The Runtime's ``AuditEmitter`` builds them here; the read-only
Review layer (``chanakya.review``) validates and interprets them here.

Enriched events and their ``details`` keys (existing keys are kept):

- ``investigation_started``: ``investigation_request_id``, ``submitted_by``,
  ``submitted_at``, ``target_refs``, ``objective``.
- ``request_proposed``: ``capability``, ``target_ref``, ``step_id``,
  ``attempt_number``, ``parameters_canonical``, ``parameters_hash``.
- ``policy_evaluated``: ``verdict``, ``matched_rule``, ``reason`` (existing)
  plus ``capability``, ``target_ref``, ``classification``, ``risk_category``,
  ``envelope`` (``capability``, ``timeout_seconds``, ``max_output_bytes``,
  ``output_schema_hash``) or ``None``.
- ``approval_requested``: ``step_id``, ``expires_at``, ``risk_context``
  (``capability``, ``target_ref``, ``parameters_canonical``,
  ``parameters_hash``).
- ``dispatch_started``: ``capability``, ``target_ref``, ``step_id``,
  ``attempt_number``, ``resolved_timeout_seconds``, ``max_output_bytes``,
  ``policy_decision_id``.

D-1, the objective: stored as text, at most ``MAX_OBJECTIVE_CHARS``, with
no control characters other than newline and tab, and rejected if it looks
credential-shaped.

D-2, parameters: stored as their canonical JSON
(``chanakya.evidence.hashing.canonical_bytes``, the project's canonical
form) plus ``compute_content_hash`` of the same mapping. They must be
JSON-compatible, at most ``MAX_PARAMETERS_BYTES`` canonical bytes, and
free of credential-shaped keys or string values. ``verify_parameters``
re-derives both from the stored text.

Screening reuses the existing patterns: the ``TargetLocator`` URL-userinfo
and ``key=`` patterns and the Finding free-text pattern (keyword followed
by ``=`` or ``:``, or a PEM private-key header). It is best-effort
(docs/THREAT-MODEL.md T-20), not a secret scanner.

Every builder fails closed with ``AuditFactError``, whose message is only a
fixed reason code; the offending value is never echoed. Nothing is
truncated, redacted or dropped.
"""
from __future__ import annotations

import json
import re
from typing import Any, Dict, List, Mapping, Optional, Tuple

from chanakya.capability.envelope import CapabilityEnvelope, is_json_compatible
from chanakya.evidence.hashing import canonical_bytes, compute_content_hash

from .finding import _TEXT_CREDENTIAL_PATTERN
from .target import _CREDENTIAL_PARAM_PATTERN, _URL_USERINFO_PATTERN

MAX_OBJECTIVE_CHARS = 2000
MAX_FACT_CHARS = 256
MAX_TARGET_REFS = 16
MAX_PARAMETERS_BYTES = 4096

FACT_UNSAFE_TEXT = "FACT_UNSAFE_TEXT"
FACT_CREDENTIAL_SHAPED = "FACT_CREDENTIAL_SHAPED"
FACT_TOO_LARGE = "FACT_TOO_LARGE"
FACT_NOT_SERIALIZABLE = "FACT_NOT_SERIALIZABLE"
FACT_INVALID = "FACT_INVALID"

_TEXT_FORBIDDEN = re.compile(r"[\x00-\x08\x0b-\x1f\x7f]")
_LINE_FORBIDDEN = re.compile(r"[\x00-\x1f\x7f]")
_HASH = re.compile(r"^sha256:[0-9a-f]{64}$")


class AuditFactError(ValueError):
    """A durable fact cannot be recorded safely. ``code`` is fixed; the
    message never contains the rejected value."""

    def __init__(self, code: str, field: str) -> None:
        self.code = code
        self.field = field
        super().__init__(f"{code}: {field}")


def _credential_shaped(text: str) -> bool:
    return bool(
        _URL_USERINFO_PATTERN.search(text)
        or _CREDENTIAL_PARAM_PATTERN.search(text)
        or _TEXT_CREDENTIAL_PATTERN.search(text)
    )


def objective_fact(value: Any) -> str:
    """D-1: the bounded, screened objective text."""
    if type(value) is not str or not value.strip():
        raise AuditFactError(FACT_INVALID, "objective")
    if len(value) > MAX_OBJECTIVE_CHARS:
        raise AuditFactError(FACT_TOO_LARGE, "objective")
    if _TEXT_FORBIDDEN.search(value):
        raise AuditFactError(FACT_UNSAFE_TEXT, "objective")
    if _credential_shaped(value):
        raise AuditFactError(FACT_CREDENTIAL_SHAPED, "objective")
    return value


def text_fact(field: str, value: Any, *, optional: bool = False) -> Optional[str]:
    """A bounded one-line fact (identifiers, capability names, timestamps)."""
    if value is None and optional:
        return None
    if type(value) is not str or not value:
        raise AuditFactError(FACT_INVALID, field)
    if len(value) > MAX_FACT_CHARS:
        raise AuditFactError(FACT_TOO_LARGE, field)
    if _LINE_FORBIDDEN.search(value):
        raise AuditFactError(FACT_UNSAFE_TEXT, field)
    if _credential_shaped(value):
        raise AuditFactError(FACT_CREDENTIAL_SHAPED, field)
    return value


def _screen_parameter_values(value: Any) -> None:
    stack = [value]
    while stack:
        item = stack.pop()
        if isinstance(item, str):
            if _credential_shaped(item) or _LINE_FORBIDDEN.search(item):
                raise AuditFactError(FACT_CREDENTIAL_SHAPED, "parameters")
        elif isinstance(item, Mapping):
            for key, child in item.items():
                # A key such as "password" is a credential carrier on its own.
                if _credential_shaped(f"{key}=x") or _LINE_FORBIDDEN.search(key):
                    raise AuditFactError(FACT_CREDENTIAL_SHAPED, "parameters")
                stack.append(child)
        elif isinstance(item, list):
            stack.extend(item)


def parameters_fact(parameters: Any) -> Tuple[str, str]:
    """D-2: ``(canonical JSON text, integrity hash)`` of ``parameters``."""
    if not isinstance(parameters, Mapping):
        raise AuditFactError(FACT_INVALID, "parameters")
    try:
        plain = json.loads(canonical_bytes(parameters).decode("ascii")) if is_json_compatible(parameters) else None
    except (TypeError, ValueError, RecursionError):
        plain = None
    if not isinstance(plain, dict):
        raise AuditFactError(FACT_NOT_SERIALIZABLE, "parameters")
    canonical = canonical_bytes(plain).decode("ascii")
    if len(canonical) > MAX_PARAMETERS_BYTES:
        raise AuditFactError(FACT_TOO_LARGE, "parameters")
    _screen_parameter_values(plain)
    return canonical, compute_content_hash(plain)


def verify_parameters(canonical: Any, digest: Any) -> bool:
    """True only if ``canonical`` is canonical JSON of an object, within
    bounds, and ``digest`` is its integrity hash."""
    if type(canonical) is not str or type(digest) is not str or not _HASH.match(digest):
        return False
    if len(canonical) > MAX_PARAMETERS_BYTES:
        return False
    try:
        parsed = json.loads(canonical)
        if not isinstance(parsed, dict) or canonical_bytes(parsed).decode("ascii") != canonical:
            return False
        return compute_content_hash(parsed) == digest
    except (TypeError, ValueError, RecursionError):
        return False


def envelope_summary(envelope: Optional[CapabilityEnvelope]) -> Optional[Dict[str, Any]]:
    """The authorized envelope without its full schema: limits plus the
    integrity hash of the output schema."""
    if envelope is None:
        return None
    return {
        "capability": envelope.capability,
        "timeout_seconds": envelope.timeout_seconds,
        "max_output_bytes": envelope.max_output_bytes,
        "output_schema_hash": compute_content_hash(envelope.to_dict()["output_schema"]),
        # Phase 15 (AuditEvent 1.2.0): the Registry-declared egress.
        "model_egress": envelope.model_egress.value,
    }


def origin_details(
    *,
    investigation_request_id: Any,
    submitted_by: Any,
    submitted_at: Any,
    target_refs: Any,
    objective: Any,
) -> Dict[str, Any]:
    """``investigation_started`` details (D-1)."""
    if not isinstance(target_refs, (list, tuple)) or not target_refs or len(target_refs) > MAX_TARGET_REFS:
        raise AuditFactError(FACT_INVALID, "target_refs")
    return {
        "investigation_request_id": text_fact("investigation_request_id", investigation_request_id),
        "submitted_by": text_fact("submitted_by", submitted_by),
        "submitted_at": text_fact("submitted_at", submitted_at),
        "target_refs": [text_fact("target_refs", ref) for ref in target_refs],
        "objective": objective_fact(objective),
    }


def request_details(*, capability: Any, target_ref: Any, step_id: Any, attempt_number: Any, parameters: Any) -> Dict[str, Any]:
    """``request_proposed`` details (D-2)."""
    canonical, digest = parameters_fact(parameters)
    return {
        "capability": text_fact("capability", capability),
        "target_ref": text_fact("target_ref", target_ref),
        "step_id": text_fact("step_id", step_id),
        "attempt_number": _positive_int("attempt_number", attempt_number),
        "parameters_canonical": canonical,
        "parameters_hash": digest,
    }


def risk_context_details(risk_context: Any) -> Dict[str, Any]:
    """The facts an approver was shown (``ApprovalRequest.risk_context``)."""
    if not isinstance(risk_context, Mapping):
        raise AuditFactError(FACT_INVALID, "risk_context")
    canonical, digest = parameters_fact(risk_context.get("parameters", {}))
    return {
        "capability": text_fact("capability", risk_context.get("capability")),
        "target_ref": text_fact("target_ref", risk_context.get("target_ref")),
        "parameters_canonical": canonical,
        "parameters_hash": digest,
    }


def _positive_int(field: str, value: Any) -> int:
    if type(value) is not int or value <= 0:
        raise AuditFactError(FACT_INVALID, field)
    return value


# -- validation of stored details (used by the Review layer) -----------------

ORIGIN_KEYS = frozenset({"investigation_request_id", "submitted_by", "submitted_at", "target_refs", "objective"})
REQUEST_KEYS = frozenset(
    {"capability", "target_ref", "step_id", "attempt_number", "parameters_canonical", "parameters_hash"}
)
POLICY_KEYS = frozenset(
    {"verdict", "matched_rule", "reason", "capability", "target_ref", "classification", "risk_category", "envelope"}
)
ENVELOPE_KEYS_V1 = frozenset({"capability", "timeout_seconds", "max_output_bytes", "output_schema_hash"})
#: Phase 15 (AuditEvent 1.2.0) adds the Registry-declared model egress.
ENVELOPE_KEYS = ENVELOPE_KEYS_V1 | {"model_egress"}
_EGRESS_VALUES = frozenset({"allowed", "evidence_only"})
APPROVAL_KEYS = frozenset({"step_id", "expires_at", "risk_context"})
RISK_CONTEXT_KEYS = frozenset({"capability", "target_ref", "parameters_canonical", "parameters_hash"})
DISPATCH_KEYS = frozenset(
    {"capability", "target_ref", "step_id", "attempt_number", "resolved_timeout_seconds", "max_output_bytes",
     "policy_decision_id"}
)

_VERDICTS = frozenset({"allow", "deny", "require_approval"})


def _is_text(value: Any, *, optional: bool = False) -> bool:
    if value is None:
        return optional
    try:
        text_fact("stored", value)
    except AuditFactError:
        return False
    return True


def _is_positive_int(value: Any) -> bool:
    return type(value) is int and value > 0


def validate_details(event_type: str, details: Any, *, egress_recorded: bool = True) -> List[str]:
    """Problems with a stored enriched ``details`` mapping, as fixed codes.
    Unknown or missing keys, wrong types and unsafe text are all reported;
    extra keys are never accepted. ``egress_recorded`` is True for AuditEvent
    1.2.0+ streams, whose envelope summary must carry ``model_egress``."""
    if not isinstance(details, Mapping):
        return ["details_missing"]
    keys = set(details)
    if event_type == "investigation_started":
        if keys != ORIGIN_KEYS:
            return ["details_shape_invalid"]
        try:
            origin_details(**{k: details[k] for k in ORIGIN_KEYS})
        except (AuditFactError, TypeError):
            return ["details_value_invalid"]
        return []
    if event_type == "request_proposed":
        if keys != REQUEST_KEYS:
            return ["details_shape_invalid"]
        problems = []
        if not all(_is_text(details[k]) for k in ("capability", "target_ref", "step_id")) or not _is_positive_int(
            details["attempt_number"]
        ):
            problems.append("details_value_invalid")
        if not verify_parameters(details["parameters_canonical"], details["parameters_hash"]):
            problems.append("parameters_hash_mismatch")
        return problems
    if event_type == "policy_evaluated":
        if keys != POLICY_KEYS:
            return ["details_shape_invalid"]
        problems = []
        if details["verdict"] not in _VERDICTS or not all(
            _is_text(details[k]) for k in ("capability", "target_ref", "matched_rule")
        ):
            problems.append("details_value_invalid")
        if not _is_text(details["classification"], optional=True) or not _is_text(details["risk_category"], optional=True):
            problems.append("details_value_invalid")
        envelope = details["envelope"]
        if envelope is not None and (
            not isinstance(envelope, Mapping)
            or set(envelope) != (ENVELOPE_KEYS if egress_recorded else ENVELOPE_KEYS_V1)
            or (egress_recorded and envelope["model_egress"] not in _EGRESS_VALUES)
            or not _is_text(envelope["capability"])
            or not _is_positive_int(envelope["timeout_seconds"])
            or not _is_positive_int(envelope["max_output_bytes"])
            or type(envelope["output_schema_hash"]) is not str
            or not _HASH.match(envelope["output_schema_hash"])
        ):
            problems.append("envelope_summary_invalid")
        return problems
    if event_type == "approval_requested":
        if keys != APPROVAL_KEYS:
            return ["details_shape_invalid"]
        context = details["risk_context"]
        if not isinstance(context, Mapping) or set(context) != RISK_CONTEXT_KEYS:
            return ["details_shape_invalid"]
        problems = []
        if not _is_text(details["step_id"]) or not _is_text(details["expires_at"], optional=True):
            problems.append("details_value_invalid")
        if not _is_text(context["capability"]) or not _is_text(context["target_ref"]):
            problems.append("details_value_invalid")
        if not verify_parameters(context["parameters_canonical"], context["parameters_hash"]):
            problems.append("parameters_hash_mismatch")
        return problems
    if event_type == "dispatch_started":
        if keys != DISPATCH_KEYS:
            return ["details_shape_invalid"]
        if not all(_is_text(details[k]) for k in ("capability", "target_ref", "step_id", "policy_decision_id")) or not all(
            _is_positive_int(details[k]) for k in ("attempt_number", "resolved_timeout_seconds", "max_output_bytes")
        ):
            return ["details_value_invalid"]
        return []
    return []


__all__ = [
    "APPROVAL_KEYS",
    "DISPATCH_KEYS",
    "ENVELOPE_KEYS",
    "FACT_CREDENTIAL_SHAPED",
    "FACT_INVALID",
    "FACT_NOT_SERIALIZABLE",
    "FACT_TOO_LARGE",
    "FACT_UNSAFE_TEXT",
    "MAX_FACT_CHARS",
    "MAX_OBJECTIVE_CHARS",
    "MAX_PARAMETERS_BYTES",
    "MAX_TARGET_REFS",
    "ORIGIN_KEYS",
    "POLICY_KEYS",
    "REQUEST_KEYS",
    "RISK_CONTEXT_KEYS",
    "AuditFactError",
    "envelope_summary",
    "objective_fact",
    "origin_details",
    "parameters_fact",
    "request_details",
    "risk_context_details",
    "text_fact",
    "validate_details",
    "verify_parameters",
]
