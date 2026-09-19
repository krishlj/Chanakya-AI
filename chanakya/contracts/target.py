"""Target contract — docs/CONTRACTS.md §6, extended per docs/TARGET-MANAGER.md
§3-§6 (Phase 4.5, "Target Identity & Lifecycle").

Metadata describing a resolvable target only — never a live connection or
credential handle (those belong to a future Target Adapter, not this
object; see docs/ARCHITECTURE.md §7 and the Phase 2 implementation notes'
"known limitations").

The Phase 4.5 additions (``status``, ``locator``, ``provenance``,
``last_verified_at``) are all optional/defaulted and additive, per
docs/TARGET-MANAGER.md §3 — no existing field's name, type, or meaning
changes, and every ``Target`` constructible before this phase remains
valid with zero changes.

Timestamp semantics (resolves Phase 4.3 finding F-3 — the
``registered_at``/``provenance.observed_at`` overlap):

- ``registered_at`` — identity-level, set once at first creation, never
  changes across later revisions (lifecycle transitions) of the same
  ``target_id``. The "birth certificate" timestamp of the identity.
- ``provenance.observed_at`` — set once with the provenance record itself
  (typically equal to ``registered_at`` for a ``user_declared`` target);
  it is *not* updated by ordinary lifecycle transitions — doing so would
  make it redundant with ``last_verified_at`` below.
- ``last_verified_at`` — the only one of the three that changes after
  creation. Updated exclusively by the two lifecycle checks
  docs/TARGET-MANAGER.md §12 names: ``DISCOVERED -> VALIDATED`` and an
  ``UNAVAILABLE -> AUTHORIZED`` recovery check.

None of the three, and no other field on ``Target``, ``TargetLocator``,
or ``TargetProvenance``, is ever consulted by anything to grant
authorization on its own (TM-INV-2, TM-INV-5) — see
``chanakya.policy.gateway`` for the one place ``status`` is read.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Mapping, Optional


class TargetStatus(str, Enum):
    """docs/TARGET-MANAGER.md §6 — six lifecycle states (``ACTIVE`` was
    deliberately excluded in the approved design as a derived,
    query-time fact about running investigations, not stored Target
    state)."""

    DISCOVERED = "discovered"
    VALIDATED = "validated"
    AUTHORIZED = "authorized"
    UNAVAILABLE = "unavailable"
    REVOKED = "revoked"
    ARCHIVED = "archived"


#: docs/TARGET-MANAGER.md §6 — the lifecycle state machine's valid
#: transitions. ``(none) -> DISCOVERED`` and ``(none) -> AUTHORIZED`` are
#: initial-registration entries, not "from" transitions, and are enforced
#: separately by ``TargetManager.register`` rather than appearing here.
#: ``ARCHIVED`` maps to an empty set: no outbound transition, the sole
#: terminal state.
ALLOWED_TARGET_STATUS_TRANSITIONS: Mapping[TargetStatus, frozenset] = {
    TargetStatus.DISCOVERED: frozenset({TargetStatus.VALIDATED, TargetStatus.ARCHIVED}),
    TargetStatus.VALIDATED: frozenset({TargetStatus.AUTHORIZED, TargetStatus.ARCHIVED}),
    TargetStatus.AUTHORIZED: frozenset({TargetStatus.UNAVAILABLE, TargetStatus.REVOKED}),
    TargetStatus.UNAVAILABLE: frozenset({TargetStatus.AUTHORIZED, TargetStatus.REVOKED}),
    TargetStatus.REVOKED: frozenset({TargetStatus.AUTHORIZED, TargetStatus.ARCHIVED}),
    TargetStatus.ARCHIVED: frozenset(),
}

#: Valid initial statuses for a brand-new registration
#: (docs/TARGET-MANAGER.md §6's two ``(none) -> *`` entries).
ALLOWED_INITIAL_TARGET_STATUSES = frozenset({TargetStatus.DISCOVERED, TargetStatus.AUTHORIZED})


# -- locator ------------------------------------------------------------------

#: docs/TARGET-MANAGER.md §5 (F-6): reject a URL-shaped locator value that
#: embeds userinfo credentials, e.g. ``https://user:pass@host/...``.
_URL_USERINFO_PATTERN = re.compile(r"://[^/@\s]+:[^/@\s]+@")

#: docs/TARGET-MANAGER.md §5 (F-6): reject a locator value carrying a
#: credential-shaped key=value pair (query string or similar), regardless
#: of locator_type. Best-effort, consistent with the project's existing
#: redaction-scanning posture (docs/THREAT-MODEL.md T-20's "novel secret
#: formats may evade" residual risk) — a real structural guarantee that no
#: field is *intended* to carry one, plus this check as a construction-time
#: backstop, not a claim of perfect detection.
_CREDENTIAL_PARAM_PATTERN = re.compile(
    r"(?i)(?:^|[?&;])(password|passwd|pwd|secret|token|api[_-]?key|access[_-]?key|"
    r"private[_-]?key|client[_-]?secret)\s*="
)


def _reject_credential_shaped_locator_value(value: str) -> None:
    if _URL_USERINFO_PATTERN.search(value):
        raise ValueError(
            "TargetLocator.value must not embed credentials (URL userinfo detected); "
            "resolve credentials via Configuration & Secrets Management, never in a locator"
        )
    if _CREDENTIAL_PARAM_PATTERN.search(value):
        raise ValueError(
            "TargetLocator.value must not embed credential-shaped parameters "
            "(e.g. password=/token=/api_key=); resolve credentials via Configuration & "
            "Secrets Management, never in a locator"
        )


@dataclass(frozen=True)
class TargetLocator:
    """docs/TARGET-MANAGER.md §5. Structured, adapter-interpreted "how to
    reach this target" — never itself an authorization mechanism (no
    consumer of this object may use it to grant or widen access) and
    never a credential carrier."""

    locator_type: str
    value: str

    def __post_init__(self) -> None:
        if not self.locator_type or not self.locator_type.strip():
            raise ValueError("TargetLocator.locator_type must be non-empty")
        if not self.value or not self.value.strip():
            raise ValueError("TargetLocator.value must be non-empty")
        _reject_credential_shaped_locator_value(self.value)


# -- provenance -----------------------------------------------------------------


class TargetProvenanceSource(str, Enum):
    """docs/TARGET-MANAGER.md §13."""

    USER_DECLARED = "user_declared"
    ADAPTER_DISCOVERED = "adapter_discovered"


@dataclass(frozen=True)
class TargetProvenance:
    """docs/TARGET-MANAGER.md §3/§13 — a lightweight envelope answering
    "how was this Target record created," distinct from
    ``EnvironmentContext``'s per-observation provenance (a future,
    Phase 4.8-scoped object). Never consulted for authorization
    (TM-INV-2)."""

    source: TargetProvenanceSource
    registered_by: str
    observed_at: str

    def __post_init__(self) -> None:
        if not self.registered_by or not self.registered_by.strip():
            raise ValueError("TargetProvenance.registered_by must be non-empty")
        if not self.observed_at or not self.observed_at.strip():
            raise ValueError("TargetProvenance.observed_at must be non-empty")


@dataclass(frozen=True)
class Target:
    target_id: str
    contract_version: str
    target_type: str
    display_name: str
    authorized_scope: str
    registered_at: str
    metadata: Mapping[str, Any] = field(default_factory=dict)
    owner_contact: Optional[str] = None
    status: TargetStatus = TargetStatus.AUTHORIZED
    locator: Optional[TargetLocator] = None
    provenance: Optional[TargetProvenance] = None
    last_verified_at: Optional[str] = None

    def __post_init__(self) -> None:
        # docs/CONTRACTS.md §6 validation requirements: "authorized_scope is
        # required and must be specific — a target record with an empty or
        # wildcard scope must be rejected at registration."
        if not self.authorized_scope or not self.authorized_scope.strip():
            raise ValueError("Target.authorized_scope must be non-empty and specific")
        if self.authorized_scope.strip() in {"*", "any", "all"}:
            raise ValueError("Target.authorized_scope must not be an unbounded wildcard")
