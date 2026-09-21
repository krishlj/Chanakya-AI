"""Evidence contract — docs/CONTRACTS.md §7 (Phase 5.2.1).

The durable, append-only, tamper-evident record of a ``ToolResult``,
forming the factual basis findings are built on. Every ``Evidence``
record is traceable back to the exact request, target, and step that
produced it (the four traceability fields ``tool_request_id``,
``tool_result_id``, ``target_id``, ``step_id`` — docs/CONTRACTS.md §7's
own validation requirement).

This module defines ONLY the data shape and its construction-time
structural validation — the same scope ``chanakya.contracts.tool_result``
and ``chanakya.contracts.audit_event`` have for their own contracts.
Nothing here performs persistence, hashing, or serialization/
deserialization: there is no durable Evidence Store yet
(``chanakya.runtime.evidence.StubEvidenceRecorder`` remains the only
existing hand-off boundary, unmodified by this phase), and
``content_hash`` is accepted here exactly as any other required string
field — this module never computes, re-derives, or verifies it against
anything. A future Evidence Store is the sole authority for what a valid
``content_hash`` actually is; this contract only records the field.

Security note: ``Evidence`` never carries the actual tool-output payload
— only ``storage_ref``, a pointer to wherever a future Evidence Store
places it (docs/CONTRACTS.md §7: "content" is not a contract field).
Every field is treated as opaque data; nothing here executes, parses,
or interprets a field's content, and no field is intended to carry a
credential (docs/THREAT-MODEL.md T-20).

``payload_hash`` (Phase 5.3, chained-hash design): an additive, optional
field — every existing construction call site that omits it continues
to work unchanged, defaulting to ``None``. When a Store persists a
separate payload object (the actual ``ToolResult.output``) alongside
this metadata record, ``payload_hash`` carries that payload's own
Store-computed integrity hash. Because ``content_hash`` above already
covers "every field except itself," including ``payload_hash`` in that
set (once set) cryptographically binds the metadata record to the
payload it references — this is the chain: tampering with the payload
alone is caught by re-hashing it against the stored ``payload_hash``;
tampering with ``payload_hash`` itself is caught by ``content_hash``'s
own existing re-verification. Like ``content_hash``, this field is
never authoritative merely because a caller supplied it — only a real
Evidence Store may assign it (``chanakya.evidence.store.EvidenceStore``).
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional, Sequence

from .enums import SUPPORTED_CONTRACT_VERSIONS, Classification

_REQUIRED_STRING_FIELDS = (
    "evidence_id",
    "contract_version",
    "investigation_id",
    "step_id",
    "tool_request_id",
    "tool_result_id",
    "target_id",
    "capability",
    "recorded_at",
    "content_hash",
    "storage_ref",
)


@dataclass(frozen=True)
class Evidence:
    evidence_id: str
    contract_version: str
    investigation_id: str
    step_id: str
    tool_request_id: str
    tool_result_id: str
    target_id: str
    capability: str
    recorded_at: str
    content_hash: str
    storage_ref: str
    #: docs/CONTRACTS.md §7: "Copied from the Registry at capture time, so
    #: history remains accurate even if the Registry entry later changes."
    #: A historical snapshot, never re-derived from a live Registry lookup
    #: (see chanakya.contracts.policy_decision.PolicyDecision.classification
    #: for where that snapshot is taken).
    classification: Classification
    tags: Sequence[str] = field(default_factory=tuple)
    redactions_applied: Optional[bool] = None
    #: Phase 5.3 — Store-computed integrity hash of a separately persisted
    #: payload object (the actual ToolResult.output), chained into
    #: content_hash above once set. ``None`` when no payload was
    #: persisted for this record (e.g. every pre-Phase-5.3 record, or any
    #: record for which no payload was supplied).
    payload_hash: Optional[str] = None

    def __post_init__(self) -> None:
        for field_name in _REQUIRED_STRING_FIELDS:
            value = getattr(self, field_name)
            if not isinstance(value, str) or not value:
                raise ValueError(f"Evidence.{field_name} must be a non-empty string")

        if self.contract_version not in SUPPORTED_CONTRACT_VERSIONS:
            raise ValueError(f"unsupported contract_version: {self.contract_version!r}")

        if not isinstance(self.classification, Classification):
            raise ValueError("Evidence.classification must be a Classification value")

        if not isinstance(self.tags, (tuple, list)) or any(not isinstance(tag, str) for tag in self.tags):
            raise ValueError("Evidence.tags must be a sequence of strings")

        if self.redactions_applied is not None and not isinstance(self.redactions_applied, bool):
            raise ValueError("Evidence.redactions_applied must be a boolean if present")

        if self.payload_hash is not None and (not isinstance(self.payload_hash, str) or not self.payload_hash):
            raise ValueError("Evidence.payload_hash must be a non-empty string if present")
