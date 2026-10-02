"""Durable Audit Log — Phase 6.

See ``chanakya.audit.log`` for the implementation and its design notes.
``FilesystemAuditLog`` implements ``chanakya.runtime.audit.AuditSink``; a
composition root passes it to ``AuditEmitter(sink=...)`` and shares that one
emitter between ``InvestigationManager`` and ``AgentLoopController``.
"""
from __future__ import annotations

from .log import (
    MAX_RECORD_BYTES,
    SYSTEM_STREAM,
    AuditLogError,
    AuditRecord,
    AuditRecordTooLargeError,
    AuditSequenceCollisionError,
    CorruptAuditLogError,
    CredentialShapedAuditDataError,
    FilesystemAuditLog,
    InvalidAuditIdentifierError,
)

__all__ = [
    "FilesystemAuditLog",
    "AuditRecord",
    "MAX_RECORD_BYTES",
    "SYSTEM_STREAM",
    "AuditLogError",
    "InvalidAuditIdentifierError",
    "AuditSequenceCollisionError",
    "AuditRecordTooLargeError",
    "CredentialShapedAuditDataError",
    "CorruptAuditLogError",
]
