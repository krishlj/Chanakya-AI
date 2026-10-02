"""Shared time helpers for the Runtime.

Two distinct notions of "now" are used throughout this package:

- ``utcnow_iso`` — an ISO 8601 UTC string, for every contract field that
  docs/CONTRACTS.md defines as a timestamp (``created_at``,
  ``started_at``, ...).
- ``utcnow_dt`` — a real ``datetime``, for internal duration math (the
  Resource Governor's per-investigation elapsed-time check) that a
  string cannot support without re-parsing it.

Both are ordinary functions (never a module-level mutable clock object)
so every component that needs "now" takes one as an injected
dependency — this is what lets tests use a fake, controllable clock
instead of real wall-clock time (docs/AGENT-RUNTIME.md's "avoid global
mutable state" code-quality expectation).
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Optional

_ISO_FORMAT = "%Y-%m-%dT%H:%M:%SZ"


def utcnow_iso() -> str:
    return datetime.now(timezone.utc).strftime(_ISO_FORMAT)


def utcnow_dt() -> datetime:
    return datetime.now(timezone.utc)


def parse_iso(value: str) -> datetime:
    return datetime.strptime(value, _ISO_FORMAT).replace(tzinfo=timezone.utc)


def add_seconds(value: str, seconds: int) -> str:
    """Used for approval-expiry math (docs/AGENT-RUNTIME.md §13):
    ``expires_at = add_seconds(requested_at, approval_expiry_seconds_default)``.
    Kept as a pure string-in/string-out helper so callers never need a
    second, datetime-typed clock dependency alongside the ISO-string
    clock used everywhere else in this package."""
    return (parse_iso(value) + timedelta(seconds=seconds)).strftime(_ISO_FORMAT)


def elapsed_seconds(start: str, end: str) -> Optional[float]:
    """Used by the Timeout Supervisor to measure a call's real duration.
    Returns ``None`` if either value cannot be parsed rather than
    raising — a timing measurement that can't be computed is treated the
    same as "no measurement available", never as a crash."""
    try:
        return (parse_iso(end) - parse_iso(start)).total_seconds()
    except ValueError:
        return None
