"""Parameter-schema validation for the Policy Gateway.

Phase 11: the validator moved to ``chanakya.capability.schema`` so the Tool
Layer can validate capability output without importing ``chanakya.policy``.
This module re-exports it unchanged; the Gateway's behavior is the same
except that error messages no longer echo the rejected value.
"""
from __future__ import annotations

from chanakya.capability.schema import SchemaValidationError, validate

__all__ = ["SchemaValidationError", "validate"]
