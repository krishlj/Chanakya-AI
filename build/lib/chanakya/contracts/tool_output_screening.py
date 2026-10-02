"""Tool-output sensitive-data screening — Phase 15 (docs/THREAT-MODEL.md
T-20, T-60).

The single authoritative screen for the content of a successful tool
result: exactly the payload that would be persisted as Evidence and could
become model context. The Agent Loop Controller calls it once, after the
capability envelope's JSON/size/schema checks and before Evidence or a
context source exists; the production Evidence recorder calls the same
function again on the payload it is handed, as a backstop, so an injected
or alternate recording path gets the same answer, never a different one.

What it detects is **credential-shaped** content, with the project's
existing patterns (URL userinfo, ``key=``/``key:`` credential assignments,
PEM private-key headers), in every string value and every mapping key, at
any depth. It is *not* general sensitive-data classification or DLP.

Behavior is detection + rejection, never redaction: a hit returns a fixed
reason code, the caller turns the result into an error whose message is
``sensitive_output_rejected: <CODE>``, and nothing of the content is
stored, retried, truncated or sent anywhere. The screen never raises and
never returns content.

Traversal is iterative and bounded (canonical size, depth and node count).
Anything that cannot be screened completely (non-JSON values, non-string
keys, over a bound) is rejected, never skipped.

The screening result carries no authority: it does not authorize a tool,
change a policy verdict, approve anything or alter risk.
"""
from __future__ import annotations

import re
from typing import Any, Mapping, Optional

from .finding import _TEXT_CREDENTIAL_PATTERN
from .target import _CREDENTIAL_PARAM_PATTERN, _URL_USERINFO_PATTERN

#: Version of this screening policy, recorded on every Evidence record that
#: passed it. A new pattern set needs a new version.
TOOL_OUTPUT_SCREENING_VERSION = "chanakya-tool-output-screen/1.0.0"
SUPPORTED_SCREENING_VERSIONS = frozenset({TOOL_OUTPUT_SCREENING_VERSION})

SENSITIVE_OUTPUT_PREFIX = "sensitive_output_rejected"
CREDENTIAL_SHAPED_VALUE = "CREDENTIAL_SHAPED_VALUE"
CREDENTIAL_SHAPED_KEY = "CREDENTIAL_SHAPED_KEY"
OUTPUT_UNSCREENABLE = "OUTPUT_UNSCREENABLE"
SCREENING_REASON_CODES = frozenset({CREDENTIAL_SHAPED_VALUE, CREDENTIAL_SHAPED_KEY, OUTPUT_UNSCREENABLE})

#: Bounds. The Evidence Store already refuses payloads over 64 KiB; these
#: keep the screen itself bounded whatever it is handed.
MAX_SCREEN_BYTES = 1_048_576
MAX_SCREEN_DEPTH = 32
MAX_SCREEN_NODES = 100_000

_VERSION = re.compile(r"^[a-z0-9][a-z0-9._/-]{0,63}$")

#: Tool output adds one value pattern to the shared set: an environment-
#: variable-style assignment whose name ends in a credential word, e.g.
#: ``KEY=...``, ``AWS_SECRET_ACCESS_KEY=...``, ``GITHUB_TOKEN=...``, as seen
#: in process command lines. Upper-case names only, so ordinary prose and
#: the observation field ``key`` are unaffected.
_ENV_ASSIGNMENT_PATTERN = re.compile(
    r"(?:^|[^A-Za-z0-9_])[A-Z0-9_]*(?:KEY|TOKEN|SECRET|PASSWORD|PASSWD|PWD|CREDENTIALS?)\s*=\s*\S"
)


def _credential_shaped(text: str) -> bool:
    return bool(
        _URL_USERINFO_PATTERN.search(text)
        or _CREDENTIAL_PARAM_PATTERN.search(text)
        or _TEXT_CREDENTIAL_PATTERN.search(text)
    )


def is_credential_shaped_value(text: str) -> bool:
    """Phase 16: THE canonical credential predicate for a string value.
    Tool output, the durable audit log (through ``screen_tool_output``) and
    the audit fact builders (``chanakya.contracts.audit_details``) all use
    it, so none of them is weaker than another (NX16-INV-4)."""
    return _credential_shaped(text) or bool(_ENV_ASSIGNMENT_PATTERN.search(text))


def is_credential_shaped_key(key: str) -> bool:
    """Phase 16: the canonical predicate for a mapping key. A key such as
    ``password`` carries a credential on its own."""
    return _credential_shaped(key) or _credential_shaped(f"{key}=x")


_credential_shaped_value = is_credential_shaped_value


def screen_tool_output(content: Any, *, max_bytes: int = MAX_SCREEN_BYTES) -> Optional[str]:
    """``None`` if ``content`` passes, otherwise one of
    ``SCREENING_REASON_CODES``. Never raises, never returns content."""
    # Imported here, not at module level: chanakya.contracts.evidence imports
    # this module, and chanakya.evidence imports chanakya.contracts.evidence
    # (the known contracts <-> evidence edge); a module-level import would
    # close that cycle. Same canonical bytes Evidence hashes, not a copy.
    from chanakya.evidence.hashing import canonical_bytes

    try:
        if not isinstance(content, Mapping):
            return OUTPUT_UNSCREENABLE
        if len(canonical_bytes(content)) > min(max_bytes, MAX_SCREEN_BYTES):
            return OUTPUT_UNSCREENABLE
        stack = [(content, 0)]
        nodes = 0
        while stack:
            item, depth = stack.pop()
            nodes += 1
            if nodes > MAX_SCREEN_NODES or depth > MAX_SCREEN_DEPTH:
                return OUTPUT_UNSCREENABLE
            if isinstance(item, str):
                if _credential_shaped_value(item):
                    return CREDENTIAL_SHAPED_VALUE
            elif item is None or isinstance(item, (bool, int, float)):
                continue
            elif isinstance(item, Mapping):
                for key, child in item.items():
                    if type(key) is not str:
                        return OUTPUT_UNSCREENABLE
                    # A key such as "password" carries a credential on its own
                    # (the same rule the Phase 12 parameter screen applies).
                    if is_credential_shaped_key(key):
                        return CREDENTIAL_SHAPED_KEY
                    stack.append((child, depth + 1))
            elif isinstance(item, (list, tuple)):
                stack.extend((child, depth + 1) for child in item)
            else:
                return OUTPUT_UNSCREENABLE
        return None
    except (TypeError, ValueError, RecursionError):
        return OUTPUT_UNSCREENABLE


def rejection_message(code: str) -> str:
    """The fixed ``ToolResult.error_message`` of a rejected output."""
    if code not in SCREENING_REASON_CODES:
        raise ValueError("unknown screening reason code")
    return f"{SENSITIVE_OUTPUT_PREFIX}: {code}"


def is_sensitive_output_rejection(error_message: Any) -> bool:
    """True for exactly the messages ``rejection_message`` produces."""
    prefix = f"{SENSITIVE_OUTPUT_PREFIX}: "
    return (
        isinstance(error_message, str)
        and error_message.startswith(prefix)
        and error_message[len(prefix):] in SCREENING_REASON_CODES
    )


def is_supported_screening_version(value: Any) -> bool:
    return type(value) is str and bool(_VERSION.match(value)) and value in SUPPORTED_SCREENING_VERSIONS


__all__ = [
    "CREDENTIAL_SHAPED_KEY",
    "CREDENTIAL_SHAPED_VALUE",
    "MAX_SCREEN_BYTES",
    "MAX_SCREEN_DEPTH",
    "MAX_SCREEN_NODES",
    "OUTPUT_UNSCREENABLE",
    "SCREENING_REASON_CODES",
    "SENSITIVE_OUTPUT_PREFIX",
    "SUPPORTED_SCREENING_VERSIONS",
    "TOOL_OUTPUT_SCREENING_VERSION",
    "is_credential_shaped_key",
    "is_credential_shaped_value",
    "is_sensitive_output_rejection",
    "is_supported_screening_version",
    "rejection_message",
    "screen_tool_output",
]
