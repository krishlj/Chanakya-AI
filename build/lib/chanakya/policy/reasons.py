"""The closed, enumerable ``matched_rule`` reason taxonomy — docs/POLICY-GATEWAY.md §11.

Every value here is a fixed literal produced directly by the Gateway's
evaluation flow (as opposed to a named ``PolicyRule.rule_id``, which is
whatever an admin called their own rule). Keeping these as named constants
(rather than inline string literals scattered through ``gateway.py``) is
what keeps the set closed and greppable.
"""

MALFORMED_REQUEST = "malformed-request"
UNKNOWN_CAPABILITY = "unknown-capability"
INSUFFICIENT_PRIVILEGE = "insufficient-privilege"
PARAMETER_SCHEMA_VIOLATION = "parameter-schema-violation"
OUT_OF_SCOPE_TARGET = "out-of-scope-target"
READ_ONLY_DEFAULT = "read-only-default"
STATE_CHANGING_DEFAULT_APPROVAL = "state-changing-default-approval"
REGISTRY_APPROVAL_REQUIRED = "registry-approval-required"
FAIL_CLOSED_ERROR = "fail-closed-error"

#: docs/POLICY-GATEWAY.md §8 — the terminal fallback for a Registry entry
#: with an invalid/missing classification. Structurally unreachable in this
#: implementation because ``Classification`` is a two-value enum enforced
#: by ``RegistryEntry``'s own validation, but retained so the constant
#: exists if that ever changes, per the design doc's own note that this
#: path "mainly guards a defensive programming gap."
DEFAULT_DENY_NO_CLASSIFICATION = "default-deny-no-classification"
