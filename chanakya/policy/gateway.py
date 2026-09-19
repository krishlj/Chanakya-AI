"""PolicyGateway — docs/POLICY-GATEWAY.md.

The sole allow/deny/require_approval authority (docs/ARCHITECTURE.md §5).
Security invariant: ``evaluate()`` has exactly one return type,
``PolicyDecision``. It never raises to its caller — every internal failure
is caught here and converted into a fail-closed ``deny`` (SR-9).

Nothing in this module reads ``ToolRequest.rationale`` or
``ToolRequest.expected_output_description`` anywhere in the decision path
(docs/POLICY-GATEWAY.md §15) — grep this file; those two attribute names do
not appear anywhere in the evaluation logic below.
"""
from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, FrozenSet, List, Mapping, Optional

from chanakya.capability.model import PermissionLevel, derive_permission_level
from chanakya.contracts.enums import Classification, RiskCategory, Verdict
from chanakya.contracts.policy_decision import PolicyDecision
from chanakya.contracts.target import TargetStatus
from chanakya.contracts.tool_request import MalformedRequestError, ToolRequest
from chanakya.registry.models import ApprovalRequirement, OSPrivilege, RegistryEntry
from chanakya.registry.registry import SecurityToolRegistry
from chanakya.targets.registry import TargetRegistry

from . import reasons
from .rules import PolicyRule, PolicySet, find_matching_rules, validate_policy_set
from .schema import SchemaValidationError, validate as validate_schema

_CONTRACT_VERSION = "1.0.0"


def _utcnow_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _best_effort_request_id(raw_request: Any) -> str:
    """Used only to label a `deny` PolicyDecision when the request is too
    malformed to even parse — never for any decision logic."""
    try:
        value = raw_request.get("tool_request_id")  # type: ignore[union-attr]
        if isinstance(value, str) and value:
            return value
    except Exception:
        pass
    return "unknown"


@dataclass(frozen=True)
class EvaluationContext:
    """Everything the Gateway needs beyond the raw request itself, standing
    in for the not-yet-implemented Agent Runtime's ``InvestigationContext``
    (docs/CONTRACTS.md §2) and Target Manager (docs/ARCHITECTURE.md §6).

    ``authorized_target_refs`` mirrors ``InvestigationContext.target_refs``.
    ``call_counts`` is a simple per-capability counter standing in for the
    cumulative rate-limit state a real Runtime would track; see "known
    limitations" for what is intentionally not modeled here (time windows,
    business-hours constraints).
    """

    authorized_target_refs: FrozenSet[str] = field(default_factory=frozenset)
    call_counts: Mapping[str, int] = field(default_factory=dict)


class PolicyGateway:
    def __init__(
        self,
        registry: SecurityToolRegistry,
        target_registry: TargetRegistry,
        policy_set: PolicySet,
        *,
        max_available_privilege: OSPrivilege = OSPrivilege.STANDARD_USER,
        skip_policy_set_validation: bool = False,
    ) -> None:
        if not skip_policy_set_validation:
            validate_policy_set(policy_set, registry)
        self._registry = registry
        self._targets = target_registry
        self._policy_set = policy_set
        self._max_available_privilege = max_available_privilege

    # -- public API ---------------------------------------------------------

    def evaluate(self, raw_request: Mapping[str, Any], context: Optional[EvaluationContext] = None) -> PolicyDecision:
        """Never raises. Always returns a ``PolicyDecision`` (SR-9)."""
        context = context if context is not None else EvaluationContext()
        request_id_for_error = _best_effort_request_id(raw_request)
        try:
            return self._evaluate(raw_request, context)
        except MalformedRequestError as exc:
            return self._deny(request_id_for_error, reasons.MALFORMED_REQUEST, str(exc))
        except Exception as exc:  # fail-closed — docs/POLICY-GATEWAY.md §9
            return self._deny(
                request_id_for_error,
                reasons.FAIL_CLOSED_ERROR,
                f"internal Gateway error ({exc.__class__.__name__}): {exc}",
            )

    # -- evaluation flow — docs/POLICY-GATEWAY.md §10 ------------------------

    def _evaluate(self, raw_request: Mapping[str, Any], context: EvaluationContext) -> PolicyDecision:
        # Step 1 — contract validation.
        request = ToolRequest.from_dict(raw_request)

        # Step 2 — Registry lookup. A disabled/quarantined/unregistered
        # capability is indistinguishable (REG-INV-3).
        entry = self._registry.get_enabled(request.capability)
        if entry is None:
            return self._deny(
                request.tool_request_id,
                reasons.UNKNOWN_CAPABILITY,
                f"capability '{request.capability}' is not a known, enabled capability",
            )

        # Least-privilege environment check (SR-21) — a structural stand-in,
        # in this phase, for what the future Tool Layer's execution
        # environment must also enforce physically once real tools exist.
        if (
            entry.required_privileges.os_privilege == OSPrivilege.ELEVATED
            and self._max_available_privilege == OSPrivilege.STANDARD_USER
        ):
            return self._deny(
                request.tool_request_id,
                reasons.INSUFFICIENT_PRIVILEGE,
                f"capability '{request.capability}' requires elevated privilege; this deployment "
                f"is configured to run at standard_user (SR-21)",
            )

        # Step 3 — parameter schema validation.
        try:
            validate_schema(entry.parameters_schema, request.parameters)
        except SchemaValidationError as exc:
            return self._deny(request.tool_request_id, reasons.PARAMETER_SCHEMA_VIOLATION, str(exc))

        # Step 4 — target scope check (investigation scope AND registration
        # scope AND supported_target_types AND lifecycle status —
        # docs/TARGET-MANAGER.md §13/§14, Phase 4.5: a read-only addition to
        # an existing Target field; TargetManager owns the transition, this
        # is the Gateway's only reference to it).
        target = self._targets.get(request.target_ref)
        if (
            request.target_ref not in context.authorized_target_refs
            or target is None
            or target.target_type not in entry.supported_target_types
            or target.status != TargetStatus.AUTHORIZED
        ):
            return self._deny(
                request.tool_request_id,
                reasons.OUT_OF_SCOPE_TARGET,
                f"target '{request.target_ref}' is not an authorized target for capability "
                f"'{request.capability}'",
            )

        matches = find_matching_rules(
            self._policy_set,
            capability=request.capability,
            target_type=target.target_type,
            target_id=target.target_id,
            classification=entry.classification,
            category=entry.category,
            action_type=entry.action_type,
        )
        rate_limit_rules = [r for r in matches if r.conditions.max_calls_per_investigation is not None]
        plain_rules = [r for r in matches if r.conditions.max_calls_per_investigation is None]

        # Step 5 — rate/cumulative check.
        rate_limited = self._check_rate_limit(request, entry, context, rate_limit_rules)
        if rate_limited is not None:
            return rate_limited

        # Step 6 — explicit rule matching (deny > require_approval > allow).
        decision = self._apply_rules(request, entry, plain_rules)
        if decision is not None:
            return decision

        # Step 7 — classification default (with the Registry's own
        # approval-requirement floor pre-empting a read_only auto-allow,
        # docs/TOOL-REGISTRY.md §3).
        return self._classification_default(request, entry)

    def _check_rate_limit(
        self,
        request: ToolRequest,
        entry: RegistryEntry,
        context: EvaluationContext,
        rate_limit_rules: List[PolicyRule],
    ) -> Optional[PolicyDecision]:
        for rule in rate_limit_rules:
            limit = rule.conditions.max_calls_per_investigation
            assert limit is not None  # filtered by caller
            calls_so_far = context.call_counts.get(request.capability, 0)
            if calls_so_far >= limit:
                reason = rule.reason_template.format(capability=request.capability, limit=limit)
                return self._decide(request, entry, rule.effect, rule.rule_id, reason, rule.risk_category_override)
        return None

    def _apply_rules(
        self, request: ToolRequest, entry: RegistryEntry, plain_rules: List[PolicyRule]
    ) -> Optional[PolicyDecision]:
        for effect in (Verdict.DENY, Verdict.REQUIRE_APPROVAL, Verdict.ALLOW):
            for rule in plain_rules:
                if rule.effect != effect:
                    continue
                if effect == Verdict.ALLOW and entry.classification == Classification.STATE_CHANGING:
                    # INV-1 runtime assertion (defense in depth) — should be
                    # unreachable given load-time validation. Skip this rule
                    # rather than honor it.
                    continue
                reason = rule.reason_template.format(capability=request.capability, target=request.target_ref)
                return self._decide(request, entry, effect, rule.rule_id, reason, rule.risk_category_override)
        return None

    def _classification_default(self, request: ToolRequest, entry: RegistryEntry) -> PolicyDecision:
        if entry.classification == Classification.READ_ONLY:
            if entry.approval_requirement == ApprovalRequirement.REQUIRED:
                return self._decide(
                    request,
                    entry,
                    Verdict.REQUIRE_APPROVAL,
                    reasons.REGISTRY_APPROVAL_REQUIRED,
                    f"capability '{request.capability}' is read-only but the Registry flags it as "
                    f"requiring approval",
                )
            return self._decide(
                request,
                entry,
                Verdict.ALLOW,
                reasons.READ_ONLY_DEFAULT,
                f"capability '{request.capability}' is classified read_only and target is in scope",
            )
        return self._decide(
            request,
            entry,
            Verdict.REQUIRE_APPROVAL,
            reasons.STATE_CHANGING_DEFAULT_APPROVAL,
            f"capability '{request.capability}' is classified state_changing; human approval required",
        )

    # -- decision construction ----------------------------------------------

    def _decide(
        self,
        request: ToolRequest,
        entry: Optional[RegistryEntry],
        verdict: Verdict,
        matched_rule: str,
        reason: str,
        risk_category_override: Optional[RiskCategory] = None,
    ) -> PolicyDecision:
        risk_category = risk_category_override
        notes = None
        if entry is not None:
            if risk_category is None:
                risk_category = entry.default_risk_category
            if verdict == Verdict.REQUIRE_APPROVAL and derive_permission_level(entry) == PermissionLevel.P4:
                notes = "justification_required"
        return PolicyDecision(
            policy_decision_id=str(uuid.uuid4()),
            contract_version=_CONTRACT_VERSION,
            tool_request_id=request.tool_request_id,
            verdict=verdict,
            matched_rule=matched_rule,
            reason=reason,
            evaluated_at=_utcnow_iso(),
            risk_category=risk_category,
            notes=notes,
        )

    def _deny(self, tool_request_id: str, matched_rule: str, reason: str) -> PolicyDecision:
        return PolicyDecision(
            policy_decision_id=str(uuid.uuid4()),
            contract_version=_CONTRACT_VERSION,
            tool_request_id=tool_request_id,
            verdict=Verdict.DENY,
            matched_rule=matched_rule,
            reason=reason,
            evaluated_at=_utcnow_iso(),
        )
