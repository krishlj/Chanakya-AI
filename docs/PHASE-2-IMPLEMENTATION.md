# Chanakya AI — Phase 2 Implementation Notes

This document records what was actually built for Phase 2 (the Security
Control Plane), how it enforces `docs/POLICY-GATEWAY.md`,
`docs/TOOL-REGISTRY.md`, and `docs/CAPABILITY-PERMISSION-MODEL.md`, and
what is deliberately not yet implemented. It does not change any design
document — it is a record of the implementation against the existing
design.

## Scope

Implemented: the Policy Gateway, the Security Tool Registry, and the
capability/permission model, plus the minimal supporting contract objects
(`ToolRequest`, `PolicyDecision`, `Target`) they require.

Deliberately not implemented: the Agent Runtime, the AI Agent, the LLM
Abstraction, MCP integration, any real security tool, and any UI. There is
no shell/subprocess/`eval`/`exec` call anywhere in `chanakya/` — verified
by inspection, since no execution path exists in this phase at all.

## Files created

```
chanakya/
  __init__.py                  package-level docstring, __version__
  contracts/
    __init__.py
    enums.py                   Verdict, Classification, RiskCategory, SUPPORTED_CONTRACT_VERSIONS
    tool_request.py            ToolRequest + from_dict() structural validation, MalformedRequestError
    policy_decision.py         PolicyDecision (immutable, frozen dataclass)
    target.py                  Target (immutable, frozen dataclass, rejects empty/wildcard scope)
  capability/
    __init__.py
    model.py                   ActionType, PermissionLevel, derive_permission_level(),
                                validate_action_type_classification() (CAP-INV-2), KNOWN_CATEGORIES
  registry/
    __init__.py
    models.py                  RegistryEntry + nested Provenance/RequiredPrivileges/ResourceLimits,
                                Status/ApprovalRequirement/TrustLevel/OSPrivilege/TargetAccess enums,
                                ALLOWED_STATUS_TRANSITIONS (lifecycle state machine)
    registry.py                SecurityToolRegistry: register/get/get_enabled/set_status/catalog_view
    exceptions.py               RegistryAdmissionError
  targets/
    __init__.py
    registry.py                TargetRegistry: minimal descriptive target store (register/get)
  policy/
    __init__.py
    reasons.py                 the closed matched_rule literal taxonomy
    schema.py                  minimal JSON-Schema-like parameter/output validator
    rules.py                   PolicyRule/PolicySet/RuleMatch/RuleConditions, find_matching_rules(),
                                validate_policy_set() (load-time invariants)
    gateway.py                 EvaluationContext, PolicyGateway.evaluate() — the enforcement point
tests/
  factories.py                 test-only builders: make_entry, make_request, make_rule
  conftest.py                  shared fixtures (registry, target_registry, gateway, contexts)
  test_gateway.py              Policy Gateway evaluation tests (the required 9 + bonus coverage)
  test_registry.py             Security Tool Registry tests (admission, lookup, lifecycle, catalog view)
  test_capability_model.py     permission-level derivation tests (P0–P4)
  test_policy_rules.py         PolicySet load-time validation tests (INV-1, CAP-INV-4, etc.)
pyproject.toml                 pytest configuration (testpaths = ["tests"])
.gitignore                     Python build/test artifacts
```

Two earlier Phase 2 design documents were extended (additively, nothing
removed) to match what the implementation needed to stay internally
consistent — see the "Update documentation" note at the end.

## Responsibilities

- **`chanakya.contracts`** — implements `docs/CONTRACTS.md`'s `ToolRequest`,
  `PolicyDecision`, and `Target` exactly as specified: same field names,
  same required/optional split, same enums. `ToolRequest.from_dict()` is
  the concrete form of "LLM output is schema-validated before being
  treated as a `ToolRequest`" (`ARCHITECTURE.md` §18) — it is the only
  place a raw dict becomes a trusted object.
- **`chanakya.capability`** — implements the `action_type` taxonomy and the
  permission-level (P0–P4) derivation from `docs/CAPABILITY-PERMISSION-MODEL.md`.
  `derive_permission_level()` is a pure function of a `RegistryEntry`'s
  already-set fields — there is no way to set a permission level directly.
- **`chanakya.registry`** — implements the closed Security Tool Registry.
  `SecurityToolRegistry.get_enabled()` is the only lookup the Gateway uses,
  and it is what makes a disabled capability indistinguishable from an
  unregistered one (REG-INV-3). `catalog_view()` is the concrete
  Capability Catalog View — the only Registry-derived structure a future
  LLM Abstraction would be allowed to read.
- **`chanakya.targets`** — a minimal, descriptive-only stand-in for target
  registration, providing just enough (`target_type`, `authorized_scope`)
  for the Gateway's scope checks. Not the future Target Manager (see
  "Known limitations").
- **`chanakya.policy`** — implements the Policy Gateway. `PolicyGateway.evaluate()`
  is the single enforcement point: it is the only function in this
  codebase that produces a `PolicyDecision`, and its return type is
  unconditional (§ Security controls, below).

## Execution flow

`PolicyGateway.evaluate(raw_request, context)` runs, in order, exactly the
flow specified in `docs/POLICY-GATEWAY.md` §10:

1. **Contract validation** (`ToolRequest.from_dict`) — malformed input
   denies immediately, before any Registry access.
2. **Registry lookup** (`registry.get_enabled`) — unknown or disabled
   capability denies with the same reason (REG-INV-3).
3. **Privilege ceiling check** — a capability declaring
   `required_privileges.os_privilege == elevated` denies if this
   deployment's configured ceiling is `standard_user` (SR-21). This is a
   policy-level stand-in for what a future Tool Layer execution
   environment must also enforce physically.
4. **Parameter schema validation** against the Registry's declared
   `parameters_schema`.
5. **Target scope check** — the target must be both in the caller-supplied
   `EvaluationContext.authorized_target_refs` (standing in for
   `InvestigationContext.target_refs`) and registered with a matching
   `target_type`.
6. **Rate/cumulative check** — any matching rule with
   `conditions.max_calls_per_investigation` fires only once the threshold
   is met; below threshold it contributes nothing.
7. **Explicit rule matching** — remaining matching rules apply in
   deny > require_approval > allow precedence order; an `allow` match
   against a `state_changing` capability is skipped even if present
   (INV-1 runtime assertion, defense in depth beyond the load-time check).
8. **Classification default** — `read_only` capabilities auto-allow
   *unless* the Registry's own `approval_requirement: required` flag
   pre-empts it (`docs/TOOL-REGISTRY.md` §3); `state_changing` capabilities
   always resolve to `require_approval`.

Every path returns a `PolicyDecision`; none of them call an LLM, and none
of them read `ToolRequest.rationale` or `expected_output_description`.

## Security controls implemented

- **Fail-closed by construction (SR-9)**: `PolicyGateway.evaluate()` wraps
  its entire body in a `try/except Exception` that converts *any*
  unexpected failure into `deny` / `matched_rule: "fail-closed-error"`.
  It has exactly one return type and cannot raise to its caller.
- **Deny-by-default (SR-1, SR-3)**: an unregistered, disabled, or
  quarantined capability is denied before reaching any rule; a
  `state_changing` capability can structurally never resolve to `allow`
  (INV-1), enforced both at `PolicySet` load time (`validate_policy_set`)
  and again at evaluation time (`_apply_rules`' explicit skip).
- **No arbitrary shell execution**: no capability schema, no rule, and no
  code path in this phase accepts or evaluates a free-form
  command/expression — there is no dispatch/execution code at all yet
  (SR-4 is satisfied by omission, and will need active enforcement once a
  Tool Layer exists).
- **Policy enforcement outside the LLM**: `PolicyGateway` and
  `SecurityToolRegistry` import nothing LLM-related, call nothing external,
  and — verified by a dedicated test
  (`test_rationale_never_influences_the_decision`) — produce byte-identical
  verdicts regardless of `rationale` content.
- **No self-granted permissions (REG-INV-1/REG-INV-2)**: `RegistryEntry`'s
  authoritative fields are plain constructor arguments; `provenance.self_declared_metadata`
  is stored but never read by any other module — grep confirms it is
  referenced only in its own definition and in test fixtures.
- **Registry overrides self-description**: the Gateway only ever calls
  `registry.get_enabled(capability)` — there is no code path that reads
  classification from anywhere else.
- **Least privilege (SR-2/SR-21)**: the `required_privileges` ceiling
  check in the evaluation flow.
- **CAP-INV-4**: `validate_policy_set` rejects any rule matching
  `action_type: destructive` without an explicit `target_id` allowlist.

## Tests performed

42 tests, all passing (`python -m pytest -v`):

- **The 9 required scenarios** — each has a directly-named test in
  `tests/test_gateway.py`: allowed read-only request, denied unknown tool,
  denied invalid capability (parameter-schema violation), denied
  unauthorized target, state-changing request requiring approval,
  malformed ToolRequest (two variants: missing field, unsupported
  `contract_version`), policy evaluation failure (simulated via a
  Registry subclass that raises), disabled tool (asserted to match the
  unknown-tool reason exactly), insufficient privilege (plus a companion
  test proving the same capability succeeds once the privilege ceiling is
  raised, so the check is a real ceiling and not a blanket deny).
- **Bonus Gateway coverage**: the Registry's `approval_requirement`
  floor overriding a read-only default; the rationale-manipulation
  regression test called for explicitly in `docs/POLICY-GATEWAY.md` §15;
  no-context-means-no-authorization; an explicit deny rule beating the
  classification default; a rate-limit rule that only fires once its
  threshold is reached.
- **Registry tests**: raw vs. gateway-facing lookup, CAP-INV-2 admission
  rejection, Capability Catalog View field-reduction and status/target-type
  filtering, the full lifecycle state machine including the
  quarantine-can-only-exit-via-review rule.
- **Capability model tests**: each `action_type` → `PermissionLevel`
  mapping (P1–P4), plus P0 for a disabled entry regardless of its
  `action_type`.
- **Policy rule validation tests**: INV-1, the category/action_type-scoped
  `allow` extension, CAP-INV-4, duplicate `rule_id` rejection, and
  rule-vs-Registry classification disagreement rejection — including that
  the `PolicyGateway` constructor itself refuses an invalid `PolicySet`.

## Known limitations

- **No real Target Manager/Adapters.** `chanakya.targets.TargetRegistry`
  is intentionally minimal — descriptive lookup only, no live
  connection/session handling. A real Target Manager (`ARCHITECTURE.md`
  §6-7) is Agent Runtime-phase work.
- **No Agent Runtime, so no real `InvestigationContext`.**
  `EvaluationContext` is a stand-in supplying just
  `authorized_target_refs` and `call_counts`; it does not persist, and it
  does not enforce `InvestigationRequest.constraints` (e.g. "read-only
  only") — that filtering was designed as an *Agent-visibility*
  optimization (`docs/TOOL-REGISTRY.md` §4), not a Gateway enforcement
  point, so its absence does not weaken enforcement, only Agent-side
  efficiency, which doesn't exist yet either.
- **No Audit Log.** Per `docs/POLICY-GATEWAY.md` §12, emitting
  `AuditEvent`s is the Agent Runtime's responsibility, not the Gateway's —
  there is no Runtime yet, so no audit trail is produced. Every
  `PolicyDecision` still carries everything a future Runtime needs to
  build one. *(Superseded: the Runtime has emitted `AuditEvent`s since
  Phase 3, and Phase 6 added the durable `chanakya.audit.FilesystemAuditLog`;
  see `docs/AGENT-RUNTIME.md` §14.)*
- **Minimal schema validator.** `chanakya.policy.schema` supports only the
  subset of JSON Schema used by this phase's examples (`type`,
  `properties`, `required`, `additionalProperties`, `items`, `enum`,
  `minimum`) — not a general-purpose implementation. Fine for now; a real
  Tool Layer may want a standard library here.
- **Rate limiting covers only call counts, not time.** `conditions.max_calls_per_investigation`
  is implemented; time-window/business-hours conditions described in
  `docs/POLICY-GATEWAY.md` §2 are not.
- **Privilege ceiling is policy-level only.** The `insufficient-privilege`
  check is a real, tested Gateway control, but it is a *proxy* for
  execution-environment enforcement — once a real Tool Layer exists, the
  execution environment itself must also be physically incapable of
  exceeding a capability's declared privilege (defense in depth this
  phase cannot provide on its own, since nothing executes yet).
- **No supply-chain integrity checking at runtime.** `Provenance.implementation_hash`
  is stored, but nothing re-verifies it (there is nothing to invoke yet);
  the automatic `enabled → quarantined` trip on a hash mismatch
  (`docs/TOOL-REGISTRY.md` §6) is not wired up.
- **No persistence.** Both registries and the policy set are in-memory
  only, constructed by the caller (tests, for now). Loading from
  versioned config files is future work.

## Documentation updated

- `README.md`: added an "Implementation status" section pointing here.
- `docs/TOOL-REGISTRY.md` and `docs/POLICY-GATEWAY.md`: no changes made
  in this implementation step (they were already extended with
  `category`/`action_type` and `match.category`/`match.action_type` in
  the prior design step). No contradiction between the design docs and
  this implementation was found, so no further edits were made to
  `ARCHITECTURE.md`, `docs/CONTRACTS.md`, `docs/THREAT-MODEL.md`,
  `docs/TOOL-REGISTRY.md`, `docs/POLICY-GATEWAY.md`, or
  `docs/CAPABILITY-PERMISSION-MODEL.md`.
