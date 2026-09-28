# Chanakya AI — Agent Runtime Design (Phase 3)

This document is the Phase 3 design specification for the **Agent
Runtime** defined in `ARCHITECTURE.md` §3. It builds on, and does not
redesign, `ARCHITECTURE.md`, `docs/CONTRACTS.md`, `docs/THREAT-MODEL.md`,
`docs/POLICY-GATEWAY.md`, `docs/TOOL-REGISTRY.md`, and
`docs/CAPABILITY-PERMISSION-MODEL.md`. No implementation code exists yet
— this is design only.

The Agent Runtime is the **controlled execution and orchestration layer**
between the AI Agent (reasoning) and the security control plane (Policy
Gateway, Security Tool Registry, and — in a later phase — the Tool
Layer). It is code, not a model: deterministic, auditable, and the only
stateful, trusted orchestrator in the system (`ARCHITECTURE.md` §3).

---

## Design principle (non-negotiable)

> **The Agent Runtime executes; it never decides.** Every capability the
> Runtime touches on the Agent's behalf has already been (a) registered
> in the Security Tool Registry, (b) evaluated by the Policy Gateway, and
> — where the verdict requires it — (c) explicitly accepted by a human
> approver. The Runtime's job is to make those three facts true before
> anything ever runs, to make it structurally impossible to skip one of
> them, and to record, unconditionally, that they happened. The Runtime
> holds no opinion of its own about whether an action is safe — that
> opinion belongs entirely to the Policy Gateway and, for state-changing
> actions, to the human approver.

This restates `ARCHITECTURE.md` §3/§17, `docs/THREAT-MODEL.md`
SR-5/SR-6/SR-7/SR-9, and is the organizing constraint behind every
section below.

---

## The Runtime MUST NOT

| # | Prohibition | Structural mechanism | Invariant | Threats addressed |
|---|---|---|---|---|
| 1 | Make security policy decisions itself | The Runtime has no allow/deny/require_approval logic of its own; `PolicyGateway.evaluate()` is the only source of a verdict | RT-INV-1 | T-15, T-19 |
| 2 | Bypass the Policy Gateway | The Dispatcher's only entry point requires a `PolicyDecision` object as a mandatory argument — there is no dispatch call that omits it | RT-INV-1 | T-15 |
| 3 | Allow arbitrary shell execution | The Runtime contains no shell/subprocess/`eval`/`exec` call and constructs no command string from Agent-controlled input; dispatch is a typed call keyed by a Registry capability name | RT-INV-8 | T-11 |
| 4 | Allow the LLM to directly execute tools | The Agent's only output artifact is `AgentTurnOutput`/`ToolRequest` (a proposal); the LLM Abstraction and Agent have no reference to the Dispatcher, the Tool Layer, or any target handle | RT-INV-1, RT-INV-8 | T-02, T-06 |
| 5 | Allow tools to bypass the Tool Registry | The Dispatcher only ever invokes a capability that a `PolicyDecision` was issued for, and a `PolicyDecision` can only be issued for a capability the Gateway found via `registry.get_enabled()` | RT-INV-1, RT-INV-8 | T-04, T-05 |
| 6 | Automatically approve state-changing actions | No default/timeout-accept path exists anywhere in the Approval Coordinator; an expired or unanswered `ApprovalRequest` never becomes an accepted decision | RT-INV-2, RT-INV-3 | T-16, T-19 |
| 7 | Treat tool output as trusted instructions | The Context Assembler is the sole place tool/target output re-enters an LLM prompt, and it always wraps it as delimited, clearly-marked data | RT-INV-7 | T-03, T-12, T-13 |

---

## Runtime invariants (RT-INV)

Referenced throughout this document; each is a structural property of
the implementation, not a convention an implementer is trusted to
remember.

- **RT-INV-1** — No dispatch occurs without a favorable, matching
  `PolicyDecision` (`verdict == allow`, or `verdict == require_approval`
  paired with an accepted `ApprovalDecision`). This is enforced by
  interface design: the Dispatcher's function signature requires a
  `PolicyDecision` (and, where applicable, an `ApprovalDecision`) as
  parameters it cannot be called without.
- **RT-INV-2** — No dispatch of a `require_approval` step proceeds
  without an `ApprovalDecision` with `decision: accept`, bound to that
  specific `approval_request_id`. A decision for one request can never be
  applied to another.
- **RT-INV-3** — No implicit or timeout-default approval exists. An
  `ApprovalRequest` that expires or is never answered resolves to "no
  dispatch," never to "proceed."
- **RT-INV-4** — Retries never reuse a prior `PolicyDecision` or
  `ApprovalDecision`. Every retry attempt is a materially new
  `ToolRequest` (new `tool_request_id`), independently evaluated by the
  Gateway and, if applicable, independently re-approved.
- **RT-INV-5** — The Runtime never rewrites, "fixes," auto-corrects, or
  reinterprets a malformed or denied `ToolRequest` on the Agent's behalf.
  A validation failure or a denial is surfaced to the Agent as
  information for its next turn, unmodified.
- **RT-INV-6** — Every `InvestigationContext` transition and every
  step-level transition emits exactly one `AuditEvent`, unconditionally,
  including internal Runtime errors and fail-closed outcomes. A failure
  to write an `Evidence` or `AuditEvent` record halts the step rather
  than letting the corresponding action be treated as having happened
  without a record.
- **RT-INV-7** — Tool/target output is only ever reintroduced into an
  LLM prompt as clearly delimited, structurally-marked **data**, never as
  an instruction-formatted segment. This is enforced at exactly one
  place: the Context Assembler.
- **RT-INV-8** — The Runtime contains no shell/subprocess/`eval`/`exec`
  call and no code path that assembles one from Agent- or
  target-controlled input. The Dispatcher's only action is a typed call
  into the (future) Tool Layer, keyed by a Registry-registered
  capability name that a `PolicyDecision` was already issued for.
- **RT-INV-9** — Cancellation is cooperative: it prevents the *next* step
  from starting; it never interrupts a dispatch already in flight in a
  way that could leave `Evidence`/`AuditEvent` records inconsistent or
  half-written.
- **RT-INV-10** — At most one `ToolRequest` is in flight (proposed →
  dispatched → resulted) per investigation at any time. Step ordering
  within one investigation is strictly sequential.
- **RT-INV-11** — No credential ever appears in `InvestigationContext`,
  `AgentTurnOutput`, `ToolRequest`, `DispatchInstruction`, a Runtime log,
  or an `AuditEvent`. The Runtime itself never holds a target credential
  — that remains scoped to a future Target Adapter, resolved at dispatch
  time from Configuration & Secrets (`ARCHITECTURE.md` §15).

---

## Lifecycle overview

```
InvestigationRequest
    ↓
InvestigationContext                    (Investigation Manager creates it; status = pending)
    ↓
Agent proposes ToolRequest              (via AgentTurnOutput, inside the Agent loop; status = running)
    ↓
Runtime receives request                (ToolRequest Intake — contract/schema validation only)
    ↓
Policy Gateway evaluates                (Policy Gateway Client — the only call path in)
    ↓
PolicyDecision
    ↓
ALLOW / DENY / REQUIRE_APPROVAL
    ↓
If REQUIRE_APPROVAL → Human Approval    (status = awaiting_approval, blocks this step only)
    ↓
If allowed (directly, or after accept) → controlled dispatch   (Dispatcher; RT-INV-1/RT-INV-2)
    ↓
ToolResult                              (Result Handler)
    ↓
Evidence                                (Evidence Writer — append-only, hashed)
    ↓
Agent continues (next turn) or investigation terminates (completed / halted / failed)
```

Every arrow in this diagram also produces at least one `AuditEvent`
(RT-INV-6); that is omitted above for readability and made explicit in
the per-section detail and in the Tool Execution Flow diagram below.

---

## Runtime component map

The Runtime is decomposed into the following components. None of them
is individually a new trust boundary — collectively they *are* the
trusted control layer (`ARCHITECTURE.md` §3) — but separating them
keeps each one's job (and therefore each one's review surface) small and
singular.

| Component | Responsibility | Inputs | Outputs | Trust level | Security boundary |
|---|---|---|---|---|---|
| **Investigation Manager** | Owns investigation creation and top-level lifecycle transitions | `InvestigationRequest` (human-originated), cancellation signals | `InvestigationContext` (created/updated), lifecycle `AuditEvent`s | Trusted control code | TB-1 (validates human input before trusting it as scope) |
| **Investigation State Store** | Authoritative, single-writer store of `InvestigationContext` and step records for the life of an investigation | State transitions from every other component | Current `InvestigationContext` snapshot on read | Trusted control code | TB-8 (internal; not directly Agent- or tool-writable) |
| **Context Assembler** | Builds the bounded context handed to the LLM Abstraction each turn: objective, Capability Catalog View, recent Evidence, prior Findings | `InvestigationContext`, `Evidence` (semi-trusted), Capability Catalog View (trusted) | A context payload for the LLM Abstraction | Trusted control code; **consumes semi-trusted tool/target output** | TB-3, TB-6 inbound, TB-7 — enforces RT-INV-7 |
| **Agent Loop Controller** | Drives the turn-by-turn loop; parses `AgentTurnOutput`; routes to ToolRequest intake, Finding/Recommendation storage, or conclusion | `AgentTurnOutput` (untrusted) | Routed calls to other components; loop continuation or termination signal | Trusted control code; **consumes untrusted Agent output** | TB-3 — schema-validates before trusting anything |
| **ToolRequest Intake** | Structural/contract validation of the Agent's raw proposal into a trusted `ToolRequest`, or a `MalformedRequestError` | Raw `AgentTurnOutput.tool_request` payload (untrusted) | A validated `ToolRequest`, or a surfaced validation error | Trusted control code; **input is untrusted** | TB-3 |
| **Policy Gateway Client** | The single, structurally-required call path from the Runtime to `PolicyGateway.evaluate()` | `ToolRequest`, `EvaluationContext` (built from `InvestigationContext`) | `PolicyDecision` | Trusted control code, calling trusted code | TB-4 — the only crossing point |
| **Approval Coordinator** | Creates an `ApprovalRequest` for a `require_approval` verdict; blocks that step; awaits and records an `ApprovalDecision` | `PolicyDecision` (verdict = require_approval), human input | `ApprovalRequest`, `ApprovalDecision` | Trusted control code; human decision is the trust anchor | TB-5 |
| **Dispatcher** | The only code path permitted to invoke the (future) Tool Layer | `DispatchInstruction` + a favorable `PolicyDecision` (+ accepted `ApprovalDecision` where applicable) | A call into the Tool Layer; raw `ToolResult` on return | Trusted control code | TB-6 outbound (credentials never present here) |
| **Result Handler** | Normalizes/validates the returned `ToolResult` shape; routes it to Evidence Writer and back into context for the next turn | `ToolResult` (semi-trusted — target-originated) | Normalized `ToolResult`, trigger to Evidence Writer | Trusted control code; **output is semi-trusted** | TB-6 inbound |
| **Evidence Writer** | The only component with write access to the Evidence Store; computes `content_hash`, assigns provenance fields | `ToolResult`, step/request identifiers | `Evidence` record | Trusted control code | TB-8 (write-only, append-only) |
| **Audit Emitter** | The only component with write access to the Audit Log; emits one `AuditEvent` per transition, unconditionally | Every other component's transition notifications | `AuditEvent` record | Trusted control code | TB-8 (write-only, append-only) |
| **Timeout Supervisor** | Enforces per-step (the effective timeout: Registry `default_timeout_seconds` capped by `RuntimeExecutionLimits.default_step_timeout_seconds`, Phase 11; post-hoc) and per-investigation (`RuntimeExecutionLimits`) timeouts | Wall-clock time, in-flight step/investigation state | Timeout signal → treated as a step or investigation failure | Trusted control code | Internal — bounds T-27 |
| **Retry Controller** | Bounded, policy-driven retry for transient tool/LLM failures; never retries a denial | Step/turn failure classification, `RuntimeExecutionLimits.max_retries_per_step` | A new attempt (new `tool_request_id`) or a terminal step failure | Trusted control code | Internal — enforces RT-INV-4 |
| **Resource Governor** | Tracks per-capability call counts (for the Gateway's rate-limit rules), step budgets, and concurrency caps | Step completions, `RuntimeExecutionLimits` | `EvaluationContext.call_counts`; budget-exceeded signals | Trusted control code | Internal — bounds T-08, T-27 |
| **Cancellation Handler** | Accepts an operator-initiated cancellation signal and drives a cooperative, safe shutdown of one investigation | Human cancellation command | Lifecycle transition to `halted`, `AuditEvent` | Trusted control code; human-triggered | TB-1 — enforces RT-INV-9 |

---

## 1. Investigation/session lifecycle

**Owner**: Investigation Manager.

An investigation begins only from a validated `InvestigationRequest`
(`docs/CONTRACTS.md` §1) — the sole contract that originates directly
from a human, outside the agent loop. The Investigation Manager:

1. Validates the request per `CONTRACTS.md` §1's own validation rules
   (`objective` non-empty; every `requested_targets` entry already known
   to the Target Manager/registry; `submitted_by` identifies a human).
   A request that fails this validation **never produces an
   `InvestigationContext`** — it is rejected back to the CLI as an input
   error, not as a `failed` investigation (there is nothing yet to fail).
2. On success, creates the initial `InvestigationContext`
   (`CONTRACTS.md` §2) with `status: pending`, `target_refs` copied from
   the request's resolved targets, empty `step_history`/`evidence_refs`/
   `finding_refs`.
3. Registers the investigation with the Resource Governor (applies
   `RuntimeExecutionLimits.max_concurrent_investigations`, §18 below) —
   an investigation that would exceed the concurrency cap stays queued,
   not silently dropped or force-started.
4. Hands control to the Agent Loop Controller, which transitions
   `status` to `running` and begins the loop (§3).
5. Owns every subsequent lifecycle transition (§15) until a terminal
   state is reached (§16), at which point the `InvestigationContext` is
   retained (never deleted) for audit/review.

A session, in this design, is exactly one investigation's lifetime — the
Runtime does not multiplex several investigations onto one
`InvestigationContext`, and one investigation's context is never shared
or merged with another's (see §19, Concurrency).

---

## 2. InvestigationContext management

**Owner**: Investigation State Store, written to by every other
component through the Investigation Manager.

`InvestigationContext` (`CONTRACTS.md` §2) is the Runtime-owned,
evolving record of one investigation. This phase's design treats it as
the **single source of truth** other components read from and propose
updates to — no component holds a competing copy of `status`,
`step_history`, or the `*_refs` arrays that could drift out of sync.

Rules enforced by the Investigation State Store, restating and making
concrete `CONTRACTS.md` §2's own validation requirements:

- `investigation_id` is assigned once, at creation, and is immutable.
- `status` may only change via the transitions defined in §15 — an
  attempted invalid transition (e.g. `pending → completed`) is a Runtime
  programming error, not a business outcome, and is treated the same as
  any other internal error (fail-closed to `failed`, per §11).
- `step_history` gains exactly one new `StepRecord` (see "Additional
  contracts," below) per proposed `ToolRequest` — never a partial or
  retroactively-edited entry. A retried step is a **new** `StepRecord`
  with its own `step_id`/`tool_request_id` and an `attempt_number`
  linking it to the earlier attempt for readability, not a mutation of
  the earlier record (mirrors `Evidence`/`AuditEvent`'s append-only
  philosophy).
- `evidence_refs`/`finding_refs`/`risk_assessment_refs`/
  `recommendation_refs` only ever gain entries that resolve to records
  that already exist by the time the reference is added — the Runtime
  writes the underlying record first, then appends the reference,
  never the reverse.
- `current_step_id` is set when a step begins and cleared when it
  reaches a terminal step-state (§15's step-level machine); it is never
  left pointing at a step that has already concluded.
- `updated_at` changes on every write; `created_at` never does.

---

## 3. Agent loop

**Owner**: Agent Loop Controller, using the Context Assembler and the
LLM Abstraction (Phase 4+ concern, treated here as an external
dependency with a stable interface).

Each iteration:

1. **Budget check** (Resource Governor / Timeout Supervisor) — if the
   per-investigation step budget or wall-clock timeout is already
   exhausted, the loop does not start another turn; the investigation
   transitions to `halted` (§16).
2. **Context assembly** (Context Assembler) — builds the turn's input:
   the objective, the Capability Catalog View (`docs/TOOL-REGISTRY.md`
   §4 — filtered, field-reduced; the Runtime never hands the Agent the
   raw Registry), recent `Evidence` wrapped as delimited data (RT-INV-7),
   and prior `Finding`s/`Recommendation`s for continuity. Secrets are
   never present here by construction (RT-INV-11) — there is nothing to
   redact because nothing credential-shaped was ever placed in
   `InvestigationContext` in the first place.
3. **Model call** (LLM Abstraction) — produces raw model output, which
   the LLM Abstraction parses into a structured `AgentTurnOutput` (see
   "Additional contracts," below) with schema validation. Malformed
   output is an Agent-layer error (`ARCHITECTURE.md` §16): the Runtime
   does not guess at intent.
4. **Routing** (Agent Loop Controller), based on `AgentTurnOutput`:
   - `next_action: conclude` → investigation transitions to `completed`
     (§16).
   - `next_action: propose_tool_request` → any accompanying `Finding`s/
     `Recommendation`s are stored first (validated per `CONTRACTS.md` §8
     /§10 — a `Finding` with empty `evidence_refs` is rejected outright,
     per SR-17), then the `tool_request` payload is handed to ToolRequest
     Intake (§4) and the full Policy Gateway → (Approval) → Dispatch →
     Evidence pipeline (§§5-9) runs for that one step.
   - Malformed `AgentTurnOutput` → bounded retry via the Retry Controller
     (§12), with corrective context (the validation error) added to the
     *next* context assembly — never silently repaired by the Runtime.
5. **Loop continuation** — once the step reaches a terminal step-state
   (§15), control returns to step 1 for the next turn.

```mermaid
flowchart TD
    Start([Loop iteration begins]) --> Budget{Step / time budget remaining?}
    Budget -- no --> Halt[Transition: running to halted]
    Budget -- yes --> Assemble["Context Assembler builds bounded context:
    objective, Capability Catalog View,
    recent Evidence as delimited DATA, prior Findings"]
    Assemble --> Call[LLM Abstraction calls the model]
    Call --> Parse{AgentTurnOutput schema-valid?}
    Parse -- no --> Malformed[Runtime records error,
    surfaces as information]
    Malformed --> RetryCheck{Retry budget remains?}
    RetryCheck -- yes --> Assemble
    RetryCheck -- no --> Fail[Transition: running to failed]
    Parse -- yes --> Route{next_action?}
    Route -- conclude --> Complete[Transition: running to completed]
    Route -- propose_tool_request --> Store[Store any Findings / Recommendations]
    Store --> Intake["ToolRequest Intake to Policy Gateway integration
    (see Tool Execution Flow diagram)"]
    Intake --> NextIter[StepRecord appended to InvestigationContext]
    NextIter --> Start

    style Halt fill:#241f33,stroke:#9b59b6,color:#f5f5f5
    style Fail fill:#3a1f1f,stroke:#c0392b,color:#f5f5f5
    style Complete fill:#1f2f1f,stroke:#2ecc71,color:#f5f5f5
```

---

## 4. ToolRequest intake

**Owner**: ToolRequest Intake.

This is the first point the Agent's untrusted output is treated as a
candidate `ToolRequest` at all. It performs exactly the structural
validation `ToolRequest.from_dict()` already implements (Phase 2,
`chanakya/contracts/tool_request.py`) — required fields present,
`contract_version` supported, `proposed_by == "agent"`, `parameters` is
an object. It does **not** validate `parameters` against a capability's
schema (that is the Gateway's job, using the Registry's declared schema
— `docs/POLICY-GATEWAY.md` §10 step 3) and does **not** consult the
Registry or any policy rule itself. A validation failure here never
reaches the Gateway; it is recorded and surfaced to the Agent as
information (RT-INV-5), consistent with `docs/POLICY-GATEWAY.md` §14's
own `malformed-request` path.

**Inputs**: raw `tool_request` payload from `AgentTurnOutput` (untrusted).
**Outputs**: a valid `ToolRequest`, or a `MalformedRequestError` handed
back to the Agent Loop Controller.
**Trust level**: trusted control code; input is untrusted.
**Security boundary**: TB-3 (`docs/THREAT-MODEL.md`).

---

## 5. Policy Gateway integration

**Owner**: Policy Gateway Client.

The Runtime's relationship to the Policy Gateway is intentionally
narrow: build an `EvaluationContext` from the current
`InvestigationContext` (authorized target refs = `target_refs`; call
counts = the Resource Governor's per-capability counters for this
investigation) and call `PolicyGateway.evaluate(tool_request,
evaluation_context)`. That is the **entire** interface — the Runtime
never inspects Registry entries or policy rules directly, never
second-guesses a `PolicyDecision`, and never calls `evaluate()` more than
once for the same `ToolRequest` (a materially new decision requires a
materially new `ToolRequest`, per `docs/POLICY-GATEWAY.md` §15 point 5).

`PolicyGateway.evaluate()` is documented to never raise and to always
return a `PolicyDecision` (fail-closed by construction, Phase 2). The
Runtime's Policy Gateway Client still wraps the call defensively — if a
future Gateway implementation ever violates its own contract and raises,
that exception is caught here and converted to the same effect as a
`deny`/`fail-closed-error` decision, never allowed to propagate into a
dispatch decision (defense in depth, mirroring the Gateway's own
internal `try/except`).

Every `PolicyDecision` received — `allow`, `deny`, or
`require_approval` — immediately produces one `AuditEvent`
(`event_type: policy_evaluated`), per `docs/POLICY-GATEWAY.md` §12,
**before** the Runtime acts on the verdict.

**Inputs**: `ToolRequest`, `EvaluationContext`.
**Outputs**: `PolicyDecision`; one `AuditEvent`.
**Trust level**: trusted code calling trusted code.
**Security boundary**: TB-4 — RT-INV-1.

---

## 6. Tool Registry integration

**Owner**: indirectly, via the Policy Gateway. The Runtime **never**
queries the Security Tool Registry directly for authorization purposes —
that would create a second path to a classification decision, which is
exactly what `docs/TOOL-REGISTRY.md` REG-INV-2 forbids ("wherever the
Policy Gateway, Tool Layer, or Risk Engine need to know a capability's
classification... they read it from the Registry's authoritative
fields... via the Gateway/Tool Layer, not a second independent lookup").

The Runtime's only direct Registry touchpoint is **read-only and
non-authorizing**: calling `registry.catalog_view()` (via the Context
Assembler) to build the filtered Capability Catalog View shown to the
Agent (`docs/TOOL-REGISTRY.md` §4). This call:

- Filters to `status == enabled`, non-`quarantined` entries whose
  `supported_target_types` intersect the investigation's target types.
- Returns only the six Agent-visible fields (`capability`,
  `display_name`, `description`, `parameters_schema`, `classification`,
  `supported_target_types`) — never privileges, resource limits,
  provenance, trust level, owner, risk category, approval requirement,
  or `operations`.
- Additionally applies the investigation-scoped optimization named in
  `docs/TOOL-REGISTRY.md` §4 point 4: if `InvestigationRequest.constraints`
  includes something like `"read-only only"`, `state_changing` entries
  are excluded from the view the Runtime shows the Agent, purely so the
  Agent doesn't spend a turn on something structurally unreachable — the
  Policy Gateway would deny/require-approval it either way, so this is a
  UX optimization, never a security control in itself.

If the Agent names a capability that isn't in the view it was shown
(hallucination, injection, or a stale view), the Runtime forwards the
`ToolRequest` to the Gateway **unmodified** — it never rewrites it toward
something valid (RT-INV-5) — and the Gateway's own Registry lookup
(`registry.get_enabled()`) returns the same `unknown-capability` denial
it would for a truly nonexistent capability (REG-INV-3).

**Inputs**: `InvestigationContext.target_refs`,
`InvestigationRequest.constraints`.
**Outputs**: Capability Catalog View (a list of reduced entries) handed
to the Context Assembler.
**Trust level**: trusted code reading trusted (admin-vetted)
configuration.
**Security boundary**: none crossed here for authorization purposes —
this is visibility shaping, not a decision point.

---

## 7. Approved tool dispatch

**Owner**: Dispatcher.

The Dispatcher is the single, narrow choke point through which anything
ever actually runs. Its calling convention is the concrete
implementation of RT-INV-1/RT-INV-2:

```
dispatch(instruction: DispatchInstruction,
         policy_decision: PolicyDecision,          # required, verdict must be ALLOW
         approval_decision: ApprovalDecision | None # required (and must be ACCEPT) iff
                                                      # policy_decision.verdict was
                                                      # REQUIRE_APPROVAL
        ) -> ToolResult
```

There is no overload, default parameter, or alternate entry point that
allows omitting `policy_decision`, and no way to pass a
`policy_decision` whose `verdict` is anything but `ALLOW` at the moment
of the call — a `require_approval` verdict must first be converted into
an `ALLOW`-shaped dispatch precondition by an accepted
`ApprovalDecision`; the Dispatcher itself does not re-derive "approved"
from the `PolicyDecision` alone. This means the Dispatcher's contract
makes T-15 (policy bypass) and T-16 (approval bypass) a compile-time/
interface-level impossibility, not merely a runtime check.

The Dispatcher resolves the effective execution parameters from the
Registry entry (via the `PolicyDecision`'s originating evaluation, not a
fresh Registry query — the entry used for dispatch must be the same one
the Gateway evaluated against) into a `DispatchInstruction`: capability,
target reference, parameters, the effective timeout and output limit,
and the identifiers needed for audit traceability. It then calls into
the (Phase 4+) Tool Layer.

> **As implemented (Phase 11).** Before Phase 11 this paragraph described
> intent only: the Runtime used the global step timeout and passed
> `resolved_resource_limits={}`.
> - **Envelope.** The Gateway now attaches a `CapabilityEnvelope` (output
>   schema, `max_output_bytes`, declared timeout) to the `PolicyDecision`.
>   The Agent Loop Controller copies it into
>   `DispatchInstruction.capability_envelope`, with:
>   - `resolved_timeout_seconds = min(envelope timeout, default_step_timeout_seconds)`;
>   - `resolved_resource_limits = {"max_output_bytes": ...}`.
> - **Fail closed.** A decision without an envelope for exactly this
>   capability is never dispatched (`dispatch_precondition_violation`).
> - **Binding.** `dispatch()` rejects an instruction whose envelope,
>   capability, timeout or limits are not bound to the decision.
>
> See "Capability execution envelope (Phase 11)" below.

Because the Tool Layer does not exist yet, Phase 3 defines this
boundary as a stable interface (`DispatchInstruction` in, `ToolResult`
out) that a future Tool Layer implements against, without depending on
any Tool Layer internals here.

**Inputs**: `DispatchInstruction`, `PolicyDecision` (verdict = allow),
optional `ApprovalDecision` (decision = accept).
**Outputs**: a call into the Tool Layer; raw `ToolResult` on return; one
`AuditEvent` (`dispatch_started`, then `dispatch_completed` or
`dispatch_failed`).
**Trust level**: trusted control code.
**Security boundary**: TB-6 outbound — no credential is ever passed
through this call; credentials are resolved inside the future Target
Adapter, not here (RT-INV-11).

---

## 8. ToolResult handling

**Owner**: Result Handler.

On return from the Dispatcher, the Result Handler:

1. Validates the `ToolResult`'s **shape** against `CONTRACTS.md` §4
   (status is one of the closed enum values, `completed_at >=
   started_at`, `output` present iff `status == success`) — this is
   shape validation, not truth validation; the Runtime never assumes
   tool output is factually correct, only that it parses.
2. Treats `output`/`raw_output` as **semi-trusted data** for the
   remainder of its life in the system (`ARCHITECTURE.md` §18) — it is
   stored verbatim as `Evidence` (§9) but is never itself executed,
   never used to construct a further `ToolRequest` automatically, and
   is only ever handed back into an LLM prompt as delimited data
   (RT-INV-7, enforced downstream by the Context Assembler).
3. Applies any redaction the capability's classification calls for
   (`CONTRACTS.md` §4 security considerations — capabilities known to
   surface secrets, e.g. environment dumps or file contents, are
   redacted before persistence) and records whether redaction occurred
   (`Evidence.redactions_applied`) rather than silently altering the
   record without a trace.
4. Classifies the outcome for the step-level state machine (§15):
   `success` → proceeds to Evidence write; `failure`/`error` → Retry
   Controller decision (§12); `timeout` → handled by the Timeout
   Supervisor's own path (§10), which constructs a synthetic `ToolResult`
   with `status: timeout` if the Tool Layer itself doesn't return one in
   time.

**Inputs**: raw `ToolResult` from the Dispatcher.
**Outputs**: a normalized `ToolResult`; a redaction decision; a
step-outcome classification.
**Trust level**: trusted control code; **input is semi-trusted**.
**Security boundary**: TB-6 inbound.

---

## 9. Evidence handoff

**Owner**: Evidence Writer.

For every `ToolResult` (success or failure — a failed execution is still
recorded, per `ARCHITECTURE.md` §16: "captured as a failed `ToolResult`,
still written to Evidence and Audit"), the Evidence Writer constructs an
`Evidence` record (`CONTRACTS.md` §7):

- Copies `investigation_id`, `step_id`, `tool_request_id`,
  `tool_result_id`, `target_id`, `capability` — all four traceability
  fields are populated from data the Runtime already holds, never
  re-derived or guessed.
- Copies `classification` from the Registry entry **as it was at
  dispatch time** (per `CONTRACTS.md` §7: "so history remains accurate
  even if the Registry entry later changes").
- Computes `content_hash` over the stored payload (tamper-evidence,
  SR-11) and assigns `storage_ref`.
- Sets `redactions_applied` per the Result Handler's redaction decision.
- Writes the record through the append-only Evidence Store interface —
  there is no update/delete path exposed to any Runtime component
  (SR-10).

**Ordering guarantee**: the `Evidence` record is written, and its write
confirmed, **before** the corresponding `evidence_id` is appended to
`InvestigationContext.evidence_refs` and **before** the result is handed
back into the Agent loop's next context assembly. If the Evidence write
itself fails, the step is treated as failed and the investigation is
halted rather than continuing with an unrecorded action (RT-INV-6,
mirroring `docs/THREAT-MODEL.md` §13's failure-modes table entry for
Evidence Store write failure).

**Inputs**: normalized `ToolResult`, step/request identifiers, Registry
classification snapshot.
**Outputs**: `Evidence` record; `evidence_id` appended to
`InvestigationContext`.
**Trust level**: trusted control code.
**Security boundary**: TB-8 — write-only, append-only.

### Tool execution flow (Diagram: intake → dispatch → evidence → audit)

```mermaid
sequenceDiagram
    participant Agent as AI Agent (untrusted output)
    participant Loop as Agent Loop Controller
    participant Intake as ToolRequest Intake
    participant GW as Policy Gateway
    participant Appr as Human Approval
    participant Disp as Dispatcher
    participant Tool as Tool Layer / Security Tool
    participant Res as Result Handler
    participant Ev as Evidence Store
    participant Aud as Audit Log

    Agent->>Loop: AgentTurnOutput (ToolRequest proposal)
    Loop->>Intake: raw ToolRequest payload
    Intake->>Intake: schema/contract validation
    alt malformed
        Intake-->>Loop: MalformedRequestError
        Loop->>Aud: AuditEvent (error)
        Loop-->>Agent: surfaced as information, next turn
    else contract-valid
        Intake->>GW: ToolRequest
        GW-->>Loop: PolicyDecision
        Loop->>Aud: AuditEvent (policy_evaluated)
        alt verdict = deny
            Loop-->>Agent: denial surfaced as information, next turn
        else verdict = require_approval
            Loop->>Appr: ApprovalRequest
            Appr-->>Loop: ApprovalDecision
            Loop->>Aud: AuditEvent (approval_decided)
            alt decision = deny or expired
                Loop-->>Agent: denial surfaced as information, next turn
            else decision = accept
                Loop->>Disp: DispatchInstruction + PolicyDecision + ApprovalDecision
                Disp->>Tool: invoke capability
                Tool-->>Disp: ToolResult
                Disp->>Res: ToolResult
                Res->>Ev: write Evidence
                Ev-->>Res: evidence_id, content_hash
                Res->>Aud: AuditEvent (dispatch_completed, evidence_recorded)
                Res-->>Agent: Evidence reference, next turn, as data
            end
        else verdict = allow
            Loop->>Disp: DispatchInstruction + PolicyDecision
            Disp->>Tool: invoke capability
            Tool-->>Disp: ToolResult
            Disp->>Res: ToolResult
            Res->>Ev: write Evidence
            Ev-->>Res: evidence_id, content_hash
            Res->>Aud: AuditEvent (dispatch_completed, evidence_recorded)
            Res-->>Agent: Evidence reference, next turn, as data
        end
    end
```

---

## 10. Timeout handling

**Owner**: Timeout Supervisor.

Two independent timeout scopes (`ARCHITECTURE.md` §3: "Enforce per-step
and per-investigation timeouts"), both sourced from trusted
configuration, never from the Agent:

- **Per-step timeout**: the Registry's `default_timeout_seconds` for the
  capability being dispatched (`docs/TOOL-REGISTRY.md` §1 item 13). If
  the Tool Layer has not returned by then, the Timeout Supervisor
  constructs a synthetic `ToolResult` with `status: timeout` (per
  `CONTRACTS.md` §4's closed status enum) and hands it to the Result
  Handler exactly as if the Tool Layer had returned it — timeout is a
  first-class outcome, not an exception path.
- **Per-investigation timeout**: `RuntimeExecutionLimits.
  max_investigation_duration_seconds` (a new, Runtime-owned
  configuration value — see "Additional contracts," below). Exceeding it
  transitions the investigation to `halted`, not `failed` — a timeout is
  an expected governance outcome, not an internal defect
  (`docs/THREAT-MODEL.md` §16's treatment of timeout as "a failure
  outcome for that step, not a crash").

A timed-out step is eligible for the same bounded retry policy as any
other transient failure (§12), subject to the same budget.

**Inputs**: wall-clock time; Registry `default_timeout_seconds`;
`RuntimeExecutionLimits`.
**Outputs**: a synthetic `ToolResult(status=timeout)`, or an
investigation-level `halted` transition.
**Trust level**: trusted control code.
**Security boundary**: internal — bounds T-27 (resource exhaustion).

---

## 11. Error handling

**Owner**: distributed — each component classifies and surfaces its own
errors per `ARCHITECTURE.md` §16; the Investigation Manager owns the
investigation-level consequence.

| Error class | Where caught | Runtime behavior |
|---|---|---|
| Malformed `AgentTurnOutput`/`ToolRequest` | ToolRequest Intake / Agent Loop Controller | Surfaced to the Agent as information for the next turn; bounded retry (§12); never auto-corrected (RT-INV-5) |
| `PolicyDecision.verdict == deny` | Agent Loop Controller | Not an error — a valid, expected outcome (`ARCHITECTURE.md` §16); recorded, surfaced as information; the investigation continues |
| `ApprovalDecision.decision == deny`, or `ApprovalRequest` expiry | Approval Coordinator | Same treatment as a policy denial — step fails, investigation continues, no auto-escalation to `halted` by default (see the `RuntimeExecutionLimits.p4_approval_expiry_action` option, §18) |
| Tool execution failure (`ToolResult.status in {failure, error}`) | Result Handler | Captured as a failed `ToolResult`, written to Evidence and Audit, handed to the Agent as information it can reason about; eligible for retry (§12) |
| Timeout (step or investigation) | Timeout Supervisor | Per §10 |
| Evidence Store write failure | Evidence Writer | The corresponding action is treated as not having durably happened; the step — and, if it recurs, the investigation — halts rather than proceeding without provenance (RT-INV-6) |
| Audit Log write failure | Audit Emitter | Same severity as an Evidence write failure — halts rather than allowing an unaudited action to proceed (RT-INV-6) |
| Human Approval Mechanism unresponsive | Approval Coordinator | `ApprovalRequest` remains `pending` (or transitions to `expired` per configured policy) — never defaults to `accept` (RT-INV-3) |
| Target unreachable / adapter misconfiguration (future Target Manager) | Dispatcher / Result Handler | `ToolResult.status = failure`; recorded; Agent informed to adjust plan; repeated occurrences count toward the retry/fatal-error budget |
| Unhandled/unexpected exception anywhere in the loop | Agent Loop Controller (outermost guard) | Caught, classified as a fatal Runtime error, `AuditEvent(severity: error)` emitted, investigation transitions to `failed` — **never** silently swallowed and **never** treated as permission to proceed |

This table is the Runtime-side elaboration of `docs/THREAT-MODEL.md`
§13's failure-modes table; nothing here contradicts it — it only adds
the concrete Runtime component responsible for each row.

---

## 12. Retry behavior

**Owner**: Retry Controller.

Retries exist only for **transient** failure classes: malformed
`AgentTurnOutput` (model-side hiccup), tool execution failure classified
as retryable by the capability's own semantics (future Tool Layer
concern — out of scope to specify further here), and timeouts. Retries
are governed by `RuntimeExecutionLimits.max_retries_per_step` and
`retry_backoff_seconds` (new, Runtime-owned configuration — see
"Additional contracts").

**What is never retried**:
- A `deny` `PolicyDecision` — per `docs/POLICY-GATEWAY.md` §15 point 5,
  a denial is not appealable by resubmission; the Agent may propose a
  *materially different* `ToolRequest` on its own initiative, but that
  is ordinary loop continuation, not a Runtime-initiated retry.
- A `deny` `ApprovalDecision` — the same principle extends to human
  denials; re-asking the same human the same question is not a Runtime
  retry policy, it would be a UX/process choice made by a human, not
  automated.
- Anything after `max_retries_per_step` is exhausted — the step reaches
  a terminal failed state (§15) and the loop continues to the *next*
  Agent turn with that failure as information, or the investigation
  fails/halts if the failure recurs across the per-investigation error
  budget (`RuntimeExecutionLimits`, §18).

**What a retry actually is**: a brand-new `ToolRequest` (new
`tool_request_id`), independently submitted to the Policy Gateway and,
if required, independently re-approved (RT-INV-4). No cached
`PolicyDecision` or `ApprovalDecision` is ever reused across attempts —
this is what prevents a single stale approval from silently covering
multiple executions of a state-changing action.

**Inputs**: step-outcome classification (from Result Handler / Timeout
Supervisor), `RuntimeExecutionLimits`.
**Outputs**: either a new attempt fed back into §4, or a terminal step
failure.
**Trust level**: trusted control code.
**Security boundary**: internal — enforces RT-INV-4.

---

## 13. Human approval integration point

**Owner**: Approval Coordinator.

This is the Runtime's implementation of `ARCHITECTURE.md` §13 (Human
Approval Mechanism) and the concrete home of SR-7/SR-8. On receiving a
`PolicyDecision` with `verdict: require_approval`:

1. Constructs an `ApprovalRequest` (`CONTRACTS.md` §11) with
   `risk_context` populated from the **actual** `ToolRequest` fields
   (`capability`, `target_ref`, `parameters`) and any linked
   `RiskAssessment` — never from `rationale` alone
   (`docs/POLICY-GATEWAY.md` §7). If `PolicyDecision.notes ==
   "justification_required"` (the P4 signal from `docs/POLICY-GATEWAY.md`
   §7/§5), the Approval Coordinator surfaces that to the UI layer as a
   requirement, though enforcing a non-empty `justification` remains a
   UI/Runtime-layer policy choice, per the same open item
   `docs/POLICY-GATEWAY.md` already flagged (`ApprovalDecision.
   justification` stays optional at the contract level).
2. Transitions the investigation to `awaiting_approval` and **blocks
   only this step** — this is deliberately scoped to the step, not a
   global lock on the Runtime process; a future multi-investigation
   Runtime (§19) must not stall unrelated investigations while one
   awaits a decision.
3. Awaits an `ApprovalDecision` from the UI layer (Phase 1: CLI). No
   polling loop treats the absence of a decision as anything other than
   "still pending" (RT-INV-3).
4. On `expires_at` (if configured) with no decision, transitions the
   `ApprovalRequest.status` to `expired` — treated identically to a
   `deny` for dispatch purposes (§11), unless
   `RuntimeExecutionLimits.p4_approval_expiry_action` is configured to
   `halt_investigation` for Permission-Level-4 requests specifically
   (an operator-chosen stricter default for the highest-risk tier, never
   the other direction).
5. On a recorded `ApprovalDecision`, emits the corresponding
   `AuditEvent` (`event_type: approval_decided`, including
   `justification` if given) and hands control back to the Agent Loop
   Controller/Dispatcher as appropriate.

**Inputs**: `PolicyDecision` (require_approval), human input via the UI
layer.
**Outputs**: `ApprovalRequest`, `ApprovalDecision`, `AuditEvent`.
**Trust level**: trusted control code; the human decision itself is the
system's trust anchor for anything beyond read-only (`ARCHITECTURE.md`
§18).
**Security boundary**: TB-5.

### Terminal approval and CLI composition (Phase 7)

`chanakya.approval.TerminalApprovalProvider(approver, *, input_fn,
output, max_attempts=3)` implements the existing `ApprovalProvider`
protocol. `chanakya.cli.main.build_runtime` wires it into
`AgentLoopController` together with the real production components.
Nothing about the approval flow above changed. The Runtime still calls
the provider only for `require_approval`, and it still checks expiry and
cancellation. `dispatch()` still refuses any ACCEPT that is not bound to
this request, tool request, policy decision and investigation.

- **Answers.** Only `approve` or `deny` is accepted, after trimming and
  lower-casing and as ASCII only. Invalid input re-prompts, and after
  `max_attempts` the provider raises `ApprovalInputError`. EOF or Ctrl+C
  raises `ApprovalAborted`. Both are `Exception` subclasses, so the
  existing backstop fails the investigation (audited `error`) and nothing
  is dispatched.
- **Display.** Capability, `target_ref`, parameters and expiry come from
  the Agent's proposal, so they are untrusted. Each is rendered with
  `json.dumps(..., ensure_ascii=True)`, so control characters and ANSI
  escapes are printed escaped. The human's input is never echoed.
- **`decided_by`.** This is the `--approver` value, or the OS user by
  default. The reserved names `agent` and `system` are refused.
- **N1 fix.** `risk_context["parameters"]` is now a deep copy
  (`copy.deepcopy`). Previously a shallow copy let anything holding the
  `ApprovalRequest` mutate nested values of the `ToolRequest` that the
  Gateway validated and that `dispatch()` would run.
- **CLI driver.** `run_investigation` loops `run_turn` with
  `capability_catalog=registry.catalog_view()` and the last few tool
  results. `max_steps_per_investigation` counts only tool proposals, so
  the CLI also caps turns (`--max-turns`, default 8). At the cap, or on
  Ctrl+C outside the approval prompt, it calls
  `InvestigationManager.cancel`, and the investigation ends `halted`
  (audited).

| ID | Invariant | Tests |
|---|---|---|
| HA/CLI-INV-1 | The CLI never evaluates policy or executes tools directly. | `test_cli_and_approval_modules_hold_no_execution_or_policy_path` |
| HA/CLI-INV-2 | The ApprovalProvider only answers Runtime-issued `ApprovalRequest`s. | `test_policy_allow_never_asks_the_human`, `test_policy_deny_never_asks_the_human`, `test_non_request_input_is_refused` |
| HA/CLI-INV-3 | Only the literal `approve` can produce ACCEPT. | `test_only_the_literal_word_approve_produces_accept`, `test_model_claiming_approval_still_requires_the_human` |
| HA/CLI-INV-4 | Invalid input, EOF and Ctrl+C never produce ACCEPT. | `test_invalid_input_exhausted_raises_and_never_accepts`, `test_eof_and_ctrl_c_abort_as_ordinary_exceptions`, `test_ctrl_c_at_the_approval_prompt_fails_closed_and_is_audited` |
| HA/CLI-INV-5 | `ApprovalRequest` data cannot mutate the original `ToolRequest` parameters. | `test_approval_request_cannot_mutate_the_dispatched_tool_request`, `test_request_is_not_mutated` |
| HA/CLI-INV-6 | All terminal-displayed untrusted values are escaped. | `test_untrusted_values_are_displayed_escaped` |
| HA/CLI-INV-7 | Credentials never appear in terminal output, model context, Evidence or Audit. | `test_main_reads_the_key_once_and_it_never_leaks`, `test_missing_api_key_exits_nonzero_without_starting` |
| HA/CLI-INV-8 | The production capability catalog comes from `SecurityToolRegistry`. | `test_catalog_comes_from_the_registry` |
| HA/CLI-INV-9 | `InvestigationManager` and `AgentLoopController` share one durable `AuditEmitter`. | `test_one_durable_audit_emitter_is_shared` |
| HA/CLI-INV-10 | Policy DENY and ALLOW never invoke the ApprovalProvider. | `test_policy_allow_never_asks_the_human`, `test_policy_deny_never_asks_the_human` |
| HA/CLI-INV-11 | Human approval never bypasses the Policy Gateway. | `test_require_approval_and_approve_executes_with_evidence_and_durable_audit`, `test_policy_deny_never_asks_the_human` |

**Deferred:** justification/comment capture (including P4
`justification_required`), async/remote/multi-approver approval,
displaying the Agent's explanation (`TurnResult` does not carry it),
investigation persistence/resume, and config files.

---

## 14. Audit event generation

**Owner**: Audit Emitter, called by every other component.

Per `ARCHITECTURE.md` §14 and `docs/POLICY-GATEWAY.md` §12, the Runtime
is the sole producer of `AuditEvent`s (the Gateway, Approval mechanism,
and Tool Layer never write to the Audit Log directly — they hand the
Runtime what it needs). This phase's design requires **one `AuditEvent`
per meaningful transition**, unconditionally — including denials,
failures, and fail-closed outcomes, since those are exactly the events
`docs/THREAT-MODEL.md` T-15/T-16/T-19's detective controls depend on.

Runtime-triggered `event_type` values (all already defined in
`CONTRACTS.md` §13's closed enum — no extension needed for the
happy-path flow):

| Trigger | `event_type` |
|---|---|
| Investigation created / starts running | `investigation_started` |
| `ToolRequest` accepted by Intake | `request_proposed` |
| `PolicyDecision` received | `policy_evaluated` |
| `require_approval` verdict | `approval_requested` |
| `ApprovalDecision` recorded (or expiry) | `approval_decided` |
| Dispatcher begins/ends a call | `dispatch_started` / `dispatch_completed` / `dispatch_failed` |
| `Evidence` written | `evidence_recorded` |
| `Finding` stored | `finding_created` |
| `RiskAssessment` stored (Phase 10, actor `system`) | `risk_assessed` |
| `Recommendation` stored | `recommendation_created` |
| Investigation reaches `completed` | `investigation_completed` |
| Investigation reaches `halted` (including cancellation, timeout, budget exhaustion) | `investigation_halted` |
| Internal Runtime error, fail-closed outcome | `error` |

`related_ids` is populated with every contract id relevant to the event
(never large payloads — `CONTRACTS.md` §13); `details` echoes small,
already-redaction-safe fields (e.g. `verdict`, `matched_rule`,
`justification`) and never re-introduces a secret a prior redaction
step removed (RT-INV-11).

**Inputs**: transition notifications from every component.
**Outputs**: `AuditEvent` records, written append-only.
**Trust level**: trusted control code.
**Security boundary**: TB-8 — write-only, append-only.

### Durable Audit Log (Phase 6)

`chanakya.audit.FilesystemAuditLog(root)` implements the existing
`AuditSink` protocol, so a composition root passes it to
`AuditEmitter(sink=...)` and shares that one emitter between
`InvestigationManager` and `AgentLoopController`. No Runtime code changed.
`NullAuditSink` remains the default, and `InMemoryAuditSink` remains the
test double.

**Storage.** `<root>/<investigation_id>/<sequence>.json` with 8-digit,
zero-padded sequence numbers (`00000001.json`, ...). Events with
`investigation_id=None` go to `<root>/system.stream/`; the `.` in that
name keeps it from ever colliding with an investigation id.
Investigation ids go through the same strict path-safety rule as the
Evidence Store (`[A-Za-z0-9_-]{1,128}`, Windows device names refused),
plus a check that the resolved stream directory is a direct child of
`root`.

**Hash chain.** Each record is
`{sequence, previous_record_hash, recorded_at, event, record_hash}`. The
store owns the four integrity fields: `AuditEvent` has no field for any
of them. `record_hash` is SHA-256 over the canonical JSON of the other
four (`chanakya.evidence.hashing`), and `previous_record_hash` is the
previous record's `record_hash` (`null` for sequence 1). The chain head
is re-read and re-hashed from disk on every append, so a restarted
process continues the chain. An append refuses to extend a stream whose
head fails its hash or whose sequence numbers have a gap.

**Atomicity.** Temp file in the stream directory → flush → `fsync` →
`os.link` to the final name, which fails if the name exists, so an
existing sequence is never overwritten → remove the temp name. On POSIX
the directory is also fsynced. Any failure leaves no final record and no
temp file.

**Write failure.** Anything `emit` raises reaches the Runtime as
`AuditSinkError`. This covers an invalid id, a record over
`MAX_RECORD_BYTES` (65,536 canonical bytes, rejected rather than
truncated), a credential-shaped `details` key or value, a broken chain
head, a sequence collision, or an I/O error. The Agent Loop Controller
then halts the investigation (`audit_sink_failure`), and the backstop
records `error` and `investigation_halted` if the sink still accepts
writes. `dispatch_started` is emitted, and therefore on disk, before the
ToolExecutor is called, so a failure there means the tool never runs.
Two existing behaviors are unchanged and recorded in
`tests/test_audit_log_runtime.py`:

- If the sink keeps failing, the halt record cannot be written either.
  The investigation still ends `halted` with nothing executed, but the
  turn is reported as `FAILED`.
- `InvestigationManager.complete/halt/fail` transition before they emit.
  A failed `investigation_completed` write therefore leaves a terminal
  `completed` investigation without a completion record (the turn is not
  reported as `CONCLUDED`).

**Review API.** `list_by_investigation(id)` returns verified records
(`AuditRecord`), or raises `CorruptAuditLogError` instead of returning
a partial list. `verify(id)` returns `False` on any integrity problem.
Both are for out-of-band human review; nothing in the Runtime, Policy
Gateway or providers imports `chanakya.audit`.

| ID | Invariant | Enforcement | Tests |
|---|---|---|---|
| AL-INV-1 | The Audit Log is append-only. | No update/delete/replace/overwrite method; exclusive `os.link`; collision fails. | `test_no_mutation_api_exists`, `test_existing_record_is_never_overwritten`, `test_sequence_collision_during_append_fails_closed` |
| AL-INV-2 | Integrity fields are generated by the store. | `emit` computes `sequence`, `previous_record_hash`, `recorded_at`, `record_hash`; `AuditEvent` has no such fields. | `test_store_owned_fields_are_present_and_computed`, `test_caller_values_in_details_or_ids_never_become_envelope_fields` |
| AL-INV-3 | The hash chain detects modification, middle deletion, reordering and insertion. | `record_hash` re-check, `previous_record_hash` links, contiguous sequence names, exact record shape, stream ownership. | `test_modified_middle_record_is_detected`, `test_deleted_middle_record_is_detected`, `test_reordered_records_are_detected`, `test_inserted_middle_record_is_detected` |
| AL-INV-4 | Every record is durable before `emit()` returns. | `fsync` before link; `dispatch_started` precedes execution. | `test_record_is_on_disk_and_fsynced_before_emit_returns`, `test_dispatch_started_is_durable_before_the_executor_runs` |
| AL-INV-5 | Any write failure fails closed through `AuditSinkError` → `HALTED`. | `AuditEmitter` wrapping + existing Runtime backstop. | `test_audit_failure_at_each_step_emission_point_halts`, `test_real_write_failure_at_dispatch_started_halts_before_execution` |
| AL-INV-6 | Investigation identifiers are isolated and path-safe. | Evidence Store identifier rule; direct-child check; one directory and chain per investigation. | `test_unsafe_investigation_ids_are_rejected_before_any_io`, `test_investigations_have_isolated_chains` |
| AL-INV-7 | The Audit Log is never model input or authorization input. | No production package imports `chanakya.audit`; the log is only a sink. | `test_no_production_package_reads_the_audit_log`, `test_audit_data_never_reaches_the_policy_gateway`, `test_anthropic_provider_flow_with_durable_audit` |
| AL-INV-8 | Size and credential controls fail closed. | `MAX_RECORD_BYTES`; best-effort credential screen of `details`. | `test_record_at_the_size_limit_is_accepted_and_one_over_is_rejected`, `test_credential_shaped_details_are_rejected_and_not_persisted` |
| AL-INV-9 | The hash chain survives a process restart. | Head re-read from disk on every append; no in-memory head. | `test_chain_continues_across_a_process_restart`, `test_restarted_log_continues_the_existing_chain` |

**Limitations.**

- **Tail truncation is not detectable**, and neither is a rewritten
  last record: nothing outside the files commits to the chain head.
  External anchoring or export is deferred.
- **The hash is unkeyed.** A local attacker who can write the files can
  recompute the whole chain; the chain detects partial edits, not a full
  rewrite (THREAT-MODEL T-18 residual; TB-9).
- **Single-process writer.** A lock serializes appends within one
  process; exclusive linking makes a concurrent collision fail closed, but
  multiple writing processes are not supported.
- **Local filesystem trust.** Durability and confidentiality depend on
  the host and its file permissions (TB-9).
- **Credential screening is best-effort.** It uses the `TargetLocator`
  patterns (URL userinfo, `password=`/`token=`-style pairs) on `details`
  keys and string values only; it is not a secret scanner. A rejected
  record halts the investigation.
- An append re-verifies only the head record; full-chain checks are
  `verify`'s job.

---

## 15. Runtime state management

Two nested state machines: an **investigation-level** machine (using
`InvestigationContext.status` exactly as defined in `CONTRACTS.md` §2 —
no new status value is introduced) and a **step-level** machine (a
Runtime-internal elaboration of one `step_history` entry's lifecycle,
new in this phase — see "Additional contracts").

### Investigation-level state machine

**States**: `pending`, `running`, `awaiting_approval`, `completed`,
`failed`, `halted`.

**Terminal states**: `completed`, `failed`, `halted`. None of the three
has an outbound transition in this phase's design — a terminated
investigation is not resumed; a fresh investigation (new
`InvestigationRequest`) is required for further work on the same
objective, deliberately keeping "what happened during investigation X"
unambiguous. (Adding a `resume` path is flagged as future work, not a
Phase 3 gap — see "Open items.")

**Valid transitions**:

| From | To | Trigger |
|---|---|---|
| *(none)* | `pending` | `InvestigationRequest` validated; `InvestigationContext` created |
| `pending` | `running` | Runtime starts the Agent loop |
| `running` | `running` | A step reaches a terminal step-state; loop continues to the next turn |
| `running` | `awaiting_approval` | A step's `PolicyDecision.verdict == require_approval` |
| `awaiting_approval` | `running` | `ApprovalDecision` recorded (accept **or** deny) or `ApprovalRequest` expired — the step concluded one way or another; the investigation itself continues |
| `running` | `completed` | `AgentTurnOutput.next_action == conclude` |
| `running` | `halted` | Operator cancellation; per-investigation timeout exceeded; step budget exhausted |
| `awaiting_approval` | `halted` | Operator cancellation while a decision is pending |
| `running` | `failed` | Fatal/unrecoverable error: Evidence/Audit write failure, retry budget exhausted on a fatal error class, or an unhandled internal exception |

**Explicitly invalid transitions** (rejected as Runtime programming
errors if ever attempted, never silently allowed):

- `pending → awaiting_approval`, `pending → completed`, `pending →
  failed`, `pending → halted` — nothing can conclude, fail, need
  approval, or halt before the loop has ever run a turn.
- `completed → *`, `failed → *`, `halted → *` — terminal states have no
  outbound edges.
- `awaiting_approval → completed` / `awaiting_approval → failed`
  directly — a pending approval must resolve to `running` (accept/deny/
  expiry) or `halted` (cancellation) first; the Agent cannot "conclude
  around" a step it is still waiting on, and an approval pending by
  itself is never a fatal error.

```mermaid
stateDiagram-v2
    [*] --> pending: InvestigationRequest validated, InvestigationContext created
    pending --> running: Runtime starts the Agent loop
    running --> running: step concludes, loop continues
    running --> awaiting_approval: PolicyDecision.verdict == require_approval
    awaiting_approval --> running: ApprovalDecision recorded, or ApprovalRequest expired
    running --> completed: AgentTurnOutput.next_action == conclude
    running --> halted: cancellation, timeout, or budget exhausted
    awaiting_approval --> halted: cancellation while a decision is pending
    running --> failed: fatal/unrecoverable error
    completed --> [*]
    failed --> [*]
    halted --> [*]
```

### Step-level state machine (new — elaborates one `StepRecord`)

```mermaid
stateDiagram-v2
    [*] --> proposed
    proposed --> validating
    validating --> step_failed: malformed ToolRequest
    validating --> policy_evaluating: contract-valid
    policy_evaluating --> step_denied: verdict = deny
    policy_evaluating --> awaiting_step_approval: verdict = require_approval
    policy_evaluating --> dispatching: verdict = allow
    awaiting_step_approval --> dispatching: ApprovalDecision accept
    awaiting_step_approval --> step_denied: ApprovalDecision deny, or expired
    dispatching --> executing
    executing --> step_completed: ToolResult.status = success
    executing --> step_failed: ToolResult.status = failure/error
    executing --> step_timed_out: Timeout Supervisor trips
    step_failed --> proposed: retry budget remains, new attempt
    step_timed_out --> proposed: retry budget remains, new attempt
    step_completed --> evidence_recorded
    step_completed --> evidence_failed: EvidenceRecorder raised
    evidence_recorded --> [*]
    evidence_failed --> [*]
    step_denied --> [*]
    step_failed --> [*]: retry budget exhausted
    step_timed_out --> [*]: retry budget exhausted
```

A step's terminal state (`evidence_recorded`, `evidence_failed`,
`step_denied`, exhausted-`step_failed`, or exhausted-`step_timed_out`) is
what allows the investigation-level machine's `running → running`
self-transition to fire, i.e. what lets the Agent loop move to its next
turn.

> **Implementation note (Phase 3 Step 3.6):** `evidence_failed` was
> added after integration testing showed the original diagram had no
> representable outcome for "dispatch genuinely succeeded, but recording
> Evidence for it then failed" — §9's own text already specified the
> correct behavior ("the investigation halts rather than continuing
> without provenance"), but the step-level machine had no terminal state
> to express it without either retracting the true `step_completed` fact
> or attempting an invalid transition. `evidence_failed` preserves
> `step_completed` as a real, prior fact while still halting the
> investigation and never adding the (unrecorded) result to
> `evidence_refs`. See `chanakya/runtime/step_record.py` and the
> `_execute_once` evidence-recording block in
> `chanakya/runtime/agent_loop.py`.

---

## 16. Investigation termination

Three, and only three, ways an investigation ends (its terminal
states, §15):

- **`completed`** — the Agent explicitly signals it has nothing further
  to propose (`next_action: conclude`), *or* the Investigation Manager
  determines the stated objective's step budget was reached with a clean
  final turn (an operator-configurable "graceful stop" rather than an
  abrupt `halted`, if `RuntimeExecutionLimits` is configured that way —
  otherwise budget exhaustion is `halted`, see below). On completion,
  any pending `Recommendation`s remain visible to the human but are
  never auto-executed (`CONTRACTS.md` §10 — a `Recommendation` has no
  path to becoming a dispatch without a brand-new, independently
  evaluated `ToolRequest`, per SR-19).
- **`halted`** — an external/governance stop: operator cancellation
  (§17), per-investigation timeout, or step-budget exhaustion (default
  behavior, §18). A halted investigation's `error_state`
  (`CONTRACTS.md` §2) records which of these occurred.
- **`failed`** — an internal/unrecoverable Runtime condition: repeated
  fatal errors beyond the retry budget, an Evidence/Audit write failure,
  or an unhandled exception. `error_state` records the failure class.

In every case, the final `InvestigationContext` — including full
`step_history`, `evidence_refs`, `finding_refs`, and any
`risk_assessment_refs`/`recommendation_refs` — is retained, never
deleted, for post-hoc human review (`ARCHITECTURE.md` §14).

---

## 17. Cancellation

**Owner**: Cancellation Handler.

Cancellation is an operator-initiated, human-in-the-loop control
action, distinct from any Agent-side decision — the Agent has no way to
cancel its own investigation (that would be indistinguishable from
`conclude` in intent but must remain audibly distinct: a human chose to
stop this, the Agent did not choose to stop).

Behavior (RT-INV-9 — cooperative, never mid-flight-destructive):

1. The Cancellation Handler accepts a cancel command scoped to one
   `investigation_id`.
2. If the investigation is `awaiting_approval`, the outstanding
   `ApprovalRequest` is treated as moot: the Runtime does not deliver it
   to a human approver further, and (absent a dedicated contract value —
   see "Open items") marks it `expired` with an `AuditEvent` detail
   explaining the request was withdrawn due to cancellation rather than
   timing out naturally.
3. If a step is mid-`dispatching`/`executing`, the Runtime does **not**
   attempt to forcibly kill the in-flight tool invocation — doing so
   could leave the target or the Evidence/Audit trail in an inconsistent
   state. It lets that one step run to its own natural
   completion/failure/timeout, records it normally (§8-9), and then
   halts before starting a next step.
4. The investigation transitions `running`/`awaiting_approval` →
   `halted`, with `error_state` recording `cancelled_by_operator` and
   the approver/operator identity, and an `AuditEvent`
   (`event_type: investigation_halted`) is emitted.

**Inputs**: an operator cancel command (human-originated, via the UI
layer).
**Outputs**: `halted` transition; `AuditEvent`.
**Trust level**: trusted control code, human-triggered.
**Security boundary**: TB-1 (human input) — enforces RT-INV-9.

---

## 18. Resource limits

Governed by the Resource Governor, reading from `RuntimeExecutionLimits`
(admin-controlled configuration — trusted, versioned, not
Agent-writable, following the same pattern as `PolicySet` and the
Security Tool Registry's own configuration):

- **Per-investigation step budget** (`max_steps_per_investigation`) —
  bounds T-08 (excessive agent autonomy / step-chaining) at the Runtime
  level, complementing the Gateway's own per-capability
  `max_calls_per_investigation` rules (`docs/POLICY-GATEWAY.md` §2).
- **Per-investigation wall-clock timeout**
  (`max_investigation_duration_seconds`) — bounds T-27.
- **Per-step timeout fallback** (`default_step_timeout_seconds`) — used
  only if a Registry entry were somehow missing its own
  `default_timeout_seconds`; defensive, since the Registry schema
  requires this field (`docs/TOOL-REGISTRY.md` §1 item 13), so this path
  should not normally trigger.
- **Retry budget** (`max_retries_per_step`, `retry_backoff_seconds`) —
  bounds runaway retry loops, a variant of T-27.
- **Concurrency cap** (`max_concurrent_investigations`) — see §19.
- **Approval expiry** (`approval_expiry_seconds_default`,
  `p4_approval_expiry_action`) — bounds how long a single pending
  decision can hold up (or, for P4, escalate) an investigation.

Resource limits are **never** relaxed by anything in the Agent's output
— they are read once from trusted configuration per investigation and
are not a field any `ToolRequest`, `AgentTurnOutput`, or `rationale` can
influence (mirrors `docs/POLICY-GATEWAY.md` §15's "no override channel"
principle, applied to the Runtime's own governance surface, not just the
Gateway's).

Evidence Store disk-quota monitoring remains an Evidence Store
responsibility per `ARCHITECTURE.md` §10/§16 (disk-full → halt with a
clear `error_state`, not silent evidence loss) — the Runtime's role is
limited to reacting correctly to that failure mode (§11), not
implementing the quota check itself.

---

## 19. Concurrency considerations

Two separate concurrency questions:

**Within one investigation**: strictly sequential (RT-INV-10). At most
one `ToolRequest` is proposed, evaluated, (approved,) dispatched, and
resulted at a time. This is a deliberate simplification, not an
oversight — it keeps:
- Audit/Evidence ordering trivially correct (no interleaved
  `step_history` entries to reconcile).
- The Gateway's `EvaluationContext.call_counts` (used for rate-limit
  rules, `docs/POLICY-GATEWAY.md` §2) a simple, race-free counter per
  investigation.
- Approval blocking behavior (§13) unambiguous — "this step is waiting"
  never has to be reconciled against "that other step also updated
  state in the meantime" within the same investigation.

**Across investigations**: the Runtime **may** run multiple independent
investigations concurrently, each with its own `InvestigationContext`,
own Resource Governor counters, and own Agent loop — up to
`RuntimeExecutionLimits.max_concurrent_investigations`. This requires:
- The `SecurityToolRegistry` and `PolicyGateway` to be safe for
  concurrent read access from multiple investigations simultaneously.
  Phase 2's `SecurityToolRegistry.set_status()` mutates shared
  dictionaries in place; concurrent admin lifecycle changes racing
  concurrent Gateway evaluations is an implementation-level concern
  flagged here for Phase 4 (Tool Layer) or a Phase 3 implementation
  step to address (e.g. a lock around registry mutation, or
  copy-on-write snapshots) — **not** a Runtime design gap, since the
  Runtime itself never mutates the Registry.
- The Evidence Store and Audit Log to support concurrent
  (investigation-scoped) append operations without cross-investigation
  interleaving corrupting either log — a storage-layer requirement,
  consistent with `ARCHITECTURE.md` §10's abstract-enough interface.
- No shared mutable state between two `InvestigationContext`s — each is
  independently owned by its own Investigation State Store instance;
  cross-investigation correlation (if ever needed) is a read-only,
  audit-side concern, never a Runtime execution-path one.

Phase 1's CLI is single-session, so this concurrency support is
forward-looking design, not a Phase 3 implementation requirement — but
the interfaces above are specified now so a Phase 4+ multi-session
Runtime doesn't require a redesign of the single-investigation pieces.

---

## 20. Runtime security boundaries

Restating `ARCHITECTURE.md` §17/§18 and `docs/THREAT-MODEL.md` §3's
trust boundaries (TB-1 through TB-10), specifically as they cross the
Runtime:

| Boundary | Crossing | Runtime control |
|---|---|---|
| TB-1 (User ↔ CLI) | `InvestigationRequest`, `ApprovalDecision`, cancellation commands enter | Validated per `CONTRACTS.md` before any state changes (Investigation Manager, Approval Coordinator, Cancellation Handler) |
| TB-3 (LLM output ↔ Runtime) | `AgentTurnOutput`/`ToolRequest` enters | Schema-validated before being treated as anything but text (ToolRequest Intake, Agent Loop Controller); never trusted as authorization (RT-INV-1) |
| TB-4 (Runtime ↔ Policy Gateway) | Every `ToolRequest` | Single call path (Policy Gateway Client); unbypassable (RT-INV-1) |
| TB-5 (Gateway ↔ Human Approval) | `require_approval` verdicts only | Approval Coordinator; no implicit accept (RT-INV-2/3) |
| TB-6 (Runtime/Tool Layer ↔ Targets) | `DispatchInstruction` out, `ToolResult` in | Dispatcher (outbound, no credentials — RT-INV-11); Result Handler (inbound, treated as semi-trusted) |
| TB-7 (Tool Layer ↔ MCP servers) | Not a Runtime-owned boundary in this phase (Tool Layer is Phase 4+); the Runtime only ever sees the Tool Layer's normalized `ToolResult`, never raw MCP traffic | N/A at this layer — inherited from `docs/TOOL-REGISTRY.md`'s admission-time vetting |
| TB-8 (Runtime ↔ Evidence Store / Audit Log) | `Evidence`/`AuditEvent` written | Evidence Writer / Audit Emitter; write-only, append-only, no read-modify path exposed to any other component |
| TB-9 (Chanakya process ↔ local OS/filesystem) | Where `InvestigationContext`/logs live in this phase (in-memory per Phase 2 pattern; persistence is future work) | Out of Runtime's direct control; inherits host-level assumptions from `docs/THREAT-MODEL.md` §6 |

**What never crosses a Runtime boundary, by construction**: a
credential (RT-INV-11); an unvalidated `ToolRequest` reaching the
Gateway (RT-INV-1 requires Intake first); a dispatch without a
`PolicyDecision` (RT-INV-1); a `require_approval` dispatch without an
accepted `ApprovalDecision` (RT-INV-2); tool/target output reaching an
LLM prompt as anything other than delimited data (RT-INV-7).

---

## Runtime interfaces / contracts

### Reused, unchanged, from `docs/CONTRACTS.md`

No field is added, removed, or reinterpreted on any of these — the
Runtime implements them exactly as specified:

| Contract | Runtime's relationship to it |
|---|---|
| `InvestigationRequest` | Intake only (Investigation Manager); never modified |
| `InvestigationContext` | Runtime-owned, evolving; the central state object (Investigation State Store) |
| `ToolRequest` | Produced by the Agent, validated by ToolRequest Intake, evaluated by the Gateway |
| `ToolResult` | Produced by the Tool Layer (future), normalized by Result Handler |
| `PolicyDecision` | Produced by the Gateway, acted on by the Runtime, never edited |
| `Target` | Read (not resolved — that's a future Target Manager job) for scope checks |
| `Evidence` | Written by Evidence Writer; append-only |
| `Finding` / `RiskAssessment` / `Recommendation` | Stored by reference in `InvestigationContext`; content never interpreted by the Runtime, only routed and persisted |
| `ApprovalRequest` / `ApprovalDecision` | Created/awaited by the Approval Coordinator |
| `AuditEvent` | Written by the Audit Emitter for every transition |

### New — Runtime-scoped additions

Following the same pattern `docs/POLICY-GATEWAY.md` used for
`PolicyRule`/`PolicySet` and `docs/TOOL-REGISTRY.md` used for
`RegistryEntry`: these are **not** additions to `CONTRACTS.md`'s 13
cross-component contracts. They are Runtime-internal objects that never
reach the Agent, the Gateway, or the Registry as authorization inputs,
introduced here because the existing contracts leave them
under-specified for a concrete Runtime to be built against. They follow
`CONTRACTS.md`'s own conventions (semver `contract_version`, opaque ids,
ISO timestamps) for consistency and future portability.

**`AgentTurnOutput`** — the schema-validated envelope for one Agent
turn's output, produced by the LLM Abstraction (not the raw model call)
and consumed only by the Agent Loop Controller. Never seen by the
Gateway, Registry, or Tool Layer.

| Field | Type | Required | Notes |
|---|---|---|---|
| `turn_id` | string (uuid) | required | Unique per turn |
| `contract_version` | string (semver) | required | |
| `investigation_id` | string | required | |
| `next_action` | enum(`propose_tool_request`, `conclude`) | required | Exactly one value; no third option |
| `tool_request` | object shaped like `ToolRequest` | required iff `next_action == propose_tool_request`; forbidden otherwise | Raw, not-yet-validated — ToolRequest Intake performs the real validation |
| `findings` | array\<`Finding`\> | optional | Validated per `CONTRACTS.md` §8 (non-empty `evidence_refs`) before storage |
| `recommendations` | array\<`Recommendation`\> | optional | Validated per `CONTRACTS.md` §10 (no `target_ref`/`parameters` shape) |
| `explanation` | string | optional | For CLI display; rendered as inert text, never executed (same rule as `ToolRequest.rationale`) |
| `produced_at` | string (timestamp) | required | |

A payload violating the `next_action`/`tool_request` pairing, or with an
unrecognized `contract_version`, is malformed — treated exactly like a
malformed `ToolRequest` (§4, §11): surfaced, never repaired by the
Runtime.

#### Evidence-grounded findings (Phase 9)

Implemented: `AgentTurnOutput.findings`. It is allowed **only with
`conclude`** (at most 20 per turn). `recommendations` is still not
implemented.

**Validation order.** On a conclude turn that carries findings, the Agent
Loop Controller:
1. validates **every** proposed finding and resolves its references
   before storing any;
2. stores each one (`FindingRecorder`, e.g. `chanakya.findings.FindingStore`);
3. calls `add_finding_ref`;
4. emits `finding_created`, whose `related_ids` hold the finding id and
   whose `details` hold only its evidence ids, never its text;
5. completes the investigation.

**Evidence references.** The Agent cites the `tool_result_id`s it saw as
`untrusted_data` sources. Each one must map, through this investigation's
own step history, to an `evidence_id` in `InvestigationContext.evidence_refs`.

**Outcomes:**
- Any invalid finding produces `MALFORMED_TURN`. Nothing is stored and
  the investigation keeps running. Invalid includes: an unknown, foreign
  or unrecorded reference; a missing or extra field (for example
  `approved`, `severity`, `target_ref`); credential-shaped or control
  characters; over-long text; more than 20 findings.
- Findings reported with no recorder configured fail the investigation
  (`finding_store_unavailable`); they are never dropped.
- A storage failure halts it (`finding_recording_failed`).

**Provider channel.** The finding channel is a Runtime-reserved,
non-dispatchable tool name, `report_findings`
(`chanakya.capability.reserved.RESERVED_FINDING_TOOL`).
- **Registry.** It refuses that name for any capability, in any letter
  case; the provider also refuses to build a caller-supplied catalog tool
  with it.
- **When enabled** (`ProviderConfig.findings_channel`, off by default and
  on in the CLI), the provider offers it with a fixed description and a
  closed schema that has no `target_ref`. A lone, well-formed call becomes
  `next_action: conclude` plus `findings`.
- **Otherwise.** Any other use of the name yields a malformed turn and
  never a `tool_request`. That covers: the channel being disabled, the
  call mixed with a capability call, a wrong input shape, or a case
  variant of the name.
- **Scope.** It never reaches ToolRequestIntake, the Policy Gateway,
  approval, the Dispatcher or a ToolExecutor.

| ID | Invariant | Tests (`tests/test_findings.py`) |
|---|---|---|
| FND-INV-1 | Findings never reach Intake, the Gateway, approval or dispatch. | `test_findings_never_reach_the_gateway_intake_or_executor`, `test_runtime_finding_path_calls_no_intake_policy_approval_or_dispatch`, `test_channel_disabled_reserved_call_never_becomes_a_tool_request` |
| FND-INV-2 | Every stored finding cites Evidence of its own investigation, resolved from tool results the Agent saw. | `test_finding_citing_a_seen_tool_result_is_stored_and_audited`, `test_foreign_investigation_tool_results_do_not_resolve`, `test_evidence_ids_cannot_be_cited_directly` |
| FND-INV-3 | Invalid findings fail closed; a batch is all-or-nothing. | `test_invalid_findings_fail_closed_and_nothing_is_stored` |
| FND-INV-4 | Credential-shaped finding text is rejected, never repaired. | `test_credential_shaped_text_is_rejected_not_repaired` |
| FND-INV-5 | Finding storage is append-only and hash-verified. | `test_store_has_no_mutation_api`, `test_collision_fails_and_never_overwrites`, `test_tampered_record_is_detected` |
| FND-INV-6 | Valid findings are never silently dropped. | `test_findings_without_a_store_fail_instead_of_being_dropped`, `test_store_failure_halts_instead_of_completing` |
| FND-INV-7 | Every stored finding has a `finding_created` audit event carrying ids only. | `test_finding_citing_a_seen_tool_result_is_stored_and_audited` |
| FND-INV-8 | Finding text shown in the terminal is escaped. | `test_cli_hostile_finding_text_is_inert_and_escaped` |
| FND-INV-9 | No capability can take the reserved channel name. | `test_registry_refuses_the_reserved_name`, `test_caller_supplied_catalog_cannot_shadow_the_channel` |

#### Deterministic risk assessment (Phase 10)

Implemented. On a conclude turn whose findings were stored, the Agent
Loop Controller rates them before completing the investigation:

```
conclude → _record_findings (unchanged) → _assess_risk → complete
```

**Boundary.** The Runtime never computes a rating (SR-18). It calls an
injected `RiskAssessor` and stores through an injected
`RiskAssessmentRecorder`, both Protocols in `agent_loop.py`, and imports
only `chanakya.contracts.risk_assessment` / `risk_taxonomy`, never
`chanakya.risk`.
- The CLI composition root wires `chanakya.risk.RiskEngine` and
  `RiskAssessmentStore`.
- With neither configured, conclude behaves exactly as in Phase 9.
- Configuring only one is a `ValueError` at construction.

**Engine.** `chanakya.risk.RiskEngine` applies rule set
`chanakya-risk-rules/1.0.0` (`docs/CONTRACTS.md` §9).
- **Finding input.** From each Finding it reads only `finding_id`,
  `investigation_id`, `category` and `evidence_refs`.
- **Evidence input.** It receives cited Evidence only as `EvidenceFacts`
  (id, investigation, capability, classification), through
  `StoreEvidenceFactsReader`. That reader uses the new, investigation-scoped
  `EvidenceStore.verify_in_investigation`: record hash, id/investigation
  match and payload hash, with no payload content returned.
- **Integrity first.** Every cited Evidence of every Finding is verified
  before any Finding is rated, so an integrity failure cannot hide behind
  "not assessed".
- **Determinism.** The engine is pure: only `assessed_at` varies.

**Validation before any write** (`_validate_risk_result`):
- The result must be a `RiskEngineResult`.
- Every assessment is rebuilt from its dict, so the contract is
  re-checked even for an object altered after construction. That check
  covers the rule-set shape, the deterministic id, severity/confidence
  consistency and the ceiling.
- Every stored-this-turn Finding appears exactly once, assessed or not
  assessed, and nothing else appears. That rejects unknown, foreign and
  duplicate references and more than 20 results.
- Each assessment must belong to this investigation, carry exactly its
  Finding's `evidence_refs` (all recorded in this investigation), rate
  that Finding's category, and stay at or below `high`.
- A `category_unrated` reason is accepted only for a Finding whose
  category is really outside the taxonomy, and `evidence_incompatible`
  only for one inside it.

Only then is anything appended. Per assessment:
`RiskAssessmentStore.append` → `add_risk_assessment_ref` →
`risk_assessed` audit event (`actor=system`; `related_ids`
risk_assessment_id and finding_id; `details` evidence_refs, severity,
confidence, scoring_method and rule_ids; never the rationale or any
finding text). Then `complete()`.

**Outcomes:**
- **Not assessed** (`category_unrated`, `evidence_incompatible`) is not a
  failure. The investigation completes and no audit event is written for
  that Finding.
- **Halt on failure.** An engine error, an Evidence integrity failure, a
  validation failure or a storage failure →
  `halt(reason="risk_assessment_failed")`, turn outcome `HALTED`.
  - No `investigation_completed` is emitted.
  - Stored Findings are never altered or removed.
  - A storage failure mid-batch leaves the earlier assessments durable,
    the same append-only posture as findings.
- **Audit failure.** A failure writing `risk_assessed` takes the existing
  backstop: `AuditSinkError` → `HALTED` (`audit_sink_failure`).

**Provider.** No risk channel, no new conclusion type, no risk fields.
- The `report_findings` schema's `category` became an `enum` of
  `RISK_CATEGORY_IDS`, with a fixed description saying it feeds rule-based
  assessment and that the model does not rate severity.
- That enum is a hint only: a category outside it is stored if otherwise
  valid and is rated `category_unrated`.

**Provenance and display.**
- `chanakya.risk.verify_risk_provenance` walks RiskAssessment → Finding →
  Evidence → payload and re-runs the engine. A rewritten and rehashed
  assessment fails recomputation, and so does a missing one.
- The CLI shows ratings only when that verification passes, labeled
  "rule-based risk (chanakya-risk-rules/1.0.0)" apart from the
  "agent-reported confidence". Otherwise it prints "risk assessments:
  failed verification; not shown".
- A finding that could not be rated is shown as
  `rule-based risk: not assessed (<reason>)`.

| ID | Invariant | Tests |
|---|---|---|
| RA-INV-1 | A RiskAssessment never reaches Intake, the Policy Gateway, approval, dispatch or a ToolExecutor, and grants no authority. | `test_risk_path_creates_no_policy_decision_approval_or_dispatch`, `test_runtime_risk_path_calls_no_intake_policy_approval_or_dispatch`, `test_authority_and_storage_packages_never_import_risk`, `test_approval_request_risk_reference_is_never_set` |
| RA-INV-2 | Ratings come only from the deterministic Risk Engine; no model output becomes an RA field. | `test_no_risk_channel_or_risk_fields_are_offered_to_the_model`, `test_model_supplied_severity_on_a_finding_never_becomes_a_rating`, `test_assessment_fields_are_engine_owned` |
| RA-INV-3 | Same Finding, Evidence and rule set → identical id, severity, confidence, rule ids and rationale. | `test_same_inputs_give_identical_assessments_with_different_clocks`, `test_fresh_engine_and_reader_reproduce_the_assessment`, `test_deterministic_id_is_stable_and_input_sensitive` |
| RA-INV-4 | Every RA references exactly one Finding of its own investigation stored in the same conclude turn, with that Finding's evidence. | `test_invalid_engine_output_halts_and_stores_nothing` (fabricated/foreign/missing/duplicate/evidence cases), `test_assessment_for_an_unknown_finding_fails` |
| RA-INV-5 | The engine reads no free text and no payload content. | `test_engine_reads_only_the_four_permitted_finding_fields`, `test_hostile_finding_text_has_no_effect`, `test_hostile_evidence_payload_has_no_effect`, `test_store_reader_never_returns_payload_content` |
| RA-INV-6 | `Finding.confidence` is never an input to RiskAssessment confidence. | `test_finding_confidence_never_changes_the_assessment` |
| RA-INV-7 | Malformed, unsupported or unverifiable input fails closed; integrity failures are never "not assessed". | `test_evidence_corruption_is_a_failure_not_not_assessed`, `test_metadata_tampering_fails_closed_even_for_unrated_categories`, `test_engine_exception_halts_and_findings_survive` |
| RA-INV-8 | Risk storage is append-only, hash-verified and duplicate-resistant. | `test_store_has_no_mutation_api`, `test_duplicate_assessment_collides_and_never_overwrites`, `test_tampered_record_is_detected`, `test_tampered_and_rehashed_contract_violations_are_still_detected` |
| RA-INV-9 | Every stored RA has exactly one `risk_assessed` event with ids and enums only. | `test_rated_finding_is_assessed_stored_audited_then_completed`, `test_mixed_batch_stores_only_rated_findings_one_event_each`, `test_audit_failure_halts_with_audit_sink_failure` |
| RA-INV-10 | No authority-shaped content; severity never exceeds the rule-set ceiling. | `test_authority_shaped_keys_are_rejected`, `test_critical_is_unreachable_under_v1_for_every_category_and_rule_shape`, `test_invalid_engine_output_halts_and_stores_nothing[critical_for_read_only]` |
| RA-INV-11 | The CLI renders risk escaped, apart from agent confidence, and withholds ratings that fail verification. | `test_cli_rates_stores_audits_and_displays_a_rated_finding`, `test_cli_withholds_ratings_that_fail_verification`, `test_cli_risk_output_is_escaped_with_hostile_finding_text`, `test_cli_shows_not_assessed_explicitly_and_never_as_safe` |
| RA-INV-12 | Phase 9 FND-INV-1..9 are unchanged; a risk failure never alters or removes a Finding. | the unchanged `tests/test_findings.py`, `test_invalid_engine_output_halts_and_stores_nothing` (findings still verify), `test_storage_failure_on_first_append_halts_without_completion` |

**Limitations.**
- **What a rating means.** It reflects the category and the provenance of
  the evidence, not the truth of the Finding. A low or absent rating does
  not establish the absence of risk.
- **Category choice.** The model still chooses a Finding's category and
  can pick the highest compatible one (T-45).
- **Local attacker.** A consistent rewrite of the Finding, Evidence and
  RiskAssessment stores defeats recomputation (T-48, T-18).
- **Partial state.** An RA written before a failed `risk_assessed` event
  stays durable without its event.

#### Versioned risk rule sets (Phase 13)

**Rule sets.** A rule set is an immutable `RiskRuleSet` in
`chanakya/contracts/risk_taxonomy.py`, identified by its `scoring_method`.
- **Registry.** The registry is an immutable mapping defined in code. It
  holds only `chanakya-risk-rules/1.0.0`, whose data is unchanged.
  `resolve_rule_set` raises for any other name; there is no fallback.
- **Active rule set.** `active_rule_set()` is the one rule set new
  assessments are produced under. It is read only by the CLI composition
  root (to build the engine and the controller) and by the provider (for
  the category vocabulary).

**Runtime.** `AgentLoopController(..., risk_rule_set=...)` requires exactly
one registered rule set whenever risk assessment is configured; a
malformed, unregistered or altered definition is refused at construction.
`_validate_risk_result` rejects a batch unless the batch, every assessment
and every not-assessed entry name the active rule set. Category, ceiling
and not-assessed-reason checks use that rule set. Nothing is re-labelled
or downgraded.

**Engine.** `RiskEngine(reader, *, rule_set=...)` has no default and refuses
an unregistered definition. `for_scoring_method(name)` returns an engine
over the same reader, bound to the registered rule set with that name, and
raises for an unknown name. This is how history is recomputed.

**Verification.**
- `verify_risk_provenance` (the current run's display) recomputes each
  stored assessment under its recorded rule set, and reports
  `scoring_method_not_active` for any rule set other than the active one.
- Review (historical) recomputes each stored assessment under its recorded
  rule set. It checks coverage only under the rule set the investigation's
  own records name, and reports unknown, mixed or audit-mismatched rule
  sets as anomalies. It never substitutes the active rule set.

**Provider.** The `report_findings` category enum is built per request from
the active rule set's categories. The schema template is never mutated.

| ID | Invariant | Tests (`tests/test_risk_rule_sets.py`) |
|---|---|---|
| RV-INV-1 | Every RiskAssessment, NotAssessedFinding and RiskEngineResult carries explicit `scoring_method` provenance. | `test_every_engine_output_carries_its_scoring_method`, `test_results_cannot_mix_or_omit_rule_sets`, `test_provenance_survives_serialization_and_storage` |
| RV-INV-2 | A risk result is validated and recomputed only under its recorded rule set. | `test_assessments_are_validated_under_the_rule_set_they_name`, `test_review_recomputes_under_the_recorded_rule_set`, `test_historical_v1_assessments_are_never_reinterpreted`, `test_current_run_verifier_recomputes_under_the_recorded_set_and_flags_non_active` |
| RV-INV-3 | v1 output is byte-identical to Phase 12 (golden). | `test_v1_outputs_are_byte_identical_to_the_pre_phase_13_golden`, `test_v1_taxonomy_severities_and_compatibility_are_frozen`, `test_provider_vocabulary_is_v1_and_unchanged` |
| RV-INV-4 | The Runtime accepts exactly one trusted active rule set and never downgrades. | `test_runtime_requires_exactly_one_registered_active_rule_set`, `test_runtime_rejects_results_from_a_rule_set_other_than_the_active_one`, `test_runtime_never_downgrades_to_v1` |
| RV-INV-5 | Rule sets are code-defined and cannot be selected or modified by the model, tools, findings, evidence, requests, the CLI, the environment or files. | `test_model_supplied_scoring_method_is_rejected`, `test_evidence_payload_cannot_select_a_rule_set`, `test_cli_has_no_rule_set_option`, `test_environment_cannot_select_a_rule_set`, `test_rule_sets_are_never_loaded_from_files_environment_or_imports`, `test_registry_and_rule_sets_are_immutable` |
| RV-INV-6 | Unknown or mismatched rule sets fail closed. | `test_unknown_rule_sets_fail_closed_without_fallback`, `test_review_fails_closed_when_the_recorded_rule_set_is_unavailable`, `test_review_flags_an_unknown_rule_set_named_in_the_audit`, `test_engine_requires_a_registered_rule_set` |

The second rule set these tests use (`test-only/risk-rules-9`) exists only
in the test file and is registered only for the duration of a test.

**Limitations.**
- The registry is a module-level immutable mapping, not an injected
  object. Tests register their rule set by temporarily replacing it, and
  anyone able to change the code can change the registry (as with any
  code).
- Review can check coverage only when the investigation's records name a
  rule set. With no stored assessments and no `risk_assessed` events,
  whether a finding should have been rated cannot be decided from durable
  history.
- Historical reassessment and v2 content are deliberately not
  implemented.

#### Capability execution envelope (Phase 11)

Every capability execution is constrained by an immutable
`CapabilityEnvelope` (`chanakya/capability/envelope.py`): `capability`,
`output_schema`, `max_output_bytes`, `timeout_seconds`. It carries no
authority; the verdict alone decides whether anything runs.

```
ToolRequest → PolicyGateway → RegistryEntry → PolicyDecision + CapabilityEnvelope
  → DispatchInstruction (timeout = min(envelope, Runtime ceiling)) → dispatch() binding check
  → handler → envelope check (serializable → size → schema) → SUCCESS → Evidence
                                                             ↘ ERROR (fixed code) → no Evidence, no retry
```

- **Source (D-1).**
  - `PolicyGateway._decide` builds the envelope with
    `envelope_from_registry_entry` from the entry it decided on and
    attaches it as `PolicyDecision.capability_envelope`. There is no
    second Registry lookup on the execution path.
  - The model, the target, the handler and `ToolRequest.parameters`
    cannot supply or change it.
  - The production executor also holds the Registry-derived envelopes
    built at composition (`build_tool_executor(...,
    capability_registry=registry)`) and refuses an instruction whose
    envelope differs. That map is a parity cross-check, never a source of
    limits.
- **Runtime.** `_execute_once` fails closed if the decision has no
  envelope for exactly this capability. Otherwise it dispatches with
  `resolved_timeout_seconds = min(envelope.timeout_seconds,
  default_step_timeout_seconds)`: the Runtime tightens and never loosens.
- **dispatch().** It refuses an instruction whose envelope differs from
  the decision's, names another capability, or claims a looser timeout or
  different limits. The check runs after the existing approval-binding
  checks and immediately before execution.
- **Tool Layer.**
  - `CapabilityDispatchExecutor` runs no handler without an envelope.
  - After the handler returns, `check_output` rejects, in order:
    non-JSON-compatible output, canonical UTF-8 output over
    `max_output_bytes`, and any `output_schema` violation.
  - A rejection is `ToolResult(status=error, error_message="capability_envelope_violation: <CODE>")`.
    The code comes from a fixed set. The message never contains output
    values, unexpected key names or `repr` of arbitrary objects.
- **Retry.** Envelope violations are deterministic. `_run_attempt_with_retries`
  records `dispatch_failed` with `retry_scheduled: false` and
  `reason: capability_envelope_violation`, and does not retry. Handler
  exceptions and timeouts keep their existing bounded retry.
- **Timeouts are post-hoc** (unchanged, T-36): a late result is replaced
  by a synthetic TIMEOUT result, but the handler is not interrupted.
- **Not enforced.** `max_cpu_seconds`, `max_memory_mb` and
  `max_concurrent_invocations` remain declarative only.

| ID | Invariant | Tests (`tests/test_capability_envelope.py` unless noted) |
|---|---|---|
| CE-INV-1 | No SUCCESS ToolResult reaches Evidence or model context unless its output conforms to the declared `output_schema`. | `test_envelope_violation_never_becomes_evidence_and_is_not_retried`, `test_executor_rejects_violations_with_fixed_messages`, `test_schema_violations_raise_fixed_codes_without_values` |
| CE-INV-2 | No successful result exceeds `max_output_bytes` in canonical UTF-8; oversized output is rejected, never truncated. | `test_exactly_max_output_bytes_is_accepted_and_one_over_is_rejected`, `test_size_is_canonical_utf8_bytes_not_characters`, `test_envelope_violation_never_becomes_evidence_and_is_not_retried[oversized]` |
| CE-INV-3 | The effective step timeout is never greater than min(Registry timeout, Runtime ceiling). | `test_effective_timeout_is_the_minimum`, `test_slow_handlers_time_out_at_the_effective_timeout`, `test_dispatch_refuses_envelopes_not_bound_to_the_decision[timeout_above_envelope]` |
| CE-INV-4 | Envelope values originate only from the authorized Registry snapshot, never from the model, target, handler or parameters. | `test_gateway_attaches_the_envelope_of_the_entry_it_decided_on`, `test_parameters_cannot_supply_or_change_the_envelope`, `test_target_metadata_cannot_change_the_envelope`, `test_handler_cannot_change_its_envelope`, `test_runtime_never_dispatches_without_a_matching_envelope`, `test_executor_parity_rejects_an_envelope_that_differs_from_the_registry`, `test_cli_executor_envelopes_equal_the_gateway_registry` |
| CE-INV-5 | Envelope validation failures never echo rejected output. | `test_schema_violations_raise_fixed_codes_without_values`, `test_schema_error_path_never_contains_value_keys`, `test_non_serializable_output_is_rejected_without_repr`, `test_cli_run_with_invalid_output_shows_only_the_fixed_code` |
| CE-INV-6 | The Tool Layer does not import `chanakya.policy`. | `test_tool_layer_never_imports_policy`, `tests/test_tool_layer.py::test_a8_executor_module_cannot_reach_policy_or_construct_its_own_dispatch` |
| CE-INV-7 | Phase 9 FND-INV invariants are unchanged. | the unchanged `tests/test_findings.py` |
| CE-INV-8 | Phase 10 RA-INV invariants are unchanged. | the unchanged `tests/test_risk_*.py` |

#### Durable authorization record and investigation review (Phase 12)

**Why.** Before Phase 12 most audit events carried only ids, so the durable
record could not say what was proposed, authorized, denied, approved or
dispatched (T-54). An investigation that ended without a terminal event
was indistinguishable from one still running (T-55). Live Runtime state
(`InvestigationContext`, `StepRecord`s) **remains in memory**. This phase
adds no persistence and no resume.

**Durable facts.** Additive `AuditEvent.details` on existing event types;
no new `event_type` and no contract version bump. Defined once in
`chanakya/contracts/audit_details.py` and built by `AuditEmitter`.

| Event | Added `details` |
|---|---|
| `investigation_started` | `investigation_request_id`, `submitted_by`, `submitted_at`, `target_refs`, `objective` |
| `request_proposed` | `capability`, `target_ref`, `step_id` (Runtime `StepRecord` id), `attempt_number`, `parameters_canonical`, `parameters_hash` |
| `policy_evaluated` | adds `capability`, `target_ref`, `classification`, `risk_category`, `envelope` (`capability`, `timeout_seconds`, `max_output_bytes`, `output_schema_hash`, or `null` for a deny without an entry) |
| `approval_requested` | `step_id`, `expires_at`, `risk_context` (`capability`, `target_ref`, `parameters_canonical`, `parameters_hash`) |
| `dispatch_started` | `capability`, `target_ref`, `step_id`, `attempt_number`, `resolved_timeout_seconds`, `max_output_bytes`, `policy_decision_id`, all taken from the `DispatchInstruction` |
| `error` from `InvestigationManager.fail` | `investigation_status: "failed"`, marking the terminal FAILED transition apart from non-terminal backstop `error` events |

- **D-1, objective.** Stored as text: at most 2000 characters, no control
  characters except newline and tab, and rejected if credential-shaped.
  - It is built in `create_investigation` *before* anything is created; a
    rejected objective raises `AuditFactError` and no investigation exists.
  - The CLI reports only the reason code.
- **D-2, parameters.**
  - Stored as canonical JSON (`chanakya.evidence.hashing.canonical_bytes`)
    plus `compute_content_hash` of the same mapping.
  - They must be JSON-compatible and at most 4096 canonical bytes, with no
    credential-shaped keys or string values.
  - `verify_parameters` re-derives both from the stored text.
- **Screening** reuses the `TargetLocator` URL-userinfo and `key=`
  patterns and the Finding free-text pattern. It is best-effort (T-20).
- **Fail closed.**
  - A fact that cannot be recorded safely becomes `AuditSinkError` with a
    fixed code, and the existing backstop halts the investigation
    (`audit_sink_failure`) before policy evaluation or dispatch.
  - The durable sink's 64 KiB record limit and `details` screen still
    apply.
  - Nothing is truncated, redacted or dropped, and rejected values are
    never echoed.

**Investigation Review** (`chanakya/review/`) is read-only. It is not an
enforcement boundary, and only the CLI imports it.
- **API.** `reconstruct_investigation(investigation_id, *, audit_log,
  evidence_store, finding_store, risk_store, risk_engine)` returns a frozen
  `InvestigationReview`.
- **Audit chain.** It verifies the chain (record hashes, links, sequence,
  shape, stream ownership). A broken chain makes the review
  `UNVERIFIABLE`, and nothing is reported as fact.
- **Replay.** It replays events and validates Phase 12 `details` against
  closed shapes, re-hashing parameters. It flags history that does not
  follow, for example:
  - a dispatch without an allow or accepted approval;
  - an approval without a `require_approval` decision;
  - mismatched capability, target or envelope;
  - duplicate or post-terminal events.
- **Cross-store checks.**
  - Audit ↔ Evidence (scoped verification, including the payload).
  - Findings: evidence of their own investigation, recorded in the audit.
  - RiskAssessments: finding, evidence and recomputation with the
    deterministic engine.
  - Orphans are reported in both directions.
- **Status.**
  - `COMPLETED`, `HALTED` or `FAILED` only when the terminal event is
    recorded.
  - `INCOMPLETE` otherwise.
  - `NOT_FOUND` when no stream exists.
- **Findings of the review.** Anomalies are fixed codes plus, at most, an
  identifier.
- **Guarantees.** It never writes, repairs, authorizes, approves, executes
  or calls a model. `python -m chanakya.cli --review <id>` reads no
  credential, builds no Runtime, provider, Gateway or executor, creates no
  directory, and renders every value escaped. It exits 0 only for a
  verified, consistent record.

| ID | Invariant | Tests |
|---|---|---|
| AR-INV-1 | Every durable policy decision identifies the capability, target and verdict. | `test_request_and_policy_and_dispatch_are_recorded`, `test_denied_request_is_reconstructable`, `test_rewritten_facts_are_detected[no_capability,no_target_ref]` |
| AR-INV-2 | Every durable proposed request preserves bounded canonical parameters and their integrity hash. | `test_parameters_are_canonical_json_with_integrity_hash`, `test_non_empty_parameters_are_recorded_even_when_denied`, `test_rewritten_facts_are_detected[params_after_hash]` |
| AR-INV-3 | Every approval-gated request preserves the risk-context facts presented for approval. | `test_approval_request_records_what_was_shown`, `test_denied_and_approval_history_is_reconstructed` |
| AR-INV-4 | Every `dispatch_started` records the resolved timeout and identifies capability and target. | `test_request_and_policy_and_dispatch_are_recorded`, `test_rewritten_facts_are_detected[looser_timeout,dispatch_target]` |
| AR-INV-5 | Objective and origin are durably reconstructable without exposing credentials. | `test_investigation_started_records_origin`, `test_credential_shaped_objective_creates_no_investigation`, `test_unsafe_objectives_are_rejected_without_echo` |
| AR-INV-6 | Review is strictly read-only and cannot execute, authorize, approve or modify anything. | `test_review_package_imports_nothing_on_the_execution_or_authorization_path`, `test_only_the_cli_imports_the_review_package`, `test_review_code_calls_no_mutating_or_executing_api`, `test_review_modifies_no_artifact`, `test_cli_review_reads_no_credential_and_builds_no_runtime` |
| AR-INV-7 | A missing terminal event is never represented as a completed investigation. | `test_crash_points_are_incomplete_never_completed`, `test_removing_completion_is_incomplete_not_completed`, `test_missing_terminal_event_is_never_consistent_completion` |

(The Phase 12 brief called these AL-INV-1..7. They are numbered AR-INV here
because AL-INV-1..9 already name the Phase 6 audit-log invariants above.)

**Limitations.**
- **Tampering the chain cannot catch.** Tail truncation and a full
  rewrite by a local attacker remain undetectable (T-18). Review does
  detect the *semantic* inconsistencies a partial rewrite leaves behind.
- **Context composition.** Which results were in each turn's model
  context is not recorded. *(Phase 14: now recorded; see "Durable agent
  turn record (Phase 14)".)*
- **Older streams.** Streams written before Phase 12 lack the facts and
  are reported with `details_missing`.
- **Over-blocking.** Screening can over-block phrasing such as
  "api key: …" in an objective.
- **Availability.** A model proposing credential-shaped parameters halts
  its own investigation (fail closed).

#### Durable agent turn record (Phase 14)

**Why.** Model influence was neither Runtime-owned nor durable. The caller
chose which tool results the model saw, and nothing checked them. Model
input, provider identity and model output were never recorded. Malformed
or rejected output left no trace, and the SDK could take the provider
endpoint from the environment (T-57, T-58, T-59).

**Flow.**

```
Runtime (owns context sources)
  → ContextAssembler → context data verified == Runtime-owned sources
  → Context Manifest + Provider Identity + Provider Request Hash
      → agent_turn_requested   (durable BEFORE the provider is called)
  → Provider Request → LLM → Provider Response
  → classification (nothing used yet)
      → agent_turn_received | agent_turn_rejected   (durable BEFORE any use)
  → ToolRequest / Finding / Conclusion → Intake → Policy Gateway → …
Review ← Context Manifest + Request Hash + Identity + Outcome (+ Evidence)
```

**Turn records are forensic records and carry no authority.** They are
never read by the Policy Gateway, approval, dispatch, the Tool Layer, the
Registry or the Risk Engine. They are never fed back into model context:
this is not conversation memory, and nothing is resumable.

- **Runtime-owned context (CT-INV-2).** The controller keeps, per
  investigation, the final tool result of each step it ran. It keeps a
  SUCCESS only when its Evidence was recorded, and a failed or timed-out
  result as a `tool_result_error` source. Since Phase 16 the content of a
  `tool_result_error` source is always a Runtime-owned failure code, never
  handler text. The model sees the last
  `MAX_CONTEXT_ENTRIES` (5) of these, in order. `run_turn(...,
  recent_tool_results=...)` is kept only for compatibility and selects
  nothing. Every entry must be one of the current Runtime-owned results,
  unaltered and not duplicated. An unknown, foreign, stale, altered or
  duplicated entry fails the investigation (`context_source_rejected`)
  before the provider is called. Whatever assembler runs, its `data` must
  equal the Runtime-owned sources exactly. The CLI no longer passes results.
- **Manifest.** It records:
  - the template version plus the instruction and objective hashes;
  - the catalog, target-view and environment-view hashes;
  - ordered context entries (`tool_result_id`, `step_id`, `evidence_id`,
    `content_hash`), never payloads;
  - the provider identity;
  - the provider request hash.

  Turn ids are deterministic (`derive_agent_turn_id`) and sequences are
  contiguous.
- **Provider (CT-INV-4).** A *declared* provider (`AnthropicProvider`)
  implements `provider_identity()`, `prepare_turn()` and `send_turn()`.
  - The Runtime records the prepared request's hash before calling
    `send_turn`.
  - `send_turn` re-verifies the hash, then sends exactly that request.
  - The endpoint is always explicit (`ProviderConfig.effective_endpoint`,
    https only).
  - The SDK client is checked to target it with no custom headers.
  - The CLI refuses to start while `ANTHROPIC_BASE_URL`,
    `ANTHROPIC_CUSTOM_HEADERS` or `ANTHROPIC_PROFILE` is set.

  An in-process provider with only `next_turn` is recorded as `undeclared`.
  Its request hash is the hash of the assembled context it was handed.
- **Outcomes (CT-INV-3).** Classification happens before anything is used:
  - more than one `tool_use` block → `multiple_tool_use_blocks`;
  - a stop reason other than `end_turn`/`tool_use`/`stop_sequence` →
    `unsupported_stop_reason`;
  - structural failure → `malformed_turn` / `reserved_channel_misuse`;
  - finding validation → `invalid_findings`;
  - intake → `malformed_tool_request`;
  - oversize → `provider_output_too_large`;
  - an exception → `provider_failure`.

  Rejections record the raw-output hash and a safe reason; raw output is
  never stored. A rejected turn consumes one step of
  `max_steps_per_investigation` (a malformed flood halts with
  `max_steps_per_investigation_exceeded`). A malformed tool request already
  consumed one through the existing path.
- **Explanation.** Untrusted text. It is recorded only if it is at most
  2000 characters, has no control characters and is not credential-shaped.
  Otherwise it is withheld: its hash and a fixed status are recorded, and
  it is never truncated or redacted. The turn is not failed, because the
  Runtime never uses the explanation. This matches the "never repair, never
  pretend" convention while keeping availability.
- **Failure semantics (CT-INV-1).**
  - A manifest write failure means no provider call; the backstop halts
    (`audit_sink_failure`).
  - An outcome write failure halts before the output is used.
  - A provider exception is recorded, then fails the investigation, as
    before.

| ID | Invariant | Tests (`tests/test_agent_turn_record.py`) |
|---|---|---|
| CT-INV-1 | Every provider call is preceded by exactly one durable manifest and followed by exactly one durable outcome, or the investigation halts before the output is used. | `test_manifest_is_durable_before_the_provider_is_called`, `test_manifest_write_failure_means_no_provider_call`, `test_outcome_write_failure_means_the_output_is_never_used`, `test_every_provider_call_has_exactly_one_outcome`, `test_provider_failure_is_recorded_then_fails_closed` |
| CT-INV-2 | Model context contains only data produced within the same investigation and composed by the Runtime. | `test_runtime_composes_context_from_its_own_results`, `test_context_window_is_the_latest_results_in_order`, `test_foreign_investigation_result_is_rejected_and_never_reaches_the_provider`, `test_caller_supplied_results_cannot_select_or_inject_context`, `test_an_assembler_that_adds_data_is_rejected` |
| CT-INV-3 | Every rejected model output is durably recorded by safe reason code and integrity hash, without persisting unsafe raw content. | `test_rejected_provider_outputs_are_recorded_and_never_used`, `test_reserved_channel_misuse_is_recorded`, `test_malformed_turn_and_malformed_request_are_recorded`, `test_invalid_findings_are_recorded_and_nothing_is_stored`, `test_oversized_output_is_recorded_then_halts`, `test_raw_model_output_is_never_persisted` |
| CT-INV-4 | Provider destination and identity are explicit, recorded, and never silently taken from implicit environment variables. | `test_declared_provider_identity_is_recorded`, `test_provider_request_hash_is_the_hash_of_the_exact_request_sent`, `test_prepared_request_is_reverified_before_sending`, `test_cli_refuses_environment_that_could_redirect_the_provider`, `test_environment_base_url_never_changes_the_recorded_or_used_endpoint`, `test_custom_headers_on_a_client_fail_closed`, `test_unsafe_endpoints_are_rejected` |
| CT-INV-5 | Turn records carry no authority: policy, approval, dispatch and risk never use them. | `test_turn_records_are_unreachable_from_authorization_execution_and_risk`, `test_evaluation_context_carries_no_turn_data`, `test_turn_data_does_not_change_what_policy_approval_and_dispatch_receive`, `test_turn_records_are_not_fed_back_into_model_context` |
| CT-INV-6 | Review verifies turn manifests against Evidence and recorded context artifacts. | `test_review_reconstructs_turns_consistently`, the `test_review_detects_*` tests (missing manifest or outcome, rejected output without a record, duplicates and gaps, forged request hash, provider or endpoint change, context mismatches, tampered Evidence, instruction mismatch, events after terminal, completion without an accepted turn), `test_turn_events_do_not_exist_before_contract_1_1_0` |
| CT-INV-7 | No credential reaches durable turn records. | `test_unsafe_explanations_are_withheld_never_persisted`, `test_raw_model_output_is_never_persisted`, `test_credential_shaped_capability_name_halts_before_use`, `test_no_credential_or_header_reaches_turn_records`, `test_stored_details_validator_rejects_unsafe_or_inconsistent_records` |

Golden fixture: `tests/fixtures/agent_turn_golden.json` pins the manifest,
outcome, provider identity and a canonical provider request hash.

**Limitations.**
- The request hash of a declared provider is computed by the provider
  adapter (trusted code). The Runtime cannot independently observe the
  bytes on the wire. A parity test shows the recorded hash equals the SDK
  kwargs, and those equal the request body.
- Review cannot recompute the provider request or the catalog/target
  hashes (neither the catalog nor the views are stored). It verifies
  instruction and objective hashes, context references and Evidence
  content, identity consistency and request/outcome agreement.
- A local attacker who rewrites the whole chain consistently is still not
  detected (T-18).
- The context window, sequence counter and context sources are in memory.
  Nothing here makes an investigation resumable.

#### Tool-output screening and model egress (Phase 15)

**Why.** A successful tool result was persisted as Evidence and shown to the
model with no content control, while every other durable text path was
credential-screened (T-20, T-60).

**Flow.**

```
ToolResult → Tool Layer envelope (JSON → size → schema)
  → Runtime: THE tool-output screen (chanakya.contracts.tool_output_screening)
      REJECT → ToolResult(error, "sensitive_output_rejected: <CODE>") → no Evidence, no context, no retry
      PASS   → Evidence (screening_version, redactions_applied=false)
             → egress gate: envelope.model_egress == allowed ? context source : Evidence only
```

- **One screen (NX-INV-1/2).** `screen_tool_output` runs in
  `AgentLoopController._execute_once` on the only path from a successful
  result to Evidence or context, whatever executor produced the result.
  - It screens exactly the payload that would be persisted (`output`,
    `raw_output`, `warnings`, `error_message`): every string value and
    every key, at any depth.
  - It uses the shared credential patterns (URL userinfo,
    `key=`/`key:` credential assignments, PEM private-key headers) plus
    upper-case env-style assignments (`KEY=`, `…_TOKEN=`, `…_SECRET=`).
  - It is bounded: 1 MiB canonical size, depth 32, 100 000 nodes. Anything
    over a bound, non-JSON or with non-string keys is rejected, never
    skipped.
  - `FilesystemEvidenceRecorder` calls the same function again as a
    backstop (same answer, not a second policy), and refuses Evidence that
    lacks the current marker.
- **Rejection (NX-INV-5).** The result becomes `status=error` with the fixed
  message `sensitive_output_rejected: <CODE>`; output, raw output and
  warnings are dropped.
  - No Evidence, no context source, no retry (`dispatch_failed` with
    `retry_scheduled: false`, reason `sensitive_output_rejected`), and no
    repair, truncation or redaction.
  - The model is not told anything about the rejected result.
- **Provenance (NX-INV-4).** Screened Evidence carries `screening_version`
  (`chanakya-tool-output-screen/1.0.0`) and `redactions_applied=false`
  ("screened, nothing redacted"). Records without the field predate
  Phase 15.
- **Egress (NX-INV-3).** `RegistryEntry.model_egress` (`allowed` /
  `evidence_only`, required, no default) is copied into
  `CapabilityEnvelope.model_egress`.
  - The Runtime records each result's authorizing envelope at dispatch.
    Only results whose envelope says `allowed` become context sources.
  - An `evidence_only` source that appears in the window fails the
    investigation (`context_source_rejected`). A caller-supplied one is
    rejected as not Runtime-owned. A manifest entry with any egress other
    than `allowed` cannot be recorded (audit fact error, so the turn halts).
  - Manifest entries record `capability` and `model_egress`; the
    `policy_evaluated` envelope summary records `model_egress`.
  - The handler, the result, parameters and the model cannot influence it.
- **Review.** For AuditEvent 1.2.0 streams it checks:
  - every Evidence record has a supported marker and
    `redactions_applied=false`, and its payload still passes the screen;
  - every context entry names its request's capability, an `allowed`
    egress, and the same egress as the authorizing envelope.

  Mixed-version streams are flagged and judged by their highest version.
  Older streams are shown as "not assessed (predates Phase 15)".
- **Provider retries.** `AnthropicProvider` sets `max_retries=0`, also on
  injected clients (`with_options`): one recorded turn is exactly one send.
- **Authority (NX-INV-6).** Screening and egress are data-flow controls.
  The Policy Gateway, approval, dispatch, intake and risk never reference
  them, and verdicts are identical for `allowed` and `evidence_only`.

| ID | Invariant | Tests (`tests/test_tool_output_screening.py`) |
|---|---|---|
| NX-INV-1 | No successful ToolResult containing a credential-shaped key or string value becomes Evidence, a context source or model context; it is rejected with a fixed code that contains no content. | `test_t60_sensitive_output_never_reaches_evidence_context_or_provider`, `test_screen_detects_credentials_at_any_depth`, `test_screen_covers_every_persisted_payload_field`, `test_rejection_error_contains_only_the_fixed_code` |
| NX-INV-2 | The screen is on the single authoritative path; no recorder, retry or injected source bypasses it. | `test_injected_evidence_recorder_never_sees_rejected_output`, `test_production_recorder_refuses_unscreened_or_unmarked_evidence`, `test_screen_is_bounded_and_fails_closed` |
| NX-INV-3 | Only output whose Registry-declared egress is `allowed` can become model context. | `test_evidence_only_output_is_evidence_but_never_model_context`, `test_handler_cannot_declare_its_own_egress`, `test_parameters_and_the_model_cannot_change_egress`, `test_evidence_only_result_cannot_be_forced_into_model_context`, `test_evidence_only_source_in_runtime_state_fails_closed`, `test_registry_requires_a_declared_egress`, `test_envelope_requires_a_declared_egress`, `test_review_flags_forged_manifest_egress` |
| NX-INV-4 | Every Phase 15-era Evidence record has explicit screening provenance; Review detects missing or inconsistent provenance. | `test_clean_evidence_records_screening_provenance`, `test_evidence_contract_validates_screening_provenance`, `test_review_flags_missing_screening_marker`, `test_review_flags_a_forged_screening_marker`, `test_historical_streams_predate_the_control_and_are_not_reported_as_screened`, `test_review_flags_mixed_contract_versions` |
| NX-INV-5 | Rejection is deterministic: not retried, repaired, truncated, partially stored or sent. | `test_rejection_never_retries_even_with_budget`, `test_t60_sensitive_output_never_reaches_evidence_context_or_provider`, `test_one_recorded_turn_is_one_provider_send` |
| NX-INV-6 | Screening and egress metadata carry no authority. | `test_screening_and_egress_are_unreachable_from_authorization`, `test_egress_never_changes_a_policy_verdict`, `test_screening_rejection_changes_no_policy_approval_or_risk` |

**Limitations.**
- Pattern-based credential detection. Novel secret formats, and sensitive
  but non-credential data, pass; general classification or DLP is
  deferred.
- The screen can over-block legitimate output with credential-like keys or
  assignments. That fails closed with a fixed code.
- Both production capabilities are `allowed`: their output still leaves
  the host by design.
- Evidence at rest is not encrypted or permission-restricted.
- Phase 15 screens *successful* output only. Failure text is covered by
  Phase 16, below.

#### Failure-path output control (Phase 16)

**Why.** Phase 15 screened *successful* tool output only. A failed or
timed-out result carried handler-authored text: the executor built
`error_message` from `f"{ExcClass}: {exc}"`, and the timeout supervisor used
the `ToolExecutionTimedOut` message. That text was written to the durable
audit log (`dispatch_failed.error_message`), became a `tool_result_error`
context source sent to the provider, and was shown by Review. The audit
log's own screen was weaker than the tool-output screen (no PEM header, no
`…_TOKEN=` assignment). Reproduced with `ValueError("GITHUB_TOKEN=…")` and a
PEM header in a handler exception (T-61).

**Principle.** A handler *signals* failure, timeout or cancellation. The
Runtime owns the text that crosses a boundary.

```
Handler ── success ──────────────→ envelope → Phase 15 screen → Evidence / egress
   │
   └─ exception / timeout / late result
        → Runtime failure normalization → fixed code
        → Runtime backstop (closed vocabulary, status agreement, no content)
            REJECT → investigation fails closed (tool_failure_output_rejected)
            PASS   → dispatch_failed (audit) + tool_result_error (context) → Review
```

- **Closed vocabulary (`chanakya.contracts.tool_failure`).** A non-success
  `error_message` must be *exactly* one of `RUNTIME_FAILURE_MESSAGES`:
  - `tool_execution_failed: <CODE>`, where the code is one of
    `HANDLER_EXCEPTION`, `HANDLER_OUTPUT_MALFORMED`, `HANDLER_NOT_REGISTERED`,
    `TARGET_NOT_REGISTERED`, `TARGET_TYPE_UNSUPPORTED`, `HANDLER_TIMEOUT`,
    `STEP_TIMEOUT_EXCEEDED` or `CANCELLED`;
  - `capability_envelope_violation: <CODE>` (Phase 11);
  - `sensitive_output_rejected: <CODE>` (Phase 15).

  There is no prefix matching and no repair. Timeout codes go with
  `status=timeout`, and only they do. The longest message is 60
  characters (bound: 96).
- **Exception normalization.** `CapabilityDispatchExecutor` maps any
  handler exception to `HANDLER_EXCEPTION`. It drops the message, the
  arguments and the class name. Dispatch-table misses, unknown targets,
  unsupported target types and non-mapping returns get their own codes;
  the capability, target reference and returned type are not echoed. The
  failure itself is kept (still `status=error`), so retry semantics are
  unchanged.
- **Timeout normalization (NX16-INV-3).** A handler's
  `ToolExecutionTimedOut` becomes `HANDLER_TIMEOUT`. A measured overrun
  becomes `STEP_TIMEOUT_EXCEEDED`. The signal's message and the measured
  duration are never recorded.
- **Cancellation.** A result that arrives after the investigation ended is
  discarded, as before (RT-INV-9). It is now replaced by a Runtime-owned
  `CANCELLED` error result, so neither its output nor its text is carried
  in the returned `TurnResult`.
- **Runtime backstop (NX16-INV-2).** `AgentLoopController._execute_once`
  checks every non-success result, whatever executor produced it, with
  `failure_result_problem`. The message must be in the vocabulary, agree
  with the status, and the result must carry no `output`, `raw_output` or
  `warnings`. A violation fails the investigation closed
  (`tool_failure_output_rejected`, details `{"code": <PROBLEM>}`). It
  happens before `dispatch_failed`, a context source or a retry. The text
  is never stripped, truncated, redacted or recorded. An executor that
  raises still reaches the existing backstop
  (`unhandled_runtime_exception`), but with the fixed
  `ToolExecutorRaisedError` in place of its exception text.
- **Defense in depth.**
  - `AuditEmitter.dispatch_failed` refuses a message outside the vocabulary
    (`AuditSinkError`, fixed code), so the text is never persisted.
  - `_remember_context_source` refuses a failure source that is not
    Runtime-owned.
  - Every turn re-checks `tool_result_error` sources before the provider
    is called (`context_source_rejected`).
- **Audit screening parity (NX16-INV-4).** `FilesystemAuditLog` screens
  `details` with `screen_tool_output`, the Phase 15 function, over every
  key and string value, bounded and iterative. Undecidable details are
  rejected. The fact builders (`chanakya.contracts.audit_details`) use the
  same canonical predicates (`is_credential_shaped_value`,
  `is_credential_shaped_key`). There is no separate audit regex.
- **Review (NX16-INV-5).** For AuditEvent 1.3.0 streams, Review checks two
  things against the vocabulary and the recorded status: every
  `dispatch_failed.error_message`, and the failure text behind every
  `tool_result_error` context entry. Violations are flagged
  (`dispatch_failure_text_invalid`, `turn_context_failure_text_invalid`)
  and withheld: the review and `--review` output say "withheld" and never
  echo the text.
  - Older streams may hold free-form failure text. It is shown, except
    credential-shaped, oversized or control-character text, which is
    withheld without an anomaly because it predates the control.
  - A stream with 1.2.0 and 1.3.0 events is flagged
    `mixed_contract_versions` and judged as 1.3.0.
- **Authority (NX16-INV-6).** Failure codes are data. The Policy Gateway,
  approval, dispatch authorization, intake, the Registry, the Risk Engine
  and the Retry Controller never reference them. Retry eligibility still
  uses `status` and the existing envelope/screening predicates.

| ID | Invariant | Tests (`tests/test_failure_path_output.py`) |
|---|---|---|
| NX16-INV-1 | Every non-success ToolResult that reaches `dispatch_failed`, context, Review or the CLI has an `error_message` from the closed Runtime vocabulary and contains no handler-supplied substring. | `test_t61_handler_exception_never_reaches_audit_context_provider_review_or_cli`, `test_handler_exception_text_never_crosses_any_boundary`, `test_credential_shaped_exception_class_name_is_not_visible`, `test_t61_live_cli_output_shows_only_the_fixed_code`, `test_no_production_path_builds_failure_text_from_exceptions`, `test_executor_never_formats_exceptions` |
| NX16-INV-2 | The vocabulary is enforced by the Runtime, not only the executor. An injected executor returning arbitrary failure text fails closed; the text never reaches audit, context or provider. | `test_injected_executor_failure_text_fails_closed`, `test_executor_that_raises_fails_closed_without_its_text`, `test_retry_attempt_with_injected_raw_text_fails_closed`, `test_cancellation_race_result_is_replaced_by_the_cancelled_code`, `test_a_failure_source_with_raw_text_in_runtime_state_fails_closed`, `test_audit_emitter_refuses_raw_failure_text` |
| NX16-INV-3 | Handler timeout signals never propagate their message; timeouts use a fixed Runtime code. | `test_malicious_timeout_message_becomes_the_fixed_timeout_code`, `tests/test_timeout_supervisor.py` |
| NX16-INV-4 | The durable audit log rejects every string the canonical predicate rejects; audit and tool-output screening share one predicate. | `test_audit_log_screen_equals_the_canonical_predicate`, `test_weakening_the_audit_predicate_is_detected`, `test_audit_fact_builders_use_the_canonical_predicate`, `test_single_predicate_no_local_copies`, `test_audit_log_rejects_unscreenable_details` |
| NX16-INV-5 | Review of 1.3.0 streams flags invalid `dispatch_failed.error_message` and invalid `tool_result_error` content, without echoing it. | `test_review_flags_forged_failure_text_and_never_echoes_it`, `test_review_flags_status_mismatch_and_oversized_text`, `test_mixed_version_downgrade_cannot_relax_failure_checks`, `test_historical_streams_keep_their_semantics`, `test_review_of_a_phase16_stream_is_consistent` |
| NX16-INV-6 | Error codes carry no authority: retry eligibility, policy, approval, authorization and risk never use handler text or screening state. | `test_failure_vocabulary_is_unreachable_from_authorization`, `test_failure_codes_change_no_policy_approval_or_risk` |

**Limitations.**
- Diagnostics are coarser: the handler's own message is not recorded
  anywhere. Debugging a handler needs a local reproduction.
- The canonical predicate is pattern-based (T-20 residual). For example,
  bare lower-case `key=value` is not a credential pattern. Parity means
  the audit log is never weaker than tool-output screening, not that
  either is complete.
- A local attacker who rewrites the whole chain as a homogeneous 1.2.0
  stream makes it look historical (T-18). Credential-shaped historical text
  is still withheld from display.
- *(Corrected in Phase 17.)* `error`/`investigation_halted` details were
  not only Runtime text: provider, adapter, store and approval exception
  text reached them too (T-62). See the next section.

#### Runtime-owned error and terminal records (Phase 17)

**Why.** Phase 16 made `ToolResult` failure text Runtime-owned, but the
Runtime's own records still embedded exception text from outside the
Runtime. A provider SDK/remote error, an adapter, a store or the approval
provider could raise; the backstop and 13 of the 19 fail/halt sites wrote
`str(exc)` (and the class name) into:
- `error`/`investigation_halted` details;
- `InvestigationContext.error_state`;
- `TurnResult.detail`, which the CLI prints.

Worse, credential-shaped or 70 KB text made the terminal audit write fail
(screen or size limit). The backstop swallowed that, so the investigation
was FAILED in memory while the durable record had no terminal event
(T-62).

**Principle.** An exception from anywhere is a signal. The Runtime owns
every record of it.

```
exception (provider / adapter / store / approval / executor / Runtime)
  → Runtime-owned exception type (ProviderFailedError, ApprovalProviderFailedError, …)
  → terminal_record(reason, category, facts)   closed, bounded, validated
  → terminal audit event written FIRST
  → only then the terminal state is published (error_state = the same record)
     sink I/O failure → HALTED audit_sink_failure, terminal_record: not_durable
```

- **Vocabulary (`chanakya.contracts.runtime_failure`).**
  - `reason`: one of `TERMINAL_REASONS`, the Runtime's existing reason
    strings.
  - `category`: one of `RUNTIME_FAILURE_CATEGORIES` allowed for that
    reason. The categories are `PROVIDER_FAILURE`, `APPROVAL_FAILURE`,
    `TOOL_EXECUTOR_FAILURE`, `RUNTIME_EXCEPTION`, `AUDIT_FAILURE`,
    `TARGET_CONTEXT_UNAVAILABLE`, `ENVIRONMENT_UNAVAILABLE`,
    `CONTEXT_SOURCE_REJECTED`, `EVIDENCE_RECORDING_FAILED`,
    `FINDING_RECORDING_FAILED`, `FINDING_STORE_UNAVAILABLE`,
    `RISK_ASSESSMENT_FAILED`, `RESOURCE_LIMIT_EXCEEDED`,
    `DISPATCH_PRECONDITION_VIOLATION`, `TOOL_FAILURE_OUTPUT_REJECTED`,
    `APPROVAL_EXPIRED` and `CANCELLED`. `unhandled_runtime_exception`
    (the backstop) takes the category of the failing component; the other
    reasons each have exactly one.
  - Optional facts: `code` (a Phase 16 problem code), `finding_count`
    (1–1000) and `cancelled_by` (≤ 256 characters, no control characters,
    canonical credential screen).
  - Anything else raises `TerminalRecordError` (fixed message) before
    anything is written or transitioned. There is no free-form `details`
    parameter any more.
- **Closed shape first.** `error`/`investigation_halted` details are
  exactly the record, plus `investigation_status: "failed"` on a terminal
  `error`. Screening remains defense in depth; it is not the control. The
  largest possible record is under 512 canonical bytes.
- **Normalization.**
  - *Provider:* any exception in `provider_identity`/`prepare_turn`/
    `send_turn`/`next_turn` becomes `ProviderFailedError`. The turn
    outcome records `error_type: PROVIDER_FAILURE`, never the class name.
  - *Approval provider:* its exceptions become `ApprovalProviderFailedError`.
    This still fails closed and is never an approval.
  - *Target/environment:* `TargetManager.collect_environment` returns
    fixed codes (`TARGET_NOT_REGISTERED`, `NO_ADAPTER_REGISTERED`,
    `ADAPTER_COLLECTION_FAILED`), and `EnvironmentContextUnavailableError`
    has fixed messages. Environment context stays unwired in the CLI.
  - *Stores:* Evidence, Finding and Risk store exceptions become their
    reason's category.
  - *`AuditEmitter`:* wraps a sink exception as `AuditSinkError("AuditSink.emit failed")`,
    with the original chained only as `__cause__`.
- **Terminal durability (P17-INV-2/3).** `InvestigationManager.complete`,
  `fail`, `halt` and `cancel` do the following in order:
  1. build and validate the record;
  2. check that the transition is allowed;
  3. write the terminal event;
  4. only then transition and release the concurrency slot.

  External text cannot make the record unrecordable (Case A: a 70 KB
  provider error still yields a durable FAILED event). If the audit sink
  itself fails (Case B, I/O), the investigation is halted in memory with
  `{"reason": "audit_sink_failure", "category": "AUDIT_FAILURE",
  "terminal_record": "not_durable"}` and `TerminalRecordUndurableError` (an
  `AuditSinkError`) is raised. The turn reports `HALTED`/`AUDIT_FAILURE`,
  the CLI prints "terminal record NOT durable", and Review reports
  `incomplete`. A completion whose event cannot be written is never
  `COMPLETED`.
- **TurnResult and CLI (P17-INV-4).** `TurnResult.detail` is `None` or a
  member of `TURN_DETAIL_CODES` (categories plus fixed notes such as
  `MALFORMED_TURN` or `AWAITING_APPROVAL_PENDING`). The constructor rejects
  anything else. The CLI prints only these codes, and the final status
  line prints `reason` and `category`. No new information reaches the
  model.
- **Review (AuditEvent 1.4.0, P17-INV-5).**
  - In 1.4.0 streams, every `error`/`investigation_halted` event must be
    exactly a closed-shape record (`terminal_details_invalid` otherwise), and
    a provider-failure `error_type` may only be `PROVIDER_FAILURE`
    (`turn_error_type_invalid`).
  - Invalid values are withheld: `terminal_reason` and `terminal_category`
    are then `None`.
  - Mixed 1.3.0/1.4.0 streams are flagged and judged as 1.4.0.
  - Older streams keep their semantics; only a plain reason token is shown.
- **Authority (P17-INV-6).** The vocabulary is descriptive. Policy,
  approval, the Registry, capability, risk, dispatch, intake and the Retry
  Controller never reference it.

| ID | Invariant | Tests (`tests/test_runtime_owned_error_records.py`) |
|---|---|---|
| P17-INV-1 | No external exception message or class name reaches audit, `error_state`, `TurnResult.detail` or the CLI. | `test_provider_exception_is_a_fixed_code_and_the_terminal_event_is_durable`, `test_real_sdk_error_body_never_crosses`, `test_provider_failure_before_sending_is_normalized`, `test_environment_adapter_exception_is_a_fixed_code`, `test_target_context_exception_is_a_fixed_code`, `test_evidence_store_exception_is_a_fixed_code`, `test_finding_and_risk_store_exceptions_are_fixed_codes`, `test_approval_provider_exception_is_a_fixed_code_and_never_approves`, `test_context_source_error_text_is_a_fixed_code`, `test_no_exception_text_reaches_terminal_or_error_records`, `test_the_static_rule_catches_reintroduced_exception_text` |
| P17-INV-2 | Terminal details are closed-shape and bounded before persistence, so attacker text cannot prevent a terminal event. | `test_every_terminal_record_is_closed_small_and_deterministic`, `test_anything_outside_the_closed_shape_is_rejected`, `test_invalid_record_is_rejected_before_anything_is_written`, `test_equivalent_failures_produce_identical_records`, the 70 KB cases |
| P17-INV-3 | Runtime terminal state and the durable terminal event agree, except on a genuine sink failure, which is explicit. | `test_terminal_event_is_durable_before_the_state_changes`, `test_genuine_sink_failure_is_explicit_and_never_claims_a_durable_terminal`, `test_cli_reports_a_not_durable_terminal_record`, `tests/test_audit_log_runtime.py` |
| P17-INV-4 | The CLI prints only Runtime-owned codes. | `test_cli_prints_only_runtime_codes`, `test_turn_result_detail_accepts_only_runtime_codes` |
| P17-INV-5 | Review of 1.4.0 streams flags and withholds invalid terminal/error details; mixed 1.3.0/1.4.0 is flagged. | `test_review_flags_forged_error_details_and_never_echoes_them`, `test_review_flags_forged_halt_details`, `test_review_flags_a_forged_turn_error_type`, `test_mixed_versions_cannot_downgrade_terminal_validation`, `test_historical_streams_keep_their_semantics`, `test_review_of_phase17_streams_is_consistent` |
| P17-INV-6 | Runtime error codes carry no authority. | `test_runtime_error_codes_are_unreachable_from_authority`, `test_a_provider_failure_changes_no_policy_or_risk` |

**Limitations.**
- Operator diagnostics are coarser: exception messages are not recorded
  anywhere, but the original stays chained as `__cause__` in the process.
- Composition-time configuration errors printed by `main()` (before any
  investigation exists) still show their trusted-code message. That is
  the one reviewed exception to the static rule.
- A genuine sink failure leaves no durable terminal event by definition:
  Review shows `incomplete`. External anchoring is out of scope (T-18).
- The Gateway's deny `reason` for a malformed request or schema violation
  is Runtime/validator text over already-screened parameters. It is a
  policy fact, not a terminal record, and is unchanged.

**`RuntimeExecutionLimits`** — admin-controlled configuration (trusted,
versioned, not Agent-writable), analogous to `PolicySet`.

| Field | Type | Required |
|---|---|---|
| `config_version` | string (semver) | required |
| `max_steps_per_investigation` | integer | required |
| `max_investigation_duration_seconds` | integer | required |
| `default_step_timeout_seconds` | integer | required (fallback only) |
| `max_retries_per_step` | integer | required |
| `retry_backoff_seconds` | integer | required |
| `max_concurrent_investigations` | integer | required |
| `approval_expiry_seconds_default` | integer | optional |
| `p4_approval_expiry_action` | enum(`fail_step`, `halt_investigation`) | required, default `fail_step` |

**`StepRecord`** — the concrete shape of one
`InvestigationContext.step_history[]` entry, clarifying (not
contradicting) `CONTRACTS.md` §2's loosely-typed "array\<object\>".

| Field | Type | Required |
|---|---|---|
| `step_id` | string | required |
| `tool_request_id` | string | required |
| `policy_decision_id` | string | required |
| `approval_request_id` | string | optional |
| `approval_decision_id` | string | optional |
| `tool_result_id` | string | optional (absent until dispatch occurs) |
| `evidence_id` | string | optional (absent until Evidence is written) |
| `status` | enum — the step-level state machine value (§15) | required |
| `attempt_number` | integer | required (1 for the first attempt; increments on retry) |
| `started_at` / `ended_at` | string (timestamp) | required / optional |

**`DispatchInstruction`** — the Runtime → Tool Layer internal call
shape. The Tool Layer does not exist yet (Phase 4+); this is the
contract a future Tool Layer implementation must accept, defined now so
the Dispatcher's interface (§7) is concrete.

| Field | Type | Required |
|---|---|---|
| `investigation_id` | string | required |
| `tool_request_id` | string | required |
| `capability` | string | required |
| `target_ref` | string | required |
| `parameters` | object | required |
| `resolved_timeout_seconds` | integer | required: `min(envelope.timeout_seconds, RuntimeExecutionLimits.default_step_timeout_seconds)` (Phase 11) |
| `resolved_resource_limits` | object | required: exactly `{"max_output_bytes": envelope.max_output_bytes}` (Phase 11) |
| `policy_decision_id` | string | required |
| `approval_decision_id` | string | optional |
| `attempt_number` | integer | required |
| `capability_envelope` | `CapabilityEnvelope` | optional in the type; the Agent Loop Controller always sets it from the `PolicyDecision`, and the production Tool Layer refuses to run without it (Phase 11) |

Never includes a credential (RT-INV-11); never visible to the Agent.

> **Implementation note (Phase 3 Step 3.6, closing a genuine gap found
> during integration testing):** `investigation_id` was added to this
> shape after `dispatch()`'s binding check was found to verify
> `ApprovalRequest.tool_request_id`/`policy_decision_id`/
> `approval_request_id` but never `ApprovalRequest.investigation_id`
> itself — meaning an approval genuinely issued for one investigation
> could, in principle, authorize a dispatch under a different one whose
> request happened to carry the same `tool_request_id`/
> `policy_decision_id` (never reachable via the normal Agent Loop
> Controller flow, which always constructs these for the current
> investigation, but not something the precondition gate itself was
> independently verifying). `dispatch()` now additionally checks
> `approval_request.investigation_id == instruction.investigation_id`
> for any `require_approval` verdict. See
> `chanakya/runtime/dispatch.py`.

---

## Traceability to `docs/THREAT-MODEL.md`

| Requirement | Runtime mechanism |
|---|---|
| SR-5, SR-6 | Dispatcher's mandatory-`PolicyDecision` calling convention (RT-INV-1) |
| SR-7, SR-8 | Approval Coordinator + Dispatcher's mandatory-`ApprovalDecision` parameter (RT-INV-2); decisions bound to one `approval_request_id`, never reused (RT-INV-4) |
| SR-9 | Policy Gateway Client's defensive wrapper around `evaluate()` (§5) — belt-and-suspenders on top of the Gateway's own fail-closed guarantee |
| SR-10, SR-11 | Evidence Writer / Audit Emitter — append-only, hashed, fully traceable (§9, §14) |
| SR-12 | Audit Emitter — one `AuditEvent` per transition, unconditionally (RT-INV-6) |
| SR-13, SR-14 | No credential ever placed on any Runtime-internal object (RT-INV-11); the Runtime itself never resolves one |
| SR-15, SR-16 | Context Assembler wraps tool/target output as data (RT-INV-7); `AgentTurnOutput`/`ToolRequest` always schema-validated before use |
| SR-17 | `Finding` storage rejects empty `evidence_refs` before it ever reaches `InvestigationContext` |
| SR-18 | `RiskAssessment` handling is validation/storage only — the Runtime never computes or overrides one itself. The deterministic Risk Engine (`chanakya.risk`, Phase 10) is injected as a `RiskAssessor`; the Runtime only validates its output against the Findings it stored |
| SR-19 | **Not implemented** (design only; corrected in Phase 15). No `Recommendation` type is produced, stored or displayed. The design requirement stands: a future `Recommendation` must never be auto-dispatched, and acting on one must go through a new, independently evaluated `ToolRequest` |
| SR-20 | Timeout Supervisor + Resource Governor (§10, §18) |
| SR-21 | Runtime does not alter or escalate `required_privileges`; it only observes the Gateway's existing SR-21 check |

---

## Security controls summary

- **Structural, not conventional, enforcement of the two critical
  boundaries** — dispatch requires a `PolicyDecision` object as a
  mandatory function parameter (RT-INV-1), and a `require_approval`
  dispatch additionally requires an accepted `ApprovalDecision` object
  as a mandatory parameter (RT-INV-2) — closing T-15/T-16 at the
  interface level, not merely by convention.
- **No default/implicit approval anywhere** — expiry and non-response
  both resolve to "no dispatch," never "proceed" (RT-INV-3).
- **Retries never launder a stale decision** — every attempt is a fresh,
  independently-evaluated `ToolRequest` (RT-INV-4).
- **The Runtime never repairs Agent output** — malformed or denied
  requests are surfaced, not corrected, preserving the Agent's actual
  (possibly hijacked or hallucinating) behavior in the audit trail
  rather than papering over it (RT-INV-5).
- **Fully audited, fail-closed on write failure** — an unrecorded action
  is treated as not having durably happened; the Runtime halts rather
  than proceed silently (RT-INV-6).
- **Untrusted/semi-trusted data never becomes instructions** — the
  Context Assembler is the single enforcement point for treating
  tool/target output as data on re-entry into an LLM prompt (RT-INV-7).
- **No execution surface beyond the Registry** — no shell/subprocess/
  `eval` anywhere in the Runtime; the Dispatcher's only action is a
  typed call keyed by an already-Gateway-approved capability (RT-INV-8).
- **Cancellation is safe, not abrupt** — it never leaves a half-recorded
  action (RT-INV-9).
- **Sequential-by-default execution within an investigation** — removes
  an entire class of ordering/race bugs from the audit trail (RT-INV-10).
- **No credential ever reachable from the Runtime's own data structures**
  (RT-INV-11).

---

## Phase 3 Step 3.6 — Integration hardening addenda

Step 3.6 ("Runtime Integration & Hardening") exercised every component
built in Steps 3.4–3.5 together, end-to-end, against the real Phase 2
Policy Gateway. It found and fixed five genuine gaps — none of them a
redesign, all additive or corrective within the existing component
boundaries. Two are documented inline above, next to the diagrams they
affect (`DispatchInstruction.investigation_id`; the step-level
`evidence_failed` state). The remaining three, consolidated here:

1. **Cancellation during the approval wait now transitions the step to
   `step_denied`, not `step_failed`.** `AWAITING_STEP_APPROVAL`'s only
   valid exits are `dispatching` and `step_denied` (§15's own diagram);
   the original implementation of the cancellation race-guard in
   §13 (Human approval integration point) tried `step_failed`, an
   invalid transition. A cancelled wait is denial-shaped ("dispatch will
   never happen for this step"), the same as an expired or rejected
   approval, so `step_denied` is both valid and the more accurate label.
2. **The retry loop (§12) now re-checks investigation status after the
   backoff sleep, not only before it.** The original implementation
   checked once, before calling `self._sleep(...)`, then proceeded
   unconditionally to the next attempt. A cancellation delivered entirely
   inside the backoff window was previously not observed until *after*
   the next attempt had already dispatched. The check is now repeated
   immediately after the sleep, closing that race.
3. **An Audit Log write failure now halts the investigation, distinctly
   from other unexpected errors, which still fail it.** §11's error
   table already specified this ("treated as equivalent in severity to
   an Evidence write failure — the Runtime halts"); the original
   `run_turn` fail-closed backstop always resolved every unexpected
   exception to `failed` regardless of source. `AuditEmitter` now wraps
   any `AuditSink.emit` failure in a dedicated `AuditSinkError`, and the
   backstop routes that specific type to `halted` instead. A related,
   narrower fix: `run_turn` now recognizes an investigation already
   `awaiting_approval` (e.g. because no `ApprovalProvider` is configured
   yet and a prior turn never resolved) and returns `awaiting_approval`
   again immediately, rather than attempting a second, structurally
   disallowed step and reaching the backstop by a confusing path.

All five were found by, and are regression-tested in, Step 3.6's
integration test suite (`tests/test_cancellation_integration.py`,
`tests/test_resource_and_error_integration.py`,
`tests/test_state_machine_integration.py`,
`tests/test_adversarial_integration.py`). None weakened an existing
security control; each closes a gap toward the already-documented
behavior.

---

## Open items (non-blocking, for a future `CONTRACTS.md`/`ARCHITECTURE.md` revision)

Following the same pattern used by `docs/THREAT-MODEL.md`,
`docs/POLICY-GATEWAY.md`, and `docs/TOOL-REGISTRY.md`. None of these
block Phase 3's design or a subsequent implementation phase.

1. **A dedicated `ApprovalRequest.status` value for "withdrawn due to
   cancellation"** — currently reuses `expired` (§17), which is accurate
   in effect (no dispatch will ever occur for it) but conflates "timed
   out naturally" with "moot because the investigation was cancelled."
   A future `CONTRACTS.md` revision could add `withdrawn` alongside
   `pending`/`decided`/`expired`.
2. **A dedicated `AuditEvent.event_type` value for cancellation** —
   currently reuses `investigation_halted` with a `details.reason:
   cancelled_by_operator` field (§14, §17), consistent with
   `CONTRACTS.md` §13's rule against inventing ad hoc `event_type`
   strings, but a dedicated `investigation_cancelled` value would make
   this queryable without inspecting `details`.
3. **A formal `InvestigationContext.status` value or sub-field for
   graceful budget-based completion** vs. operator/timeout `halted` (§16)
   — currently both resolve to `halted` with different `error_state`
   contents; a future revision could distinguish "ended because the
   configured step budget was reached without incident" from "ended
   because someone/something stopped it," if that distinction proves
   useful for reporting.
4. **`InvestigationContext.step_history`'s loose `array<object>` typing**
   — this document's `StepRecord` (above) is a concrete proposal for
   what that object should contain; adopting it formally into
   `CONTRACTS.md` is additive and non-breaking.
5. **Resuming a `halted`/`failed` investigation** — explicitly out of
   scope for this design (§15); if a future phase wants this, it needs
   its own state-machine and audit-trail design (what carries over, what
   re-validates) rather than an ad hoc addition here.

None of these require touching `ARCHITECTURE.md`, `docs/CONTRACTS.md`,
`docs/THREAT-MODEL.md`, `docs/POLICY-GATEWAY.md`,
`docs/TOOL-REGISTRY.md`, or `docs/CAPABILITY-PERMISSION-MODEL.md` for
Phase 3 to proceed; they are queued for whenever those documents are
next revisited.

---

## Runtime architecture diagram

```mermaid
flowchart TD
    subgraph AgentSide["Reasoning (untrusted output)"]
        LLMAbs[LLM Abstraction]
        AgentOut[AgentTurnOutput]
    end

    subgraph RuntimeCore["Agent Runtime (trusted control code)"]
        IM[Investigation Manager]
        CA[Context Assembler]
        ALC[Agent Loop Controller]
        RI[ToolRequest Intake]
        GWC[Policy Gateway Client]
        AC[Approval Coordinator]
        DISP[Dispatcher]
        RH[Result Handler]
        EW[Evidence Writer]
        AE[Audit Emitter]
        TS[Timeout Supervisor]
        RC[Retry Controller]
        RG[Resource Governor]
        CH[Cancellation Handler]
        ISS[(Investigation State Store)]
    end

    subgraph Enforcement["Policy, Approval, Registry"]
        GW[Policy and Security Gateway]
        REG[(Security Tool Registry)]
        APR[Human Approval Mechanism]
    end

    subgraph ExecutionZone["Execution (semi-trusted, future phase)"]
        TL[MCP / Tool Layer]
        TOOLS[Security Tools]
    end

    subgraph StorageZone["Storage (append-only)"]
        EVS[(Evidence Store)]
        AUD[(Audit Log)]
    end

    IM --> ISS
    IM --> CA
    CA --> LLMAbs
    LLMAbs --> AgentOut
    AgentOut --> ALC
    ALC --> RI
    RI --> GWC
    GWC -- ToolRequest --> GW
    GW -. checks .-> REG
    GW -- PolicyDecision --> ALC
    ALC --> AC
    AC -- ApprovalRequest --> APR
    APR -- ApprovalDecision --> AC
    AC --> DISP
    ALC --> DISP
    DISP -- DispatchInstruction --> TL
    TL --> TOOLS
    TOOLS -- ToolResult --> TL
    TL --> RH
    RH --> EW
    EW --> EVS
    RH --> CA
    ALC --> AE
    GWC --> AE
    AC --> AE
    RH --> AE
    AE --> AUD
    TS -.-> ALC
    TS -.-> DISP
    RC -.-> ALC
    RG -.-> GWC
    RG -.-> ISS
    CH -.-> IM
    CH -.-> ISS

    style AgentSide fill:#3a1f1f,stroke:#c0392b,color:#f5f5f5
    style RuntimeCore fill:#1f2f1f,stroke:#2ecc71,color:#f5f5f5
    style Enforcement fill:#1f2530,stroke:#3498db,color:#f5f5f5
    style ExecutionZone fill:#332a1f,stroke:#e67e22,color:#f5f5f5
    style StorageZone fill:#241f33,stroke:#9b59b6,color:#f5f5f5
```
