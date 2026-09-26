# Phase 10 — Risk Assessment: Architecture and Readiness Inspection

Status: **inspection and design proposal only.** No production code, test,
contract or existing document was changed to produce this report.

> **Implementation status (Phase 10, `v0.10.0-risk-assessment`).**
> Conditions C-1..C-4 were approved and implemented. Open questions O-1
> and O-2 were resolved with their proposed defaults: no audit event for
> not-assessed findings, and no exit-code change on verification failure.
>
> Deviations from this report. Each one keeps or strengthens a control:
>
> 1. **Where the rule-set data lives.** The data (base severities,
>    compatibility, rule-id vocabulary) is in
>    `chanakya/contracts/risk_taxonomy.py` together with the category ids,
>    not in `chanakya/risk/rules.py`. This lets the Runtime validate engine
>    output without importing `chanakya.risk`. `rules.py` holds only the
>    evaluation logic.
> 2. **Stricter contract.** It enforces internal rule-set consistency:
>    - the canonical `rule_ids` shape;
>    - severity equal to the category base, capped by the ceiling;
>    - confidence consistent with its rules.
>
>    A rehashed record with an altered severity is therefore rejected on
>    read, before recomputation. Rule ids form a closed vocabulary.
>    Capability ids appear only in the rationale.
> 3. **Verification before the category gate.** The engine verifies every
>    cited Evidence of every Finding before applying the category gate
>    (Rule 1). A corrupt record therefore fails closed even for an unrated
>    category.
> 4. **New EvidenceStore method.** `EvidenceStore` gained
>    `verify_in_investigation`, because the existing `get`/`verify` search
>    every investigation. `get_payload`'s file check moved into a private
>    helper; its behavior is unchanged.
> 5. **Extra Runtime check.** The Runtime also checks that a not-assessed
>    reason matches the Finding's category, which prevents suppressing a
>    rating as `category_unrated`.
> 6. **Capability id check.** The engine requires cited Evidence
>    capabilities to match `[a-z0-9_]{1,64}` and fails closed otherwise.
> 7. **Package exports.** `chanakya/contracts/__init__.py` is unchanged:
>    `Finding` is not exported there either.
> 8. **Strict CLI display.** The CLI withholds all ratings on any
>    verification problem, including an assessment missing after a halted
>    risk step.
> 9. **Test count.** It is 2226 rather than about 2060, because of heavier
>    parametrization.

Inputs inspected: `ARCHITECTURE.md`, `docs/CONTRACTS.md`,
`docs/AGENT-RUNTIME.md`, `docs/THREAT-MODEL.md`,
`docs/TARGET-AWARE-AGENT-CONTEXT.md`, every module under `chanakya/`
(contracts, findings, evidence, runtime, providers, policy, registry,
capability, tools, targets, approval, audit, cli), the test suite, git
history and tags.

---

## 1. Executive Summary

Phase 9 ends every successful investigation with evidence-grounded,
append-only, audited `Finding`s. Nothing rates them. The design documents
reserve a **Risk Engine** for this and state three requirements that decide
most of Phase 10's shape:

- `ARCHITECTURE.md` §11: risk comes from "explicit, auditable criteria …
  rather than relying solely on LLM judgment … given the same findings and
  the same rules, the same risk assessment results."
- `THREAT-MODEL.md` SR-18: `RiskAssessment` is "computed by explicit,
  versioned, reproducible criteria (`scoring_method`) and is not solely
  derived from Agent-reported confidence."
- `CONTRACTS.md` §9: `RiskAssessment.confidence` is "the Risk Engine's own
  confidence, computed independently of any Agent-reported confidence", and
  T-07 requires the two confidences to be shown side by side, not blended.

Several pieces are already in place: the `RiskCategory` enum, the
`risk_assessed` audit event type, `InvestigationContext.risk_assessment_refs`
with `add_risk_assessment_ref`, and `ApprovalRequest.risk_assessment_ref`.
There is **no `RiskAssessment` implementation**: no contract class, no
engine, no store, no Runtime path, no emitter method and no CLI display.

**Recommendation:** a **deterministic, versioned Risk Engine** with no model
in the loop. It rates each Finding stored in the conclude turn from:

- the Finding's category, which must belong to a closed rule-set taxonomy;
- the Runtime-owned provenance of the Evidence the Finding cites, re-read
  and verified from the Evidence Store.

It never reads free text or evidence payloads. The Runtime invokes it
through an injected Protocol, the same way it uses `FindingRecorder`. The
Runtime validates the engine's output, stores it append-only, audits it,
and only then completes the investigation. Nothing downstream (Gateway,
approval, dispatch) ever reads it.

**Verdict: READY WITH CONDITIONS** (§26). The conditions are owner
decisions: the rule-set taxonomy and severity table, the documented
amendments to `CONTRACTS.md` §9, and one small provider-schema change. None
of them is a technical blocker.

---

## 2. Current Checkpoint

| Item | Observed value |
|---|---|
| Branch | `main` |
| HEAD | `68c8e9cb8e8b58a0ffd4315e4541a8006353bec8` — "Phase 9: add evidence-grounded findings" |
| Tag at HEAD | `v0.9.0-evidence-grounded-findings` (annotated: `git cat-file -t` → `tag`; resolves to HEAD) |
| Working tree | clean (`git status --porcelain` empty) before this report was written |
| Test suite | **1896 passed**, 0 failed, 0 skipped (`python -m pytest -q`, 33.7 s, Python 3.13.1) |
| Test files | 58 `tests/test_*.py` |

Minor observations. They do not block Phase 10, and nothing was changed:
- `pyproject.toml` still says `version = "0.2.0"` and describes the project
  as the Phase 2 control plane.
- The `CONTRACTS.md` preamble still says "no implementation code exists
  yet".

---

## 3. Current Architecture

The actual flow in code:

```
CLI (chanakya/cli/main.py: build_runtime = composition root)
  └─ InvestigationManager.create_investigation / start
  └─ loop: AgentLoopController.run_turn(investigation_id, AnthropicProvider, catalog, recent_results)
        ├─ TimeoutSupervisor.check_investigation_timeout
        ├─ target context (TargetManager) + optional environment context → scope-checked
        ├─ ContextAssembler.assemble → AssembledContext (instructions | untrusted_data | investigation_targets)
        ├─ ResourceGovernor.check_context_size
        ├─ AgentProvider.next_turn  (AnthropicProvider → mapping.py; report_findings reserved channel)
        ├─ ResourceGovernor.check_provider_output_size
        ├─ AgentTurnOutput.from_dict  (structural; findings only with conclude, ≤ 20)
        ├─ propose_tool_request → ToolRequestIntake → PolicyGateway.evaluate → (approval) → dispatch()
        │        → ToolExecutor → ToolResult → Evidence (EvidenceStore, hashed) → evidence_recorded
        └─ conclude → [_record_findings → FindingStore.append → add_finding_ref → finding_created]
                    → InvestigationManager.complete  → investigation_completed
  └─ _report_findings (escaped display from FindingStore)
```

**Where Finding sits:** `AgentLoopController._record_findings` /
`_build_findings` (`chanakya/runtime/agent_loop.py:506-594`). They run only
on a `conclude` turn, after structural validation and before
`InvestigationManager.complete()`. After the last `finding_created` event
the only remaining step is `complete()`, which is terminal. Findings are
never fed back to the model, and nothing in `policy`, `tools`, `registry`
or approval reads them (FND-INV-1, tested).

---

## 4. Existing RiskAssessment Contract

| Artifact | Location | State |
|---|---|---|
| Contract **specification** | `docs/CONTRACTS.md` §9 | Defined: `risk_assessment_id`, `contract_version`, `finding_refs` (non-empty), `severity` (5-value enum), `confidence` (3-value), `scoring_method` (required), `assessed_at`, optional `rationale`, optional `mitigations_suggested` |
| Contract **class** | — | **Does not exist.** There is no `chanakya/contracts/risk_assessment.py` |
| Severity enum | `chanakya/contracts/enums.py:30` `RiskCategory` | Exists. Its docstring names it `RiskAssessment.severity`. It is also used by the Registry (`default_risk_category`) and by `PolicyDecision.risk_category` |
| Audit event type | `chanakya/contracts/audit_event.py:35` `RISK_ASSESSED` | Exists in the closed enum. **Never emitted**: `AuditEmitter` has no `risk_assessed` method |
| Context refs | `InvestigationContext._risk_assessment_refs`, `add_risk_assessment_ref` | Exist. **Never called** by production code |
| Approval link | `ApprovalRequest.risk_assessment_ref` | Exists, defaults to `None`, **never set** |
| Runtime rule | `AGENT-RUNTIME.md` SR-18 row | "pass-through/storage only — the Runtime never computes or overrides one itself" |
| Module skeleton | `ARCHITECTURE.md` "Proposed module skeleton" | `risk/  # Risk Engine`. **Does not exist** |
| Finding guard | `tests/test_findings.py:184,409` | `severity` is a *forbidden* key on a Finding and on a model-proposed finding. Severity must not come from the model through the Finding channel |

**Conclusion:** the contract is **specified only**. The pieces around it are
wired but unused.

Deficiencies in the §9 specification that Phase 10 must resolve (see §10):
- It has no `investigation_id`. Every other investigation-scoped record
  (`Evidence`, `Finding`) has one, and the store layout and
  foreign-reference rejection both need it.
- It has no evidence provenance. You can only reach Evidence through a
  second lookup, so a RiskAssessment cannot be checked against the evidence
  it was computed from.
- It has no rule trace. `scoring_method` names the rule set but not which
  rules fired.
- `mitigations_suggested` overlaps with Recommendations, which are out of
  scope (§9).

---

## 5. Current Production Flow

Traced through the real code:

1. **Investigation.** `cli.run_investigation` builds an
   `InvestigationRequest`. `InvestigationManager.create_investigation`
   checks the targets against `TargetRegistry` and `start()` emits
   `investigation_started`.
2. **Agent Provider.** `AgentLoopController._run_turn_body` assembles
   context, checks its size, then calls `AnthropicProvider.next_turn`,
   which runs `mapping.build_request_kwargs` and `messages.create`.
   - The `system` parameter is Runtime instructions only.
   - The user message is JSON with `investigation_targets` and
     `untrusted_data`.
   - `tools` holds the catalog tools (each with the reserved `target_ref`)
     plus `report_findings` when `findings_channel=True` (it is on in the
     CLI).
3. **Tool request.** `mapping._response_to_turn` turns a `tool_use` block
   into a raw `tool_request`. `AgentTurnOutput.from_dict` checks structure,
   then `_handle_tool_request_turn` → `ToolRequestIntake` builds a validated
   `ToolRequest` (`request_proposed`).
4. **Policy Gateway.** `PolicyGateway.evaluate(raw, EvaluationContext)`
   returns a `PolicyDecision` (`policy_evaluated`). A `require_approval`
   verdict goes to `_handle_require_approval` → `TerminalApprovalProvider`.
5. **Tool Executor.** `dispatch(instruction, decision, approval…)` checks
   its preconditions (RT-INV-1/2) and calls `ToolExecutor.execute` →
   handler (`list_listening_ports` / `observe_local_host_environment`).
   Emits `dispatch_started` / `dispatch_completed`.
6. **Tool result.** On `SUCCESS` the step completes. On `TIMEOUT` or
   failure the step ends with **no Evidence**, so any Evidence that exists
   came from a successful result.
7. **Evidence.** The Runtime builds `Evidence` with the Gateway's
   `classification` snapshot. `FilesystemEvidenceRecorder` →
   `EvidenceStore.append` computes `content_hash` and `payload_hash`
   (chained). Then `add_evidence_ref` and `evidence_recorded`.
8. **Finding.** On a conclude turn that carries `findings` (from the
   `report_findings` channel), `_build_findings` maps each cited
   `tool_result_id` to an `evidence_id` through this investigation's own
   `step_history`, requiring it to be in `context.evidence_refs`.
   `FindingStore.append` is all-or-nothing on validation and halts on a
   storage failure. Then `add_finding_ref` and `finding_created` (ids
   only).
9. **Current terminal state.** `InvestigationManager.complete` →
   `COMPLETED` + `investigation_completed`. The CLI prints the final
   status, the evidence count and escaped findings.

There is **no step between 8 and 9 today**. That gap is where Risk
Assessment belongs (§15).

---

## 6. Gap Analysis

Each item below was verified absent in the repository.

| # | Missing piece | Evidence of absence |
|---|---|---|
| G-1 | A `RiskAssessment` contract class with fail-closed validation | No `contracts/risk_assessment.py`; `contracts/__init__.py` exports none |
| G-2 | Contract fields for investigation binding, evidence provenance, rule trace and producer identity | §9 lacks `investigation_id`, `evidence_refs`, a rule trace and `assessed_by` |
| G-3 | A Risk Engine (rule set + evaluator) | No `chanakya/risk/`; `grep -i risk` finds only enums, Gateway and Registry uses |
| G-4 | A closed, versioned finding-category taxonomy the engine can rate | `Finding.category` is any `[a-z0-9_]{1,64}`, chosen freely by the model; no vocabulary exists |
| G-5 | A read path from the engine to verified Evidence metadata | The Runtime holds only evidence ids. `EvidenceStore.get` searches **all** investigations (`_find_evidence_file`), so a scoped read (`list_by_investigation`) plus an explicit investigation check is needed |
| G-6 | A Runtime hook between findings and completion | `_run_turn_body` goes straight from `_record_findings` to `complete()` |
| G-7 | A Runtime-side validator for engine output (references, counts, uniqueness) | None |
| G-8 | Durable, append-only RiskAssessment storage | None (`FindingStore` is the template) |
| G-9 | An `AuditEmitter.risk_assessed` method | Only the enum value exists |
| G-10 | CLI display that marks risk as rule-based and unverified | `_report_findings` shows findings only |
| G-11 | A read-time provenance verifier (RA → Finding → Evidence → payload) | None; each store verifies itself only |
| G-12 | Static import-boundary tests for the new package | None exist for a `risk` package |
| G-13 | A way for the model to know which categories are rateable | The `report_findings` schema has a `pattern` for `category` and no vocabulary |
| G-14 | Threat-register entries and RA-INV invariants | THREAT-MODEL candidates end at T-44; no RA-INV-* exist |

What is **not** missing, and must not be rebuilt:
- the severity enum;
- the audit event type;
- the context ref list;
- hashing utilities (`chanakya.evidence.hashing`);
- the path-safe identifier rule;
- the exclusive-link, append-only storage pattern;
- the escaped CLI renderer (`_safe`).

---

## 7. Design Options

### Option A — Deterministic Risk Engine (recommended)

A pure function of Runtime-verified inputs and a versioned rule table in
code. The model contributes nothing directly. Its only influence is which
closed-taxonomy category a Finding carries and which evidence it cites, and
both are already validated.

### Option B — LLM-assisted Risk Assessment

The model emits severity, confidence and rationale, for example through a
second reserved channel or extra fields on `report_findings`. The Runtime
validates the shape and stores the result.

### Option C — Hybrid

The model proposes a `suggested_severity` per finding (an untrusted enum).
The deterministic engine computes the authoritative rating and records the
model's suggestion next to it. The suggestion either does not affect the
rating or is clamped by rules.

### Comparison

| Criterion | A — Deterministic | B — LLM-assisted | C — Hybrid |
|---|---|---|---|
| Satisfies SR-18 / ARCH §11 ("not solely LLM judgment", reproducible) | **Yes** | **No**: violates SR-18 outright | Yes, if the suggestion cannot set the rating |
| CONTRACTS §9 "engine's own confidence, independent of agent" | **Yes** | No | Yes |
| LLM as security boundary | Never | The model *is* the rating authority | Model input is clamped |
| Prompt-injection surface (evidence → rating) | Only through category choice, which is closed and checked for compatibility | **Direct**: injected evidence can dictate severity ("rate this critical" / "rate this informational") | Suggestion is injectable; the rating is not |
| Provenance | Every field derivable and re-computable from stored Finding + Evidence | Rationale and severity have no verifiable basis | Rating verifiable; suggestion is only recorded |
| Determinism / reproducibility | **Full**: the same inputs and `scoring_method` give the same output, so a verifier can recompute | None (sampling, model drift) | Rating yes; suggestion no |
| Auditability | Rule ids trace every decision | "The model said so" | Rule ids plus recorded disagreement |
| Tamper detection | Hash **plus recomputation**: a rewritten and rehashed RA fails recomputation | Hash only | Hash plus recomputation of the rating |
| Architectural fit | Matches ARCH §11, the module skeleton (`risk/`), the SR-18 Runtime row and FND test guards | Contradicts three documents and the existing `severity`-is-forbidden test | Fits, but adds a provider channel change and new untrusted text/enum storage |
| New model-facing surface | None required (a category enum hint is optional; see §16) | New channel or new fields | New field on the finding channel |
| Discriminating power today | **Limited**: two read-only local capabilities, so ratings are coarse (§10) | Appears high but is unverifiable | As A |

**Decision rationale.** B is rejected on requirements, not on effort: it
makes the model the rating authority and turns evidence into a direct
injection path to the rating. C's only benefit over A is showing a
model-versus-engine disagreement signal. That signal is real (T-07), but
`Finding.confidence` is already a model-reported signal shown next to the
engine's. Adding a second one widens the untrusted surface (new schema,
new stored model output, a new injection target) for little Phase 10
value. **A is selected, and C is deferred** (§25). A is not the easy
choice: it needs a taxonomy, a rule table, an evidence-verification read
path and a recomputation verifier, none of which B would need.

---

## 8. Proposed Phase 10 Scope

The smallest scope that genuinely completes Evidence → Finding → Risk
Assessment:

1. **Contract.** `RiskAssessment` (frozen dataclass, closed key set,
   fail-closed validation, `to_dict`/`from_dict`) with the §10 fields.
2. **Taxonomy and rule set v1.** A closed finding-category vocabulary and a
   versioned rule table `chanakya-risk-rules/1.0.0` covering category base
   severity, category↔capability compatibility, a classification ceiling
   and a corroboration-based confidence.
3. **Risk Engine.** A pure evaluator (`chanakya/risk/engine.py`). It takes
   the Findings stored this turn plus a read-only Evidence reader, verifies
   the cited Evidence (investigation-scoped, hash and payload-hash), and
   returns assessed and not-assessed outcomes. Deterministic ids.
4. **RiskAssessmentStore.** Append-only, content-hashed, investigation-
   partitioned, size-bounded, with exclusive creation.
5. **Runtime integration.** An injected `RiskAssessor` +
   `RiskAssessmentRecorder` Protocol pair. On conclude, after findings are
   stored and before `complete()`, the Runtime validates the engine output,
   stores it, calls `add_risk_assessment_ref` and emits `risk_assessed`.
   Any failure halts with `risk_assessment_failed`.
6. **Audit.** An `AuditEmitter.risk_assessed` method carrying ids and enums
   only.
7. **Provenance verifier.** A read-only function that re-walks RA → Finding
   → Evidence → payload and **recomputes** each RA.
8. **Provider (minimal).** The `report_findings` schema lists the taxonomy
   for `category` (an `enum` from a provider-neutral constant). There is no
   new channel and no new conclusion type.
9. **CLI.** Escaped display of the verified assessment under each finding,
   labeled as rule-based and not independently verified, next to the
   agent-reported confidence. "Not assessed" is shown explicitly.
10. **Tests** (§20), **invariants** (§14), **threat-model and doc updates**
    (§13, §23).

---

## 9. Explicit NON-GOALS

| Item | Phase 10? | Reason |
|---|---|---|
| Recommendations | **Out** | A separate contract (§10) with its own SR-19 non-dispatch guarantees. `mitigations_suggested` is deferred with it, because free-text "mitigations" are recommendation-shaped and invite remediation |
| Remediation | **Out** | Any action needs a new `ToolRequest` through the Gateway. There are no state-changing capabilities |
| Autonomous state-changing actions | **Out** | Contradicts read-only default (SR-1). RA must never trigger anything (RA-INV-1) |
| New tools / capabilities | **Out** | RA rates existing evidence and needs no new observation. The Registry stays unchanged |
| Offensive capabilities | **Out** | Not in the project's purpose |
| MCP expansion | **Out** | Unrelated to rating |
| GUI | **Out** | CLI display only (ARCH §1) |
| Multi-agent behavior | **Out** | The engine is code, not an agent |
| Investigation memory (feeding findings/RA back to the model) | **Out** | It would add a new model-input channel (T-40 control: "findings are never fed back into model context in this phase") |
| Production deployment | **Out** | Local, single-process, as today |
| Model-suggested severity (Option C) | **Out** | Deferred (§7, §25) |
| RA as approval risk context (`ApprovalRequest.risk_assessment_ref`) | **Out** | RA exists only after conclude, when no approval can be pending. Wiring it later needs its own review (T-46) |
| Payload-content rules (e.g. counting non-loopback listeners) | **Out** | They would make the engine parse semi-trusted target data. A candidate for rule set 1.1 (§25) |
| Multi-finding (aggregate) assessments | **Out** | v1 is strictly one RA per Finding, for clean provenance |
| External threat intel / CVE feeds | **Out** | ARCH §20 names them as additive future work |

---

## 10. RiskAssessment Contract Design

### Proposed fields (`contract_version` `1.0.0`)

| Field | Type | Origin | Semantics / validation |
|---|---|---|---|
| `risk_assessment_id` | str | **Engine-derived, deterministic** | `uuid5(NAMESPACE, f"{investigation_id}:{finding_id}:{scoring_method}")`. A second assessment of the same finding under the same rule set gets the same id, so storage collides structurally (RA-INV-8). Path-safe |
| `contract_version` | str | Runtime constant | Must be in `SUPPORTED_CONTRACT_VERSIONS` |
| `investigation_id` | str | **Derived** from the Finding; **validated** by the Runtime | Must equal the conclude turn's investigation. **Addition to §9** |
| `finding_refs` | tuple[str] | **Derived** | Exactly **one** `finding_id` in v1, which must be among the findings stored in this conclude turn |
| `evidence_refs` | tuple[str] | **Derived** | Must equal that Finding's `evidence_refs` (same order). Each must be verified Evidence of the same investigation. **Addition to §9** |
| `severity` | `RiskCategory` | **Engine-computed** | Enum only. `critical` is unreachable under rule set 1.0.0 (ceiling rule) |
| `confidence` | `low`/`medium`/`high` | **Engine-computed** | Strength of the *evidentiary basis* under the rule set, never the truth of the finding. `Finding.confidence` is **not** an input |
| `scoring_method` | str | Engine constant | Must be in `SUPPORTED_SCORING_METHODS = {"chanakya-risk-rules/1.0.0"}`. Unknown on read → corrupt |
| `rule_ids` | tuple[str] | **Engine-computed** | Non-empty, distinct, `[a-z0-9_.-]{1,64}`. Every rule id must exist in the named rule set. **Addition to §9** |
| `assessed_at` | str (ISO UTC) | **Runtime clock** (injected into the engine) | Excluded from recomputation equality |
| `assessed_by` | str | Constant `"risk_engine"` | Any other value is rejected (in particular `"agent"`). **Addition to §9** |
| `rationale` | str | **Engine template** | Built only from rule ids, the taxonomy category id and Registry capability ids. It never contains model-authored or target-authored text. ≤ 1000 chars, one paragraph, no control characters, and the Finding credential screen still applies as defense in depth |
| `mitigations_suggested` | — | **Not supported** | The key is rejected. Deferred with Recommendations. **Documented deviation from §9** |

Closed shape: `from_dict` requires exactly the key set above. Any extra key
fails closed, including `approved`, `authorized`, `verdict`, `action`,
`target_ref`, `parameters`, `capability`, `policy_decision_id`, `priority`
and `mitigations_suggested`. Error messages name the field and never echo
its value, following the Finding convention.

### Ownership summary

- **Runtime-owned:** `contract_version`, `assessed_at`, the investigation
  binding check, reference validation and all persistence.
- **Engine-owned (trusted code):** `risk_assessment_id`, `severity`,
  `confidence`, `scoring_method`, `rule_ids`, `rationale`, `assessed_by`.
- **Derived and validated:** `investigation_id`, `finding_refs`,
  `evidence_refs`.
- **Model-originated:** **none.** Indirect model influence is limited to
  (a) choosing a taxonomy category for a Finding and (b) choosing which
  already-validated evidence the Finding cites. Both are bounded by rules
  (§12, T-45).

### Rule set `chanakya-risk-rules/1.0.0` (proposal; owner sign-off required)

The engine evaluates one Finding at a time:

1. **Category gate.** If `Finding.category` is `None` or outside the
   taxonomy, the finding is **not assessed** (`category_unrated`). No
   default severity is ever guessed.
2. **Evidence verification.** Every cited `evidence_id` must be in
   `EvidenceStore.list_by_investigation(investigation_id)` (scoped read,
   hash re-verified) and pass `EvidenceStore.verify(id)` (payload hash).
   Anything else **raises**. This is an integrity failure, not "not
   assessed".
3. **Compatibility.** Each category declares the capabilities whose
   evidence can support it. If **no** cited evidence comes from a
   compatible capability, the finding is **not assessed**
   (`evidence_incompatible`).
4. **Base severity.** Taken from the category table.
5. **Ceiling.** If every cited Evidence has `classification == read_only`,
   severity is capped at `high`. Read-only local observation never
   establishes `critical` in v1.
6. **Confidence** (independent of `Finding.confidence`):
   - `high` if compatible evidence comes from ≥ 2 distinct capabilities and
     all cited evidence is compatible;
   - `medium` if all cited evidence is compatible;
   - `low` if only some is compatible.

Illustrative taxonomy. The final table is a **condition** (§26):

| Category id | Base severity | Compatible capabilities |
|---|---|---|
| `network_exposure` | medium | `list_listening_ports` |
| `unexpected_listener` | low | `list_listening_ports` |
| `service_inventory` | informational | `list_listening_ports` |
| `platform_configuration` | low | `observe_local_host_environment` |
| `unsupported_platform_version` | medium | `observe_local_host_environment` |
| `observation` | informational | any registered capability |

**Stated limitation.** Rule set 1.0.0 rates *what kind of claim is made and
what kind of evidence backs it*. It does not check whether the claim is
true, because it deliberately reads no payload or text. The CLI wording
says so (§19).

---

## 11. Provenance Design

```
RiskAssessment ──finding_refs[0]──▶ Finding ──evidence_refs[*]──▶ Evidence ──payload_hash──▶ payload (ToolResult.output …)
  investigation_id ══════════════════ investigation_id ═════════════ investigation_id
  evidence_refs  ═══(must equal)═════ evidence_refs                  tool_request_id / tool_result_id / step_id / target_id
  content_hash (RA store)             content_hash (FindingStore)    content_hash + payload_hash (EvidenceStore)
  recomputable from ─────────────────▶ category ──────────────────── capability, classification
```

It stays verifiable at three points.

**Write time (Runtime, before any RA write):**
- The engine output is a tuple of `RiskAssessment` objects (type-checked)
  plus a not-assessed tuple of `(finding_id, reason_code)`.
- Every stored-this-turn finding appears **exactly once** across the two
  tuples; nothing else may appear.
- `ra.investigation_id == investigation_id`.
- `ra.finding_refs[0]` is a finding id stored *in this turn*, looked up in
  the Runtime's own in-memory tuple, not in engine-supplied data.
- `ra.evidence_refs == finding.evidence_refs`, and each is in
  `context.evidence_refs`.
- `ra.risk_assessment_id` equals the deterministic derivation, and no id
  repeats in the batch.

Any mismatch raises and halts the investigation (`risk_assessment_failed`),
before anything is stored.

**Store time:**
- `RiskAssessmentStore._read` rejects any record whose `investigation_id`
  or filename disagrees with its directory, mirroring `FindingStore`.
- Exclusive `os.link` rejects duplicates.

**Read time (the `verify_risk_provenance` function, used by the CLI and by
tests):** for each RA,
- the finding exists in `FindingStore.list_by_investigation(same id)`;
- the evidence ids match;
- each evidence verifies (metadata and payload) and belongs to the same
  investigation;
- **the engine is re-run on the stored Finding and Evidence, and severity,
  confidence, rule ids, rationale and id must be identical.**

**How fabricated or foreign references are rejected:**

| Attempt | Where it dies |
|---|---|
| RA cites a finding id that doesn't exist | Runtime write check (not in this turn's set); the read verifier (not in FindingStore) |
| RA cites a finding of another investigation | Runtime check (the set is this turn's own); the store directory/`investigation_id` check; the read verifier |
| RA evidence differs from the finding's | Runtime equality check; the read verifier |
| Finding cites foreign evidence | Already impossible (FND-INV-2). The engine also rejects it (`list_by_investigation` scoping) |
| Evidence tampered after the finding | `EvidenceStore` hash/payload-hash check in the engine and the verifier |
| RA rewritten and rehashed | **Recomputation mismatch** in the verifier |
| RA, Finding and Evidence all rewritten consistently | Not detectable locally; T-18 residual, unchanged |

---

## 12. Trust Boundary Analysis

No new trust boundary is introduced. RA is a new **sink** behind TB-3 and a
new record behind TB-8, produced by trusted code.

| Element | Trust | Analysis |
|---|---|---|
| Model-generated risk | **Does not exist** under Option A | The provider has no risk channel. `severity` stays a forbidden Finding key (existing test) |
| Finding content (`title`, `description`) | Untrusted, model-authored | **Never read by the engine.** It never appears in RA or the audit record. CLI output is escaped |
| `Finding.category` | Untrusted value, structurally bounded | The only model-chosen engine input. It must be in the closed taxonomy, or the finding is not assessed. Its effect is capped by the compatibility and ceiling rules |
| `Finding.confidence` | Untrusted self-report | **Not an input** (independence per §9/T-07). Displayed separately |
| `Finding.evidence_refs` | Runtime-resolved (FND-INV-2) | Re-verified against the Evidence Store by the engine |
| Evidence metadata (`capability`, `classification`, ids) | **Trusted provenance.** Runtime-assigned, Gateway snapshot, hash-verified | Engine input |
| Evidence payload / tool output | Semi-trusted target data | **Not read by the engine** in v1. Its integrity is verified (payload hash) but its content is not interpreted |
| Target metadata (`Target`, `TargetContextView`, environment) | Descriptive / untrusted | **Not an engine input.** `Evidence.target_id` is carried only as provenance |
| Risk score / severity | Trusted computation, **no authority** | An opinion label. Nothing in the Gateway, approval, dispatch, Registry or tools reads it (RA-INV-1) |
| Runtime | Trusted orchestrator | Calls the engine through a Protocol, validates, stores and audits it. Never computes a rating (keeps SR-18 row) |
| Policy Gateway | Sole authority | Unchanged and unaware of RA. `PolicyDecision.risk_category` stays a Registry snapshot, unrelated to RA |

---

## 13. Threat Model Updates

These are candidates, following the Phase 8/9 convention; numbering
continues after T-44.

- **T-45 candidate — Severity steering through category choice** (TB-3; a
  T-06/T-07 variant). The model, possibly steered by injected evidence,
  labels a finding with a higher-severity taxonomy category.
  *Controls:* closed taxonomy; category↔capability compatibility; the
  read-only ceiling; the engine never reads text or payloads; rule ids and
  both confidences are shown.
  *Residual:* the model can still pick the highest *compatible* category.
- **T-46 candidate — Risk rating treated as authority or automation
  input** (TB-4/TB-5; a T-43 variant). A future change feeds severity into
  policy, approval defaults or auto-remediation.
  *Controls:* RA-INV-1 static import tests (policy, tools, registry and
  approval never import `chanakya.risk` or the RA contract);
  `ApprovalRequest.risk_assessment_ref` stays unset; no Gateway input.
- **T-47 candidate — Fabricated, foreign or duplicate risk references**
  (TB-8). A buggy or substituted assessor returns an RA for a finding that
  doesn't exist, belongs to another investigation, or has altered evidence.
  *Controls:* the Runtime write-time checks (§11); deterministic ids plus
  exclusive create; the read verifier.
- **T-48 candidate — Risk-store tampering** (a T-18 variant).
  *Controls:* content hash; append-only; `risk_assessed` in the
  hash-chained Audit Log; **recomputation** in the verifier.
  *Residual:* a consistent rewrite of all three stores.
- **T-49 candidate — Rule-set drift / irreproducible ratings.** The table
  is edited without a version bump, so stored ratings no longer recompute.
  *Controls:* `scoring_method` versioned; a closed set of supported
  methods; tests pin the full table; the verifier flags mismatches.
- **T-50 candidate — False assurance from low or absent ratings** (a T-07
  variant, and "Abuse Case 1" applied to risk). Injection steers the model
  to omit the category or pick a benign one, and the operator reads
  "informational" or "not assessed" as "safe".
  *Controls:* "not assessed" is displayed distinctly and never rendered
  as a severity; the CLI states that ratings reflect rule-based evidence
  classification and do not show absence of risk.
  *Residual:* human judgment.
- **T-51 candidate — Partial state after a failure.** Findings are stored,
  the RA write or audit fails, and the investigation is `HALTED`. An
  operator could misread the missing ratings.
  *Controls:* halt reason `risk_assessment_failed` is displayed; findings
  are shown as "not assessed"; the verifier distinguishes "missing" from
  "not assessed".

Considered and **not** added as new threats, because existing controls
already cover them:
- Prompt injection through evidence or Finding descriptions reaching the
  rating. Structurally closed: the engine reads neither, so what remains
  is T-45.
- A risk flood. Bounded 1:1 by the existing 20-finding cap; recorded as a
  resource item (§22).

---

## 14. Security Invariants

| ID | Invariant | Planned enforcement |
|---|---|---|
| RA-INV-1 | A RiskAssessment never reaches Intake, the Policy Gateway, approval, dispatch or a ToolExecutor, and grants no authority. | `policy`/`tools`/`registry`/`approval` never import `chanakya.risk` or `contracts.risk_assessment` (AST test); the Runtime RA path calls none of them (AST test like FND); `risk_assessment_ref` stays unset |
| RA-INV-2 | Ratings are produced only by the deterministic Risk Engine. No model output becomes an RA field, and the provider has no risk channel. | No RA key in provider mapping; `severity` still forbidden on findings; `assessed_by == "risk_engine"` |
| RA-INV-3 | The same Finding, the same Evidence and the same `scoring_method` give identical `severity`, `confidence`, `rule_ids`, `rationale` and `risk_assessment_id`. | Pure engine; deterministic id; recomputation tests; no clock or randomness in rated fields |
| RA-INV-4 | Every RA references exactly one Finding of its own investigation that was stored in the same conclude turn, and its `evidence_refs` equal that Finding's. Anything else fails closed. | Runtime write checks; store read checks; verifier |
| RA-INV-5 | The engine reads no free text and no payload content: only the taxonomy category, Evidence metadata and verification results. | Engine signature / reader Protocol exposes metadata and `verify()` only; a test uses hostile text and payloads and asserts identical output |
| RA-INV-6 | `Finding.confidence` is never an input to `RiskAssessment.confidence`. | Tests: varying `Finding.confidence` leaves the RA unchanged |
| RA-INV-7 | Malformed, unsupported or unverifiable input fails closed. Unrated categories are "not assessed" and never defaulted; engine or integrity errors halt with `risk_assessment_failed`. | Runtime handling + tests |
| RA-INV-8 | RA storage is append-only and hash-verified, and duplicates collide. | No mutation API; exclusive `os.link`; deterministic id |
| RA-INV-9 | Every stored RA has exactly one `risk_assessed` audit event, carrying ids and enums only, never rationale text. | Emitter method + tests |
| RA-INV-10 | An RA cannot carry authority-shaped content: a closed key set, and severity ≤ the rule-set ceiling (`critical` unreachable in 1.0.0). | Contract validation + tests |
| RA-INV-11 | The CLI renders every RA escaped, labeled rule-based and not independently verified, separate from agent confidence. It withholds ratings that fail provenance verification. | CLI tests |
| RA-INV-12 | Phase 9 invariants FND-INV-1..9 are unchanged. A Risk Assessment failure never alters or removes a stored Finding. | Full regression; a failure-injection test that asserts findings persist |

---

## 15. Runtime Integration

**Placement:** inside `AgentLoopController._run_turn_body`'s existing
conclude branch, between `_record_findings(...)` returning `None` and
`self._investigations.complete(...)`:

```
conclude + findings
  → _record_findings            (unchanged Phase 9 behavior; findings durable and audited)
  → _assess_risk(findings)      (new; only when findings were stored this turn)
       engine = self._risk_assessor         (injected Protocol; Runtime never computes)
       result = engine.assess(investigation_id, stored_findings, assessed_at=self._clock())
       validate result against stored_findings + context        (§11)
       for ra: recorder.append(ra) → context.add_risk_assessment_ref → audit.risk_assessed
  → complete()
```

- **No alternate execution path.** The same turn, the same terminal
  transition. Nothing new is dispatchable. `_assess_risk` gets an AST test
  forbidding `ToolRequestIntake`, `_policy_evaluator`,
  `_approval_provider`, `dispatch(`, `_executor` and `_execute_once`.
- **Findings are persisted first.** Phase 9 semantics are untouched, and a
  risk failure can't make valid findings disappear.
- **Configuration mirrors `finding_recorder`:**
  - `risk_assessor=None` and `risk_recorder=None`: the path is skipped
    entirely, which is backward-compatible with every existing test.
  - Only one of the two configured: a composition error (`ValueError` at
    construction).
  - The CLI wires both.
- **Failures:**
  - An engine exception, a validation mismatch or a store error:
    `halt(reason="risk_assessment_failed")` → `HALTED`, turn outcome
    `HALTED`.
  - An audit failure raises `AuditSinkError`, and the existing backstop
    halts (`audit_sink_failure`).
  - None of these are model-caused, so none of them return
    `MALFORMED_TURN`.
- **Not assessed is not a failure:** the investigation completes normally.
- The Runtime imports only `chanakya.contracts.risk_assessment` (for
  validation and types), never `chanakya.risk`.

---

## 16. Provider Integration

| Alternative | Assessment |
|---|---|
| New reserved channel (e.g. `report_risk`) | Rejected. It would make the model a rating source (Option B/C) and add a second reserved name and dispatch-adjacent surface |
| Structured risk fields in the response | Rejected, for the same reason. It also contradicts the existing forbidden-`severity` Finding test |
| New conclusion type / `NextAction` value | Rejected. Risk is computed after a normal conclude, and `NextAction` is closed at two values by design |
| **No provider change** | Viable. But the model does not know the taxonomy, so most findings would be "not assessed", and Phase 10 would not genuinely deliver ratings |
| **Minimal schema hint (recommended)** | `_FINDING_TOOL_SCHEMA.items.properties.category` becomes an `enum` of the taxonomy ids, imported from a provider-neutral constant in `chanakya/contracts/` (not from `chanakya.risk`). Its fixed description adds that category is used by rule-based rating. The Runtime still accepts any valid `Finding.category` (contract unchanged), and schema conformance is not trusted: a non-taxonomy category just results in "not assessed". No new channel, no new mapping logic |

---

## 17. Storage

A durable, append-only store is **required**, following FND-INV-5/6
precedent and CONTRACTS conventions. A rating that is shown but not stored
would be unauditable.

- **Module:** `chanakya/risk/store.py`, `RiskAssessmentStore(root)`,
  mirroring `FindingStore`.
- **Layout:** `<root>/<investigation_id>/<risk_assessment_id>.json`. The
  CLI uses root `<workdir>/risk`.
- **Record:** `{"risk_assessment": <to_dict>, "recorded_at": <store-owned>,
  "content_hash": "sha256:…"}`. The hash covers the canonical JSON of the
  first two keys (`chanakya.evidence.hashing`) and is re-verified on every
  read.
- **Integrity:**
  - an exact key-set check;
  - `from_dict` validation, including a supported `scoring_method`;
  - the directory, `investigation_id` and filename must agree;
  - `list_by_investigation` raises `CorruptRiskAssessmentError` rather than
    return a partial list;
  - `verify()` returns a bool.
- **Immutability:** there is no update, delete or replace method. A write
  goes temp file → fsync → exclusive `os.link`, and a collision raises
  `RiskAssessmentIdCollisionError`. Deterministic ids turn a duplicate
  assessment into a collision.
- **Identifiers:** the Evidence Store path-safety rule
  (`[A-Za-z0-9_-]{1,128}`, Windows device names refused) plus a
  direct-child check.
- **Size:** `MAX_RECORD_BYTES = 8192`, well above the largest valid record:
  20 evidence refs, a 1000-char rationale and ~10 rule ids fit in about
  3 KiB. Anything larger is rejected, never truncated.
- **Failure behavior:**
  - An append error propagates, and the Runtime halts
    (`risk_assessment_failed`).
  - A partial batch is possible, because earlier RAs of the batch are
    already durable. This is identical to Phase 9's finding batch
    behavior; the verifier and CLI show which findings lack an RA.
- **Limitation:** the local-file hash is unkeyed (T-18 residual). The
  recomputation check (§11) is the added defense.

---

## 18. Audit

- New `AuditEmitter.risk_assessed(investigation_id, ra)`, emitted once per
  stored RA, after `append` succeeds and before `complete()`.
  - `event_type = risk_assessed` (it already exists in the closed enum, so
    no contract bump).
  - `actor = "system"`: the engine is trusted code, not the agent.
  - `related_ids = {"risk_assessment_id": …, "finding_id": …}`.
  - `details = {"evidence_refs": [...], "severity": …, "confidence": …,
    "scoring_method": …, "rule_ids": [...]}`, all ids and enums.
    **`rationale` is never included.**
- No event for not-assessed findings (§26, open question O-1). Absence is
  reproducible, because a deterministic re-run gives the same result.
- The durable chain model is unchanged:
  - `FilesystemAuditLog` has no new code;
  - the credential screen still applies to `details`;
  - AL-INV-7 is kept: `chanakya.risk` does not import `chanakya.audit`,
    and the Runtime emits through the existing `AuditEmitter`.
- An audit write failure → `AuditSinkError` → `HALTED`
  (`audit_sink_failure`). The RA record may already be durable without its
  event. This is the same documented state Phase 9 has for findings; the
  verifier reports it only if a future phase lets it read the Audit Log,
  which is deferred.

---

## 19. CLI Impact

- `build_runtime` constructs `RiskAssessmentStore(workdir/"risk")` and
  `RiskEngine(evidence_store, rule_set=RULE_SET_V1)`, and injects both.
  `CliRuntime` gains `risk_store`.
- `_report_findings` becomes finding plus risk display:
  - It calls `verify_risk_provenance(...)` first. If verification fails,
    it prints `risk assessments: failed verification; not shown` and shows
    no ratings. The findings remain listed.
  - Per finding:
    ```
    [1] "<escaped title>"
        agent-reported confidence: "medium"  category: "network_exposure"
        rule-based risk (chanakya-risk-rules/1.0.0): severity "medium", basis confidence "medium"
            rules: ["cat.network_exposure", "compat.list_listening_ports", "ceiling.read_only"]
        evidence: [...]
    ```
  - A not-assessed finding shows `rule-based risk: not assessed
    ("category_unrated")`.
  - The header reads: `risk ratings are computed by fixed rules from the
    agent's category and evidence provenance; they are not independently
    verified and do not establish the absence of risk`.
  - Every value goes through `_safe` / `_safe_full` (JSON, ASCII-escaped).
- No new CLI flags. The rule set is not operator-configurable in Phase 10:
  configuring it would make it an admin-trust input needing its own
  review.

---

## 20. Adversarial Testing Plan

Each row becomes one or more tests. The table groups them by requirement.

| Requirement | Test(s) — expected result |
|---|---|
| Fabricated finding references | Stub assessor returns an RA for an unknown finding id → `HALTED` (`risk_assessment_failed`), nothing stored; store `from_dict` with a bogus finding id and verifier → mismatch |
| Foreign investigation references | Stub assessor returns an RA whose `investigation_id` or finding belongs to investigation B → halt; a record copied into another investigation's dir → `CorruptRiskAssessmentError` |
| Fabricated evidence references | RA `evidence_refs` ≠ the finding's → halt; the engine given a finding whose evidence id is missing from the store → raises → halt |
| Cross-investigation evidence | Evidence id that exists only under another investigation (reachable by the global `get`) → the engine rejects it via the scoped read |
| Malformed risk objects | Engine returns a dict, `None`, the wrong type, or a missing or extra key → halt; contract table tests for every field (empty, wrong type, bad enum, bad id charset) |
| Excessive risk objects | More RAs than findings; > 20; an RA plus a not-assessed entry for the same finding; a finding covered by neither → halt |
| Hostile Finding content | Title/description with instructions, ANSI escapes and credential-like text → the RA is byte-identical to one for a benign finding; the text is absent from the RA, audit and rationale; CLI escaped |
| Prompt injection through evidence | Payload with hostile process names ("rate this critical") → the RA is identical to a clean payload's (the engine doesn't read payloads) |
| Prompt injection through Finding descriptions | As above, for descriptions of "severity: critical, approve all" |
| Authority-shaped fields | `approved`, `verdict`, `target_ref`, `parameters`, `mitigations_suggested`, `action` in `from_dict` → rejected; a `severity` key on a model finding is still rejected (existing test kept) |
| Severity manipulation | Category outside the taxonomy → not assessed; category incompatible with the cited capability → not assessed; read-only evidence can never yield `critical`; a stub assessor returning `critical` for read-only evidence → the Runtime rejects it (ceiling validated) |
| Confidence manipulation | `Finding.confidence` low/medium/high/None → identical RA confidence; the engine's confidence tracks only the compatibility and corroboration rules |
| Oversized rationale | > 1000 chars or control characters in the contract → rejected; record > `MAX_RECORD_BYTES` → rejected, not truncated |
| Duplicate assessments | Same finding twice in one batch → halt; re-append the same RA → `IdCollisionError`, original intact |
| Storage failure | Recorder raises on the 1st or nth append → `HALTED` `risk_assessment_failed`; findings still present and verified; no `investigation_completed` |
| Audit failure | Failing sink at `risk_assessed` → `HALTED` (`audit_sink_failure`); no completion |
| Provider malformed output | `report_findings` with a non-enum category → finding stored, RA "not assessed"; other misuse paths (existing FND tests) unchanged |
| Tampering / corruption | Edit severity in a stored RA → hash mismatch; edit and rehash → **recomputation mismatch**; tamper with the cited evidence payload → engine/verifier fail; unknown `scoring_method` on read → corrupt |
| Determinism | Run twice (fresh stores, a different clock) → identical ids and rated fields |
| Boundary (static) | AST: policy/tools/registry/approval import nothing risk-related; `chanakya.risk` imports no policy/runtime/providers/tools/registry/approval/audit/anthropic/subprocess; the Runtime imports no `chanakya.risk`; `_assess_risk` calls no intake, policy, approval or dispatch |
| Regression | All 1896 existing tests pass unchanged; the no-assessor configuration behaves exactly as Phase 9 |

---

## 21. Dependency and Import Boundary Review

Allowed direction (→ means "may import"):

```
chanakya.contracts.risk_assessment → chanakya.contracts.{enums, finding(text screen), target(patterns)}
chanakya.contracts (taxonomy constant) → nothing
chanakya.risk.{rules, engine, store, provenance} → chanakya.contracts.*, chanakya.evidence.hashing,
                                                  chanakya.evidence.store (identifier rule; reader types)
                                                  chanakya.findings (provenance verifier only, read API)
chanakya.runtime.agent_loop → chanakya.contracts.risk_assessment   (Protocols only; never chanakya.risk)
chanakya.providers.mapping → chanakya.contracts (taxonomy constant)  (never chanakya.risk)
chanakya.cli.main → chanakya.risk                                   (composition root only)
```

Forbidden, and to be enforced by tests:
- `chanakya.policy`, `chanakya.tools`, `chanakya.registry` and
  `chanakya.approval` → anything risk-related (RA-INV-1).
- `chanakya.risk` → `chanakya.policy`, `chanakya.runtime`,
  `chanakya.providers`, `chanakya.tools`, `chanakya.registry`,
  `chanakya.approval`, `chanakya.audit`, `anthropic`, `httpx`,
  `subprocess`.
- `chanakya.runtime` → `chanakya.risk`. The package is injected, following
  the `FindingRecorder` pattern, and `test_invariant_10…` style
  constraints stay intact.

The existing test `test_no_production_package_reads_the_audit_log` is
extended to include `risk`.

Verified today: `chanakya.findings` imports only contracts and evidence
(hashing and the identifier rule). The new package follows the same
footprint, so **no forbidden direction is created**.

---

## 22. Resource Governance

| Dimension | Impact | Control |
|---|---|---|
| Context size (`max_context_bytes`) | **None.** RA is never sent to the model | RA-INV-2; no ContextAssembler change |
| Provider output (`max_provider_output_bytes`) | Negligible: a taxonomy `enum` in the request schema (request side, not output) | Existing limit unchanged |
| Assessment count | ≤ 1 per finding, so ≤ 20 per investigation (inherits `MAX_FINDINGS_PER_INVESTIGATION`) | Runtime coverage check; new `MAX_RISK_ASSESSMENTS_PER_INVESTIGATION = 20` |
| Assessment size | Rationale ≤ 1000 chars; ≤ 20 evidence refs; rule ids ≤ 16 × 64 chars | Contract validation |
| Storage | ≤ 20 × 8 KiB per investigation | `MAX_RECORD_BYTES`; reject, never truncate |
| Engine work | ≤ 1 `list_by_investigation` + ≤ 400 `verify()` calls per conclude (20 findings × 20 refs); `verify` re-reads the payload (≤ 64 KiB each) | Bounded by existing caps. Dedupe evidence ids across findings so each is verified once |
| Runtime limits | RA runs inside the conclude turn. The investigation timeout is checked at turn start and is not preemptive (existing T-36 residual) | The engine does no network, subprocess or blocking I/O beyond bounded local reads |

---

## 23. Implementation Plan

Test counts are estimates from a baseline of **1896**.

| Step | Files | Purpose | Tests | Invariants | Est. total |
|---|---|---|---|---|---|
| 10.1 Contract | `chanakya/contracts/risk_assessment.py` (new); `chanakya/contracts/risk_taxonomy.py` (new, category ids only); `chanakya/contracts/__init__.py` (exports) | `RiskAssessment` with closed shape, fail-closed validation, `to_dict`/`from_dict`, supported scoring methods | `tests/test_risk_assessment_contract.py`: field table, authority keys, sizes, credential screen, round trip | RA-INV-10 | ~1926 |
| 10.2 Rule set + engine | `chanakya/risk/__init__.py`, `rules.py`, `engine.py` (new) | Rule table v1; pure evaluator; scoped evidence verification; deterministic ids; not-assessed reasons | `tests/test_risk_engine.py`: each rule, ceiling, compatibility, confidence, determinism, hostile text/payload invariance, foreign evidence | RA-INV-2,3,5,6,7 | ~1966 |
| 10.3 Store | `chanakya/risk/store.py` (new) | Append-only, hashed, partitioned store | `tests/test_risk_store.py`: append/list/verify, restart, no mutation API, collision, tamper, misfiled, unsafe ids, oversize, write failure | RA-INV-8 | ~1986 |
| 10.4 Audit emitter | `chanakya/runtime/audit.py` (one method) | `risk_assessed`, ids/enums only | Emitter tests (in the 10.5 file) | RA-INV-9 | — |
| 10.5 Runtime integration | `chanakya/runtime/agent_loop.py` (`RiskAssessor`/`RiskAssessmentRecorder` Protocols, constructor args, `_assess_risk`, validation) | Hook between findings and completion; fail-closed handling | `tests/test_risk_runtime.py`: happy path, fabricated/foreign/duplicate/excess, storage and audit failure, findings persist, disabled path unchanged, AST no-dispatch | RA-INV-1,4,7,9,12 | ~2016 |
| 10.6 Provenance verifier | `chanakya/risk/provenance.py` (new) | Read-only chain walk plus recomputation | `tests/test_risk_provenance.py`: clean, each break point, rehash-tamper detection | RA-INV-3,4 | ~2028 |
| 10.7 Provider schema | `chanakya/providers/mapping.py` (category enum + fixed description) | Make categories rateable | Additions to `tests/test_findings.py` or a new provider test: schema content, determinism, non-enum category still handled | RA-INV-2 | ~2033 |
| 10.8 CLI | `chanakya/cli/main.py` | Compose engine and store; verified, escaped, labeled display | `tests/test_cli_composition.py` / new CLI risk tests: end to end, hostile text, not assessed, verification failure withholds ratings | RA-INV-11 | ~2041 |
| 10.9 Boundaries + adversarial sweep | `tests/test_risk_boundaries.py` (new); extend the `test_audit_log.py` package list | Import matrix; remaining §20 rows | — | RA-INV-1 | ~2060 |
| 10.10 Docs | `docs/CONTRACTS.md` §9 (amendments + implementation note), `ARCHITECTURE.md` §11/§12 status, `docs/AGENT-RUNTIME.md` (RA section, RA-INV table, SR-18 row, audit table), `docs/THREAT-MODEL.md` (T-45..T-51 candidates) | Record the design as implemented | — | — | ~2060 |

Each step ends with the full suite green before the next begins.

---

## 24. Checkpoint Plan

1. **Final verification:**
   - `python -m pytest -q`: all pass, count recorded (expected ≈ 2060) and
     no skipped tests added;
   - static boundary tests pass;
   - a manual `git diff --stat` review confirms no unrelated file changed;
   - a final implementation audit against RA-INV-1..12 and the §20 table.
2. **Commit** (on `main`, per the existing phase convention):
   `Phase 10: add deterministic risk assessment`, with the required
   `Co-Authored-By` trailer.
3. **Annotated tag:** `v0.10.0-risk-assessment`, message `Phase 10: add
   deterministic, evidence-grounded risk assessment`.
4. **Clean tree:** `git status --porcelain` is empty after the tag, and
   `git describe --exact-match` shows the new tag.
5. No push unless explicitly requested.

---

## 25. Deferred Work

| Item | Suggested phase | Note |
|---|---|---|
| Recommendations (+ `mitigations_suggested`) | Phase 11 candidate | Its own contract and SR-19 non-dispatch proofs |
| Hybrid model-suggested severity (Option C) | Later | Recorded disagreement signal only; needs its own threat review |
| Payload-content rules (e.g. non-loopback listeners, specific OS versions) | Rule set 1.1 | The engine would parse semi-trusted payloads and needs a strict schema reader |
| Aggregate / multi-finding assessments | Later | Needs a provenance design for N:1 |
| RA as approval risk context | Only after state-changing capabilities exist | T-46 review required |
| Operator-configurable rule sets | Later | An admin-trust config surface, like `PolicySet` |
| Audit-log cross-check in the verifier | Later | Currently AL-INV-7 keeps the Audit Log out of production reads |
| Keyed or external anchoring of stores | Later | T-18 residual across Evidence, Finding, RA and Audit |
| Investigation memory (RA/findings back to the model) | Later | New model-input channel |

---

## 26. Final Readiness Verdict

**READY WITH CONDITIONS**

The architecture already reserves every hook Risk Assessment needs, and the
recommended design adds no new trust boundary, execution path or model
authority. Nothing in the codebase blocks implementation. These owner
decisions must be made before Step 10.1:

- **C-1 — Approve Option A (deterministic, model-free rating).** This
  follows directly from SR-18 and ARCH §11, but it is a product decision.
- **C-2 — Approve the taxonomy and severity table** (§10). Category ids,
  base severities, compatibility and the read-only `high` ceiling are
  security judgments that need owner sign-off, not implementer choice.
- **C-3 — Approve the documented amendments to `CONTRACTS.md` §9:**
  - add `investigation_id`, `evidence_refs`, `rule_ids` and `assessed_by`;
  - restrict `finding_refs` to exactly one in v1;
  - defer `mitigations_suggested`.
- **C-4 — Approve the minimal provider schema change** (§16). Without it,
  Phase 10 is technically complete but most findings would be "not
  assessed".

Open questions, each with a default proposed in this report:

- **O-1:** Should not-assessed findings get an audit record? Default: no
  new event type; absence is deterministic and reproducible.
- **O-2:** Should the CLI exit code change when risk verification fails?
  Default: no; ratings are withheld and a message is shown.
