# Anthropic Multi-Tool Response Investigation

Investigation only. No source, test or configuration file was changed. Nothing was committed or pushed.

- Baseline: `main` at `0c07286` ("Confine durable investigation data placement"), tag `v0.20.0-durable-data-placement-confinement`
- Working tree: clean apart from the untracked `PHASE-21-ARCHITECTURE-READINESS-REPORT.md` (and this report)
- Investigation examined: `54ce659a-f076-466b-8d4b-caa990c7b38d` (audit chain in `D:\Chanakya-Data\audit\…`, 18 records)
- Installed SDK: `anthropic 1.7.0`

## Classification

**PROVIDER COMPATIBILITY ISSUE.**

The Runtime rejected the turn on purpose, and that rejection is correct. The actual defect is in the Anthropic request that Chanakya builds. The Runtime accepts one tool call per turn, but the request never tells the Messages API about that limit. Nothing about the security design is wrong. The Runtime has no orchestration defect either: it did what it was designed to do.

---

## 1. Observed Failure

All eight turns of the real run went the same way. The audit log records:

| Turn | `agent_turn_requested.provider_request_hash` | `agent_turn_rejected` outcome | `stop_reason` | `tool_use_blocks` | explanation | `proposed_capability` |
|---|---|---|---|---|---|---|
| 1–8 | `sha256:5dbf1ad1…3d2a43` (identical on all 8) | `multiple_tool_use_blocks` | `tool_use` | **2** | `absent` | `null` |

- `context_entries: []` on every turn. No tool ever ran, so the model context never changed, and the request was byte-identical each time.
- The `raw_output_hash` differs from turn to turn. That does **not** show the model answering differently: the mapped turn includes a fresh `uuid4` `turn_id` and a `produced_at` timestamp (`mapping._response_to_turn`), so the hash would change anyway.
- After `DEFAULT_MAX_TURNS = 8` (`chanakya/cli/main.py:106`) the CLI called `InvestigationManager.cancel`. That is why the final state is `halted / cancelled_by_operator / CANCELLED`. The 8-turn CLI limit is lower than `max_steps_per_investigation=10`, so it was reached first. Each rejected turn used one step (`_rejected_turn`).
- The CLI shows `malformed_turn detail="MULTIPLE_TOOL_USE_BLOCKS"` because `_rejected_turn` returns `TurnOutcome.MALFORMED_TURN` (the public turn outcome) with `detail = rf.MULTIPLE_TOOL_USE_BLOCKS`. The durable turn record keeps the more specific outcome, `multiple_tool_use_blocks`.

## 2. Exact Validation Path

1. **Request build**: `chanakya/providers/mapping.py::build_request_kwargs`
   Produces `model`, `system`, `messages` (a single `user` message), `max_tokens`, optional `extra_body.temperature` and `tools`. It adds the two catalog capabilities and, because the CLI sets `findings_channel=True` (`cli/main.py:594`), the reserved `report_findings` tool. **It sets no `tool_choice`, so there is no `disable_parallel_tool_use`.** No code under `chanakya/` or `tests/` mentions either one.
2. **Send**: `chanakya/providers/anthropic_provider.py::AnthropicProvider.send_turn`
   Calls `self._client.messages.create(**request_kwargs)`, then:
   - `mapping.response_metadata(response)` → `(stop_reason, tool_use_blocks)`, where
     `tool_use_blocks = sum(1 for block in content if block.type == "tool_use")` (`mapping.py:255-262`)
   - `mapping.response_to_turn_mapping_with_findings(...)` → turn mapping (maps `tool_use_blocks[0]` only)
   - returns `ProviderResponse(turn, stop_reason, tool_use_blocks)`
3. **Classify**: `chanakya/runtime/agent_loop.py::AgentLoopController._classify_turn` (line 976)
   ```python
   if turn.tool_use_blocks is not None and turn.tool_use_blocks > 1:
       return AgentTurnOutcome.MULTIPLE_TOOL_USE_BLOCKS, None, None, None, rf.MULTIPLE_TOOL_USE_BLOCKS
   ```
   This is the **first** check, ahead of the stop-reason check, `AgentTurnOutput.from_dict`, reserved-channel checks and `ToolRequestIntake`. Neither the mapped turn nor any block's name or input is looked at.
4. **Record + reject**: `_record_outcome` writes `agent_turn_rejected` (outcome, raw-output hash, stop reason, block count; no raw output). `_rejected_turn` charges one step and returns `TurnOutcome.MALFORMED_TURN`.

Constants:
- `chanakya/contracts/agent_turn.py:103`: `AgentTurnOutcome.MULTIPLE_TOOL_USE_BLOCKS = "multiple_tool_use_blocks"`
- `chanakya/contracts/runtime_failure.py:202`: `MULTIPLE_TOOL_USE_BLOCKS = "MULTIPLE_TOOL_USE_BLOCKS"`

**Validation rule:** a provider response may contain **at most one** `tool_use` content block. The rule is documented as CT-INV-3 in `docs/AGENT-RUNTIME.md:1782-1783` ("Classification happens before anything is used: more than one `tool_use` block → `multiple_tool_use_blocks`") and in `docs/CONTRACTS.md:1037`.

## 3. Anthropic Response Shape

This comes from the durable, sanitized turn records of the real run, not from a guess:

- `stop_reason == "tool_use"`
- exactly **2** content blocks with `type == "tool_use"`
- `explanation_status == "absent"`: the mapping found no non-empty `text` block. `_response_to_turn` joins every non-empty `TextBlock.text` into `explanation`, and none existed.

So the response content has this structure:

```
content = [
  tool_use(id=…, name=<capability A>, input={…}),
  tool_use(id=…, name=<capability B>, input={…}),
]
stop_reason = "tool_use"
```

This is the standard Messages API parallel tool use shape: one assistant message with several `tool_use` blocks, each with its own `id`. Block types other than `text` or `tool_use` (such as thinking blocks) are ignored by the mapping and not counted, so the records can't rule them out. They are not relevant to the rejection.

`tests/test_agent_turn_record.py:571-574` and `tests/test_anthropic_provider_sdk_security.py:1144-1190` already use this exact shape as fixtures.

## 4. Chanakya Expected Response Shape

For each turn, the Runtime accepts exactly one of:

- **Tool proposal**: `content` has **exactly one** `tool_use` block, naming a catalog capability, with an `input` that includes the reserved target parameter. `stop_reason ∈ {end_turn, tool_use, stop_sequence}`. It maps to `next_action: "propose_tool_request"` with a single `tool_request` dict (not a list).
- **Findings**: exactly one `tool_use` block named `report_findings` with `input == {"findings": [...]}`. Maps to `next_action: "conclude"` + findings.
- **Conclusion**: no `tool_use` block. Text only becomes `explanation`.

`AgentTurnOutput` and `ToolRequestIntake` define one `tool_request` per turn. Nothing in the contract, the intake, the Policy Gateway call, the approval flow (`AWAITING_APPROVAL` suspends one pending request), dispatch or evidence handles a list of requests.

## 5. Root Cause

**The Anthropic Messages API allows parallel tool use by default. Chanakya's request (`mapping.build_request_kwargs`) never sets `tool_choice: {"type": "auto", "disable_parallel_tool_use": true}`, so the model may, and here did, return two `tool_use` blocks in one turn. The Runtime's one-action-per-turn invariant (CT-INV-3) then rejects the whole turn.**

Three more factors made this a full stall rather than a single bad turn:

1. **Nothing in the instructions sets the limit.** The Runtime-authored template (`render_instructions`, `chanakya-agent-instructions/1`) says nothing about one action per turn. The model sees two independent, read-only tools and a two-part objective ("platform **and** listening services"), so parallel calls are a natural choice.
2. **A rejection changes nothing.** Rejected turns are not fed back to the model. That is deliberate: turn records are forensic and never become conversation memory (CT-INV-5). With no tool results, the next request is byte-identical (same `provider_request_hash` on all 8 turns), so the model tends to make the same choice again. The run was stuck until the turn limit.
3. **No turn history.** Each request is one `user` message. There are no `assistant`/`tool_result` pairs, so no earlier `tool_use_id` has to be answered. This matters for the fix (§9): it means limiting the model to one tool call per turn causes no protocol problems.

### Which tools did the model request?

**This cannot be proven from the records, and the security controls should not be weakened to find out.**

- `proposed_capability` is `null`: `_classify_turn` rejects before parsing, and the rejection record intentionally leaves out tool names and inputs from rejected output.
- Raw output is never stored. Only its hash is kept, and that hash includes a `uuid4` and a timestamp, so it can't be matched against guessed contents.
- The catalog offered exactly three tools: `observe_local_host_environment`, `list_listening_ports` (`chanakya/tools/handlers/`), and the reserved `report_findings`.

The likeliest explanation is **`observe_local_host_environment` + `list_listening_ports`**. It fits the objective wording one-to-one, there were no text blocks, and the context was empty so there was nothing to report yet. Still, a duplicate call or a capability paired with `report_findings` would have produced the same record: `_classify_turn` returns `multiple_tool_use_blocks` before any reserved-channel check (see `test_agent_turn_record.py:574`). Treat this as a likely explanation, not a proven one.

## 6. Security Significance

**Is the rejection intentional?** Yes. It is category **A (an intentional security invariant)** and **D (a contract design decision)**.

- `mapping.response_metadata` docstring (Phase 14): *"so the Runtime can record them and reject a cut-off or multi-tool turn instead of silently using the first block."*
- `test_multiple_tool_use_blocks_are_rejected_and_never_reach_the_gateway`: *"a turn carrying two actions is rejected as a whole … instead of silently running the first."* It pairs a benign capability with `terminate_process` to show why.
- `test_multiple_tool_use_blocks_map_only_the_first` documents that the mapping layer on its own would drop the second block. The Runtime count check exists to stop that silent loss.

The failure to tell the model about the limit is not intentional. That part is **B (an accidental provider compatibility limitation)**.

**What would change if the Runtime accepted several tool calls per turn?**

| Property | Today (one per turn) | If N blocks were accepted per turn |
|---|---|---|
| Policy Gateway | One `evaluate` per turn; its verdict covers the whole turn | N separate verdicts. Decide what happens when some are allowed and some denied: run the allowed ones and drop the denied? Fail the turn? Either way the result diverges from what the model asked for |
| Per-tool authorization / capability envelope | Checked for one capability | Checked N times. Scope checks on a later call could depend on a result the model has not yet seen |
| Target scope | One `target_ref` validated | Several targets per turn. Easier to fan out across targets in one step |
| Approval | One pending request; `AWAITING_APPROVAL` suspends the turn | Needs batch or per-item approval. An operator could approve a bundle without evaluating each item (approval fatigue, a benign action hiding a risky one) |
| Execution | One dispatch | Order matters: serial or parallel? Parallel breaks deterministic ordering |
| Partial execution / failure | All-or-nothing per turn | Tool 1 succeeds and tool 2 fails, or tool 2 is denied after tool 1 ran. Needs defined rollback and reporting. Read-only tools soften this, but the contract has to hold for future non-read-only capabilities |
| Output screening / evidence | One result, one evidence record | N results. Evidence and context ordering must be defined and stable |
| Audit ordering | Linear: requested → received → proposed → decision → result | Interleaved records per sub-request. Review reconstruction (`review/reconstruction.py`) assumes one proposal per turn |
| Resource limits | 1 step, ≤1 tool call per turn | One turn could spend N tool calls. `max_tool_calls_per_investigation` still caps the total, but budget use per model decision grows |
| Retry behaviour | One step retried | Per-item retry, which interacts with partial success |
| Turn determinism / replay | One turn maps to one action | One turn maps to a set of actions. Review and replay need a canonical order |
| Tool-request provenance | Proposal links to one turn id | Needs sub-indices; `tool_request_hash` in the turn record is a single value |
| Model authority | One decision per model output; the Runtime re-checks after every result | The model plans several actions ahead without seeing results in between. That gives the model more autonomy in each decision |

**Taking only the first block** is ruled out, as the brief requires, and the existing tests reject it as well. The model's intent would be silently discarded. The action it planned second might be the one it depended on, or one the operator should have seen. And the parts of a turn that were dropped would never reach the audit log.

## 7. Why Fail-Closed Behavior Was Correct

- Nothing ran without a check: `proposed_capability` is `null`, no `tool_request_proposed` event exists, and there were 0 evidence records, 0 Gateway calls and 0 approvals requested.
- Model intent was never partly honoured or silently dropped.
- Each rejection was durably recorded with a fixed outcome code, stop reason, block count and raw-output hash. No raw model output or credential-shaped text was stored.
- Every rejected turn used a step, so a repeating failure is bounded (8 CLI turns, 10 max steps).
- Review verified the chain (18 records, consistent, 0 anomalies).
- The operator saw a precise reason (`MULTIPLE_TOOL_USE_BLOCKS`), which is what made this investigation possible.

The one cost is **availability**: the investigation could not make progress. That is a compatibility problem, not a security failure.

## 8. Options Considered

| # | Option | Verdict |
|---|---|---|
| 1 | Take the first `tool_use` block | **Rejected.** Silently discards model intent; explicitly forbidden and contradicted by existing tests |
| 2 | Take all blocks and run each through Intake → Gateway → Envelope → Approval → Execution → Screening → Evidence → Audit | **Possible, but not the minimum change.** Every row of §6 needs a design decision: contract (list of requests), runtime orchestration, batch/partial approval, audit schema and Review reconstruction, resource accounting, partial-failure semantics. It should be a separate, deliberately scoped phase, if it is wanted at all |
| 3 | Queue the extra blocks and run them on later turns | **Rejected.** The Runtime would be deciding on the model's behalf; queued actions run against context the model never saw. It adds hidden state and weakens the rule that each step comes from a fresh model decision |
| 4 | Only add wording to the instruction template ("propose exactly one action per turn") | **Not enough on its own.** Advisory only; the model can still ignore it. It also changes `instructions_hash` and needs a template version bump that Review knows about (`reconstruction.py:473`) |
| 5 | **Set `tool_choice = {"type": "auto", "disable_parallel_tool_use": true}` in the provider request, keep the Runtime count check unchanged** | **Recommended.** The provider then asks the API for what the Runtime already enforces. Supported by the installed SDK: `ToolChoiceAutoParam` has `disable_parallel_tool_use: bool` in `anthropic 1.7.0`. `auto` keeps both conclude paths (text-only and `report_findings`). The CT-INV-3 backstop stays in place, so any output that still has more than one block is rejected exactly as today |
| 6 | Feed the rejection reason back to the model | **Out of scope.** Conflicts with CT-INV-5 (turn records never enter model context) and would need a new Runtime-authored feedback channel. It could be considered later as a separate, generic "rejected turn" design |

## 9. Minimum Safe Change

**Provider-only request change + tests.** No change to the contract, Runtime, Policy Gateway, approval, evidence, resource governance or Review.

In `chanakya/providers/mapping.py::build_request_kwargs`, add the parameter only when `tools` is non-empty (the API rejects `tool_choice` without tools):

```python
if tools:
    kwargs["tools"] = tools
    kwargs["tool_choice"] = {"type": "auto", "disable_parallel_tool_use": True}
```

- **Leave** `_classify_turn`'s `tool_use_blocks > 1` rejection **exactly as it is**, as defence in depth: a provider-side hint is not a Runtime guarantee.
- **Leave** `_response_to_turn`'s `tool_use_blocks[0]` mapping as it is. It is only reachable after the Runtime count check has passed.
- Audit/Review: no schema change. `tool_choice` is part of the prepared payload, so the recorded `provider_request_hash` already covers it. Review compares manifest and outcome hashes rather than rebuilding the payload, so nothing breaks.
- Optional, same change: bump `ProviderConfig` `config_version` (currently `1.1.0`) so audit records made before and after the change can be told apart by a recorded fact as well as by request hash. `AuditEvent` does not need a new version.
- Update `docs/AGENT-RUNTIME.md` (CT-INV-4 provider section) to say that the declared provider requests at most one tool call and the Runtime still enforces it.

Not required, but worth doing: have the CLI stop early after consecutive rejections with an identical `provider_request_hash`, instead of spending all `DEFAULT_MAX_TURNS = 8` turns on a request that cannot change. This is a usability change, not part of the fix.

## 10. Required Regression Tests

Tests that pin the exact request shape **will need deliberate updates**, which is expected:
`tests/test_anthropic_provider_sdk_security.py:290, 319, 435` and `tests/test_anthropic_provider_target_context.py:261` assert `set(body) == {"model","system","messages","max_tokens","tools"[, "temperature"]}`.

New or updated tests:

1. **Request shape**: with a non-empty catalog, the body contains `tool_choice == {"type": "auto", "disable_parallel_tool_use": true}` exactly, and no other new top-level keys.
2. **No tools → no `tool_choice`**: an empty catalog with the findings channel off omits both `tools` and `tool_choice` (`test_anthropic_provider_sdk_security.py:340, 876`; `test_anthropic_provider_target_context.py:322`; `test_findings.py:553` keep passing).
3. **Findings channel only**: when only `report_findings` is present, `tool_choice` is still `auto` (never `any`/`tool`), so a text-only conclusion stays possible.
4. **Hash coverage**: the prepared `request_hash` changes when `tool_choice` changes, and `send_turn` rejects a payload whose `tool_choice` was changed after preparation.
5. **Backstop unchanged**: the existing `test_multiple_tool_use_blocks_are_rejected_and_never_reach_the_gateway` and `test_rejected_provider_outputs_are_recorded_and_never_used` still pass with the new request. A two-block response is still `multiple_tool_use_blocks`, with 0 Gateway calls, 0 executions and 0 evidence records.
6. **No forced tool**: a regression guard that `tool_choice.type` is never `any`, `tool` or `none` (so the model is never forced to act, and conclusion always stays possible).
7. **Single-block happy path through the real mapping**: one `tool_use` block → `tool_request` outcome → Gateway → approval under `--require-approval`, unchanged.
8. **Manual real-provider check**, after implementation: re-run the same CLI command. Expected: turn 1 is accepted as `tool_request`, one approval prompt appears, and later turns propose the second capability and then `report_findings`.

## 11. Release Impact

- **Security:** no regression and no exposure. All controls held and the failure was fail-closed.
- **Functionality:** the only production provider (Anthropic) cannot finish an ordinary multi-part read-only investigation when the model decides to call tools in parallel. That behaviour is likely for any objective with two parts. For a release that claims working real-provider end-to-end investigations, this is a **release blocker** until the §9 change is made and the §10 tests pass. Offline and scripted-provider paths are not affected (2946/2946 tests pass at baseline).

## 12. Recommendation

1. Classify as a **PROVIDER COMPATIBILITY ISSUE**. Do not relax CT-INV-3.
2. In a dedicated, small change: add `tool_choice: {"type": "auto", "disable_parallel_tool_use": true}` in `build_request_kwargs` when tools are present, update the tests that pin request shape, add the §10 tests, and document it next to CT-INV-4. Optionally bump the provider `config_version`.
3. Keep the Runtime's `tool_use_blocks > 1` rejection as the authoritative backstop.
4. Re-run the same real Anthropic end-to-end command to confirm.
5. Treat real multi-action turns (option 2) as a separate design decision, and only if a need appears. It touches the contract, orchestration, approval, audit/Review, resource accounting and partial-failure handling.

---

### Baseline verification (no source changes)

```
git status --short --branch   → ## main / ?? PHASE-21-ARCHITECTURE-READINESS-REPORT.md
git log -1 --oneline          → 0c07286 Confine durable investigation data placement
git describe --tags --exact-match HEAD → v0.20.0-durable-data-placement-confinement
```

Targeted tests: `test_agent_turn_record.py`, `test_anthropic_provider_sdk_security.py`, `test_agent_loop_controller.py`, `test_agent_provider_boundary.py`, `test_anthropic_provider.py`, `test_anthropic_provider_failure_hardening.py`, `test_anthropic_provider_runtime_integration.py`, `test_anthropic_provider_target_context.py`, `test_provider_config.py`, `test_provider_logging_egress.py`, `test_provider_transport_isolation.py` → **524 passed**.
Full suite → **2946 passed**.

No API key was read, printed or persisted. No new request was sent to the provider. The evidence comes only from existing sanitized audit records, source and tests.
