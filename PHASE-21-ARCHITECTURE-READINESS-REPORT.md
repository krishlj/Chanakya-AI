# Phase 21 — Architecture & Readiness Inspection

Inspection only. No source, test, contract, dependency, configuration or
documentation file was modified. This report is the only new file, and it is
deliberately left uncommitted. Nothing was pushed.

Date: 2026-09-29. Host: Windows 11, Python 3.13.1, Git 2.55.0.

---

## 1. Baseline Verification

| Item | Expected | Observed | Result |
|---|---|---|---|
| Branch | `main` | `main` | ✅ |
| HEAD | `0c0728676d283db147d3c7d0cddd0c5b173a2033` | `0c0728676d283db147d3c7d0cddd0c5b173a2033` | ✅ |
| Tag | `v0.20.0-durable-data-placement-confinement` | exact match at HEAD (annotated) | ✅ |
| Previous commit | `2ac98adc55bb16bf9967de568bcdf5321e92ac02` | `HEAD^` = `2ac98ad…` | ✅ |
| Working tree | clean | `git status --porcelain` empty | ✅ |
| GitHub | not pushed | `origin` = `github.com/krishlj/Chanakya-AI`, `git ls-remote` returns no refs, no remote-tracking branches | ✅ |
| `pytest -q` | 2946 passed | **2946 passed**, 0 failed | ✅ |
| `pytest -q -W error -rsxX` | 2946 passed | **2946 passed**, 0 skipped, 0 xfailed, 0 warnings | ✅ |

`git show --stat HEAD` shows the Phase 20 change set: 9 files, +1353/−13.

## 2. Current Architecture

The architecture below was reconstructed from `chanakya/` (95 modules, about
17.3k lines) and the 2946 tests, not from the documentation alone.

```
User (terminal)
 └─ CLI  chanakya/cli/main.py  (composition root; the only reader of ANTHROPIC_API_KEY)
     ├─ --review ──► chanakya/review (read-only reconstruction; builds no Runtime/provider)
     └─ build_runtime()
         ├─ Phase 20 placement  runtime/workdir_placement.py  (runs first; stores get only the verified root)
         ├─ SecurityToolRegistry  registry/  (2 entries, fixed in code: bootstrap.py)
         ├─ TargetRegistry + TargetManager  targets/  (one AUTHORIZED target: local-host)
         ├─ PolicyGateway  policy/  (sole allow/deny/require_approval authority)
         ├─ CapabilityDispatchExecutor  tools/executor.py  (fixed handler table)
         ├─ Evidence/Finding/RiskAssessment stores + FilesystemAuditLog  (durable, append-only)
         ├─ RiskEngine  risk/  (deterministic, rule set from trusted code)
         ├─ TerminalApprovalProvider  approval/
         └─ AgentLoopController  runtime/agent_loop.py
               InvestigationManager (state machine) → ResourceGovernor (budgets)
               ContextAssembler (Runtime-owned model context; tool output wrapped as data)
               → AgentProvider = AnthropicProvider  providers/ (verified transport, logging check)
               → ToolRequestIntake → PolicyGateway.evaluate → (Approval) → dispatch()
               → TimeoutSupervisor → executor → handler → envelope check_output
               → Tool-output screening (Phase 15) → Evidence → AuditEmitter
               → conclude: Findings (evidence-grounded) → RiskEngine → RiskAssessments
```

The requested chain holds in code and in a live offline run (§10):
User → CLI → Investigation Manager → Agent Runtime → Provider → ToolRequest →
Policy Gateway → Capability Registry → Capability Envelope → Tool Execution →
Tool Output Screening → Evidence → Findings → Risk Assessment → Human
Approval → Audit → Review.

Human Approval sits between the Gateway and dispatch; it is shown last only
because the prompt lists it there.

**Differences between the documentation and the implementation.** None of
these is a security defect.

| # | Documented | Actual |
|---|---|---|
| D-1 | `ARCHITECTURE.md` "Phase 1 implementation scope (not started yet)" | Implemented (Phases 3–20). The heading is stale. |
| D-2 | `ARCHITECTURE.md` package layout lists `agent/`, `llm/`, `config/` | These are `runtime/` and `providers/`. There is no `config/` package; configuration is code-defined in the CLI and `registry/bootstrap.py`. |
| D-3 | §15: configuration "lives in versionable config files" | Policy rules, Registry entries, target, limits and model are constants in trusted code. This is stricter, not weaker. |
| D-4 | THREAT-MODEL §9 / SR-22: "pinned/locked dependencies … vulnerability scanning" | Not implemented: one lower-and-upper-bounded direct dependency, no lock file, no hashes (§7). |
| D-5 | THREAT-MODEL §9: "runs under a dedicated, non-administrator account" | Operational guidance only; not checked by the CLI (§8). |
| D-6 | `Recommendation` contract | Not produced, stored or displayed (already recorded as SR-19 "not implemented"). Only enum/field remnants exist. |
| D-7 | `pyproject.toml` `version = "0.2.0"` | Tags are at v0.20.0. There is no `[build-system]` and no console-script entry point; the CLI runs as `python -m chanakya.cli` from a checkout. |
| D-8 | Prompt labels T-21 "filesystem/local trust", T-27 "execution isolation", T-41 "finding predicate" | In the register, T-21 = API-key exposure, T-27 = DoS/resource exhaustion, T-41 = secrets copied into findings. §6 assesses both the register entry and the concern named in the prompt. |

## 3. Implemented Security Controls

Each control below was verified by code inspection and by the passing tests.

- **LLM is reasoning only.**
  - Model output is schema-validated into `AgentTurnOutput`/`ToolRequest`.
  - The reserved `report_findings` call can only conclude; it can never
    become a tool request.
  - Findings never reach the Gateway, approval or dispatch (T-43 tests).
- **Runtime is never the policy authority.**
  - `dispatch()` requires a matching `PolicyDecision`.
  - For `require_approval`, it also requires an ACCEPT bound to the same
    `approval_request_id` (`runtime/dispatch.py:145`).
  - The executor imports nothing from `chanakya.policy`.
- **Policy Gateway is the enforcement point.**
  - It is fail-closed.
  - Disabled and unregistered capabilities are indistinguishable.
  - It enforces the target-scope and permission ceilings.
  - State-changing classifications cannot be granted an illegitimate allow.
  - Rate and step limits are enforced through the ResourceGovernor.
  - Verified by `test_gateway.py`, `test_security_invariants.py`,
    `test_boundary_matrix.py` and `test_capability_model.py`.
- **Registry is an explicit allowlist.**
  - Exactly two entries, `observe_local_host_environment` and
    `list_listening_ports`.
  - Both are `READ_ONLY`, `ActionType.OBSERVE`, `ApprovalRequirement.NONE`
    and `model_egress=ALLOWED`.
  - The executor is a fixed dispatch table; nothing is discovered or
    imported by name.
- **No shell.** There is no `subprocess`, `os.system`, `Popen`, `eval` or
  `exec` anywhere in `chanakya/`. The only native access is `ctypes`
  `GetExtendedTcpTable`/`GetExtendedUdpTable` (Windows) or the `/proc/net`
  reads (Linux) in `listening_ports.py`.
- **Target Manager is descriptive only.**
  - The target context is data for the model.
  - Authorization is `Target.status` plus Gateway scope.
  - `LocalHostAdapter` reads no environment variables except `container`.
- **Capability envelope (Phase 11).**
  - The Gateway attaches the envelope, and the executor cross-checks it
    against the Registry.
  - Output is checked for JSON compatibility, canonical size and the
    declared schema before anything can become Evidence.
  - The timeout is the capability's declared value, capped by the Runtime
    ceiling.
- **Model egress / output screening (Phase 15).**
  - Successful output is screened for credential-shaped content and is
    rejected, not redacted.
  - Only `model_egress=ALLOWED` output reaches the model.
- **Failure-path control (Phase 16).** Handler exception text never crosses
  a boundary; only fixed `tool_execution_failed: <CODE>` messages do.
- **Runtime-owned error and terminal records (Phase 17).** `error_state`
  holds closed-vocabulary codes only, and the terminal record is durable
  before the state changes.
- **Agent turn records (Phase 14).** Every model turn has a durable manifest:
  provider, model, endpoint, config version, request hash, context sources,
  and a screened explanation.
- **Provider transport isolation (Phase 18).**
  - `trust_env=False`; no proxy; system trust store via `truststore`; no
    redirects; 0 retries.
  - The SDK environment variables that redirect the endpoint are refused by
    the CLI.
  - The transport is verified before use and at every send.
- **SDK logging egress (Phase 19).** The whole `anthropic`/`httpx2`/
  `httpcore2` logger namespace is checked at construction, at preparation
  and before every send.
- **Evidence and audit.**
  - Both are append-only with exclusive create.
  - Records are content-hashed, and the audit is a per-investigation hash
    chain.
  - Records are re-verified on read.
  - Review reports anomalies (missing terminal event, chain breaks,
    orphans, cross-investigation references, risk recomputation mismatch).
- **Durable data placement (Phase 20).** The canonical `.gitignore` is
  established or verified before the first store is created. The repository
  `.gitignore` also lists `.chanakya/`. Review never runs placement.

## 4. Trust Boundaries

| Boundary | Crossing | Control in force |
|---|---|---|
| TB-1 User → CLI | objective, approval answer | Objective screened as an audit fact (`AuditFactError`). Approval accepts the literal `approve`/`deny` only; untrusted values are rendered with `json.dumps(ensure_ascii=True)`. |
| TB-2 Runtime → provider (host → Anthropic) | model context | Runtime-composed context; screened tool output; `model_egress` gate; fixed endpoint; transport and logging verified per send. |
| TB-3 Provider → Runtime | model turn | Schema validation; the findings channel is conclude-only; no authority. |
| TB-4 Runtime → Gateway → dispatch | ToolRequest | Registry lookup, target scope, ceilings, rate limits, envelope, approval binding. |
| TB-6 Tool/target output → Runtime | handler output | Envelope size and schema; screening; fixed failure codes; wrapped as data in context. |
| TB-8 Runtime → durable stores | records | Append-only, hashed, chained; Phase 20 placement. |
| Stores → VCS → remote | files | Runtime-owned exclusion plus the repository `.gitignore`. |
| Stores → Review | read | Read-only; creates nothing (P20-INV-5, AR-INV-6/7). |

## 5. Phase 11–20 Regression Status

Each group was run separately with `-W error`; all passed, and all are also
included in the full 2946-test run.

| Phase | Control | Test group | Result |
|---|---|---|---|
| 11 | Capability execution envelope | `test_capability_envelope.py` | 164 passed |
| 12 | Durable authorization record + Review | `test_authorization_record.py`, `test_investigation_review.py` | 126 passed |
| 13 | Versioned risk rules | `test_risk_rule_sets.py`, `test_risk_provenance.py` | 64 passed |
| 14 | Agent turn record + context composition | `test_agent_turn_record.py`, `test_context_assembler.py` | 82 passed |
| 15 | Output screening + model egress | `test_tool_output_screening.py` | 43 passed |
| 16 | Failure-path output control | `test_failure_path_output.py` | 57 passed |
| 17 | Runtime-owned error/terminal records | `test_runtime_owned_error_records.py` | 54 passed |
| 18 | Provider transport isolation | `test_provider_transport_isolation.py` | 60 passed |
| 19 | Provider logging completeness | `test_provider_logging_egress.py` | 30 passed |
| 20 | Durable data placement | `test_durable_workdir_placement.py` | 57 passed |
| Core | RT-INV / boundary matrix / Gateway / dispatch | `test_security_invariants.py`, `test_boundary_matrix.py`, `test_rt_inv_end_to_end.py`, `test_gateway.py`, `test_dispatch_boundary.py`, `test_step_3_5_security_invariants.py` | 90 passed |

The live offline run in §10 also exercised Phases 11–15 and 17–20 end to end:

- envelope recorded;
- authorization record and approval bound;
- risk rules `chanakya-risk-rules/1.0.0`;
- three agent-turn manifests;
- evidence "screened chanakya-tool-output-screen/1.0.0";
- terminal record durable;
- verified transport;
- canonical exclusion present.

## 6. Known Residual Risks

These criteria were applied to every row: Is it still present? Is it reachable
with the current two read-only capabilities? Does it cross a boundary? Can it
cause unauthorized execution, secret exposure, policy bypass or evidence/audit
corruption?

| ID | Finding | Current Status | Release Impact | Classification |
|----|---------|----------------|----------------|----------------|
| T-17 | Approver identity is an unauthenticated string (`--approver`, else the OS user); in-process code could construct an `ApprovalDecision` | Present. Decisions are bound to one `approval_request_id` (no replay or cross-request reuse); dispatch re-checks the binding; reserved names are refused; expiry is supported. | Not reachable for authorization: both capabilities are `ApprovalRequirement.NONE`, so approval is an optional extra gate (`--require-approval`). Forging needs code execution in the process, which already defeats every in-process control (T-25). | NON-BLOCKING RESIDUAL |
| T-18 | Audit/evidence tamper-evidence, not tamper-prevention; no external anchoring | Present. A local attacker with write access can rewrite and rehash a whole consistent chain. | Needs local file-write access (T-25). Accidental or partial corruption is detected by Review. Does not silently break integrity against anyone without host access. | NON-BLOCKING RESIDUAL (anchoring = FUTURE HARDENING) |
| T-21 (register) | Provider API key exposure | Mitigated. Read once by `main()`; never printed, logged or stored; transport and logging controls (P18/P19). The offline E2E confirmed the key value is absent from bodies, output and durable files. | None | NON-BLOCKING RESIDUAL |
| T-21 (as labelled: local filesystem trust) | Stores rely on OS permissions; no encryption at rest | Present; documented. | Same host trust as the operator's own files. | NON-BLOCKING RESIDUAL |
| T-22 | Sensitive evidence leakage | VCS path mitigated (Phase 20). Provider egress by design: hostname, OS facts, listening addresses, PIDs and process names are sent to Anthropic (`model_egress=ALLOWED`). Credential-shaped output is screened. | A documented design tradeoff, not a bypass. Needs clear operator disclosure in the release notes/README. | NON-BLOCKING RESIDUAL |
| T-23 | Dependency integrity (no lock, no hashes) | Present (§7). | Does not bypass any runtime control. The project's own SR-22 requires lock + scan "before release", so it belongs in release preparation. | NON-BLOCKING RESIDUAL — required release-prep item |
| T-24 | Dependency vulnerabilities / reproducibility | Present: ranges only (`anthropic>=1.7.0,<2.0`), transitive dependencies unpinned, no scan on record. | Same as T-23. | NON-BLOCKING RESIDUAL — required release-prep item |
| T-27 | DoS / resource exhaustion | Mitigated for scope: step, tool-call and duration budgets; output-size limits; bounded reads (16 MiB per table, 5 negotiation attempts); finding limits. | Local, self-inflicted at worst. | NON-BLOCKING RESIDUAL |
| T-27 (as labelled: execution isolation) | Handlers run in-process, same user, no sandbox | Present (§8). | Two fixed, reviewed, read-only handlers; no attacker-supplied code or parameters. Not reachable as a security failure today. | FUTURE HARDENING (required before MCP / third-party / state-changing tools) |
| T-36 | Timeout is post-hoc, not preemptive | Present: a late result is discarded, the handler is not interrupted. | The handlers make no blocking or network calls; worst case is a stall of the local CLI. No unauthorized result is accepted. | FUTURE HARDENING |
| T-41 (register) | Secrets copied from evidence into findings | Present; best-effort pattern screening (reject, not redact). | Bounded: the current evidence (platform facts, sockets) carries no credential fields. | NON-BLOCKING RESIDUAL |
| T-41 (as labelled: finding predicate / authorization consistency) | Findings have no authority | Holds: findings never reach Gateway, approval or dispatch (T-43 tests). | None | NON-BLOCKING RESIDUAL |
| T-45 | Severity steering through category choice | Present: the model can pick the highest *compatible* category. The closed taxonomy, compatibility gate and read-only ceiling (`critical` unreachable) hold; the E2E shows medium as the maximum. | Affects the rating, never authorization; ratings are labelled rule-based and unverified. | NON-BLOCKING RESIDUAL |
| T-60 (P15) | Screening is pattern-based; novel secret formats may pass | Present; documented. | Current outputs contain no credential material. | NON-BLOCKING RESIDUAL |
| T-61/T-62 (P16/P17) | Failure text and exception text | Mitigated: closed code vocabulary. | None | NON-BLOCKING RESIDUAL |
| T-63 (P18) | No certificate pinning; no proxy support | Present by design. | System trust store; no redirect or proxy route. | FUTURE HARDENING |
| T-64 (P19) | Monkeypatched logging, custom logger classes, OS-level capture, thread races | Present; in-process only. | Needs code in the process. | NON-BLOCKING RESIDUAL |
| T-65 (P20) | `git add -f`, pre-tracked files, other VCS, TOCTOU by a local attacker | Present; documented. | Needs deliberate action or local attacker access. | NON-BLOCKING RESIDUAL |
| — | Live state is in memory only; no resume | Present (documented gap). | A crash leaves durable, reviewable records; a restart starts a new investigation. | FUTURE FEATURE |
| — | Agent explanation not shown live; no approval justification collected | Present (documented gap). | Cosmetic / UX. | FUTURE FEATURE |

**No row meets any of the nine release-blocker criteria.**

## 7. Dependency / Supply Chain Assessment

- **Declared (direct):** `anthropic>=1.7.0,<2.0`. It is the only entry in
  `pyproject.toml` `[project].dependencies`.
- **Installed and exercised:**
  - `anthropic 1.7.0` requires anyio, docstring-parser, httpx2, jiter,
    pydantic, sniffio and typing-extensions.
  - `httpx2 2.13.0` requires anyio, httpcore2, idna and truststore.
  - `httpcore2 2.13.0` requires h11 and truststore.
  - `truststore 0.10.4`.
- **Undeclared direct imports:**
  - `chanakya/providers/transport.py` imports `httpx2` (line 58) and
    `truststore` (line 193) directly. Both arrive only transitively through
    `anthropic`.
  - The code pins the SDK's logger/transport layout by test (Phase 19). A
    future `anthropic` 1.x that drops or renames `httpx2` would therefore
    break at import, not silently: the failure is closed, but it is a
    reproducibility gap.
- **Test-only:** `pytest` (9.1.1 installed), plus `pydantic` imported by tests.
  No test extra or dev-requirements file is declared.
- **Lock files / hashes:** none. No `requirements*.txt`, lock file, `--hash`
  pins or build-system table.
- **Standard library only elsewhere:** everything else in `chanakya/`,
  including `ctypes` for the Windows socket tables.
- **Python:** `requires-python = ">=3.9"`. No 3.10+-only syntax was found,
  but the suite has only been run on 3.13.1.

**Assessment.** Dependency integrity cannot bypass the Gateway, the Registry
or any Runtime control, so it is not a release blocker under the §12
criteria. However, the project's own SR-22 ("pinned/locked and scanned
before release") is unmet. Treat it as a **mandatory release-preparation
step**, not a new implementation phase:

1. a hash-pinned lock (for example `pip-compile --generate-hashes`);
2. declare `httpx2` and `truststore` explicitly;
3. declare a test extra;
4. one vulnerability scan (`pip-audit`) recorded in the release notes.

## 8. Execution Isolation Assessment

- **In-process.** Handlers run synchronously in the CLI's Python process
  (`CapabilityDispatchExecutor.execute` → `handler.run`). There is no
  subprocess, thread pool or sandbox.
- **Privileges.** Same OS user as the operator; there is no privilege check
  and no drop. Under an elevated shell on Windows, `list_listening_ports` can
  see more process names. Nothing escalates.
- **Filesystem.** The environment handler reads platform APIs and at most
  `/.dockerenv` and `/proc/1/cgroup`. The ports handler reads `/proc/net/*`
  and `/proc/*/fd` links (Linux) or the IP Helper tables (Windows). Neither
  takes a path parameter, so no unrelated file can be requested.
- **Network.** Handlers do no network I/O. The only network egress is the
  provider call.
- **CPU and memory.** No OS limits. Bounded by design: 16 MiB per socket
  table, output ≤ 60–64 KiB by envelope, and step, tool-call and duration
  budgets.
- **Timeout.** Per-step timeouts (10 s and 15 s envelopes, capped by the
  Runtime ceiling) are measured post-hoc. An overrunning result is discarded
  as `STEP_TIMEOUT_EXCEEDED`, but the handler is not interrupted (T-36).
- **Cancellation.** Ctrl+C cancels the investigation through
  `InvestigationManager.cancel` (audited HALTED). It cannot interrupt a
  running handler mid-call.
- **Effect on the Runtime.** A raising handler becomes a fixed-code ERROR
  result and cannot crash the loop. A handler returns only a mapping; it
  receives the target and parameters, not the Gateway, stores or provider.
  It could only affect the Runtime by being malicious code, and both
  handlers are first-party and reviewed.
- **Bypassing the Gateway.** Not possible through the data path: handlers are
  reached only via `dispatch()` with an authorized `DispatchInstruction`.

**Verdict.** Acceptable for the current scope of two fixed, parameter-free,
read-only first-party handlers. Process isolation and preemptive timeouts
become required **before** MCP, third-party, remote or state-changing
capabilities are added: FUTURE HARDENING, not a first-release blocker.

## 9. Approval / Identity Assessment

| Question | Answer |
|---|---|
| Identity representation | Free-text `approver` (`--approver`, default `getpass.getuser()`); `agent`/`system` reserved; recorded as `decided_by` and the audit `actor`. |
| Authenticated? | **No.** Local-session trust only (documented T-17). |
| Investigation-bound? | Yes. The request carries the `investigation_id`, and the decision is audited in that investigation's chain. |
| Request-bound? | Yes. The decision's `approval_request_id` must equal the request's; `dispatch()` refuses otherwise. The request shows the capability, target and canonical parameters, and Review re-displays them. |
| Risk-bound? | Bound to the PolicyDecision (classification and risk category shown); not to a Finding's RiskAssessment, which does not exist until conclude. |
| Expiry | Supported (`expires_at`; an expired decision is audited `expired` by `system`). The CLI policy sets none (`expires_at: null`). |
| Replay | Prevented: one decision per request id, never reused (SR-8, RT-INV-4). |
| Forgeable by local code? | Yes, by code running in the same process. That attacker already controls the process (T-25). |
| Matters for the current release? | Marginally. Both capabilities are read-only and `ApprovalRequirement.NONE`; approval is an operator opt-in extra gate. |

**Not a release blocker.** Authenticated identity is FUTURE HARDENING,
required before remote approval, multi-user use or state-changing
capabilities.

## 10. End-to-End Runtime Readiness

**Live Anthropic validation not executed because the required environment
credential was unavailable.** `ANTHROPIC_API_KEY` is not set in this
environment. This is an **environment prerequisite**, not a code defect. The
CLI refuses correctly (`error: environment variable ANTHROPIC_API_KEY is not
set`, exit 2) and creates no workdir.

**Offline end-to-end run performed.** Script:
`scratchpad/p21_e2e.py`, outside the repository. Everything was production
code except the Anthropic HTTP endpoint, which was replaced by
`httpx2.MockTransport`: no network, scripted model replies, and a
placeholder key string that is not a credential.

The run exercised, for real:

- `cli_main.main()`, `build_runtime` and Phase 20 placement;
- `AnthropicProvider` (request construction, SDK call, response mapping,
  findings channel);
- Policy Gateway (`--require-approval`) and the terminal approval prompt;
- the envelope, both LocalHost capabilities on this Windows host, and
  screening;
- the Evidence, Finding, Risk and Audit stores, the Risk Engine and `--review`.

Results:

| Step | Observed |
|---|---|
| Objective → CLI → Investigation | `investigation: <uuid>`, exit 0, `final status: completed` |
| Provider → ToolRequest (×2) | 3 provider HTTP requests; turns 1–2 `tool_request` accepted, turn 3 `findings` |
| Gateway → Approval | `require_approval` by rule `cli-require-approval`; 2 prompts; `accept by "p21-operator"` |
| Envelope → capability | `observe_local_host_environment` (10 s / 65536 B) and `list_listening_ports` (15 s / 60000 B), both `success` |
| Screening → Evidence | 2 records, "verified; screened chanakya-tool-output-screen/1.0.0" |
| Model context | Turn 3 context lists both `tool_result:` sources (Runtime-composed) |
| Findings | 2, evidence-grounded |
| Risk | 2 assessments: `low`/medium basis (`platform_configuration`), `medium`/medium basis (`network_exposure`), rule set `chanakya-risk-rules/1.0.0`, provenance verified |
| Audit | 26 records, chain verified |
| Review | `consistency: consistent`, `anomalies: 0`, exit 0; workdir byte-for-byte unchanged by Review |
| Placement | canonical `.gitignore` present |
| Secret hygiene | placeholder key absent from request bodies, terminal output and all durable files |

An earlier run in which the scripted model cited mismatched evidence and an
unrated category correctly produced "not assessed (`evidence_incompatible` /
`category_unrated`)" instead of guessing.

**Classification of the three questions.**

1. *Architecture supports end-to-end execution:* **yes**, demonstrated.
2. *Environment is missing a prerequisite:* **yes**. An Anthropic API key
   and outbound HTTPS to `api.anthropic.com` are required for a live run.
3. *Code prevents end-to-end execution:* **no**.

The remaining unknown for a live run is real-model behaviour: tool selection,
`report_findings` usage and category choice. It is not Runtime correctness.

## 11. First Release Scope

| Component | Status |
|---|---|
| CLI (`python -m chanakya.cli`, `--review`) | ✅ Working (offline E2E + tests) |
| Anthropic provider | ✅ Working against the SDK with a mock transport; ⏳ live call not yet validated (credential unavailable) |
| LocalHost target | ✅ |
| `observe_local_host_environment` | ✅ (real run on this host) |
| `list_listening_ports` | ✅ (real run on this host, Windows IP Helper path) |
| Evidence generation | ✅ |
| Evidence-grounded findings | ✅ |
| Deterministic risk assessment | ✅ |
| Human approval mechanism | ✅ (`--require-approval`; the default policy allows the two read-only capabilities) |
| Durable audit | ✅ |
| Investigation review | ✅ |

**Not ready or not in scope:**

- live provider validation (environment);
- packaging (`pip install` gives no entry point, and the version metadata is
  stale);
- a dependency lock and scan (SR-22);
- MCP, remote targets, state-changing actions, identity, resume, GUI/API
  (future features, correctly excluded).

## 12. Remaining Gaps

None of these requires new security architecture or a numbered hardening
phase.

1. **Live provider validation.** One real run with the operator's key and a
   safe read-only objective, followed by `--review`.
2. **Release-prep for SR-22 (T-23/T-24).**
   - hash-pinned lock;
   - declare `httpx2` and `truststore`;
   - add a test extra;
   - record a `pip-audit` result.
3. **Release metadata and docs.**
   - `pyproject` version;
   - optional console-script entry;
   - fix the stale `ARCHITECTURE.md` headings and layout (D-1, D-2);
   - README operator notes: data sent to Anthropic (hostname, OS, ports,
     PIDs, process names), run as a non-administrator, keep `--workdir`
     outside repositories, the post-hoc timeout.
4. **Known residuals to state in the release notes:** T-17, T-18, T-36, T-45,
   T-60, T-63, T-64, T-65 residuals.

## 13. Release Blockers

**None.** Checked against the nine §12 criteria:

1. Gateway bypass: none found; covered by the dispatch, boundary-matrix and
   RT-INV tests.
2. Unauthorized capability execution: none; Registry allowlist plus Gateway
   plus bound approval.
3. Arbitrary code or shell: none in `chanakya/`; no path or command
   parameters.
4. Secret leakage: none found. The key is read once and was absent from
   every output, body and file in the E2E run.
5. Tool/model output becoming instructions: none. Output is wrapped as data,
   and findings have no authority.
6. Silent audit/evidence integrity violation: none without local host
   compromise (T-18, documented).
7. Non-functional first-release flow: no. It runs end to end, and only the
   live credential is missing.
8. Reachable security failure with current capabilities: none identified.
9. Investigation verification impaired: no. Review verified chain,
   provenance and risk recomputation; `anomalies: 0`.

## 14. Phase Decision

- **Question 1 — Is another implementation phase required before a first
  controlled release?** **No.**
- **Question 2 — Smallest required scope:** not applicable. No genuine
  release blocker exists.
- **Question 3 — Path forward:**

```
END-TO-END VALIDATION (live, with the operator's key)
  → FINAL SECURITY AUDIT
  → DOCUMENTATION / RELEASE PREPARATION (incl. SR-22 lock + scan, packaging metadata)
  → GITHUB PUSH
  → v1.0.0
```

No Phase 22+ is justified by the evidence. Execution isolation, preemptive
timeouts, authenticated identity, audit anchoring and certificate pinning are
FUTURE HARDENING. They become prerequisites only when the scope grows (MCP,
third-party, remote or state-changing capabilities).

## 15. Recommended Next Step

1. Review this report, then decide whether to keep it (commit as
   documentation) or discard it.
2. Live E2E validation.
   - The operator sets `ANTHROPIC_API_KEY` in their own shell, not in any
     file.
   - From a directory **outside** the repository, run:

     ```
     python -m chanakya.cli "Read-only: summarize this host's platform and listening services" --workdir D:\Chanakya-Data --require-approval
     ```

   - Then run `python -m chanakya.cli --review <id> --workdir D:\Chanakya-Data`
     and confirm `consistency: consistent`.
3. Release preparation (non-phase): SR-22 lock + `pip-audit`, declare the
   direct transitive imports, version/entry-point metadata, README operator
   disclosure, and the stale architecture headings.
4. Final security audit against the tagged release candidate, then push and
   tag `v1.0.0`.

---

PHASE 21 VERDICT:
READY FOR END-TO-END VALIDATION

- Current test count: 2946 passed (`pytest -q` and `pytest -q -W error`); 0 failed, 0 skipped, 0 xfailed, 0 warnings
- HEAD: `0c0728676d283db147d3c7d0cddd0c5b173a2033`
- Tag: `v0.20.0-durable-data-placement-confinement`
- Working tree: clean except this uncommitted report (`?? PHASE-21-ARCHITECTURE-READINESS-REPORT.md`)
- Implementation changed: no
- Live Anthropic validation performed: no (credential unavailable; offline full-path run performed with only the HTTP endpoint mocked)
- Release blockers: none
- Recommended next action: live end-to-end validation with the operator's API key, then final security audit and release preparation
