# Chanakya AI — Final Security Audit & Release Readiness

**Scope:** the complete implementation at `main` / `91dca31`. The audit covers source, tests, packaging, documentation, Git history (Phase 0 → HEAD), the stored real-provider investigation and the durable workdir. It is not a numbered phase.
**Method:** independent inspection and re-execution; earlier phase reports were not relied on. No implementation file was modified. Packaging and dependency checks ran in an isolated copy (`git archive HEAD`) and a throwaway virtual environment in the session scratchpad, outside the repository.
**Result:** **PASS WITH RELEASE PREPARATION**. No security blocker was found. The release is held back by packaging, dependency locking and documentation.

---

## 1. Audit Baseline

| Check | Expected | Observed |
|---|---|---|
| Branch | `main` | `main` (no upstream tracking, no remote-tracking refs, so nothing pushed from this clone; `origin` is configured) |
| HEAD | `91dca31 Fix Anthropic parallel tool request compatibility` | `91dca3101b4fafa2be0e6bffa9ce4aaef12bf0f1` ✔ |
| Tag on HEAD | none | none (`git describe --exact-match` fails) ✔ |
| Previous tag | `v0.20.0-durable-data-placement-confinement` | on `0c07286` ✔ |
| Working tree | two untracked Phase 21 reports | exactly those two (+ this report) ✔ |
| `pytest -q` | 2970 passed | **2970 passed**, 0 failed, 0 skipped, 0 xfailed |
| `pytest -q -W error` | 2970 passed, 0 warnings | **2970 passed**, 0 warnings |

History: 33 commits (Phase 0 `1143f47` → `91dca31`) and 32 tags (`v0.1-foundation` … `v0.20.0-…`). There is no Phase 1 commit; the Phase 1 scope was folded into Phases 2–8, which matches `ARCHITECTURE.md`'s "Phase 1" decisions. `v0.1-foundation` and `v0.2-security-control-plane` are lightweight tags; the other 30 are annotated.

## 2. Architecture Verification

The implemented flow was verified in code (`chanakya/cli/main.py::build_runtime`, `runtime/agent_loop.py`, `runtime/dispatch.py`) and confirmed end to end by the real investigation (§6):

```
User → CLI (cli/main.py) → InvestigationManager → AgentLoopController (Runtime)
  → AnthropicProvider (providers/) → AgentTurn classification (CT-INV-3) → ToolRequestIntake
  → PolicyGateway (policy/gateway.py) → SecurityToolRegistry.get_enabled → CapabilityEnvelope
  → TerminalApprovalProvider (when REQUIRE_APPROVAL) → dispatch() (runtime/dispatch.py)
  → ToolExecutor + handler (tools/) → envelope checks → tool-output screening
  → EvidenceStore → Finding validation/FindingStore → RiskEngine/RiskAssessmentStore
  → FilesystemAuditLog (hash chain) → Review (review/, read-only)
```

Authority separation was checked by import analysis of the packages, not by reading docs:

| Component | Role verified | Evidence |
|---|---|---|
| LLM / provider | reasoning and proposal only | `chanakya/providers` imports no policy, dispatch, tools, evidence or audit module; it returns a mapping only |
| Runtime | orchestration and execution | calls the Gateway for every request; `dispatch()` requires a `PolicyDecision`; the Runtime never builds a verdict |
| Policy Gateway | sole authorization authority | `evaluate()` returns only a `PolicyDecision`; any exception becomes a `deny` |
| Registry | capability allowlist | `get_enabled()` is the only lookup; unknown, disabled and quarantined capabilities are indistinguishable |
| Target Manager | descriptive | target views reach the model as data; the Gateway re-resolves `target_ref` by id and status |
| Risk Engine | deterministic | imports only contracts and the evidence/finding store readers; the active rule set comes from code |
| Evidence | provenance and integrity | content and payload hashes, re-verified on read |
| Audit | durable history | per-investigation SHA-256 chain, exclusive create (`os.link`) |
| Review | read-only verification | imports contracts, the audit-log reader and store readers only; no runtime, tools, Gateway or provider |

**The LLM never becomes the security authority.** A model turn is a proposal. It is validated, and then independently authorized by the Gateway, the Registry, the envelope and approval.

## 3. Policy and Authorization

| Property | Result | Where |
|---|---|---|
| Fail closed | ✔ | `PolicyGateway.evaluate` catches everything and returns `deny` (`FAIL_CLOSED_ERROR`) |
| Deny by default for anything unregistered | ✔ | Step 2: `get_enabled()` → `UNKNOWN_CAPABILITY` deny |
| Registry lookup cannot be bypassed | ✔ | The Gateway resolves the entry itself; the envelope is derived from that same entry; `dispatch()` refuses an envelope that differs from the decision's |
| Gateway cannot be bypassed | ✔ | `dispatch()` is the only path to `executor.execute` and requires a matching `PolicyDecision` (ids, verdict, envelope); `test_dispatch_boundary`, `test_security_invariants`, `test_rt_inv_end_to_end` |
| Permission ceiling | ✔ | `ELEVATED` is denied at `STANDARD_USER` (SR-21); both capabilities are `STANDARD_USER`/`TARGET_READ` |
| Target scope | ✔ | The investigation's authorized refs, the Target Registry entry, `supported_target_types` and `status == AUTHORIZED` are all required |
| Parameter validation | ✔ | Registry `parameters_schema` is enforced before the rules run; both capabilities take `{}` with `additionalProperties: false` |
| Rate limits | ✔ (mechanism) | Rule-based `max_calls_per_investigation` in the Gateway. The CLI policy set declares none, so the Resource Governor's hard caps apply (10 steps, 10 tool calls per investigation, one concurrent investigation) |
| Explicit deny beats approval/allow | ✔ | `_apply_rules` evaluates DENY → REQUIRE_APPROVAL → ALLOW |
| State-changing never gets an illegitimate allow | ✔ | Load-time `validate_policy_set` plus the runtime INV-1 skip of ALLOW rules; the classification default is REQUIRE_APPROVAL |
| Approval cannot authorize an unregistered capability | ✔ | Approval is requested only after a Gateway REQUIRE_APPROVAL verdict, which needs a Registry entry. `dispatch()` binds approval to the tool request, policy decision, approval request and investigation |
| Model output cannot execute tools | ✔ | The provider has no route to dispatch; a turn is classified, then goes through intake and the Gateway |
| The Runtime makes no policy decisions | ✔ | The Runtime acts on `PolicyDecision.verdict` and never computes one |

Both registered capabilities go through the same `run_turn → intake → evaluate → approval → dispatch` path. The real run confirms it: each produced `request_proposed`, `policy_evaluated`, `approval_requested/decided`, `dispatch_*` and `evidence_recorded`.

Note: without `--require-approval`, read-only capabilities are **allowed by default** (the `READ_ONLY_DEFAULT` classification default) once scope and schema pass. This is the documented design, not a gap. The README should say it (RP-6).

## 4. Capability Inventory

These two capabilities are the complete production set (`registry/bootstrap.py::production_registry_entries`, which a test keeps in parity with `tools/bootstrap.py`):

| Field | `observe_local_host_environment` | `list_listening_ports` |
|---|---|---|
| Tool id | `local-host-environment-observer-v1` | `local-host-listening-ports-v1` |
| Action type | `OBSERVE` | `OBSERVE` |
| Classification / permission | `read_only` / P1 | `read_only` / P1 |
| Privilege | `standard_user`, `target_read` | `standard_user`, `target_read` |
| Target scope | `local_host` only | `local_host` only |
| Parameter schema | `{}`, closed | `{}`, closed |
| Output schema | closed; fixed observation keys (os, release, version, platform, architecture, **hostname**, python_version, cpu_count, is_containerized) | closed; `ports[]` of protocol, port, local_address, pid, **process base name** |
| Output limit | 65,536 bytes | 60,000 bytes |
| Timeout | 10 s (post-hoc, T-36) | 15 s (post-hoc, T-36) |
| Model egress | `allowed` | `allowed` |
| Approval requirement | `NONE` (CLI `--require-approval` adds a rule) | `NONE` |
| Handler | `LocalHostEnvironmentHandler` → `LocalHostAdapter` (stdlib `platform`/`socket`) | `ListeningPortsHandler`: Linux `/proc/net/*`; Windows `GetExtended{Tcp,Udp}Table` + `OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION)`/`QueryFullProcessImageNameW` (base name only) |
| Status | `ENABLED` | `ENABLED` |
| Platforms | any | Linux, Windows; other platforms fail closed (`UnsupportedPlatformError`) |

A source scan of `chanakya/` found no `subprocess`, `os.system`, `os.popen`, `eval`, `exec`, `shell=True`, `pickle` or `marshal`, and no outbound socket or `urllib`/`requests` use. The only `ctypes` use is the two read-only Windows API calls above.

- **No unrestricted shell or arbitrary command execution.**
- **No offensive or remote execution.**
- **No state-changing capability is registered.**

## 5. Anthropic Provider (fix `91dca31`)

| Check | Result |
|---|---|
| `tool_choice={"type":"auto","disable_parallel_tool_use":True}` sent when tools are present | ✔ `providers/mapping.py::build_request_kwargs`, fresh copy per request of `_TOOL_CHOICE`; tested on the SDK-serialized wire body |
| No `tool_choice` when tools are absent | ✔ (`test_no_tools_means_no_tool_choice`, `test_wire_request_without_tools_has_no_tool_choice`) |
| Runtime `MULTIPLE_TOOL_USE_BLOCKS` protection retained | ✔ `agent_loop.py::_classify_turn`, the first check, unchanged |
| CT-INV-3 intact; only one `tool_use` block accepted | ✔ two-, duplicate-, findings-plus-tool and three-block replies are rejected with no Gateway call, approval, dispatch, evidence or finding |
| First-tool-only behaviour absent | ✔ `mapping._response_to_turn` maps `blocks[0]`, but the turn is used only after the Runtime has confirmed there is exactly one block; `test_multiple_tool_use_blocks_are_rejected_and_never_reach_the_gateway` |
| Parallel execution absent | ✔ `AgentTurnOutput` carries one `tool_request`; there is no list path |
| Request hash covers the complete request | ✔ `_prepare` hashes the full deep-copied payload, including `tool_choice`; the golden test shows the only change from the previous pin is `tool_choice` |
| Hash checked before sending | ✔ `send_turn` recomputes it and raises before `messages.create`; `test_tampered_tool_choice_is_refused_before_sending` |

Other provider controls re-verified: explicit https endpoint; no custom headers; `max_retries=0`; `trust_env=False`; system trust store through `truststore`; no redirects; SDK debug-logging check at construction, preparation and every send; `ProviderIdentity` + `TransportPolicy` recorded in every manifest.

## 6. Real End-to-End Validation

Stored investigation `c6fd58a7-4774-4738-bf8c-b06eabf81f65` was re-reviewed during this audit (`--review`, exit 0):

| Item | Expected | Observed |
|---|---|---|
| Turn 1 | `observe_local_host_environment`, approved, executed | ✔ accepted, `tool_use_blocks=1`, approval `accept`, dispatch `success` |
| Turn 2 | `list_listening_ports`, approved, executed | ✔ accepted, `tool_use_blocks=1`, approval `accept`, dispatch `success` |
| Turn 3 | `report_findings`, completed | ✔ `findings` accepted, `tool_use_blocks=1` |
| Status | completed | `completed` |
| Evidence | 2 | 2, both verified and screened (`chanakya-tool-output-screen/1.0.0`) |
| Findings | 10 | 10, each citing one of the two evidence ids |
| Risk assessments | 9 | 9 (the tenth finding is recorded as not assessed: `evidence_incompatible`) |
| Audit records | 41 | 41, chain verified |
| Consistency / anomalies | consistent / 0 | consistent / 0 |

Provider provenance: `anthropic` / `claude-opus-5-5` / `https://api.anthropic.com` / config `1.1.0`, with a distinct request hash per turn.

The approvals in that run were supplied by piping `approve`, with the operator's explicit consent. Only the two read-only capabilities could be approved. The earlier failed run `54ce659a-…` (pre-fix, 8 × `multiple_tool_use_blocks`, halted) is also stored and reviews consistent.

## 7. Model Egress and Secret Protection

| Control | Status |
|---|---|
| Tool-output screening (success path) | ✔ one Runtime-owned screen before Evidence or context; a hit rejects the result with a fixed code |
| Failure-path screening | ✔ closed failure vocabulary; the backstop rejects anything else |
| Runtime error sanitization | ✔ Runtime-owned exception types; closed error/terminal records; the CLI prints codes only |
| Provider transport isolation | ✔ explicit `httpx2` client, `trust_env=False`, verified before every send |
| SDK logging protection | ✔ namespace-wide DEBUG check (`anthropic`, `httpx2`, `httpcore2`) |
| Request-body logging | ✔ no `logging` use in `chanakya/` other than the check itself; no `print()` anywhere in `chanakya/` |
| Environment variable isolation | ✔ the credential is read once (`cli/main.py`, `environ.get(API_KEY_ENV_VAR)`); redirecting and transport variables are refused by name, values never read; the adapter reads only `os.environ.get("container")` |
| Redirects / retries / TLS | ✔ `follow_redirects=False`, `max_retries=0`, `CERT_REQUIRED` + hostname check through the `truststore` system store |
| Credential handling | ✔ the key goes to the SDK constructor, `del api_key` afterwards, never stored on the provider, never in the body (`x-api-key` header only) |
| Audit credential screening | ✔ `audit/log.py::_screen_credentials` uses the tool-output screen; a hit or an over-limit record (64 KiB) is rejected, never truncated |
| Provider/SDK exception text | ✔ never recorded (P17-INV-1); a fixed `PROVIDER_FAILURE` category |
| Provider response logging | ✔ none; raw output is stored only as a hash |

Residuals (non-blocking): screening is pattern-based (T-20/T-41). Gateway deny reasons are free-form text (they can include exception text on the fail-closed path). They go only to the audit log, credential-screened, and to escaped CLI output, never to the model (NB-3).

## 8. Evidence / Finding / Risk

**Evidence:**
- append-only by application semantics;
- `content_hash` + `payload_hash`, re-verified on read;
- investigation-scoped directories;
- the production recorder refuses unscreened Evidence and re-screens.

Residual: Evidence uses check-then-`os.replace` rather than the exclusive `os.link` create that Finding, Risk and Audit use. This is documented, and harmless with one concurrent investigation (NB-2).

**Findings:**
- `evidence_refs` are required and non-empty;
- each ref resolves only through *this* investigation's step history to recorded Evidence;
- closed field set, so the model cannot declare authority fields;
- at most 20 per investigation, with bounded text;
- credential- and PEM-screened, rejected rather than redacted.

**Risk:**
- deterministic `RiskEngine` under the code-defined, versioned rule set `chanakya-risk-rules/1.0.0` (golden-frozen);
- evidence↔category compatibility checked (`evidence_incompatible` seen in the real run);
- the engine never reads finding text or payloads;
- the model supplies no severity;
- read-only ceiling `high` (`critical` unreachable);
- Review recomputes every rating under its recorded rule set.

## 9. Audit / Review

**Audit:**
- per-investigation SHA-256 chain, with store-owned sequence, previous hash and record hash;
- exclusive create;
- terminal records written before the state is published.

**Recorded facts:**
- agent turn records (manifest before send, one outcome before use);
- authorization records (proposal, decision, envelope, approval, dispatch);
- provider identity, request hashes and transport policy;
- model-egress metadata per context entry.

**Review checks:**
- chain integrity and contract versions;
- turn sequencing;
- orphaned or missing Evidence, Findings and RiskAssessments;
- evidence integrity and screening markers;
- finding↔evidence consistency;
- risk recomputation;
- incomplete streams, which are never reported as completed.

**Review is read-only.** `review_investigation` builds no Runtime, provider, Gateway or executor, and reads no credential. It never runs workdir placement. It opens stores only if their directories exist, and `_ReadOnlyEvidence` neither creates its root nor exposes `append`. The review package imports no writer path, so it cannot execute tools, invoke the provider, alter data or create missing records.

## 10. Durable Data Placement

- Phase 20 controls are intact: `build_runtime` runs `establish_durable_workdir` before any store exists.
- Placement covers canonical resolution (symlinks and junctions), the Git boundary (a `.git` directory or `.git` file, worktrees, submodules, nested repositories), and refusal inside `.git`.
- The Runtime-owned `.gitignore` (`*`) is created exclusively and verified byte for byte. A tampered, weaker or linked exclusion is refused with `WORKDIR_*` codes. Store roots must be plain directories.
- `test_durable_workdir_placement.py` passes in-repo.
- The one failure in the isolated copy was environmental: that test needs the real repository.

Actual workdir `D:\Chanakya-Data`:
- **not inside any Git repository** (`git rev-parse` fails);
- holds the canonical Runtime-owned `.gitignore`;
- `git status --ignored` in the repository shows no investigation data.

## 11. Dependency / Supply Chain

| Item | Finding |
|---|---|
| Declared dependencies | `anthropic>=1.7.0,<2.0` only (`pyproject.toml`) |
| Undeclared direct imports | **`httpx2`** and **`truststore`** (`chanakya/providers/transport.py`), available only transitively through `anthropic` |
| Lock file / hashes | **none** (no requirements file, lock or hashes) |
| Tested versions (this machine) | Python 3.13.1, anthropic 1.7.0, httpx2 2.13.0, truststore 0.10.4, pytest 9.1.1 |
| What a clean install resolves today | **anthropic 1.9.0, httpx2 2.13.1**, truststore 0.10.4, pydantic 2.13.5 |
| Clean-install test result | the suite under anthropic 1.9.0 / httpx2 2.13.1: **2969 passed, 1 environmental failure** (the Git-repository test, not applicable in an export) |
| `requires-python` | declares **`>=3.9`**, but `anthropic`, `httpx2`, `httpcore2` and `truststore` all require **`>=3.10`** |
| Test dependencies | `pytest` is not declared (no `[project.optional-dependencies]`) |
| Private-internals coupling | `transport.verify_client` reads SDK/httpx2 private attributes (documented). A future SDK layout change **fails closed**: an availability risk, not a bypass. Unpinned ranges make this reachable on a routine install |
| Vulnerability scanning | not performed in-project (T-24) |

What must be done before v1.0.0 (RP-1 … RP-3):

1. Declare `httpx2` and `truststore` as direct dependencies.
2. Publish a lock with exact versions **and hashes** for the tested set, and state the supported range policy.
3. Correct `requires-python` to `>=3.10` and test on the declared minimum.
4. Run one dependency vulnerability scan (e.g. `pip-audit`) against the lock.

## 12. Documentation

| Drift | Location | Required change |
|---|---|---|
| Title and framing are "Phase 0" | `ARCHITECTURE.md:1-7` | Mark it as the architecture of v1.0.0 (or add a current-state preface) |
| Module skeleton lists packages that do not exist (`agent/`, `llm/`, `config/`) and omits real ones (`providers/`, `contracts/`, `capability/`, `findings/`, `review/`) | `ARCHITECTURE.md:729-749` | Replace with the actual package map |
| "Phase 1 implementation scope (not started yet)" | `ARCHITECTURE.md:751-757` | Remove or mark delivered |
| "Configuration … lives in versionable config files" | `ARCHITECTURE.md` §15 | State that policy, registry, limits and rule sets are code-defined in v1.0.0 |
| Package docstring says "Phase 2 … not implemented: Agent Runtime, LLM Abstraction, Tool Layer" | `chanakya/__init__.py` (ships in the wheel) | Update |
| `__version__ = "0.2.0"`; `pyproject` `version = "0.2.0"` (tags are at v0.20.0) | `chanakya/__init__.py`, `pyproject.toml` | Set `1.0.0` together |
| Stale dependency comment ("not-yet-implemented Phase 5.6 step") | `pyproject.toml` | Update |
| README lacks installation, supported Python/OS, API key setup, actual CLI usage, the capability list, approval/review usage, the default allow for read-only without `--require-approval`, and one-tool-per-turn | `README.md` | Add a "Using Chanakya AI" section |
| **Operator data disclosure is missing** (see §14) | `README.md` | Add (required) |
| Threat register not consolidated: T-28–T-33 exist only in `TARGET-MANAGER.md`/`TARGET-AWARE-AGENT-CONTEXT.md`; T-34+ are "candidates" | `docs/THREAT-MODEL.md` | Add them to the register with a final status (§14 of this report) |
| One-tool-per-turn | `docs/AGENT-RUNTIME.md` | ✔ already accurate (updated in `91dca31`) |
| Real Anthropic provider | `README.md`, `ARCHITECTURE.md` §4 | README mentions "the Anthropic provider" only; add model default, endpoint and the key variable |

## 13. Packaging / CLI

Tested from a clean `git archive HEAD` export:

| Step | Result |
|---|---|
| Build | ✔ `pip wheel .` builds `chanakya-0.2.0-py3-none-any.whl`. There is **no `[build-system]` table**, so pip falls back to legacy setuptools, and the build needs network access for setuptools |
| Wheel contents | ✔ all 16 subpackages, including `tools/handlers`; no non-Python data files are needed |
| Install in a fresh venv | ✔ installs, resolving anthropic 1.9.0 (§11) |
| Configure the key | ✔ `ANTHROPIC_API_KEY` (only by reading the source; undocumented) |
| Run the CLI | ⚠ `python -m chanakya.cli --help` works outside the repository, but **there is no `chanakya` console script** (no `[project.scripts]`), although argparse calls the program `chanakya` |
| Read-only investigation / review | ✔ functionally (proven in-repo by the real run; `--review` works from the installed package against the stored workdir) |
| Metadata | ✗ version `0.2.0`; `Requires-Python >=3.9` wrong; no `readme`, `license`, authors, URLs or classifiers; **no LICENSE file in the repository** |

**A clean user can install and run it, but only by knowing `python -m chanakya.cli` and `ANTHROPIC_API_KEY` from the source.** Packaging is not release-grade yet (RP-2 … RP-5).

## 14. Threat Model Final Status

Uses the repository's actual IDs: T-01–T-27 in the `docs/THREAT-MODEL.md` register; T-28–T-33 in the target design docs; T-34–T-65 as THREAT-MODEL candidates. **None is release-blocking.**

| ID | Threat | Final status | Basis / residual |
|---|---|---|---|
| T-01 | Harmful user objective | MITIGATED | Gateway independent of wording; read-only capability set |
| T-02 | Direct prompt injection | RESIDUAL ACCEPTED | A hijacked model can only propose; budgets cap it |
| T-03 | Indirect injection via tool output | PARTIALLY MITIGATED | Data channel, fixed failure codes, turn records; steering within valid output remains |
| T-04 | Malicious MCP tool definitions | MITIGATED (N/A) | No MCP; Registry admin-defined in code |
| T-05 | Malicious MCP server runtime | MITIGATED (N/A) | No MCP; envelope size, schema and time checks apply to handlers |
| T-06 | Hallucination | RESIDUAL ACCEPTED | Evidence-grounded findings; misinterpretation remains |
| T-07 | Overconfident conclusions | PARTIALLY MITIGATED | Agent and rule confidence shown separately; CLI disclaimers |
| T-08 | Step chaining | PARTIALLY MITIGATED | 10-step / 10-call caps; read-only only; no cumulative policy rules |
| T-09 | Parameter manipulation | MITIGATED | Both capabilities take `{}` (closed) |
| T-10 | Privilege escalation | MITIGATED (current scope) | Standard-user, read-only handlers; `ELEVATED` denied |
| T-11 | Arbitrary command execution | MITIGATED | No shell, subprocess or eval anywhere (§4) |
| T-12 | Hostile target | PARTIALLY MITIGATED | As T-03; the target is the operator's own host |
| T-13 | Untrusted file parsing | MITIGATED (N/A) | No file-reading capability; `/proc/net` parsers are strict |
| T-14 | Compromised tool output | PARTIALLY MITIGATED | Stdlib/OS APIs only; schema, not truth |
| T-15 | Policy bypass | MITIGATED | Structural `dispatch()` preconditions; tests; Review flags dispatch without a decision |
| T-16 | Approval bypass | MITIGATED | Four-way approval binding plus investigation binding |
| **T-17** | Approval spoofing | RESIDUAL ACCEPTED | One-time binding ✔. `decided_by` is free-form (`--approver`) and the prompt reads stdin, so approvals can be scripted by whoever controls the session (as in the validation run). Acceptable for a local, single-operator CLI; **document it** (RP-6) |
| **T-18** | Audit/evidence tampering | PARTIALLY MITIGATED | Hash chains, re-verification, risk recomputation, version-downgrade checks; an unkeyed full-chain rewrite by a local attacker remains (documented) |
| T-19 | Fail-open | MITIGATED | Gateway exception → deny; Runtime backstops |
| T-20 | Credential exposure | PARTIALLY MITIGATED | One screening predicate on every sink; pattern-based |
| **T-21** | API key exposure | MITIGATED | Single read, no logging or printing; transport isolated; secret scan clean (§16); key in process memory is inherent |
| **T-22** | Sensitive evidence leakage | PARTIALLY MITIGATED | Git egress mitigated (T-65); host telemetry reaches the provider **by design**; **operator disclosure missing (RP-7)**; no encryption at rest |
| **T-23** | Supply-chain compromise | **PARTIALLY MITIGATED; release preparation** | One declared dependency (plus two undeclared); **no lock or hashes** (RP-1) |
| **T-24** | Dependency vulnerabilities | **PARTIALLY MITIGATED; release preparation** | No scan performed (RP-3); ongoing maintenance after release |
| T-25 | Compromised host | RESIDUAL ACCEPTED | Out of scope by design |
| T-26 | Remote targets | N/A | No remote adapter |
| **T-27** | Resource exhaustion | MITIGATED (current scope) | Step, call, duration and output caps; provider output limit; residual is T-36 |
| T-28 | Target impersonation | MITIGATED (current scope) | `local_host` only; the Gateway re-resolves by id |
| T-29 | Locator scope confusion | N/A | No locators exposed or used |
| T-30 | Stale target info | MITIGATED | Gateway re-reads status each evaluation |
| T-31 | Adapter compromise / SSRF | N/A (current scope) | Local adapter only, no network |
| T-32 | Authorization confusion via target context | MITIGATED | The Gateway is the sole authority |
| T-33 | Cross-investigation context leakage | MITIGATED | Runtime-owned, id-scoped sources |
| T-34 | Host data over-collection to provider | RESIDUAL ACCEPTED | Minimal fields; must be disclosed (RP-7) |
| T-35 | Output as injection carrier | PARTIALLY MITIGATED | As T-03 |
| **T-36** | Hanging capability (non-preemptive timeout) | RESIDUAL ACCEPTED | Both handlers bounded, no blocking I/O; a late result is discarded; preemption is future hardening (NB-1) |
| T-37 | Parsing divergence | MITIGATED | Strict parsers, fail whole |
| T-38 | Registry/handler drift | MITIGATED | Parity test and executor check |
| T-39 | Fabricated finding | MITIGATED | Refs resolved through own history |
| T-40 | Finding text injection/display | MITIGATED | Control characters rejected; escaped output; not fed back |
| **T-41** | Secrets copied into findings | PARTIALLY MITIGATED | Pattern screen; unstructured secrets pass |
| T-42 | Finding-store tampering | PARTIALLY MITIGATED | As T-18 |
| T-43 | Finding as authority | MITIGATED | No reader in policy, approval or dispatch |
| T-44 | Finding flood | MITIGATED | 20 per investigation, bounded |
| **T-45** | Severity steering via category | RESIDUAL ACCEPTED | Closed taxonomy, compatibility, `high` ceiling; the model can still pick the highest *compatible* category |
| T-46 | Risk as authority | MITIGATED | AST import rules |
| T-47 | Fabricated/foreign risk refs | MITIGATED | Batch validation, deterministic ids |
| T-48 | Risk-store tampering | PARTIALLY MITIGATED | Recomputation; full consistent rewrite remains (T-18) |
| T-49 | Rule-set drift | MITIGATED | Versioned, golden-frozen |
| T-50 | False assurance from low ratings | PARTIALLY MITIGATED | Explicit disclaimers; human judgment |
| T-51 | Partial state after risk failure | MITIGATED | Halt plus Review reporting |
| T-52 | Unenforced output contract | MITIGATED | Envelope enforcement; string lengths unbounded (bounded by byte limit) |
| T-53 | Timeout drift | MITIGATED | min(declared, ceiling); residual T-36 |
| T-54 | Unreconstructable authorization history | MITIGATED | Authorization record plus Review |
| T-55 | Silent incomplete investigation | MITIGATED | `INCOMPLETE` reporting |
| T-56 | Rule-set downgrade | MITIGATED | No fallback; recorded-set recomputation |
| T-57 | Unrecorded model influence | MITIGATED | Turn records |
| T-58 | Caller-composed context | MITIGATED | Runtime-owned context |
| T-59 | Environment-controlled destination | MITIGATED | Explicit endpoint plus refusal |
| T-60 | Unscreened success output | MITIGATED (pattern-based) | Screen before Evidence or context |
| T-61 | Unscreened failure text | MITIGATED | Closed vocabulary |
| T-62 | Free-form exception text in records | MITIGATED | Runtime-owned records; Gateway deny reasons are the remaining free-form field (NB-3) |
| T-63 | Environment-controlled transport | MITIGATED | Verified transport; relies on SDK internals, fails closed |
| T-64 | Request body via logger hierarchy | MITIGATED (in-process) | Namespace-wide check |
| T-65 | Durable data in the Git tree | MITIGATED | Placement confinement (§10) |

Totals (65 threats): MITIGATED 43 (including N/A-in-scope), PARTIALLY MITIGATED 15, RESIDUAL ACCEPTED 7, **RELEASE BLOCKING 0**. T-23, T-24 and the T-22 disclosure need release-preparation work, not security fixes.

## 15. Test Results

| Run | Result |
|---|---|
| `pytest -q` (in-repo, Python 3.13.1, anthropic 1.7.0) | **2970 passed**, 0 failed, 0 skipped, 0 xfailed |
| `pytest -q -W error` (in-repo) | **2970 passed**, 0 warnings |
| Security core: gateway, policy rules, dispatch boundary, security invariants, step 3.5 invariants, RT-INV end-to-end, boundary matrix, adversarial integration, registry, envelope, capability model (`-W error`) | 291 passed |
| Provider: single-tool request, SDK security, transport isolation, logging egress, failure hardening, agent turn record, provider boundary (`-W error`) | 389 passed |
| Egress, integrity and data: tool-output screening, failure-path output, runtime-owned errors, audit log, authorization record, review, evidence store, findings, risk provenance, rule sets, workdir placement, terminal approval (`-W error`) | 765 passed |
| Clean-install venv (anthropic 1.9.0 / httpx2 2.13.1, `-W error`, from the `git archive` export) | 2969 passed, 1 environmental failure (needs a real Git repository) |

No test was modified or skipped for this audit. Coverage was not reduced.

## 16. Secret Scan

Patterns: Anthropic key format, any `sk-ant-` token, `x-api-key`, AWS access key and secret assignment, PEM private-key header, GitHub/Slack/Google tokens, JWT, password/secret/token assignment, and the **actual `ANTHROPIC_API_KEY` value** (compared in memory, never printed).

| Scope | Real secret | Notes |
|---|---|---|
| Tracked files at HEAD | **NOT FOUND** | `sk-ant-` matches: 4 synthetic, sentinel-named test constants (`tests/test_agent_turn_record.py`, `test_anthropic_provider_sdk_security.py`, `test_anthropic_single_tool_request.py`, `test_durable_workdir_placement.py`). PEM matches: header lines only, no key material, in screening tests. `password=` matches: screening-test fixtures. `x-api-key`: the header *name* in provider code, docs and tests |
| Full Git history (all commits) | **NOT FOUND** | Same synthetic fixtures only; no real-format Anthropic key; actual key value NOT FOUND |
| Untracked Phase 21 reports | **NOT FOUND** | — |
| `D:\Chanakya-Data` (93 files) | **NOT FOUND** | No key, no `sk-ant-`, no `x-api-key`, no PEM, no tokens |
| AWS / GitHub / Slack / Google / JWT | **NOT FOUND** anywhere | — |

The workdir does contain host telemetry (hostname, IPv6 addresses, process names, ports). It is investigation data, not a credential, and it stays outside the repository.

## 17. Remaining Release Preparation

| ID | Issue | Impact | Required Before v1.0.0 | Classification |
|----|-------|--------|------------------------|----------------|
| RP-1 | No dependency lock or hashes; `httpx2` and `truststore` imported directly but undeclared; a clean install resolves untested versions (anthropic 1.9.0) | Unreviewed dependency changes (T-23); transport verification may fail closed on a future SDK | **Yes** | RELEASE PREPARATION |
| RP-2 | `requires-python = ">=3.9"` but dependencies require `>=3.10`; only 3.13 tested | Misleading install metadata | **Yes** | RELEASE PREPARATION |
| RP-3 | No dependency vulnerability scan (T-24) | Unknown CVE exposure at release | **Yes** (one scan against the lock) | RELEASE PREPARATION |
| RP-4 | `pyproject`/`__version__` at `0.2.0`; no `[build-system]`; no `[project.scripts]` (`chanakya` command absent); no readme, license, authors or classifiers metadata; `pytest` not declared as a test extra | Not a release-grade package | **Yes** | RELEASE PREPARATION |
| RP-5 | No LICENSE file (owner's choice) | Legal usability of a public release | **Yes** | RELEASE PREPARATION |
| RP-6 | README lacks install, Python/OS support (Linux/Windows; macOS fails closed for ports), API key setup, CLI usage, capability list, approval/review usage, read-only default-allow without `--require-approval`, one-tool-per-turn, free-form approver identity (T-17) | Operators cannot use it safely without reading source | **Yes** | RELEASE PREPARATION |
| RP-7 | **Operator data disclosure missing** (§ below) | Uninformed egress of host telemetry to a third party (T-22/T-34) | **Yes** | RELEASE PREPARATION |
| RP-8 | `ARCHITECTURE.md` drift (Phase 0 framing, nonexistent `agent/`/`llm/`/`config/`, "not started yet", config-file claim); stale `chanakya/__init__.py` docstring; stale `pyproject` comment | Misleading architecture docs | **Yes** | RELEASE PREPARATION |
| RP-9 | Threat register not consolidated (T-28–T-33 outside `THREAT-MODEL.md`; T-34+ still "candidate"; no final status) | Incomplete security record | **Yes** (can reuse §14) | RELEASE PREPARATION |
| NB-1 | Non-preemptive step timeout (T-36) | A hung handler blocks the CLI; current handlers are bounded | No | NON-BLOCKING RESIDUAL |
| NB-2 | Evidence store uses check-then-replace, not exclusive create | Theoretical same-id race; one concurrent investigation | No | FUTURE HARDENING |
| NB-3 | Gateway deny `reason` is free-form (may carry exception or schema text) | Screened audit text only; never reaches the model | No | FUTURE HARDENING |
| NB-4 | Approver identity free-form; approvals readable from piped stdin (T-17) | Local operator can script approvals | No (document in RP-6) | NON-BLOCKING RESIDUAL |
| NB-5 | Unkeyed audit chain; full consistent rewrite undetected (T-18) | Local attacker with write access | No | NON-BLOCKING RESIDUAL |
| NB-6 | Pattern-based credential screening (T-20/T-41/T-60) | Novel secret formats pass | No | NON-BLOCKING RESIDUAL |
| NB-7 | Severity steering within compatible categories (T-45) | Ratings bounded by `high` ceiling | No | NON-BLOCKING RESIDUAL |
| NB-8 | Transport verification uses private SDK attributes | Fails closed on SDK change (availability) | No (mitigated by RP-1 pinning) | NON-BLOCKING RESIDUAL |
| NB-9 | No encryption or permission hardening at rest (T-22) | Local readers | No (document in RP-7) | NON-BLOCKING RESIDUAL |
| NB-10 | Real-provider E2E validated on Windows only; Linux path fixture-tested | Platform confidence | No (recommended smoke test) | RELEASE PREPARATION (optional) |
| NB-11 | Two lightweight early tags | Cosmetic | No | FUTURE HARDENING |
| FF-1 | MCP, remote targets, state-changing capabilities, resume, preemptive sandboxing, CI pipeline | Out of v1.0.0 scope | No | FUTURE FEATURE |

### Required operator disclosure (RP-7), checked against the implementation

The release README must state:

- **What is collected:**
  - OS name, release, version, platform string, architecture, **hostname**, Python version, CPU count and container flag;
  - every listening TCP/UDP socket: local address (which can include **public IPv6/IPv4 addresses**), port, **PID** and **process executable base name**.
  - No process arguments, environment variables, file contents or credentials are collected.
- **Where it goes:**
  - both capabilities are `model_egress: allowed`, so this screened output, the **objective text** and the target description are **sent to the configured Anthropic endpoint** (`https://api.anthropic.com`, default model `claude-opus-5-5`) as model context;
  - Anthropic's data-handling terms apply.
- **Where it is stored:**
  - under `--workdir` (default `.chanakya` in the current directory; recommended outside any repository): objectives, Evidence payloads, Findings, risk ratings and the Audit Log;
  - the data is not encrypted at rest;
  - a Runtime-owned `.gitignore` keeps the workdir out of Git.
- **Credentials:**
  - `ANTHROPIC_API_KEY` is read once and sent only as the API header;
  - it is not intended to appear in Evidence, Findings, audit records or model context;
  - tool output is screened for credential-shaped content and rejected on a hit, and that screening is pattern-based.

## 18. Release Blockers

**None.** Each blocker criterion was checked:

| # | Criterion | Result |
|---|---|---|
| 1 | Gateway bypass | none found (§3) |
| 2 | Unauthorized capability execution | none |
| 3 | Arbitrary code or shell execution | none (§4) |
| 4 | Credential leakage | none (§7, §16) |
| 5 | Model/tool output as trusted instructions | none; data channel only, and CT-INV-3 intact |
| 6 | Silent Evidence/Audit compromise | none; tampering is detected apart from the documented full-rewrite residual |
| 7 | Core investigation non-functional | no; the real E2E completed (§6) |
| 8 | Reachable serious failure with current capabilities | none |
| 9 | Unreliable verification | no; Review consistent, 0 anomalies |

## 19. Final Release Decision

**RELEASE PREPARATION REQUIRED.**

The implementation is security-ready for a v1.0.0 whose scope is a local, read-only, policy-gated, audited investigation. The remaining work is packaging, dependency locking and documentation (RP-1 … RP-9). None of it needs a new security phase.

## 20. Recommended Release Sequence

1. **Dependencies (RP-1, RP-2, RP-3):**
   - declare `anthropic`, `httpx2` and `truststore` directly;
   - set `requires-python = ">=3.10"`;
   - choose the supported versions (the tested 1.7.0 set, or 1.9.0 after the full suite passes on it);
   - produce a hashed lock (e.g. `pip-compile --generate-hashes` or `uv lock`);
   - run `pip-audit` against the lock;
   - run the full suite (`-W error`) on the minimum and latest supported Python.
2. **Packaging (RP-4, RP-5):**
   - add `[build-system]` and `[project.scripts] chanakya = "chanakya.cli.main:main"` (wrapped with `sys.exit` semantics);
   - add `readme`, `license`, authors, URLs, classifiers and a `test` extra;
   - add the LICENSE file;
   - set version `1.0.0` in `pyproject.toml` and `chanakya/__init__.py`.
3. **Documentation (RP-6, RP-7, RP-8, RP-9):**
   - README: install, usage, the full data disclosure, supported platforms, approval semantics and one-tool-per-turn;
   - `ARCHITECTURE.md`: current-state corrections and package map;
   - `chanakya/__init__.py` docstring;
   - consolidated threat register with the §14 statuses.
4. **Clean-room verification:**
   - build the wheel;
   - install it with the lock in a fresh venv, outside the repository;
   - run the `chanakya` console command against the real provider with `--require-approval` and a workdir outside any repository;
   - run `chanakya --review <id>`;
   - optionally repeat on Linux (NB-10).
5. Run the full suite in-repo (`pytest -q` and `-W error`).
6. Commit the release preparation, commit this audit report, and create the annotated `v1.0.0` tag.
7. Publish to GitHub only after steps 1–6. Re-run the §16 secret scan on the exact tree being pushed.
