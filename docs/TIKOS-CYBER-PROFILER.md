# Tikos Cyber Profiler — Injection Screen on Tool Output (Design)

Status: **design proposal, not implemented.** No source, test, contract or
dependency file is changed by this document. Implementation starts only after
this design is approved.

Decision recorded: Tikos Cyber Profiler is integrated as an **injection screen
on tool output** (not as a Target Adapter and not as an agent-callable
capability).

---

## 1. Why

The consolidated threat register leaves **T-03** (indirect prompt injection
through tool/target output) and **T-35** (capability output as an injection
carrier) at **PARTIALLY MITIGATED**, residual Medium: "the model can still be
steered within valid output". Every control today is structural (data-channel
framing, capability allowlisting, evidence-cited findings, turn records). There
is no control that looks at *whether a given output is trying to inject*.

The Tikos Cyber Profiler is an external classifier that takes a text and
returns a prompt-injection / cyber-threat verdict. Placed on the path from
Evidence to model context, it adds a **preventive** control for T-03/T-35:
output classified as a threat stays as Evidence (raw fact is never lost) but
is withheld from the model.

It is deliberately *not* a capability the model can call: the model would
decide when to screen, which is exactly what an injected model would avoid.

## 2. The external service (as documented)

Source: `https://tikos.readme.io/reference/cyber-profiler` and linked pages,
read 2026-11-23.

| Item | Value |
|---|---|
| Endpoint | `POST https://cyberprofiler.tikos.uk/analyse` |
| Request body | `{"prompt": "<text, length >= 1>"}` (`authToken` in body is optional; **not used** here) |
| Auth | API key ("auth token") as `Authorization: Bearer <key>` |
| Liveness / readiness | `GET /` → `ok`; `GET /health` → `ready` (200) or 503. No auth |
| Errors | 401 key missing/unknown · 403 key disabled or **source IP not permitted** · 422 invalid body · 502 classifier error · 503 cannot authenticate/record |
| 200 body | **Not published.** Examples show `verdict` (`benign`/`threat`), `threat_probability`, `confidence.refer_to_analyst`, `payloadId` |
| Rate limits | Not documented |
| Mode | Synchronous; no job polling |
| Retention | Landing page: "no input data retained". `payloadId` exists for support, so per-request records exist server-side |
| Key issuance | Request access at tikos.tech/cyber-profiler → TIKOS platform → Cyber Profiler → Configuration |

Gaps that the design must treat as unknowns: response schema, maximum
`prompt` length, rate limits, retention period/location.

## 3. Where it sits

Current flow (ARCHITECTURE.md, Phase 15):

```
ToolResult → envelope (JSON, size, schema) → credential screen → Evidence → egress gate → model context
```

Proposed flow:

```
ToolResult → envelope → credential screen → Evidence
           → [injection screen: Tikos] → egress gate → model context
```

- **After the credential screen.** Only output that has already passed
  `screen_tool_output` is ever sent to Tikos, so credential-shaped content
  never leaves the host on this path.
- **After Evidence.** Evidence is written exactly as today. The verdict never
  changes, redacts or deletes Evidence.
- **Before the egress gate.** The screen can only **downgrade** a result's
  effective egress from `allowed` to `evidence_only`. It can never upgrade.
  A capability declared `evidence_only` is never sent to Tikos (nothing to
  decide, and no unnecessary egress).
- **Successful output only.** Failure results already carry only fixed
  Runtime-owned codes (Phase 16) and are not screened.

The single check point is `AgentLoopController` where context sources are
built (today `_record_context_source`, which already returns early on
sensitive-output rejection and non-`allowed` egress). The injection verdict
becomes one more early return there.

## 4. Behavior

### 4.1 Request

- Text sent: the canonical JSON (`chanakya.evidence.hashing.canonical_bytes`)
  of the Evidence `output`, decoded as UTF-8. Exactly the bytes that would
  have become model context, nothing more (no investigation id, objective,
  target identity or host name outside the output itself).
- One request per eligible result. No batching, no parallelism (consistent
  with one tool call per turn, CT-INV-3).
- Bounded timeout (proposal: 10 s), **no retries**, no redirects.

### 4.2 Verdict mapping (closed)

| Tikos outcome | Screen result | Effective egress |
|---|---|---|
| 200, `verdict == "benign"`, `refer_to_analyst` false | `INJECTION_SCREEN_PASSED` | unchanged (`allowed`) |
| 200, `verdict == "threat"` | `INJECTION_SUSPECTED` | `evidence_only` |
| 200, `refer_to_analyst` true | `INJECTION_REFERRED` | `evidence_only` |
| 200 with any other shape / unknown verdict | `INJECTION_UNSCREENABLE` | unchanged (advisory, §4.3) |
| 401 / 403 / 422 / 502 / 503 / timeout / TLS or transport error | `INJECTION_SCREEN_UNAVAILABLE` | unchanged (advisory, §4.3) |
| Output larger than the screen's byte bound | `INJECTION_UNSCREENABLE` | unchanged (advisory, §4.3) |

Parsing is strict: a closed set of expected keys and types; unknown or
missing fields fail to `INJECTION_UNSCREENABLE`. `threat_probability` is
recorded but **never** used as a threshold by Chanakya (the provider's own
verdict decides; no tunable numbers that drift).

### 4.3 Failure mode — advisory (decided)

When the screen is enabled and Tikos cannot give a usable verdict
(`INJECTION_SCREEN_UNAVAILABLE` or `INJECTION_UNSCREENABLE`), the screen is
**advisory**: effective egress is unchanged (`allowed`) and the failure is
recorded in the audit log, the context manifest and the CLI summary. An
outage, rate limit or unexpected response never blocks an investigation.

Only a usable verdict of `threat` or `refer_to_analyst` withholds output from
the model. Consequence for T-68: an attacker who can make Tikos unavailable
(or produce an unscreenable output) gets the pre-screen behavior, which is
exactly today's T-03 baseline; Review shows every such unscreened context
entry.

### 4.4 Enabling

- Off by default. Enabled per run with a CLI flag (proposal:
  `--injection-screen tikos`).
- Enabled without `TIKOS_API_KEY` set → the CLI refuses to start (fixed
  message, key name only).
- The CLI prints, before the first turn, that eligible tool output will be
  sent to `cyberprofiler.tikos.uk` (operator disclosure, same spirit as the
  README "Operator data disclosure").

### 4.5 Authority (unchanged invariants)

Like the credential screen and `model_egress` (NX-INV-6), the verdict carries
**no authority**:

- the Policy Gateway, approval and dispatch never read it;
- it does not change risk, findings or the capability envelope;
- it is never shown to the model (the model is not told that an output was
  withheld, or why).

## 5. Transport and key handling

- **No Tikos SDK.** The `tikos` package is not added. Requests go through an
  explicitly built `httpx2` client with the Phase 18 transport policy:
  `trust_env=False`, system trust store, redirects off, no retries, bounded
  timeout, verified at construction and before every send (reuse
  `chanakya.providers.transport` verification). This avoids a new dependency
  (T-23/T-24) and the environment-controlled transport problem (T-63).
- **Pinned endpoint.** `https://cyberprofiler.tikos.uk/analyse`, fixed in
  code; not configurable from the environment or CLI.
- **Key.** Read once from `TIKOS_API_KEY` in `main()` (the CLI stays the only
  reader of credentials), passed to the screen client, sent only as
  `Authorization: Bearer`. Never in the body, never logged, displayed, stored,
  or part of an error. Logging-egress checks (Phase 19) extended to the screen
  client's logger namespace.
- **Errors.** Fixed codes only; no response text, status reason, header or
  `payloadId` content is fed back to the model.

## 6. Records and contracts

Proposed additions (contract versions bump accordingly):

- **Audit event** `injection_screened` per eligible result: `tool_result_id`,
  `evidence_id`, `content_hash` sent, screen provider id
  (`tikos-cyber-profiler`), screen policy version
  (`chanakya-injection-screen/1.0.0`), result code (§4.2), HTTP status class,
  and `payloadId` if present (for support correlation).
- **Context manifest** entries record the injection screen version and result
  for each context entry when the screen is enabled.
- **Review** verifies: no context entry exists for a result whose screen
  result is `INJECTION_SUSPECTED` or `INJECTION_REFERRED` (when the run had
  the screen enabled); every context entry has a screen record; the
  `content_hash` sent matches the Evidence. Unscreened entries (advisory
  failures) are listed, not treated as anomalies.
- **CLI summary** shows counts per screen result. Never the screened content.

## 7. Threat-model additions

New trust boundary:

| ID | Boundary | Concern |
|---|---|---|
| TB-8 | Runtime ↔ injection-screen provider (network) | Tool output leaves the host to a second third party; provider-side compromise, MITM, or misclassification |

New candidate threats:

- **T-66 — Tool-output egress to the screen provider** (extends T-22, T-34).
  Host telemetry and HTTP bodies reach Tikos. *Controls:* only
  credential-screened output, only `allowed`-egress capabilities, opt-in flag,
  operator disclosure, pinned host. *Residual:* accepted and disclosed, as
  for the LLM provider.
- **T-67 — Screen-provider API key exposure** (mirrors T-21). *Controls:* as
  §5.
- **T-68 — Screen evasion / false negative.** An injection classified
  `benign` still reaches the model. *Controls:* all existing T-03 controls
  remain; the screen is additive. *Residual:* T-03 stays PARTIALLY MITIGATED
  (lower likelihood), never MITIGATED on the strength of a classifier.
- **T-69 — Screen as denial of context** (false positives, outage, rate
  limiting, or an attacker making outputs look like threats). *Effect:* a
  false positive withholds context; an outage does not (advisory mode, §4.3).
  No unsafe action results either way. *Controls:* counts per screen result
  in the CLI summary and Review.
- **T-70 — Forged or malformed screen response.** *Controls:* verified
  transport (no proxy/CA from environment), strict closed parsing, unknown →
  unscreenable.
- **T-71 — Screen verdict treated as authority.** *Controls:* §4.5, with
  tests that the Gateway/approval/dispatch/risk modules import nothing from
  the screen.

## 8. Tests (planned)

- Verdict mapping table (§4.2), one test per row, using an injected fake
  client; no network in the default test suite.
- Strict parser: unknown keys, wrong types, missing verdict → unscreenable.
- Egress: a `threat` result never becomes a context source; Evidence is
  unchanged; `evidence_only` capabilities are never sent.
- Credential-shaped output is rejected before the screen and never sent.
- Transport verification for the screen client (mirrors
  `test_provider_transport_isolation.py`).
- Key never in body, logs, audit records, errors or CLI output.
- Authority: no import of the screen from policy, approval, dispatch, risk.
- Advisory: an unavailable/unscreenable result still becomes a context
  source and is recorded as unscreened.
- Review detects a context entry for a `threat`/`referred` result, or one
  with no screen record.
- Optional live smoke test behind an explicit marker and `TIKOS_API_KEY`,
  skipped by default.

## 9. Decisions and remaining questions

Decided by the operator (2026-11-23):

1. **Failure mode: advisory.** If Tikos is unavailable, output still reaches
   the model (§4.3).
2. **Delivery:** local working copy first, then pushed to GitHub.
3. **API key:** obtained by the operator from tikos.tech/cyber-profiler and
   set as `TIKOS_API_KEY` in the operator's environment.

Proposed defaults, unless the operator says otherwise:

4. Auth via `Authorization: Bearer` (not `authToken` in the body).
5. The operator's objective is not screened in this phase (T-02); it is
   operator-authored and already credential-screened.

To confirm with Tikos once a key exists: maximum `prompt` length, rate
limits, response schema, retention of request records, and whether the
source-IP allowlist (403) needs the operator's IP registered.
