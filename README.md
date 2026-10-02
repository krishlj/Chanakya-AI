# Chanakya AI

Chanakya AI is an AI-assisted security investigation tool for **authorized,
defensive** use. You give it an objective in plain language; a Claude model
(through the Anthropic API) proposes read-only observations of the local host;
Chanakya decides, enforces, records and verifies everything around that model.

Version 1.1.0 investigates **the local host only**, with **three read-only
capabilities** (two host observers and one approval-gated local HTTP probe),
from a command-line interface.

> Use Chanakya AI only on systems you own or are authorized to investigate.

**Quick links:** [Chanakya AI in Action](#chanakya-ai-in-action) ·
[Case studies](docs/README.md#case-studies) ·
[Architecture](#architecture) ·
[Documentation](docs/README.md) ·
[Installation](#installation) ·
[Development](#development-and-testing)

## Contents

1. [Chanakya AI in Action](#chanakya-ai-in-action)
2. [Why this matters](#why-this-matters)
3. [Public vs private investigation data](#public-vs-private-investigation-data)
4. [Architecture](#architecture)
5. [Security model](#security-model)
6. [Evidence and auditability](#evidence-and-auditability)
7. [Capabilities](#capabilities)
8. [Scope of v1.1.0](#scope-of-v110)
9. [Project evolution](#project-evolution)
10. [Documentation](#documentation)
11. [Requirements](#requirements)
12. [Installation](#installation)
13. [API key](#api-key)
14. [Command-line usage](#command-line-usage)
15. [A safe first investigation](#a-safe-first-investigation)
16. [Human approval](#human-approval)
17. [Operator data disclosure](#operator-data-disclosure)
18. [Development and testing](#development-and-testing)
19. [Security limitations](#security-limitations)
20. [License](#license)

## Chanakya AI in Action

Two real investigations run with Chanakya AI v1.1.0 against the real
Anthropic API.

### 1. Local Host Security Investigation

> Chanakya AI performed a read-only investigation of a Windows host,
> discovering platform information and listening services while producing
> evidence, findings, deterministic risk assessments, and a durable audit
> trail.

| | |
|---|---|
| **Target** | The local Windows 11 host (`local-host`) |
| **Capabilities** | `observe_local_host_environment`, `list_listening_ports` |
| **Control** | `--require-approval`: both capabilities approved by the operator, one per model turn |
| **Observed** | Platform facts; SMB/RPC/NetBIOS listeners beyond loopback; a Docker-published TCP 3000; UDP name-resolution and discovery protocols; global IPv6 listeners |
| **Results** | 2 Evidence records · 8 Findings · 8 rule-based risk assessments (3 medium, 2 low, 3 informational) · 38 hash-chained audit records |
| **Review** | `completed`, audit chain verified, consistent, 0 anomalies |

**Read the case study:** [docs/case-studies/LOCAL-HOST-SECURITY-INVESTIGATION.md](docs/case-studies/LOCAL-HOST-SECURITY-INVESTIGATION.md)

> *Sanitized portfolio report — raw host data is intentionally excluded.*

### 2. Local Web Security Investigation

> Chanakya AI investigated a locally hosted OWASP Juice Shop instance,
> collected HTTP evidence, identified a wildcard CORS configuration, and
> supported a manually performed remediation.

| | |
|---|---|
| **Target** | OWASP Juice Shop training instance on `127.0.0.1:3000` |
| **Capability** | `http_probe_local` (one benign, approval-gated HTTP `GET` per run) |
| **Observed** | **Wildcard CORS configuration identified** (`Access-Control-Allow-Origin: *`) |
| **Remediation** | Performed **manually by the operator** in the Juice Shop source (explicit local-origin allowlist). Chanakya v1.1.0 does not modify code. |
| **Verification boundary** | BEFORE state confirmed with evidence. AFTER runtime verification was **not completed**: the remediated Docker image/container was not successfully built and started. |

The CORS observation is a configuration finding, not a confirmed exploitable
vulnerability; exploitability depends on application-specific conditions that
were not tested.

**Read the case study:** [docs/case-studies/LOCAL-WEB-SECURITY-ASSESSMENT-JUICE-SHOP.md](docs/case-studies/LOCAL-WEB-SECURITY-ASSESSMENT-JUICE-SHOP.md)

## Why this matters

Chanakya AI is not an LLM that receives unrestricted host access and executes
commands. The model only proposes; everything else is deterministic code that
decides, enforces and records. The v1.1.0 workflow is:

```
Objective
   ↓
Model proposes
   ↓
Runtime validates
   ↓
Policy Gateway controls
   ↓
Registered capability executes
   ↓
Output is screened
   ↓
Evidence is recorded
   ↓
Findings cite evidence
   ↓
Risk is calculated deterministically
   ↓
Audit trail is recorded
   ↓
Review verifies the investigation
```

The **local-host case study** demonstrates this architecture against real host
observations. The **Juice Shop case study** demonstrates the same architecture
against a controlled local web application.

## Public vs private investigation data

Investigations collect sensitive, environment-specific data (see
[Operator data disclosure](#operator-data-disclosure)). This repository only
ever contains the public half.

| Public (in this repository) | Private (never in this repository) |
|---|---|
| Sanitized case studies | The raw investigation workdir |
| Architecture and methodology | Raw Evidence records and payloads |
| Capabilities and security controls | Complete audit records |
| Anonymized evidence and record examples | Actual hostnames |
| Investigation workflow | Actual IP addresses |
| Lessons learned | Process ids (PIDs) |
| | Detailed local socket inventories |
| | Environment-specific process information |

**Keep raw investigation data outside the Git repository.** The project
convention is a dedicated directory such as `D:\Chanakya-Data` on Windows (or
`~/chanakya-data` on Linux), passed with `--workdir`. Chanakya also writes a
`.gitignore` into every workdir as defence in depth, but that does not protect
against `git add -f`, other version-control systems, or backup/sync tools.

When publishing a case study, summarize rather than copy: replace host-specific
values with neutral labels such as `[HOSTNAME REDACTED]`,
`[IP ADDRESS REDACTED]`, `[PID REDACTED]`, `[PROCESS NAME REDACTED]` and
`[EVIDENCE-ID-REDACTED]`, never with made-up values, and do not publish
screenshots that show any of them.

## Architecture

Chanakya is a layered system in which safety is structural rather than
prompted. The model sits behind an LLM abstraction and a custom agent loop; it
never dispatches tools itself.

| Layer | Role |
|---|---|
| CLI | Accepts the objective, prompts for approval, runs read-only review |
| Agent Runtime | Owns the investigation loop, turn validation, budgets and terminal records |
| LLM abstraction / Anthropic provider | Fixed endpoint, isolated transport, hashed requests, one tool call per turn |
| Target Manager | Resolves `local-host`; rejects anything out of scope |
| Policy Gateway | The only allow / deny / require_approval authority |
| Security Tool Registry | The closed set of registered capabilities and their envelopes |
| Tool Layer | Read-only local handlers with schema-checked output |
| Evidence Store | Hashed, append-only tool output |
| Findings / Risk Engine | Evidence-cited findings; deterministic, versioned risk rules |
| Audit Log | Durable, hash-chained record of every decision |

The full specification, including trust boundaries, data flow and the
package map, is in [`ARCHITECTURE.md`](ARCHITECTURE.md).

## Security model

**The model proposes; it never executes and never authorizes.** Every model
reply passes through the same chain before anything runs:

```
Model reply
  → Runtime turn validation (at most one tool call per turn)
  → ToolRequest intake (schema validation)
  → Policy Gateway (the only allow / deny / require_approval authority)
  → Security Tool Registry (only registered capabilities exist)
  → Capability envelope (parameters, timeout, output size and schema)
  → Human approval, when the Gateway requires it
  → Tool execution (read-only local handler)
  → Tool-output screening (credential-shaped content is rejected)
  → Evidence (hashed, append-only)
  → Findings (must cite this investigation's Evidence)
  → Risk assessment (deterministic, versioned rules; no model input)
  → Durable, hash-chained audit log
  → Review (read-only verification)
```

- **One action per turn.** Chanakya asks the Anthropic API for at most one tool
  call per turn, and the Runtime independently rejects any reply that contains
  more than one tool call. Nothing is run from such a reply. Chanakya never
  runs several tools from one model turn, and never runs tools in parallel.
- **Fail closed.** A Gateway error, an unknown capability, an out-of-scope
  target, a malformed reply or an unscreenable output results in a denial or a
  recorded rejection, never in an action.
- **Untrusted data stays data.** Tool output reaches the model only in a
  separate data channel, never as instructions.

## Evidence and auditability

Every capability output becomes a hashed, append-only Evidence record; every
finding must cite Evidence from the same investigation; every risk rating is
computed by versioned rules; and every step is written to a hash-chained
audit log that can be verified later without calling the model.

### Reviewing an investigation

```
chanakya --review INVESTIGATION_ID --workdir D:\Chanakya-Data
```

Review reads the durable records and verifies them:

- the audit hash chain;
- the consistency of requests, policy decisions, approvals, dispatches and
  model turns;
- Evidence integrity and screening;
- that every finding cites evidence;
- that every risk rating recomputes under its recorded rule set.

It reports `status`, `audit chain`, `consistency` and any anomalies. Review is
read-only: it reads no API key, calls no model, runs no tool and creates no
files. It exits 0 only when the record is verified and consistent.

### Where data is stored

Everything durable is written under `--workdir`:

| Path | Contents |
|---|---|
| `audit/<investigation_id>/` | Hash-chained audit log: objective, submitter, each model turn's context manifest and outcome (including the model's explanation text when it passes screening), proposed capability and parameters, policy decisions, approvals, dispatches, provider identity and request hashes |
| `evidence/<investigation_id>/` | Evidence records and their full tool-output payloads |
| `findings/<investigation_id>/` | Findings (model-written text and cited evidence ids) |
| `risk/<investigation_id>/` | Rule-based risk assessments |
| `.gitignore` | Created by Chanakya; excludes everything in the workdir from Git |

- Chanakya creates that `.gitignore` before writing anything and refuses to
  run if it has been altered. This protects against `git add`, not against
  `git add -f`, other version-control systems, or backup/sync tools.
- The data is **not encrypted** and Chanakya does not change file permissions.
  Protect the workdir as you would any sensitive host inventory.
- Records are append-only. Chanakya never edits or deletes them; delete an
  investigation's directories yourself when you no longer need them.

## Capabilities

The complete v1.1.0 set is registered in `chanakya/registry/bootstrap.py`. No
other capability can be requested: anything unregistered is denied by the
Policy Gateway.

| Capability | What it does | Class | Target | Parameters | Timeout | Max output |
|---|---|---|---|---|---|---|
| `observe_local_host_environment` | Coarse OS/platform facts through Python's standard library | read-only | local host | none | 10 s | 65,536 bytes |
| `list_listening_ports` | Listening TCP/UDP sockets from the kernel socket tables (Linux `/proc/net`; Windows `GetExtendedTcpTable`/`GetExtendedUdpTable`) | read-only | local host | none | 15 s | 60,000 bytes |
| `http_probe_local` | One bounded HTTP `GET` to a service on `127.0.0.1`, returning a bounded response snapshot (status, capped headers, capped body snippet) | read-only (active probe, P2) | local host (`127.0.0.1` only) | `port` (1-65535), `path` (absolute) | 5 s | 60,000 bytes |

The first two run with the privileges of the account running Chanakya (use a
non-administrator account) and make no network connection. `http_probe_local`
is the one active capability: it makes a single loopback HTTP request through
the standard library `http.client`, follows no redirects, and **requires human
approval** on every call. Its connection host is the hard-coded literal
`127.0.0.1` — never a parameter — so no request can leave localhost. None of
the three start a subprocess or run a shell. Every output must match a closed
schema; anything else is rejected and never becomes Evidence.

## Scope of v1.1.0

Supported:

- The local host as the only target.
- Three read-only capabilities: `observe_local_host_environment`,
  `list_listening_ports` and `http_probe_local` (see
  [Capabilities](#capabilities)).
- Anthropic as the only model provider.
- Terminal approval, durable evidence/findings/risk/audit records, and
  read-only review.

Not supported in v1.1.0: shell or arbitrary command execution, state-changing
actions, remote targets, MCP servers, running more than one tool per turn,
remediation or recommendations, resuming an interrupted investigation, and any
web interface or API.

## Project evolution

Chanakya was built in small, tagged phases, each adding one control or
capability and its tests.

| Release / tag | Milestone |
|---|---|
| `v0.1-foundation` | Architecture, contracts and threat model |
| `v0.2` – `v0.4` | Security control plane, Agent Runtime, target and environment intelligence |
| `v0.5.x` | Tool layer, Evidence contract and store, payload integrity, Anthropic provider and transport hardening, target-aware context |
| `v0.6.0` – `v0.7.0` | Durable audit log; human approval and CLI |
| `v0.8.0` | `list_listening_ports` capability |
| `v0.9.0` – `v0.10.0` | Evidence-grounded findings; deterministic risk assessment |
| `v0.11.0` – `v0.14.0` | Capability execution envelope, authorization record and review, versioned risk rules, durable agent-turn records |
| `v0.15.0` – `v0.20.0` | Tool-output screening and egress control, failure-path output control, provider environment isolation, egress logging, workdir confinement |
| **`v1.0.0`** | First release: local host investigation with two read-only capabilities |
| **`v1.1.0`** | Controlled local web security: approval-gated `http_probe_local`, local XSS training lab |

Release validation, audit and engineering reports are indexed in
[`docs/README.md`](docs/README.md).

## Documentation

The full documentation index is **[`docs/README.md`](docs/README.md)**: case
studies, design specifications, release and validation reports, engineering
reports and labs.

Start here:

- [Local Host Security Investigation](docs/case-studies/LOCAL-HOST-SECURITY-INVESTIGATION.md)
  (sanitized case study)
- [Local Web Security Assessment: OWASP Juice Shop](docs/case-studies/LOCAL-WEB-SECURITY-ASSESSMENT-JUICE-SHOP.md)
  (case study)
- [`ARCHITECTURE.md`](ARCHITECTURE.md): architecture, including
  "Implementation status at v1.1.0"
- [`docs/THREAT-MODEL.md`](docs/THREAT-MODEL.md): threat model and the
  consolidated threat register

## Requirements

- **Python 3.10 or later.** Tested on CPython 3.10, 3.11, 3.12 and 3.13.
- **Operating system.**
  - **Windows:** fully supported. The end-to-end release validation ran against
    the real Anthropic API on Windows 11.
  - **Linux:** supported by all three capabilities (`list_listening_ports` reads
    `/proc/net`). Linux support is covered by fixture-based tests; no live
    end-to-end run on Linux is part of the v1.1.0 validation.
  - **Other platforms (for example macOS):** `list_listening_ports` refuses to
    run (the step fails closed); `observe_local_host_environment` and
    `http_probe_local` work.
- **An Anthropic API key** and direct HTTPS access to `https://api.anthropic.com`.
  HTTP proxies are not supported (see [API key](#api-key)).

## Installation

Chanakya pins its dependencies in two hashed lock files:

| File | Contents |
|---|---|
| `requirements.lock` | Runtime dependencies, exact versions, sha256 hashes |
| `requirements-test.lock` | Runtime plus test dependencies |

Install the locked dependencies first with `--require-hashes`, then install
Chanakya itself with `--no-deps`, so that nothing unpinned is pulled in.

Create and activate a virtual environment (from the repository root):

```
python -m venv .venv
```

- Windows (PowerShell): `.venv\Scripts\Activate.ps1`
- Windows (cmd): `.venv\Scripts\activate.bat`
- Linux: `source .venv/bin/activate`

### From a source checkout

```
python -m pip install --require-hashes -r requirements.lock
python -m pip install --no-deps .
```

### From a built wheel or source distribution

To build a wheel yourself from a checkout:

```
python -m pip wheel --no-deps -w dist .
```

Then, with the release's `requirements.lock`:

```
python -m pip install --require-hashes -r requirements.lock
python -m pip install --no-deps dist/chanakya-1.1.0-py3-none-any.whl
```

A source distribution (`chanakya-1.1.0.tar.gz`) installs the same way and ships
both lock files.

### Check the installation

```
chanakya --help
python -c "import chanakya; print(chanakya.__version__)"
python -m pip check
```

The version is `1.1.0`. `python -m chanakya.cli` is equivalent to `chanakya`.

## API key

Chanakya reads the Anthropic API key from one environment variable,
`ANTHROPIC_API_KEY`, once at start-up.

Windows (PowerShell):

```
$env:ANTHROPIC_API_KEY = "YOUR_ANTHROPIC_API_KEY"
```

Linux:

```
export ANTHROPIC_API_KEY="YOUR_ANTHROPIC_API_KEY"
```

- Never commit the key to Git or write it into a file inside the repository.
  Set it in your shell session or through your operating system's secret
  store.
- Chanakya sends the key only in the API request header to
  `https://api.anthropic.com`. It does not print, log or store it.
- Without the key, Chanakya exits with code 2 and creates nothing.

The provider endpoint is fixed. Chanakya refuses to start (exit code 2) while
any of these environment variables is set, because they could redirect or
intercept provider traffic. Only the names are checked; values are never read.

- `ANTHROPIC_BASE_URL`, `ANTHROPIC_CUSTOM_HEADERS`, `ANTHROPIC_PROFILE`,
  `ANTHROPIC_AUTH_TOKEN`, `ANTHROPIC_LOG`
- `HTTPS_PROXY`, `HTTP_PROXY`, `ALL_PROXY`, `NO_PROXY` (and their lower-case
  forms)
- `SSL_CERT_FILE`, `SSL_CERT_DIR`, `NETRC`

TLS is verified against the operating system's trust store.

## Command-line usage

```
chanakya [OPTIONS] "OBJECTIVE"
chanakya --review INVESTIGATION_ID [--workdir WORKDIR]
```

| Option | Meaning |
|---|---|
| `OBJECTIVE` | What to investigate, in plain language. Sent to the model (see [disclosure](#operator-data-disclosure)) and recorded. Credential-shaped text is rejected. |
| `--workdir WORKDIR` | Where durable investigation data is written. Default: `.chanakya` in the current directory. Use a directory outside any Git repository. |
| `--require-approval` | Ask a human to approve every capability before it runs. |
| `--review INVESTIGATION_ID` | Read-only: rebuild and verify a past investigation from `--workdir`. No model call, no tool execution, no API key needed. |
| `--approver NAME` | Name recorded on approval decisions. Default: your OS user name. Free-form; not an authenticated identity. |
| `--model MODEL` | Anthropic model id. Default: `claude-opus-5-5`. |
| `--max-turns N` | Maximum model turns before Chanakya cancels the investigation. Default: 8. |
| `-h`, `--help` | Show help. |

Exit codes: `0` completed (or review verified and consistent), `1` not
completed (or review not consistent), `2` configuration error (for example
missing key, refused environment, refused workdir), `130` interrupted.

Built-in limits per investigation: 10 steps, 10 tool calls, 15 minutes, and one
investigation at a time.

## A safe first investigation

Use a workdir **outside** your Git repositories, so investigation data about
your host can never be committed or pushed by accident.

Windows:

```
chanakya "Read-only: summarize this host's platform and listening services" --workdir D:\Chanakya-Data --require-approval
```

Linux:

```
chanakya "Read-only: summarize this host's platform and listening services" --workdir ~/chanakya-data --require-approval
```

What happens:

1. Chanakya prints the investigation id.
2. The model proposes one capability per turn. With `--require-approval`, each
   proposal is shown to you and nothing runs until you type `approve`.
3. When the model has enough evidence, it reports findings.
4. Chanakya prints the evidence count, each finding with the evidence it cites,
   and a rule-based risk rating (or "not assessed" with a reason).

Findings are the model's opinions grounded in evidence, not verified facts.
Risk ratings are computed by fixed rules and do not establish the absence of
risk.

## Human approval

With `--require-approval`, a policy rule requires approval for every
capability. Without it, the Policy Gateway **allows the two read-only
capabilities by default** once the target and parameters pass its checks.

At each prompt:

- Type exactly `approve` to run the action, or `deny` to refuse it. Other
  answers (including `y` or `yes`) are rejected and you are asked again, up
  to three attempts; after that the investigation fails and nothing is run.
- End of input or Ctrl+C at the prompt fails the investigation; nothing is run.
- Approval is bound to that one request and cannot be reused.
- Answers are read from standard input, so whoever controls the terminal (or
  pipes input into it) answers the prompt. The approver name is not
  authenticated.

## Operator data disclosure

**An investigation sends information about this host to the configured
Anthropic provider.** Read this before running one.

**What the capabilities collect (read-only):**

- `observe_local_host_environment`:
  - OS name, release and version;
  - platform string and architecture;
  - **hostname**;
  - the Python version running Chanakya;
  - CPU count;
  - whether it appears to run in a container.
- `list_listening_ports`: every listening TCP/UDP socket, with:
  - protocol and port;
  - **local address**, which can include **public IPv4/IPv6 addresses** of
    the host;
  - the owning **process id** and **process executable name** (base name
    only).
- `http_probe_local`: for one operator-approved HTTP `GET` to a service on
  `127.0.0.1`, the response status line, a bounded set of response headers,
  and a bounded snippet of the response body of that local service.

They do **not** collect process arguments, environment variables, file
contents, user data or credentials.

**What is sent to Anthropic (`https://api.anthropic.com`)**, as model context
on each turn:

- the Runtime's instruction text, which includes **your objective** and the
  investigation id;
- a description of the target (`local-host`, type `local_host`, display name
  "Local host");
- the list of available capabilities;
- the screened output of the capabilities that have run in this investigation
  (the data listed above).

All three v1.1.0 capabilities are registered as allowed to send their output to
the model. How Anthropic handles data it receives is governed by your
agreement with Anthropic, not by Chanakya. Chanakya does not control retention
or use by the provider.

**What stays on this machine:** the durable records described in
[Where data is stored](#where-data-is-stored). They include the full tool
output, your objective, the model's findings and explanations, and the
approvals.

**Credentials:**

- The API key is sent only as the API request header. It is not intended to
  appear in Evidence, Findings, audit records, tool output or model context.
- Tool output, objectives, parameters, findings, explanations and audit
  details are screened for credential-shaped content (for example key/token
  assignments, URL credentials and private-key headers). A match is rejected,
  not redacted; an unsafe model explanation is withheld (only its hash is
  recorded).
- This screening is pattern-based. It cannot recognize every secret format, and
  it does not classify other sensitive data (such as hostnames or IP
  addresses, which are sent by design).

## Development and testing

From a source checkout, in a virtual environment:

```
python -m pip install --require-hashes -r requirements-test.lock
python -m pip install --no-deps -e .
python -m pytest -q
python -m pytest -q -W error
```

The suite must pass with no failures, skips or warnings. To change a
dependency, regenerate the locks as described at the top of
`requirements.lock`, then re-run the full suite and a vulnerability scan (for
example `pip-audit -r requirements.lock --require-hashes --disable-pip`).

## Security limitations

Known and accepted for v1.1.0 (unchanged since v1.0.0; details:
`docs/THREAT-MODEL.md` §8, "Consolidated threat register (v1.0.0)"):

- **Prompt injection** through host data (for example a crafted process name)
  can still steer the model's conclusions. It cannot make anything execute
  outside the registered read-only capabilities (T-03, T-35).
- **Findings can be wrong.** They must cite real evidence but may misinterpret
  it (T-06, T-07). Risk ratings are rule-based and capped at `high` for
  read-only evidence (T-45).
- **Credential screening is pattern-based** (T-20, T-41).
- **Host data is sent to the provider by design** (T-22, T-34).
- **Local tampering.** The audit log is tamper-evident, not tamper-proof. An
  attacker with write access who rewrites all records consistently is not
  detected (T-18).
- **Approver identity** is the OS user or a free-form name (T-17).
- **Timeouts are checked after a capability returns**, not preemptively. Both
  capabilities are bounded and make no blocking calls (T-36).
- **Workdir data is not encrypted at rest** (T-22, T-65).
- **A compromised host** is out of scope (T-25).

## License

MIT. See `LICENSE`.
