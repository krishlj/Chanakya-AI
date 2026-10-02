# Local Host Security Investigation with Chanakya AI

> **This is a sanitized portfolio representation of a local host
> investigation. Raw investigation records are intentionally not
> published because they contain environment-specific host and network
> information.**

## Overview

This case study describes a real investigation in which **Chanakya AI
v1.1.0** examined the Windows machine it was running on, in read-only
mode, with human approval required for every action.

The investigation used the two v1.1.0 host-observation capabilities:

- `observe_local_host_environment` (coarse OS/platform facts)
- `list_listening_ports` (listening TCP/UDP sockets from the kernel socket
  tables)

It produced durable Evidence, model-written Findings that cite that
Evidence, deterministic rule-based risk assessments, and a hash-chained
audit trail, and it was then verified with Chanakya's read-only review.

> **Authorization:** The investigated host is owned and operated by the
> operator who ran the investigation.

### What was sanitized

The structure, sequence, counts, categories, severities and rule-engine
behaviour below come from the actual stored investigation and its
read-only review. Anything that could identify or fingerprint the
operator's machine has been removed or replaced with a neutral label.
No values were invented to replace redacted data.

| Removed from this report | Shown as |
|---|---|
| Hostname | `[HOSTNAME REDACTED]` |
| IPv4 / IPv6 addresses and prefixes (LAN, virtual adapters, global IPv6) | `[IP ADDRESS REDACTED]` |
| Process ids | `[PID REDACTED]` |
| Names of third-party applications and their executables | `[PROCESS NAME REDACTED]` or a generic category |
| Investigation, evidence, finding, step and request ids | `[INVESTIGATION-ID-REDACTED]`, `[EVIDENCE-ID-REDACTED]`, ... |
| Record hashes and request hashes | `sha256:[REDACTED]` |
| Operator account name | `[OPERATOR]` |
| OS build number, CPU count, Python patch version | omitted |
| The complete socket inventory and raw tool-output payloads | summarized by category only |
| Raw Evidence, Findings, risk and audit JSON | not published |

Well-known Windows protocol ports (for example SMB 445 and the RPC
endpoint mapper 135) are kept because they are present on a default
Windows installation and are needed to explain the findings. TCP port
3000 and the presence of Docker are kept because they are the link to the
[Juice Shop case study](LOCAL-WEB-SECURITY-ASSESSMENT-JUICE-SHOP.md).

## Environment

| Component | Details |
|---|---|
| Security agent | Chanakya AI v1.1.0 |
| Model provider | Anthropic, model `claude-opus-5-5`, endpoint `https://api.anthropic.com` |
| Target | `local-host` (type `local_host`) |
| Host | Windows 11, AMD64, `[HOSTNAME REDACTED]` |
| Capabilities used | `observe_local_host_environment`, `list_listening_ports` |
| Approval mode | `--require-approval` (every capability needed explicit operator approval) |
| Investigation data location | `D:\Chanakya-Data` (private; outside the Git repository) |
| Date | 2026-10-02 |

## 1. Objective

The investigation was started from the command line with a read-only
objective and the approval gate enabled (shown with the canonical private
workdir):

```text
chanakya "Read-only: summarize this host's platform and listening services" --workdir D:\Chanakya-Data --require-approval
```

Investigation ID:

```text
[INVESTIGATION-ID-REDACTED]
```

The objective is recorded as the first entry of the audit chain
(`investigation_started`), together with the submitter
(`[OPERATOR]`), the submission time, and the target reference
`local-host`.

## 2. Investigation workflow

The run took **three model turns**. Each turn contained exactly one
proposal; the Runtime would have rejected a turn with more than one.

| Turn | Model proposal | Policy decision | Approval | Dispatch | Evidence |
|---|---|---|---|---|---|
| 1 | `observe_local_host_environment` | `require_approval` (rule `cli-require-approval`), classification `read_only` | `accept` by `[OPERATOR]` | `success` (timeout 10 s, max output 65,536 bytes) | `[EVIDENCE-ID-REDACTED-1]` |
| 2 | `list_listening_ports` | `require_approval` (rule `cli-require-approval`), classification `read_only` | `accept` by `[OPERATOR]` | `success` (timeout 15 s, max output 60,000 bytes) | `[EVIDENCE-ID-REDACTED-2]` |
| 3 | `report_findings` | — (findings are not a capability) | — | — | — |

Before turn 2 the model recorded a short explanation, which passed
credential screening and was stored in the audit log:

```text
"Platform facts are already collected. Next I'll list the listening ports."
```

Both capabilities ran with no parameters (`{}`), inside their registered
execution envelopes, and produced output that matched their closed output
schemas. Both outputs passed tool-output screening
(`chanakya-tool-output-screen/1.0.0`) before they became Evidence and
before they were sent back to the model as data.

## 3. What was observed

### Platform

- Windows 11 on AMD64.
- Not running inside a container.
- Hostname: `[HOSTNAME REDACTED]`.
- Patch level, Windows edition and firewall state are **not** collected by
  `observe_local_host_environment`, and the finding says so.

### Listening services (summarized by category)

The complete socket inventory is not published. By category, the
`list_listening_ports` evidence contained:

| Category | Observation | Bound to |
|---|---|---|
| Windows file sharing | SMB on TCP 445 | all IPv4 and IPv6 interfaces |
| Windows RPC | RPC endpoint mapper on TCP 135; RPC dynamic listeners (including the Print Spooler's RPC endpoint) | all IPv4 and IPv6 interfaces |
| NetBIOS | TCP 139, UDP 137/138 | the LAN address and virtual-adapter addresses `[IP ADDRESS REDACTED]` |
| Name resolution / discovery (UDP) | LLMNR, mDNS, SSDP/UPnP | all interfaces (LLMNR, mDNS); selected interfaces (SSDP) |
| IPsec | IKE on UDP 500/4500 | all interfaces |
| Docker | A container port published by the Docker backend on **TCP 3000** | all IPv4 and IPv6 interfaces |
| Other Windows system services | Connected Devices Platform and a COM-hosting system process (the latter also bound to TCP 3000) | all / IPv6 interfaces |
| Virtualization platform | `[PROCESS NAME REDACTED]` authorization service | all IPv4 interfaces |
| Third-party desktop applications | `[PROCESS NAME REDACTED]` (several) | some on all interfaces, several loopback-only |
| Global IPv6 | Listeners bound to globally routable IPv6 addresses `[IP ADDRESS REDACTED]` | — |

PIDs (`[PID REDACTED]`) and exact local addresses are recorded in the raw
Evidence but are omitted here.

## 4. Findings

The model reported **8 findings**. Every finding cites one of the two
Evidence records from this investigation; Chanakya rejects any finding
that cites nothing or cites evidence from elsewhere.

Findings are the model's interpretation of the evidence. They are
grounded, not verified: the risk engine and the review check provenance,
not truth.

| # | Finding (sanitized title) | Category | Model confidence | Cites |
|---|---|---|---|---|
| F1 | Host platform: Windows 11, AMD64, not containerized | `platform_configuration` | high | host-environment evidence |
| F2 | SMB, NetBIOS and RPC endpoint mapper are listening on non-loopback interfaces | `network_exposure` | high | listening-ports evidence |
| F3 | Docker-published port 3000 on all interfaces, plus a Windows system process also bound to port 3000 | `unexpected_listener` | medium | listening-ports evidence |
| F4 | Virtualization-platform authorization service listening on all IPv4 interfaces | `network_exposure` | high | listening-ports evidence |
| F5 | Other services listening on all interfaces: RPC dynamic ports, Print Spooler, Connected Devices Platform, a third-party application | `service_inventory` | high | listening-ports evidence |
| F6 | Loopback-only TCP services (four, names redacted) | `service_inventory` | high | listening-ports evidence |
| F7 | Name-resolution and discovery protocols active on UDP (LLMNR, mDNS, NetBIOS, SSDP), plus IPsec IKE | `network_exposure` | high | listening-ports evidence |
| F8 | Host has global IPv6 addresses, so IPv6 listeners may be reachable without NAT | `observation` | medium | listening-ports evidence |

### Notes on the findings

- **F2 and F8 (exposure beyond loopback).** The model noted that SMB, the
  RPC endpoint mapper and other listeners are bound to all interfaces,
  including globally routable IPv6 addresses, which are not shielded by
  the NAT that usually protects IPv4 home networks. It explicitly stated
  that actual reachability depends on Windows Firewall and the upstream
  router, **which this investigation did not check**.
- **F3 (Docker on port 3000).** The model observed that the Docker
  backend published TCP 3000 on all interfaces rather than only on
  `127.0.0.1`, which suggests a container port reachable from other
  machines. It recommended confirming which container owns the port and
  binding it to loopback if wider exposure is not intended. It also
  stated that **no probe of the service was done**. (That service was the
  OWASP Juice Shop instance examined in the second case study.)
- **F7 (LLMNR / NetBIOS).** The model noted that LLMNR and NetBIOS name
  resolution are known spoofing/poisoning risks on untrusted networks and
  suggested disabling them if they are not needed.
- **F5 (Print Spooler).** The model suggested reviewing whether the Print
  Spooler needs to be reachable over RPC if network printing is not used.
- **F6 (loopback-only services).** Recorded as inventory: these services
  are not reachable from the network.

These are observations and suggestions recorded by the model. Chanakya
v1.1.0 does not change host configuration, and no remediation was
performed as part of this investigation.

## 5. Deterministic risk assessment

Each finding was rated by the risk engine using the versioned rule set
`chanakya-risk-rules/1.0.0`. The model has no input into the rating.
**8 of 8 findings were assessed.**

| Finding | Category | Base severity (rule) | Result | Basis confidence |
|---|---|---|---|---|
| F2, F4, F7 | `network_exposure` | medium | **medium** | medium |
| F3 | `unexpected_listener` | low | **low** | medium |
| F1 | `platform_configuration` | low | **low** | medium |
| F5, F6 | `service_inventory` | informational | **informational** | medium |
| F8 | `observation` | informational | **informational** | medium |

Summary: **3 medium, 2 low, 3 informational.**

Example rule rationale, as recorded (the format is identical for every
assessment; only the category and capability differ):

```text
Rule set chanakya-risk-rules/1.0.0.
evidence.verified: 1 cited evidence record(s) verified in this investigation.
category.network_exposure: category network_exposure has base severity medium.
compat.all: compatible evidence capabilities: list_listening_ports; incompatible: none.
ceiling.read_only: all cited evidence is read_only, so severity is at most high.
confidence.medium: all cited evidence is compatible.
Result: severity medium, basis confidence medium.
This rates the category and evidence provenance only; it does not verify the finding.
```

The rating reflects the finding's category and the provenance of its
evidence. It does not establish the absence of risk, and it does not
confirm that a finding is correct.

## 6. Audit trail

The investigation produced **38 hash-chained audit records**. Each record
contains the hash of the previous record, so any edit, deletion or
reordering breaks the chain.

| Audit event | Count |
|---|---|
| `investigation_started` | 1 |
| `agent_turn_requested` / `agent_turn_received` | 3 / 3 |
| `request_proposed` | 2 |
| `policy_evaluated` | 2 |
| `approval_requested` / `approval_decided` | 2 / 2 |
| `dispatch_started` / `dispatch_completed` | 2 / 2 |
| `evidence_recorded` | 2 |
| `finding_created` | 8 |
| `risk_assessed` | 8 |
| `investigation_completed` | 1 |
| **Total** | **38** |

Each model turn record carries the provider identity (`anthropic`,
`claude-opus-5-5`, `https://api.anthropic.com`, config `1.1.0`), a
distinct request hash (`sha256:[REDACTED]`), and a manifest of which tool
results were in the model's context on that turn.

An anonymized example of an audit record's shape:

```json
{
  "sequence": 1,
  "previous_record_hash": null,
  "record_hash": "sha256:[REDACTED]",
  "recorded_at": "2026-10-02T[TIME]Z",
  "event": {
    "event_type": "investigation_started",
    "actor": "system",
    "investigation_id": "[INVESTIGATION-ID-REDACTED]",
    "details": {
      "objective": "Read-only: summarize this host's platform and listening services",
      "submitted_by": "[OPERATOR]",
      "target_refs": ["local-host"]
    }
  }
}
```

An anonymized example of an Evidence record's shape (the payload itself,
which holds the host data, is stored separately and is not shown):

```json
{
  "evidence_id": "[EVIDENCE-ID-REDACTED-2]",
  "investigation_id": "[INVESTIGATION-ID-REDACTED]",
  "capability": "list_listening_ports",
  "classification": "read_only",
  "screening_version": "chanakya-tool-output-screen/1.0.0",
  "redactions_applied": false,
  "content_hash": "sha256:[REDACTED]",
  "payload_hash": "sha256:[REDACTED]",
  "storage_ref": "[REDACTED]"
}
```

## 7. Read-only review

The stored investigation was verified with:

```text
chanakya --review [INVESTIGATION-ID-REDACTED] --workdir D:\Chanakya-Data
```

Review reads the durable records only: no API key, no model call, no tool
execution, no files created.

| Check | Result |
|---|---|
| Status | `completed` |
| Audit chain | verified (38 records) |
| Consistency (requests, policy decisions, approvals, dispatches, model turns) | consistent |
| Evidence | 2 records, both verified and screened |
| Findings | 8, each citing this investigation's Evidence |
| Risk assessments | 8, rule-based under `chanakya-risk-rules/1.0.0` |
| Anomalies | 0 |
| Exit code | `0` (verified and consistent) |

## 8. What this demonstrates

```text
Objective ("Read-only: summarize this host's platform and listening services")
   ↓
Model proposes one capability per turn
   ↓
Runtime validates the turn (exactly one proposal)
   ↓
Policy Gateway decides: require_approval (rule cli-require-approval)
   ↓
Operator approves  →  registered read-only capability executes
   ↓
Output is schema-checked and screened
   ↓
Evidence is recorded (hashed, append-only)
   ↓
Findings cite that Evidence
   ↓
Risk is calculated deterministically (chanakya-risk-rules/1.0.0)
   ↓
Every step is in the hash-chained audit log
   ↓
Review verifies the investigation
```

- **The model never touched the host directly.** It could only propose
  one of the registered read-only capabilities; it did not run commands
  and could not choose parameters outside the capability schemas.
- **Nothing ran without approval.** Both capabilities waited for the
  operator to type `approve`.
- **Findings were grounded.** Each finding cites a real Evidence record,
  and the model stated the limits of its evidence (firewall state, router
  configuration and service behaviour were not checked).
- **Risk was separate from the model.** Severity came from fixed,
  versioned rules, and each rationale says it does not verify the
  finding.
- **The whole run is reconstructable.** The audit chain records what the
  model saw on each turn, what it proposed, who approved it and what
  came back.

## 9. Data handling for this case study

The host data collected by these capabilities is sensitive by design:
hostname, local and public IP addresses, process ids and executable
names. As documented in the README's *Operator data disclosure*, this
data is sent to the configured Anthropic provider as model context, and
it is stored unencrypted in the investigation workdir.

For that reason:

- The raw investigation workdir (audit, evidence, findings and risk
  records) is **not** in this repository and must never be added to it.
- Only this sanitized summary is published.
- Keep raw investigation data outside the Git repository. The project
  convention is a dedicated directory such as `D:\Chanakya-Data` on
  Windows or `~/chanakya-data` on Linux.

See [Public vs private investigation data](../../README.md#public-vs-private-investigation-data)
in the README.

## 10. Limitations

- Firewall state, router configuration and Windows edition/patch level
  were not collected, so reachability from other machines was **not**
  established.
- No service was probed in this investigation; the Docker port 3000
  finding is about how the port is bound, not about the application.
- Findings are model-written and may misinterpret evidence.
- Risk ratings are capped at `high` for read-only evidence and rate
  category and provenance only.
- The audit log is tamper-evident, not tamper-proof (see
  `docs/THREAT-MODEL.md`).
