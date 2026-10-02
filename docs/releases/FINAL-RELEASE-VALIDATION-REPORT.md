# Chanakya AI v1.0.0 — Final Release Validation

This was a validation only:
- nothing in the repository was modified: no application, security, dependency, lock or report file;
- nothing was committed, tagged or pushed;
- all builds, environments and test runs were outside the repository, in the session scratchpad;
- durable investigation data went to `D:\Chanakya-Data-Release-Smoke`.

**Verdict: RELEASE VALIDATION — PASS WITH NON-BLOCKING FINDINGS** (see §22–§23).

| # | Item | Result |
|---|---|---|
| 1 | Exact commit tested | `97cc10892b02c8768fa6a8ca82b2b86799ae7925` (`97cc108 Finalize v1.0.0 documentation`) |
| 2 | Python | CPython 3.13.1 (fresh `venv`) |
| 3 | Platform | Windows-11-10.0.26200-SP0, AMD64 |
| 4 | Package version | `1.0.0` (`chanakya.__version__` and distribution metadata) |
| 5 | Wheel | `chanakya-1.0.0-py3-none-any.whl`, sha256 `18e5be0163aadde124ad4d4da1a3b5e23b5aa0d28b40f3ebebdaa3b41a5642c1` |
| 6 | sdist | `chanakya-1.0.0.tar.gz`, sha256 `187c323fa06f64280bb55a09478f20e72aaceb1eedf379b3b5bdd74f1a2ab31e` |
| 7 | Clean install | **PASS** |
| 8 | `pip check` | **PASS** (No broken requirements found) |
| 9 | CLI | **PASS WITH NON-BLOCKING**: `chanakya --help` and `python -m chanakya.cli --help` work; `--version` is not a CLI option (§22) |
| 10 | Real Anthropic smoke test | **PASS** on the second attempt; the first attempt hit an Anthropic HTTP 503 outage and failed closed as designed (§6–7, §22) |
| 11 | Investigation ID | `bb5fff86-8a52-4c95-b2b0-da047628a1b9` (failed attempt: `77f6860b-bc39-4022-a8ed-4944371c8e4c`) |
| 12 | Review | **PASS**: completed, audit chain verified, consistent, 0 anomalies |
| 13 | Evidence records | 2 |
| 14 | Findings | 7 |
| 15 | Risk assessments | 7 |
| 16 | Audit records | 36 |
| 17 | Full test suite (clean environment) | **PASS**: 2991 passed, 0 failed, 0 skipped, 0 xfailed |
| 18 | `-W error` | **PASS**: 2991 passed, 0 warnings |
| 19 | pip-audit | **PASS**: 0 known vulnerabilities (PyPI and OSV), all 17 lock entries covered |
| 20 | Secret scan | **PASS**: no real credential anywhere; all matches classified |
| 21 | Documentation verification | **PASS** (no blocking discrepancy) |
| 22 | Deviations | 3, all non-blocking (§22) |
| 23 | Remaining release blockers | **None** from validation (§23) |

## 1. Repository Baseline

| Check | Result |
|---|---|
| `git rev-parse HEAD` | `97cc10892b02c8768fa6a8ca82b2b86799ae7925` ✔ |
| `git log -1 --oneline` | `97cc108 Finalize v1.0.0 documentation` ✔ |
| Tracked tree | clean (`git diff --quiet HEAD`), before and after validation |
| Untracked files | `FINAL-SECURITY-AUDIT-REPORT.md`, `PHASE-21-ANTHROPIC-MULTI-TOOL-INVESTIGATION.md`, `PHASE-21-ARCHITECTURE-READINESS-REPORT.md`, `RELEASE-PREP-RP1-RP4-REPORT.md`, `RELEASE-PREP-RP5-RP9-REPORT.md`, plus this report. None modified or deleted |
| `git tag --list` | 32 tags, `v0.1-foundation` … `v0.20.0-durable-data-placement-confinement`; **no `v1.0.0`** |
| `D:\Chanakya-AI\.chanakya` | does not exist |

## 2. Build From Exact Commit

- **Source:** `git archive 97cc108…`, the committed tree only, not the working tree. It was built with `python -m build` (build 1.6.1) in an isolated build environment.
- **Result:** 0 warning or deprecation lines, and both artifacts built.

| Check | Wheel | sdist |
|---|---|---|
| Built | ✔ | ✔ (220 entries) |
| Version 1.0.0 | ✔ `Version: 1.0.0` | ✔ `PKG-INFO` `Version: 1.0.0` |
| MIT license | ✔ `License-Expression: MIT`, `License-File: LICENSE`, `dist-info/licenses/LICENSE` | ✔ `License-Expression: MIT`, `LICENSE` |
| `requirements.lock` / `requirements-test.lock` | n/a | ✔ / ✔ |
| `ARCHITECTURE.md` | n/a | ✔ |
| `docs/` | n/a | ✔ all 10 documents |
| `README.md` | long description | ✔ |
| `Requires-Python` | `>=3.10` | `>=3.10` |

The artifact hashes differ from those in the RP reports because they were built from a different tree and at a different time. These §2 hashes are for the exact-commit build.

## 3. Fresh Environment

- A new `venv` outside the repository, created only for this validation; no existing Chanakya environment was reused.
- Dependencies were installed with `python -m pip install --require-hashes -r requirements.lock`, then the wheel with `--no-deps`. Every command ran from an empty directory outside any source tree.

| Command | Result |
|---|---|
| `python --version` | `Python 3.13.1` |
| `pip check` | `No broken requirements found.` |
| `chanakya --version` | `chanakya: error: unrecognized arguments: --version`, exit 2 (§22) |
| `python -m chanakya.cli --version` | same, exit 2 (§22) |
| `chanakya --help` | full usage, exit 0 ✔ |
| `python -m chanakya.cli --help` | same usage, exit 0 ✔ |

## 4. Installed Package

| Check | Result |
|---|---|
| Import | ✔ `import chanakya` |
| Imported from | `…\scratchpad\final\venv\Lib\site-packages\chanakya\` (inside the fresh venv) |
| Not the repository | ✔ the path is outside `D:\Chanakya-AI`, and no `sys.path` entry points into the repository |
| Version | `1.0.0` (`__version__` and `importlib.metadata`) |
| License metadata | `License-Expression: MIT`; LICENSE installed under `dist-info/licenses/` |
| Missing dependencies | none (`pip check`) |

## 5. Release Locks

- The installed versions were compared with `requirements.lock` from the exact commit. Its content is identical, apart from line endings, to the committed file and to the working tree; the lock files were not regenerated or modified.
- **Result:** all 15 entries that apply to Windows with Python 3.13 **MATCH**. These are annotated-types 0.8.0, anthropic 1.7.0, anyio 4.15.1, docstring-parser 0.18.0, h11 0.16.0, httpcore2 2.13.0, httpx2 2.13.0, idna 3.20, jiter 0.17.0, pydantic 2.13.5, pydantic-core 2.46.5, sniffio 1.3.1, truststore 0.10.4, typing-extensions 4.16.0 and typing-inspection 0.4.4.
- `exceptiongroup` (Python <3.11) and `httpx2-jsfetch` (emscripten) are correctly not installed.
- Nothing is installed that is not in the lock.
- The test environment (§17) was also installed from `requirements-test.lock` with hashes, and matches it exactly.

## 6–7. Real Anthropic Smoke Test and Investigation Flow

Command, run with the installed `chanakya` command from outside the repository:

```
chanakya "Read-only: summarize this host's platform and listening services" --workdir D:/Chanakya-Data-Release-Smoke --require-approval
```

Approvals were answered by piping `approve`, with the owner's explicit consent for this smoke test. Only the two registered read-only capabilities can reach an approval prompt. The API key was checked for presence only and was never printed.

**Attempt 1: `77f6860b-bc39-4022-a8ed-4944371c8e4c`. Failed closed on an Anthropic outage.**

- Turn 1 was rejected with `provider_failure`. The investigation ended `failed` (`unhandled_runtime_exception` / `PROVIDER_FAILURE`); exit 1; 0 evidence, 0 findings; nothing was executed.
- **Diagnosis**, which weakened no control:
  - the durable turn record shows the request manifest and the verified transport (no proxy, system TLS, no redirects, 0 retries, no debug logging);
  - a local-only check with the installed package re-ran the send-time logging check and transport re-verification: both passed and matched the recorded identity;
  - one minimal diagnostic request (text "diagnostic", no host data, printing only the exception class and status code) returned `anthropic.InternalServerError`, **HTTP 503**.
- Periodic minimal probes returned 503 for about 12 minutes, then succeeded.
- Chanakya behaved as designed: no SDK retry (`max_retries=0`), provider error text withheld, the failure durably recorded, fail closed.
- The review of this failed investigation also **passes**: status `failed`, chain verified (5 records), consistent, 0 anomalies.

**Attempt 2: `bb5fff86-8a52-4c95-b2b0-da047628a1b9`. Completed. PASS.**

| Turn | Model proposal (one `tool_use` block) | Gateway | Approval | Execution |
|---|---|---|---|---|
| 1 | `observe_local_host_environment` | `require_approval` (rule `cli-require-approval`) | accept | success → Evidence `301a1834-…` |
| 2 | `list_listening_ports` | `require_approval` | accept | success → Evidence `a14aa1a3-…` |
| 3 | `report_findings` | — | — | 7 findings, 7 risk assessments; `investigation_completed` |

Durable audit events: `investigation_started` 1; `agent_turn_requested` 3; `agent_turn_received` 3 (all accepted, `tool_use_blocks=1`, `stop_reason=tool_use`); `request_proposed` 2; `policy_evaluated` 2; `approval_requested` 2; `approval_decided` 2; `dispatch_started` 2; `dispatch_completed` 2; `evidence_recorded` 2; `finding_created` 7; `risk_assessed` 7; `investigation_completed` 1. **Total 36.**

| Requirement | Verified |
|---|---|
| Investigation starts | ✔ |
| Anthropic provider works | ✔ (attempt 2) |
| One-tool-per-turn compatibility | ✔ every turn exactly one `tool_use` block; no `multiple_tool_use_blocks` |
| Policy Gateway invoked | ✔ 2 `policy_evaluated` |
| Approval enforced | ✔ 2 prompts, each shown before execution; 2 `approval_decided` accept |
| Read-only capabilities execute | ✔ both succeeded |
| Evidence created | ✔ 2, verified and screened (`chanakya-tool-output-screen/1.0.0`) |
| Findings created | ✔ 7, each citing one of the two evidence ids |
| Risk assessments | ✔ 7 (rule set `chanakya-risk-rules/1.0.0`) |
| Normal terminal state | ✔ `completed`, exit 0 |
| No credentials in Evidence, Findings, Audit, terminal output or review output | ✔ (§20) |

## 8. Read-Only Review

Command, run from the fresh environment:

```
chanakya --review bb5fff86-8a52-4c95-b2b0-da047628a1b9 --workdir D:/Chanakya-Data-Release-Smoke
```

Exit 0. Exact summary:

```
status: "completed"
audit chain: verified (36 records)
consistency: consistent
requests: 2
model turns: 3 (forensic records of model influence; they authorize nothing)
evidence records: 2
findings: 7 (agent opinions grounded in evidence; not verified facts)
risk assessments: 7 (rule-based; not independently verified)
anomalies: 0
```

- The audit chain is verified.
- The investigation is consistent.
- Evidence integrity is verified: both records are "verified; screened".
- Every finding's evidence references resolve: the review lists each finding with its evidence id.
- Risk assessment references resolve and recompute: 7 shown, no withheld ratings.
- There are 0 anomalies.
- Review is read-only: the workdir had 60 files before and 60 after. Review builds no provider, Gateway or executor and reads no key, as established in the audit.

## 9. Data Placement

| Check | Result |
|---|---|
| Durable data location | `D:\Chanakya-Data-Release-Smoke` (`audit/`, `evidence/`, `findings/`, `risk/`), outside any Git repository (`git rev-parse` fails there) |
| Runtime-owned exclusion | `.gitignore` present with rule `*` |
| Repository | no investigation data written; `.chanakya` absent; tracked tree unmodified; no new untracked files other than this report |
| Credentials persisted | none (§20) |
| Review read-only | ✔ (§8) |

## 10. Test Suite From the Clean Environment

**Environment:**
- a second fresh venv outside the repository;
- `requirements-test.lock` installed with `--require-hashes`, exact match;
- the release wheel installed with `--no-deps`;
- `pip check` clean.

The suite was run from the `git archive` export of `97cc108`:

| Run | Result |
|---|---|
| `python -m pytest -q` | **2991 passed**, 0 failed, 0 skipped, 0 xfailed |
| `python -m pytest -q -W error` | **2991 passed**, 0 warnings |

The count matches the expected 2991. How the installed wheel relates to the tested code:
- `tests/conftest.py` deliberately puts the source root next to `tests/` at the front of `sys.path`, so the suite always tests that tree. I did not modify the tests to change this.
- The installed wheel's 95 Python modules were compared file by file with that exported source: **95/95 identical** (line endings aside), none missing either way.
- So the suite ran against code byte-identical to the installed package, with exactly the locked dependencies.
- One existing test checks the repository `.gitignore` through Git, so the scratch export was `git init`-ed. That was done in the scratch copy only.

## 11. pip-audit

pip-audit 2.10.1 against the exact-commit `requirements.lock`, run with `--require-hashes --disable-pip`:

| Source | Packages audited | Vulnerabilities |
|---|---|---|
| PyPI (also validates hashes) | 15 | 0 |
| OSV | 15 | 0 |
| Marker-conditional pins not installable here (`exceptiongroup 1.3.1`, `httpx2-jsfetch 1.0`), audited explicitly on both sources | 2 | 0 |

- All 17 lock entries are covered, and no known vulnerability was found.
- No dependency change is required, and none was made.

## 12. Final Secret Scan

**Scope:**
- tracked files at `97cc108` (198);
- full Git history (all commits and branches);
- the six untracked reports;
- the wheel contents (101 files) and sdist contents (198 files);
- the smoke workdir;
- the smoke and review terminal output.

**Patterns:**
- Anthropic keys, both real-format and any `sk-ant-` token;
- `x-api-key`;
- AWS keys;
- PEM private-key headers;
- GitHub, Slack and Google tokens;
- JWTs;
- password/secret/token assignments;
- the **actual `ANTHROPIC_API_KEY` value**, compared in memory and never printed.

| Match | Where | Classification |
|---|---|---|
| Actual API key value | nowhere | — |
| Real-format Anthropic key | nowhere | — |
| `sk-ant-` tokens (4 distinct) | 4 test files (+ the sdist copies, + history) | **intentional fixture**: synthetic sentinel constants (lengths 27–42, all sentinel-marked) |
| PEM private-key headers | 7 test files (+ sdist, + history) | **intentional fixture**: header lines only, no key body (9 in history, none followed by key material) |
| password/secret/token assignments | 4 test files (+ sdist, + history) | **intentional fixture** for the credential screens |
| `x-api-key` | provider source, docs, tests, 2 reports, wheel/sdist | **header name / non-secret**: no `x-api-key` with a value anywhere in history |
| AWS / GitHub / Slack / Google / JWT | nowhere | — |
| Smoke workdir, terminal and review output | — | no matches |

**Result: PASS.** No real credential exists in the release tree, history, artifacts, reports or investigation data.

## 13. Documentation Verification

All required documents are present: `README.md`, `ARCHITECTURE.md`, `docs/CONTRACTS.md`, `docs/THREAT-MODEL.md`, `docs/AGENT-RUNTIME.md`, `docs/TARGET-MANAGER.md`, `FINAL-SECURITY-AUDIT-REPORT.md`, `RELEASE-PREP-RP1-RP4-REPORT.md` and `RELEASE-PREP-RP5-RP9-REPORT.md`. `LICENSE` is present too.

| Check | Result |
|---|---|
| Documentation tests (`tests/test_release_documentation.py`, in the 2991) | pass: README capabilities, CLI options, refused variables, documented commands, `ARCHITECTURE.md` package map, threat register T-01..T-65 |
| README vs installed CLI | consistent; the README never claims `--version`, and documents `python -c "import chanakya; print(chanakya.__version__)"`, which works |
| README vs observed run | consistent: approval prompt wording, `approve`/`deny`, one tool per turn, output shape, workdir layout, review summary fields |
| Report test counts | consistent as a sequence: 2970 (audit at `91dca31`) → 2981/2982 (RP-1..RP-4) → 2991 (RP-5..RP-9, this validation) |
| Report commits | consistent: `91dca31` → `69da3d1` → `56481af` → `97cc108` |
| Threat statuses | the register in `docs/THREAT-MODEL.md` matches `FINAL-SECURITY-AUDIT-REPORT.md` §14 (verified in RP-9) |

Non-blocking observations (reported only; nothing was rewritten):
1. `FINAL-SECURITY-AUDIT-REPORT.md` is a point-in-time audit of `91dca31`. Its packaging, dependency and documentation findings (RP-1..RP-9) have since been resolved, as recorded in the two RP reports. Read together, they are consistent.
2. The RP reports list artifact hashes from their own builds. The authoritative hashes for `97cc108` are those in §2 of this report.

## 22. Deviations

| # | Deviation | Impact | Classification |
|---|---|---|---|
| D-1 | **`chanakya --version` and `python -m chanakya.cli --version` are not supported.** argparse rejects them (exit 2, usage error, no side effects). The CLI has never had a `--version` option, and no document claims one. The version is available through `python -c "import chanakya; print(chanakya.__version__)"` (documented) and `importlib.metadata`. I did not add the option, because this step forbids changing the CLI | Cosmetic / usability | NON-BLOCKING. Optional before tagging: add `--version` in a separate, reviewed change |
| D-2 | **The first live smoke attempt failed with an Anthropic HTTP 503** (service unavailable for about 12 minutes). Chanakya failed closed correctly; the retry after recovery completed | None on Chanakya; external availability | NON-BLOCKING (external; behaved as designed) |
| D-3 | **The test suite imports the adjacent source tree** (by design in `tests/conftest.py`), not site-packages | None: the source is byte-identical to the wheel (95/95), and the dependencies came from the hashed lock | NON-BLOCKING (method note) |

Other method notes:
- The scratch export was `git init`-ed for one repository test.
- Approvals were piped with the owner's consent.
- One minimal diagnostic provider request plus periodic probes were made during the outage (no host data).
- Two investigations now exist in `D:\Chanakya-Data-Release-Smoke` (failed `77f6860b…`, completed `bb5fff86…`); both review clean.

## 23. Remaining Release Blockers

**None from this validation.** What remains before release, all owner actions:

1. Optionally decide on D-1 (`--version`). If you want it, add it as a separate reviewed commit and re-run this validation.
2. Decide whether to commit the audit, release-preparation and validation reports.
3. Create the annotated `v1.0.0` tag on the validated commit (`97cc108`, or a successor if step 1 or 2 adds commits).
4. Before publishing, re-run the secret scan and pip-audit on the exact tree and lock being pushed.
5. Push to GitHub.

Optional: a Linux live smoke test (NB-10), and `uv python uninstall 3.10 3.11 3.12` to remove the extra interpreters used in RP-2.

---

**RELEASE VALIDATION — PASS WITH NON-BLOCKING FINDINGS**
