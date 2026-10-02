# Release Preparation — RP-5 through RP-9

Final release documentation preparation for Chanakya AI v1.0.0. This is not a
security phase.

- No security architecture, Policy Gateway, Runtime enforcement, capability,
  provider control, Evidence, Finding, Risk, Audit or Review behavior changed.
- Source files changed only in docstrings and comments. This was verified by
  comparing each touched module's AST, docstrings stripped, against the
  previous commit: identical.
- Nothing was pushed, and no `v1.0.0` tag exists.

| Item | Status |
|---|---|
| RP-5 License / release metadata | **PASS** |
| RP-6 README installation and usage | **PASS** |
| RP-7 Operator data disclosure | **PASS** |
| RP-8 Documentation drift | **PASS** |
| RP-9 Threat register | **PASS** |

**Baseline:**
- `main` at `56481af Add MIT license for v1.0.0`; latest architectural tag `v0.20.0-durable-data-placement-confinement`.
- 2982 passed (plain and `-W error`).
- Untracked: the three existing reports and `RELEASE-PREP-RP1-RP4-REPORT.md`, all left untouched.

**Result:** commit `97cc108`; 2991 passed, 0 warnings.

## RP-5 License / Release Metadata

**PASS.** Verified; no license change was needed.

| Check | Result |
|---|---|
| `LICENSE` exists | ✔ standard MIT text |
| Copyright | `Copyright (c) 2026 krishlj`, matching `authors = [{ name = "krishlj" }]` in `pyproject.toml` and the repository's Git identity |
| `pyproject.toml` | `license = "MIT"`, `license-files = ["LICENSE"]` (PEP 639); no conflicting `License ::` classifier |
| Wheel | `License-Expression: MIT`, `License-File: LICENSE`; contains `chanakya-1.0.0.dist-info/licenses/LICENSE` |
| sdist | `PKG-INFO` `License-Expression: MIT`; contains `chanakya-1.0.0/LICENSE` |
| Installed distribution | `importlib.metadata`: version `1.0.0`, license `MIT`, LICENSE file installed |
| README | "License: MIT. See `LICENSE`." |

## RP-6 README Installation and Usage

**PASS.** `README.md` was rewritten. It covers all 17 required topics:

1. what Chanakya AI is;
2. the security model (the full enforcement chain and one action per turn);
3. the v1.0.0 scope, with what is not supported;
4. requirements: Python ≥3.10 (tested 3.10–3.13), Windows/Linux support and its evidence base, macOS behavior, API access, no proxies;
5. installation from a source checkout, a built wheel or an sdist;
6. locked dependency installation (`--require-hashes`, then `--no-deps`);
7. API key (`ANTHROPIC_API_KEY`, placeholder `YOUR_ANTHROPIC_API_KEY`, never commit it, refused environment variables);
8. CLI usage: every option, defaults, exit codes, built-in limits;
9. a safe first investigation with an out-of-repository workdir, and why it matters;
10. human approval;
11. review;
12. workdir and data storage;
13. provider data disclosure (RP-7);
14. capabilities;
15. security limitations, with threat IDs;
16. development and testing;
17. license.

Only the two real capabilities are documented. Nothing is documented that
does not exist: no shell, arbitrary commands, remote execution, MCP,
offensive tools, state-changing actions or multi-tool execution. The "not
supported" list states these explicitly.

**CLI facts taken from the code** (`chanakya/cli/main.py`):
- options `--workdir` (default `.chanakya`), `--require-approval`, `--review`, `--approver`, `--model` (default `claude-opus-5-5`) and `--max-turns` (default 8);
- exit codes 0 / 1 / 2 / 130;
- limits of 10 steps, 10 tool calls, 900 s and one concurrent investigation;
- the refused environment variables, which are the `FORBIDDEN_SDK_ENVIRONMENT` and `FORBIDDEN_TRANSPORT_ENVIRONMENT` constants.

**README command validation.** Every command was run in a fresh copy of the working tree outside the repository, unless noted:

| README command | How validated | Result |
|---|---|---|
| `python -m venv .venv` + `.venv\Scripts\Activate.ps1` | PowerShell | ✔ |
| `python -m pip install --require-hashes -r requirements.lock` | PowerShell and bash | ✔ |
| `python -m pip install --no-deps .` | PowerShell | ✔ |
| `python -m pip wheel --no-deps -w dist .` | bash | ✔ builds `chanakya-1.0.0-py3-none-any.whl` |
| `python -m pip install --no-deps dist/chanakya-1.0.0-py3-none-any.whl` | bash | ✔ |
| `chanakya --help` / `python -m chanakya.cli --help` | both shells | ✔ exit 0 |
| `python -c "import chanakya; print(chanakya.__version__)"` | both shells | ✔ `1.0.0` |
| `python -m pip check` | both shells | ✔ No broken requirements |
| `$env:ANTHROPIC_API_KEY = "YOUR_ANTHROPIC_API_KEY"` | PowerShell: set, presence checked, value never printed, then cleared | ✔ |
| Safe investigation (Windows form) | argument parsing checked; run without a key: `error: environment variable ANTHROPIC_API_KEY is not set`, exit 2, workdir not created. The same arguments completed live against the real API in investigation `c6fd58a7-…` | ✔ (no new live call, as instructed) |
| Safe investigation (Linux form, `~/chanakya-data`) | argument parsing checked (automated test) | ✔ |
| `chanakya --review INVESTIGATION_ID --workdir D:\Chanakya-Data` | PowerShell, installed command, on `c6fd58a7-…` | ✔ completed; chain verified (41), consistent, 0 anomalies, exit 0 |
| Refused environment | `HTTPS_PROXY` set: `TRANSPORT_ENVIRONMENT_REFUSED`, exit 2 | ✔ |
| `python -m pip install --require-hashes -r requirements-test.lock` + `python -m pip install --no-deps -e .` | bash, fresh copy | ✔ editable install from the checkout |
| `python -m pytest -q` / `python -m pytest -q -W error` | bash, fresh copy (tree before the new doc test) | ✔ 2982 / 2982 passed |
| `source .venv/bin/activate` (Linux) | Not executable on this Windows host; standard `venv` layout | not run |
| `pip-audit -r requirements.lock --require-hashes --disable-pip` | Same invocation used in RP-3 | ✔ (previously run) |

`tests/test_release_documentation.py` re-parses every `chanakya …`
investigation and review command in the README with the real argument
parser on every test run.

## RP-7 Operator Data Disclosure

**PASS.** The README section "Operator data disclosure" states, from the
implementation:

**What is collected**
- `observe_local_host_environment`: OS name, release and version; platform; architecture; **hostname**; Python version; CPU count; container indicator.
- `list_listening_ports`: protocol, port, **local address (which can include public IPv4/IPv6 addresses)**, **process id** and **process executable base name**.
- Explicitly not collected: process arguments, environment variables, file contents, user data or credentials.

**What is sent to `https://api.anthropic.com`**
- The Runtime instruction text, which includes **the objective** and the investigation id.
- The target description (`local-host`, `local_host`, "Local host").
- The capability list.
- The screened output of capabilities that have run (both are `model_egress: allowed`).
- The CLI wires no separate environment-context source, and none is claimed.

**Where it is stored**
- The `--workdir` layout: `audit/`, `evidence/`, `findings/`, `risk/` and the Runtime-owned `.gitignore`.
- Not encrypted, and permissions are not changed.
- Append-only records; the operator deletes them.

**Credentials**
- The key is sent only in the API header, and is not intended to appear in Evidence, Findings, audit records, tool output or model context.
- Screening is pattern-based and rejects rather than redacts; unsafe explanations are withheld.

**Provider policy.** No claim is made about Anthropic retention or training. The README says only that the operator's agreement with Anthropic governs it and that Chanakya does not control it.

## RP-8 Documentation Drift

**PASS.** Corrections were made with status notes; accurate historical text was kept.

| File | Change |
|---|---|
| `ARCHITECTURE.md` | Title no longer "(Phase 0)". New section **"Implementation status at v1.0.0"**: the implemented flow; scope; in-process Tool Layer with no MCP; one tool call per turn (provider `disable_parallel_tool_use` **and** Runtime CT-INV-3; multiple/parallel execution **not** supported); code-defined configuration; approve/deny only with a free-form approver; no corrective retry of rejected turns; post-hoc timeouts; unencrypted workdir. §15 config note. Design-level diagram and §19 state-changing example labelled as design. **"Proposed module skeleton" replaced by "Package map (v1.0.0)"**: the 16 real packages; `agent/`, `llm/` and `config/` explained as never created. **"Phase 1 implementation scope (not started yet)" → "(delivered)"** |
| `README.md` | Rewritten (RP-6/RP-7); the stale implementation-status list is removed |
| `docs/AGENT-RUNTIME.md`, `CONTRACTS.md`, `POLICY-GATEWAY.md`, `TOOL-REGISTRY.md`, `CAPABILITY-PERMISSION-MODEL.md`, `TARGET-MANAGER.md` | One-line v1.0.0 note after the stale "No implementation code exists yet" header, naming the implementing package |
| `docs/AGENT-RUNTIME.md`, `docs/THREAT-MODEL.md` (T-63, T-64) | "Dependencies are not locked / unlocked (T-23)" annotated with the v1.0.0 hashed lock |
| `chanakya/__init__.py` | Package docstring replaced (was "Phase 2 … Deliberately NOT implemented: Agent Runtime, LLM Abstraction, Tool Layer") |
| `chanakya/providers/__init__.py` | "Not implemented yet: bootstrap that resolves the key, retries" replaced by the actual state (CLI resolves the key; `max_retries` 0; one tool call per request; CT-INV-3 backstop) |
| `chanakya/runtime/__init__.py` | "Not implemented in this step: an LLM provider, a real Tool Layer, Evidence Store, Audit Log" replaced by where each is implemented |
| `chanakya/evidence/__init__.py` | "Not wired into the Agent Runtime yet" corrected |
| `chanakya/runtime/agent_turn.py`, `runtime/audit.py`, `runtime/dispatch.py`, `policy/gateway.py` | "future Tool Layer" / "not-yet-implemented Runtime" wording corrected |
| `chanakya/providers/mapping.py` | Comment at `tool_use_blocks[0]` states this is **not** first-tool-wins: a multi-block turn is rejected by the Runtime before this mapping is used |
| `MANIFEST.in` | Ships `ARCHITECTURE.md` and `docs/*.md` in the sdist, so the documentation tests run from a source release |

- **Version information:** 1.0.0 everywhere (`pyproject` dynamic version, `chanakya.__version__`, README).
- **Parallel execution:** no document implied that parallel tool execution is supported. The provider/Runtime distinction is now stated in README, `ARCHITECTURE.md`, the package docstring and the provider docstring.

## RP-9 Threat Register

**PASS.** A new section in `docs/THREAT-MODEL.md` §8: **"Consolidated threat register (v1.0.0)"**.

- **Source of truth:** the repository's register. T-01 to T-27 and the T-34 to T-65 entries come from `docs/THREAT-MODEL.md`. T-28 to T-31 come from `docs/TARGET-MANAGER.md` §15, and T-32/T-33 from `docs/TARGET-AWARE-AGENT-CONTEXT.md`. Those were previously outside the register; they are adopted with their original definitions, and both documents now point to the register.
- **Consistency check:** a script extracted every threat definition and every inline `T-##` reference in `README.md`, `ARCHITECTURE.md`, all `docs/*.md` and the release reports. **No ID is used with two meanings and no duplicates exist**, so nothing was renumbered. T-28 to T-32 were simply absent from the main register (fixed).
- **Statuses:** exactly those of `FINAL-SECURITY-AUDIT-REPORT.md` §14; a script compared all 65 entries. The only relabelling: the six threats the audit marked N/A for v1.0.0 (T-04, T-05, T-13, T-26, T-29, T-31) are now **FUTURE**, which is not a better rating than "mitigated". Release-preparation facts (lock, scan, disclosure) are recorded in the basis column; no threat was upgraded because of them.

| Status | Count | IDs |
|---|---|---|
| MITIGATED | 37 | T-01, 09, 10, 11, 15, 16, 19, 21, 27, 28, 30, 32, 33, 37, 38, 39, 40, 43, 44, 46, 47, 49, 51, 52, 53, 54, 55, 56, 57, 58, 59, 60, 61, 62, 63, 64, 65 |
| PARTIALLY MITIGATED | 15 | T-03, 07, 08, 12, 14, 18, 20, 22, 23, 24, 35, 41, 42, 48, 50 |
| RESIDUAL ACCEPTED | 7 | T-02, 06, 17, 25, 34, 36, 45 |
| FUTURE | 6 | T-04, 05, 13, 26, 29, 31 |

- Each row also names its **future hardening**, for example preemptive timeouts (T-36), an authenticated approver (T-17), external audit anchoring (T-18) and encryption at rest (T-22).
- SR-22 (lock and scan before release) is marked met.
- The Phase 0 header ("No implementation code exists yet") is annotated.

## Validation

- **Code unchanged.** AST comparison, docstrings stripped: all 9 touched `chanakya/` modules are identical to `56481af`.
- **README commands.** Run or parse-checked as above.
- **Documentation tests.** `tests/test_release_documentation.py` (9 tests) keeps the docs consistent with the code:
  - README capability table = the registered capabilities;
  - README options = the parser's options;
  - documented commands parse;
  - README lists every refused environment variable;
  - placeholder-only key;
  - one-tool-per-turn and disclosure facts present;
  - `ARCHITECTURE.md` package map = actual packages, and no "not started yet";
  - the register covers T-01 to T-65 exactly once, with valid statuses;
  - the package docstring is current.
- **Secret scan** of all 20 changed or new files: sk-ant tokens, `x-api-key` values, real-format Anthropic keys, password/secret/token assignments, PEM private keys, AWS/GitHub tokens, JWTs and the actual `ANTHROPIC_API_KEY` value (compared in memory). **All clean.** Only the placeholder `YOUR_ANTHROPIC_API_KEY` appears.

## Files Changed

Commit `97cc108` "Finalize v1.0.0 documentation", 21 files (+804 / −148):

- **Top level:** `README.md`, `ARCHITECTURE.md`, `MANIFEST.in`
- **docs/:** `AGENT-RUNTIME.md`, `CAPABILITY-PERMISSION-MODEL.md`, `CONTRACTS.md`, `POLICY-GATEWAY.md`, `TARGET-AWARE-AGENT-CONTEXT.md`, `TARGET-MANAGER.md`, `THREAT-MODEL.md`, `TOOL-REGISTRY.md`
- **chanakya/ (docstrings and comments only):** `__init__.py`, `evidence/__init__.py`, `policy/gateway.py`, `providers/__init__.py`, `providers/mapping.py`, `runtime/__init__.py`, `runtime/agent_turn.py`, `runtime/audit.py`, `runtime/dispatch.py`
- **New:** `tests/test_release_documentation.py`

Not committed: `FINAL-SECURITY-AUDIT-REPORT.md`, both Phase 21 reports, `RELEASE-PREP-RP1-RP4-REPORT.md` and this report.

## Test Results

| Run | Result |
|---|---|
| `pytest -q` (repository) | **2991 passed** (2982 + 9 documentation tests), 0 failed, 0 skipped, 0 xfailed |
| `pytest -q -W error` (repository) | **2991 passed**, 0 warnings |
| README dev commands in a fresh copy (`-q` and `-W error`) | 2982 / 2982 passed (copy taken before the documentation test was added) |
| Documentation + packaging tests from the extracted sdist (`-W error`) | 21 passed |

## Packaging Results

Built with `python -m build` from a clean copy of the final tree; no build warnings.

| Artifact | sha256 |
|---|---|
| `chanakya-1.0.0-py3-none-any.whl` | `ce748a5ae4bafed64c48c79cf8adb21c387cd8d9609c9951d541f6889c296c45` |
| `chanakya-1.0.0.tar.gz` (220 entries) | `d6b16d1d867db2339b3de912260080154b9a4b51386498f5f307821dd655cd05` |

| Check | Wheel | sdist |
|---|---|---|
| Version 1.0.0 | ✔ | ✔ |
| `License-Expression: MIT` | ✔ | ✔ |
| LICENSE included | ✔ `dist-info/licenses/LICENSE` | ✔ |
| README included | ✔ as the long description (`text/markdown`), identical to `README.md` | ✔ `README.md`, identical |
| Locks | n/a | ✔ both |
| `ARCHITECTURE.md`, `docs/` | n/a | ✔ |
| Entry point | `chanakya = chanakya.cli.main:main` | — |
| `Requires-Python` / `Requires-Dist` | `>=3.10` / anthropic, httpx2, truststore (+ `test` extra) | same |

Clean install from `requirements.lock` (`--require-hashes`) plus the wheel (`--no-deps`), run from outside any source tree:
- `pip check` passes, and the version reports 1.0.0 with license MIT;
- `chanakya --help` and `python -m chanakya.cli --help` both work;
- the new package docstring is present;
- the dependencies are the locked set (anthropic 1.7.0, httpx2 2.13.0, truststore 0.10.4).

## Remaining Release Work

| # | Item | Blocks v1.0.0 |
|---|---|---|
| 1 | Final release validation from a clean install: build the artifacts from `97cc108`, install from `requirements.lock` + wheel outside the repository, run the `chanakya` command against the real Anthropic API with `--require-approval` and an out-of-repository workdir, then `chanakya --review` (FINAL-SECURITY-AUDIT-REPORT §20 step 4) | Yes, the planned final gate |
| 2 | Re-run pip-audit on `requirements.lock` immediately before tagging | Yes (release-day check) |
| 3 | Project owner decides whether to commit `FINAL-SECURITY-AUDIT-REPORT.md` and the release-preparation reports | Owner decision |
| 4 | Create the annotated `v1.0.0` tag | Yes, final step |
| 5 | Re-run the secret scan on the exact tree to be published, then publish to GitHub | After tagging |
| 6 | Linux live smoke test (NB-10) | No (recommended) |
| 7 | Optional cleanup: `uv python uninstall 3.10 3.11 3.12` (interpreters installed under `%APPDATA%\uv\python` for RP-2) | No |
