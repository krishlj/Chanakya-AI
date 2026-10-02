# RELEASE-READINESS-v1.1.0-REPORT

Release-readiness audit for the next Chanakya AI release, which would add the
`http_probe_local` capability on top of v1.0.0. **Inspection and verification
only** — no feature was added, no architecture changed, no tag created, nothing
pushed. No release commit was made (the version bump and documentation
corrections below are deferred for review, per instructions).

**Final verdict: RELEASE READINESS — PASS WITH NON-BLOCKING FINDINGS**

---

## 1. Current commit

`03efdce079344a6a0a419194f298610d666d605a` (HEAD → `main`)
— "Add local XSS training lab".

Working tree is clean except one pre-existing, unrelated untracked file
(`FINAL-V1.0.0-RELEASE-REPORT.md`), which predates this work and is not part of
any commit here.

## 2. Previous release

`v1.0.0` → `1f816352f98704a310408fd02daacea8d4d0f9f6`
("Document v1.0.0 release validation"). **Confirmed unchanged.**

## 3. Changes since v1.0.0

Two commits, both additive:

| Commit | Summary |
|---|---|
| `d16a732` | Add controlled local web security capability (`http_probe_local`) |
| `03efdce` | Add local XSS training lab (`labs/local-xss/`) |

`git diff --stat v1.0.0..HEAD` — 15 files, +1918/-18:

- **New capability:** `chanakya/tools/handlers/http_probe_local.py`; registry
  entry + wiring in `chanakya/registry/bootstrap.py`, `chanakya/tools/bootstrap.py`;
  README capability row and package-docstring update in `chanakya/__init__.py`.
- **Tests:** new `tests/test_http_probe_local.py` (65 tests); three pre-existing
  capability-set assertions updated to the three-capability set
  (`tests/test_listening_ports.py`, `tests/test_cli_composition.py`,
  `tests/test_release_documentation.py`).
- **Training lab (not a capability):** `labs/local-xss/`.
- **Reports:** POC readiness/implementation and lab reports (docs only).

No change to `chanakya/policy/`, `chanakya/runtime/`, contracts, the risk
engine, evidence, findings, approval, audit, or review. No change to
`pyproject.toml`, `LICENSE`, `MANIFEST.in`, `requirements.lock`, or
`requirements-test.lock`.

## 4. Current capabilities

Three, all `local_host`-only, all with closed output schemas:

| # | Capability | Class | Action / Level | Approval | Notes |
|---|---|---|---|---|---|
| 1 | `observe_local_host_environment` | read-only | observe / P1 | none | Coarse OS/platform facts (stdlib). |
| 2 | `list_listening_ports` | read-only | observe / P1 | none | Kernel socket tables (stdlib). |
| 3 | `http_probe_local` | read-only | execute_readonly_probe / **P2** | **required** | One bounded HTTP GET to `127.0.0.1`; the new capability. |

No Nmap, Nessus, Semgrep, Trivy, YARA, Metasploit, exploit framework, arbitrary
shell/command execution, remote/cloud targets, or MCP exists — and none is
claimed as implemented anywhere in the documentation.

## 5. Security controls (http_probe_local — verified end to end)

| Control | Status |
|---|---|
| Registry integration | Enabled entry in `production_registry_entries()`; executor registers it. |
| Policy Gateway integration | Evaluated by the unchanged Gateway; verdict `require_approval`. |
| Permission level | **P2** derived from `execute_readonly_probe` (never independently set). |
| Target restriction | `supported_target_types = ("local_host",)`; Gateway + executor both enforce. |
| Localhost enforcement | Connection host is the code constant `127.0.0.1` (never a parameter); `require_loopback_host` guards the fetcher; refuses public/LAN/hostname/scheme inputs. |
| Approval requirement | `approval_requirement = REQUIRED`; dispatch refuses without a bound ACCEPT. |
| Parameter validation | Closed schema (`port`, `path`, `additionalProperties: false`) + handler re-validation of port range and path. |
| Output limits | Closed output schema; 60,000-byte canonical ceiling; oversized output rejected, never truncated. |
| Timeout | 5 s envelope timeout + explicit socket timeout in the fetcher; bounded read. |
| Evidence integration | Successful result becomes a hash-chained Evidence record. |
| Finding integration | Findings cite the probe's Evidence; screened untrusted text. |
| Risk integration | Deterministic Risk Engine rates it (unchanged rule set). |
| Audit integration | request/policy/approval/dispatch/evidence all written to the durable log. |
| Review integration | Full investigation reconstructs consistently (`test_e2`). |
| Isolation | Handler imports no `chanakya.policy` / `chanakya.runtime` / `subprocess`; no shell/eval. |

**No release-blocking security defect was found. No change was made to the
capability.**

## 6. Package status

- `pyproject.toml`, `LICENSE`, `MANIFEST.in`, `requirements.lock`,
  `requirements-test.lock` are **byte-identical to v1.0.0** (`git diff
  v1.0.0..HEAD` on those paths is empty).
- **No new dependency** was introduced — `http_probe_local` uses only the
  standard library (`http.client`). The declared runtime deps (`anthropic`,
  `httpx2`, `truststore`) and test deps are unchanged.
- **`labs/` is excluded from the distribution:** `packages.find` includes only
  `chanakya*`, `labs/local-xss/` has no `__init__.py`, and `MANIFEST.in` does
  not reference it — so it ships in neither the wheel nor the sdist.
- `test_release_packaging.py` (in-suite) validates that declared dependencies
  match the code's third-party imports, that both locks are exact + hashed, and
  that the version/console script are consistent — **all passing**.
- **Version:** `chanakya.__version__` is still `"1.0.0"` (dynamic source for the
  package version). This **must** be bumped to `1.1.0` in the release commit
  (see §13/§14) — deferred per instructions.
- Wheel/sdist build was **not** re-run here: the build toolchain (`build`,
  `twine`) is intentionally not a project dependency and is not installed in
  this environment; per the v1.0.0 process it runs from a throwaway environment
  at release time. Packaging **configuration** is unchanged from the v1.0.0
  build that succeeded.

## 7. Documentation status

**Accurate:**
- README `## Capabilities` table lists all **three** current capabilities and
  correctly marks `http_probe_local` as an active (P2), approval-required,
  loopback-only probe.
- The package docstring (`chanakya/__init__.py`) names all three capabilities.
- No documentation claims any unimplemented technology (Nmap/Nessus/Semgrep/
  Trivy/YARA/exploitation/remote targets/shell) as currently supported.
- `test_release_documentation.py` (README capability table == registered set,
  CLI options, refused env vars, package map, threat register) — **all passing**.

**Stale (non-blocking; to fix in the v1.1.0 release commit):**
- `chanakya/__init__.py` `__version__ = "1.0.0"` → should be `"1.1.0"`.
- README `## Scope of v1.0.0` says *"Two read-only capabilities:
  observe_local_host_environment and list_listening_ports"* — this undercounts
  and should list all three (and the section be relabeled for v1.1.0). The
  Capabilities table below it is already correct, so the README is internally
  inconsistent on the count.
- `ARCHITECTURE.md` "Implementation status at v1.0.0" and "§8 MCP / Tool Layer"
  enumerate only the two original capabilities; they should mention
  `http_probe_local`, and the various `v1.0.0` labels updated to `v1.1.0`.
- **Coordination note:** several doc-consistency tests key off the literal
  string `v1.0.0` (e.g. `## Package map (v1.0.0)`) and the threat register
  `T-01..T-65`. Relabeling the docs to `v1.1.0` must be done in the **same**
  commit as the matching test updates, which is exactly why these changes were
  deferred to the reviewed release commit rather than made piecemeal now.

The original product vision (Nmap/Nessus/scanners/remediation/etc.) is described
separately in `ARCHITECTURE.md` "§20 Future Extensibility" and "Decisions locked
in for Phase 1" as future/design scope, correctly distinct from the implemented
capability set.

## 8. Test results

| Run | Result |
|---|---|
| `pytest -q` | **3056 passed** in ~124 s |
| `pytest -q -W error` | **3056 passed** in ~128 s (0 warnings) |

0 failed, 0 skipped, 0 xfailed, 0 warnings — matches the expected current
result. The count rose from the v1.0.0 baseline solely because of the 65 new
`test_http_probe_local.py` tests; the four adjusted assertions were **corrected
to the now-accurate three-capability set, not weakened**, and no test was
modified to reach a number.

The training lab's own validation (`labs/local-xss/test_app.py`, isolated from
the Chanakya suite by `testpaths = ["tests"]`) also passes: **6 passed** under
`-W error`.

## 9. Secret scan

Scanned the whole tracked tree and, specifically, every file changed since
v1.0.0 for `sk-ant-*` tokens, PEM private keys, Slack/GitHub/AWS tokens, and
`api_key`/`secret`/`password`/`token` assignments. **Clean** — only the
placeholder `YOUR_ANTHROPIC_API_KEY` appears in the README, and the only
credential-shaped strings are deliberate test fixtures (e.g. `hunter2`,
`abc123`) and the finding/locator regexes that screen for such patterns. No real
credential anywhere.

## 10. Dependency audit

- The dependency set is **unchanged from v1.0.0** (locks byte-identical; no new
  import). `http_probe_local` adds no dependency.
- v1.0.0's release audit ran `pip-audit 2.10.1` (`--require-hashes
  --disable-pip`) against both locks and found **0 known vulnerabilities** across
  all pinned packages (documented in `RELEASE-PREP-RP1-RP4-REPORT.md` and
  `FINAL-RELEASE-VALIDATION-REPORT.md`). Because the locks have not changed, that
  result still applies to this release.
- `pip-audit` is intentionally **not** a project dependency and is not installed
  in this environment; a fresh scan of the (unchanged) lock is a release-day step
  in a throwaway environment, consistent with the v1.0.0 process. **Non-blocking**
  because no dependency changed.

## 11. XSS training lab status

`labs/local-xss/` — verified as:

- **Training-only / deliberately vulnerable:** every page and the module
  docstring carry an "INTENTIONALLY VULNERABLE TRAINING APP" label; one endpoint
  (`GET /search?q=`) reflects input without encoding (reflected XSS) and nothing
  else.
- **Localhost-only:** `build_server` binds `127.0.0.1` and refuses any
  non-loopback host; observed listening on `127.0.0.1:8080` (never `0.0.0.0`).
- **Separate from Chanakya source:** lives under `labs/`, imports nothing from
  `chanakya/`, and is excluded from the package (no `__init__.py`, not in
  `packages.find`/`MANIFEST.in`).
- **Not a Chanakya capability:** it is a target, not a registered capability;
  the registry still holds exactly the three capabilities in §4.
- Validation passes (`6 passed`). The lab was **not** expanded.

## 12. Known limitations

- `http_probe_local`: HTTP only (no HTTPS), `GET` only, no request body, no
  redirect following; the loopback **port** is a bounded parameter while the
  **host** is fixed; reads at most 4,096 body bytes (reports `body_truncated`).
- Resource limits other than output size and timeout remain declarative Registry
  metadata (no process isolation) — the same documented gap as the existing
  capabilities.
- A finding from this capability rates `informational` under the frozen v1 risk
  taxonomy's generic `observation` category; a non-informational severity would
  need an additive rule-set version (intentionally not added).
- Wheel/sdist build and `pip-audit` were not re-executed in this environment
  (tooling not installed); both are release-day steps against an unchanged
  packaging config and unchanged locks.

## 13. Release blockers

**None.** No release-blocking security, packaging, test, or documentation defect
was found. The items below are **non-blocking** and belong in the reviewed
release commit:

1. Bump `chanakya.__version__` `1.0.0` → `1.1.0`.
2. Update README `## Scope of v1.0.0` (capability count/list) and relabel to
   v1.1.0; update `ARCHITECTURE.md` implementation-status/§8 to include
   `http_probe_local`; update the doc-consistency tests that key off the literal
   `v1.0.0` strings — all in one coordinated commit.
3. (Release-day, unchanged from v1.0.0) build wheel + sdist and re-run
   `pip-audit` on the unchanged lock in a throwaway environment.

## 14. Recommended release version

**v1.1.0.** `http_probe_local` is a new, backward-compatible functional
capability (additive; no breaking change to any contract, CLI, or existing
capability). Under semantic versioning that is a **minor** bump: not a patch
(`v1.0.1` — it is a new feature), and not a major (`v2.0.0` — nothing is
breaking). The tag and version change are **deferred** until this report is
reviewed.

---

**RELEASE READINESS — PASS WITH NON-BLOCKING FINDINGS**

The tree is functionally and securely ready to release as **v1.1.0**. The only
outstanding work is the version bump and the documentation/version-label
corrections in §13, to be made in the reviewed release commit — no code, policy,
runtime, or dependency change is required.
