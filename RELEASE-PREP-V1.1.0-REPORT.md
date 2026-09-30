# RELEASE-PREP-V1.1.0-REPORT

Coordinated v1.1.0 release-metadata preparation. Only version, release/scope
documentation wording, and the version-tied documentation-consistency tests were
changed. No source behavior, no dependency, and no security control was modified.
No tag was created; nothing was pushed.

**Final verdict: V1.1.0 RELEASE PREPARATION — PASS**

---

## 1. Previous version

`1.0.0` (tag `v1.0.0` → `1f816352f98704a310408fd02daacea8d4d0f9f6`, unchanged).

## 2. New version

`1.1.0` — SemVer **minor** bump (a new backward-compatible security capability,
`http_probe_local`, was added; nothing is breaking). `chanakya.__version__` now
resolves to `1.1.0`, and both built artifacts report `1.1.0`.

## 3. Release commit scope

Exactly the coordinated release-metadata changes, in five files:

| File | Change |
|---|---|
| `chanakya/__init__.py` | `__version__` `1.0.0` → `1.1.0`. |
| `README.md` | Version/scope wording `v1.0.0` → `v1.1.0` where it describes the current release; capability count two → **three**; `http_probe_local` added to scope, platform notes, data-disclosure list, egress note, and install/version strings. |
| `ARCHITECTURE.md` | "Implementation status" and related current-release labels `v1.0.0` → `v1.1.0`; §8 Tool Layer lists `http_probe_local` (and the "no network traffic" claim corrected — the probe makes one loopback request); "Package map" heading bumped; delivered-scope note updated. |
| `tests/test_release_documentation.py` | Package-map split string `(v1.0.0)` → `(v1.1.0)`. |
| `tests/test_release_packaging.py` | Version assertion `1.0.0` → `1.1.0` (and the test renamed accordingly). |

No other file was changed. No unrelated documentation change was made.

## 4. Current capabilities

Three, all `local_host`-only, all read-only classification, all with closed
output schemas — now consistently documented as such:

1. `observe_local_host_environment` — observe / P1 / no approval.
2. `list_listening_ports` — observe / P1 / no approval.
3. `http_probe_local` — execute_readonly_probe / **P2** / **approval required**;
   one bounded HTTP GET to `127.0.0.1`.

No Nmap, Nessus, Semgrep, Trivy, YARA, Metasploit, exploitation, remote/cloud
targets, or shell/arbitrary command execution exists, and none is claimed as
implemented. The broader product vision remains documented separately as future
scope (ARCHITECTURE §20 "Future Extensibility"), distinct from the current
implementation.

## 5. Documentation changes

- README `## Capabilities` table already listed all three; the surrounding
  release framing now matches: intro ("three read-only capabilities"),
  `## Scope of v1.1.0` (lists all three), platform-support notes, the
  operator-data-disclosure list (adds what `http_probe_local` collects), the
  model-egress note ("All three v1.1.0 capabilities"), and the version strings in
  the install commands.
- ARCHITECTURE "Implementation status at v1.1.0", §8 Tool Layer (adds
  `http_probe_local`; corrects the network-traffic statement), the diagram note,
  §15 config note, "Package map (v1.1.0)", and the delivered-scope paragraph.
- **Intentionally preserved** (historical/meaning-preserving): the named artifact
  "Consolidated threat register (v1.0.0)" in `docs/THREAT-MODEL.md` and the two
  references to it are left at `v1.0.0` — that register is the v1.0.0 threat
  snapshot and was not re-derived for the new capability, so relabelling it would
  overstate its coverage. Likewise "released as v1.0.0 with that scope" remains as
  an accurate historical statement (with a note that v1.1.0 added the third
  capability). `docs/THREAT-MODEL.md` was **not** modified.

## 6. Test results

| Run | Result |
|---|---|
| `pytest -q` | **3056 passed** (0 failed, 0 skipped, 0 xfailed) |
| `pytest -q -W error` | **3056 passed** (0 warnings) |

The count is unchanged from the pre-commit baseline: no test was added or removed.
Two existing release-metadata tests were **updated in place** to validate the
v1.1.0 documentation and version (the package-map heading split and the
`__version__ == "1.1.0"` assertion) — corrections to keep them accurate, not
weakenings, exactly as item 6 of the task required.

## 7. Package build results

Both artifacts built cleanly (isolated PEP 517 backend; **no build warnings**):

| Artifact | Result |
|---|---|
| `chanakya-1.1.0-py3-none-any.whl` | Version 1.1.0; `License-Expression: MIT`; `Requires-Dist`: anthropic, httpx2, truststore (+ test extras) — unchanged; top level is `chanakya` + dist-info only. |
| `chanakya-1.1.0.tar.gz` (sdist) | `PKG-INFO` version 1.1.0; ships `LICENSE`, `requirements.lock`, `requirements-test.lock` (per `MANIFEST.in`). |

Verified:
- **version = 1.1.0** in both. ✔
- **MIT license** present (`dist-info/licenses/LICENSE`; `License-Expression: MIT`). ✔
- **`requirements.lock` unchanged**, **`requirements-test.lock` unchanged**
  (`git diff v1.0.0..HEAD` on both is empty). ✔
- **No new dependency** (`http_probe_local` is standard-library only; `pyproject.toml`
  unchanged). ✔
- **`labs/local-xss` excluded** from both wheel and sdist (not a package, no
  `__init__.py`, not in `MANIFEST.in`; `packages.find` includes only `chanakya*`). ✔
- `http_probe_local` handler is present in both artifacts. ✔

(Build tooling is intentionally not a project dependency; it was used transiently
and did not alter the project or its locks. Any stray local build directory was
removed and is not committed.)

## 8. Secret scan

Scanned the whole tracked tree for `sk-ant-*` tokens, PEM private-key headers,
Slack/GitHub/AWS tokens. **PASS** — the only matches are pre-existing, deliberate
**test fixtures** (fake `sk-ant-phase…`, `AKIASECRET…`, `ghp_…`, and
`BEGIN … PRIVATE KEY` strings) that exercise the credential-screening logic in
seven test files; none is a real credential, and **none is modified by this
commit**. The README contains only the placeholder `YOUR_ANTHROPIC_API_KEY` (no
`sk-ant-` string). No secret values are printed in this report.

## 9. Dependency status

**Unchanged from v1.0.0.** Runtime deps remain `anthropic>=1.7.0,<2`,
`httpx2>=2.13.0,<3`, `truststore>=0.10.4,<1`; test extras unchanged. No dependency
was added, upgraded, or downgraded. `requirements.lock` and `requirements-test.lock`
are byte-identical to v1.0.0, so v1.0.0's clean `pip-audit` result (0 known
vulnerabilities) continues to apply. `pip-audit` on the unchanged lock remains a
release-day step in a throwaway environment.

## 10. XSS lab status

`labs/local-xss/` is **unchanged** by this commit and remains training-only,
deliberately vulnerable, localhost-only, separate from the Chanakya source, not a
registered capability, and excluded from the distribution. It is not part of the
Chanakya test suite (`testpaths = ["tests"]`).

## 11. Security behavior unchanged

No change was made to the Policy Gateway, Agent Runtime, Evidence, Findings, Risk
Engine, Human Approval, Audit, Review, provider, transport security, target
security boundaries, the `http_probe_local` implementation, the risk rule set
(`chanakya-risk-rules/1.0.0`, untouched), or the security architecture. The
release-prep diff is confined to version metadata, release/scope documentation
wording, and two version-tied test assertions. The full suite (including all
security-invariant and adversarial tests) passes under both `pytest -q` and
`pytest -q -W error`.

## 12. Known non-blocking limitations

- `http_probe_local`: HTTP only, `GET` only, no request body, no redirect
  following; loopback **port** is a bounded parameter while the **host** is a
  fixed constant; reads at most 4,096 body bytes.
- Resource limits other than output size and timeout remain declarative Registry
  metadata (no process isolation) — the pre-existing, documented gap.
- The "Consolidated threat register (v1.0.0)" retains its v1.0.0 label; it has not
  been re-derived to add threat entries specific to `http_probe_local`. This is a
  documentation-scope note, not a functional gap, and was intentionally left
  unchanged per the release scope.
- `pip-audit` and the artifact build are release-day steps in a throwaway
  environment; both were exercised here against the unchanged lock/config with no
  findings and no warnings.

---

**V1.1.0 RELEASE PREPARATION — PASS**

The tree is ready to be tagged `v1.1.0` after this release-preparation commit is
reviewed. No tag was created and nothing was pushed.
