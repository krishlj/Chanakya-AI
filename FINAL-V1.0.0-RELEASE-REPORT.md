# Chanakya AI — v1.0.0 Local Release Report

This report is written after tagging, so it is not part of the tagged tree. It
is left untracked; see "Note on this report" below.

| # | Item | Result |
|---|---|---|
| 1 | Release version | **1.0.0** (`chanakya.__version__`, package metadata) |
| 2 | Source commit before the release-evidence commit | `97cc10892b02c8768fa6a8ca82b2b86799ae7925` (`97cc108 Finalize v1.0.0 documentation`), the commit validated in `FINAL-RELEASE-VALIDATION-REPORT.md` |
| 3 | Final release commit | `1f816352f98704a310408fd02daacea8d4d0f9f6` (`1f81635 Document v1.0.0 release validation`) |
| 4 | Tag name | `v1.0.0` (annotated, message "Chanakya AI v1.0.0") |
| 5 | Tag target commit | `1f816352f98704a310408fd02daacea8d4d0f9f6` (= HEAD of `main`) |
| 6 | Test results | **PASS**: `pytest -q` 2991 passed; `pytest -q -W error` 2991 passed, 0 warnings; 0 failed, 0 skipped, 0 xfailed |
| 7 | pip-audit | **PASS**: 0 known vulnerabilities; PyPI and OSV; all 17 `requirements.lock` entries covered |
| 8 | Secret scan | **PASS**: no real credentials |
| 9 | Package build | **PASS**: wheel and sdist from the exact commit, no warnings |
| 10 | Clean install | **PASS**: fresh venv, locked install with `--require-hashes`, `pip check` clean |
| 11 | Real Anthropic validation | **PASS**: investigation `bb5fff86-8a52-4c95-b2b0-da047628a1b9` from the installed package |
| 12 | Review | **PASS**: completed; audit chain verified (36 records); consistent; 0 anomalies |
| 13 | Evidence / Findings / Risk | 2 / 7 / 7 |
| 14 | Documentation reports committed | 6 reports in `1f81635` (below) |
| 15 | Non-blocking findings | 3 (below) |
| 16 | Security behavior changed | **No** |
| 17 | GitHub push | **Not performed** |

## Release history

```
1f81635 (HEAD -> main, tag: v1.0.0) Document v1.0.0 release validation
97cc108 Finalize v1.0.0 documentation
56481af Add MIT license for v1.0.0
69da3d1 Prepare v1.0.0 dependencies and packaging
91dca31 Fix Anthropic parallel tool request compatibility
0c07286 (tag: v0.20.0-durable-data-placement-confinement) Confine durable investigation data placement
```

- `97cc108` is an ancestor of `1f81635`; no history was rewritten or amended.
- Tags: the 32 earlier tags are unchanged, plus `v1.0.0`, 33 in total. No other tag was created.

## Final local checks (this step)

| Step | Check | Result |
|---|---|---|
| 1 | HEAD `97cc108`; tracked tree clean; only the six reports untracked | PASS |
| 2 | Each of the six reports scanned individually | PASS: no credential. Only scan-pattern names (`sk-ant-` as text, no token body) and the `x-api-key` header name |
| 3 | Tracked files (198 at the time), full Git history (all refs), locks, docs, wheel (101 files), sdist (198 files), and the actual `ANTHROPIC_API_KEY` value compared in memory | **NO REAL CREDENTIALS**. Classified matches: 4 synthetic sentinel test keys; 10 PEM header-only fixtures (no key body); 5 screening-test assignments; `x-api-key` header names; scan-pattern text. No real-format Anthropic key, AWS, GitHub, Slack, Google or JWT token; the key value appears nowhere |
| 4 | pip-audit on `requirements.lock` (`--require-hashes --disable-pip`), PyPI and OSV, plus the 2 marker-conditional pins | PASS: 15 + 2 audited per source, 0 vulnerabilities; locks unmodified |
| 5 | `pytest -q` / `pytest -q -W error` | PASS: 2991 / 2991, 0 warnings; the run left no changes |
| 6 | Staged set = exactly the six reports (all `A`, 2033 insertions) | PASS; committed as `1f81635` |
| 7 | Commit verification | PASS: working tree clean; commit touches only the six `.md` reports; 0 files differ from `97cc108` under `chanakya/`, `tests/`, locks, `pyproject.toml`, `MANIFEST.in`, `LICENSE`, `README.md`, `ARCHITECTURE.md` or `docs/` |
| 8 | Release tree | PASS: 204 tracked files (95 `chanakya/`, 85 `tests/`, 24 top-level/docs/release); all release documents tracked; no untracked files; only `__pycache__`/`.pytest_cache` ignored on disk |
| 9 | `git tag -a v1.0.0 -m "Chanakya AI v1.0.0" 1f81635` | PASS: tag object of type `tag`, target `1f81635`. `git tag -v` reports **"error: no signature found"** because the tag is annotated but unsigned; no GPG signing key is configured, and signing was not requested |
| 10 | Pre-push state | PASS: clean tree; `v1.0.0` → `1f81635` = HEAD; exactly 4 commits after `91dca31`; no remote-tracking refs and no upstream configured, so nothing has been pushed |

## Build, install and live validation (from `FINAL-RELEASE-VALIDATION-REPORT.md`, commit `97cc108`)

**Build.** Wheel and sdist were built from `97cc108` with no warnings:

| Artifact | sha256 |
|---|---|
| `chanakya-1.0.0-py3-none-any.whl` | `18e5be0163aadde124ad4d4da1a3b5e23b5aa0d28b40f3ebebdaa3b41a5642c1` |
| `chanakya-1.0.0.tar.gz` | `187c323fa06f64280bb55a09478f20e72aaceb1eedf379b3b5bdd74f1a2ab31e` |

- Both carry version 1.0.0 and MIT license metadata, with LICENSE included.
- The sdist also includes `README.md`, both locks, `ARCHITECTURE.md` and `docs/`.
- `1f81635` adds only top-level reports, which are not part of the wheel. Rebuilding from the tag gives the same package code and metadata. The sdist would additionally list nothing new, because the reports aren't in `MANIFEST.in`.

**Clean install.**
- A fresh venv outside the repository, Python 3.13.1, Windows 11 AMD64.
- Installed from `requirements.lock` with `--require-hashes`, then the wheel with `--no-deps`.
- `pip check` is clean, and every installed version matches the lock.
- The package imports from the venv, not the repository.
- `chanakya --help` and `python -m chanakya.cli --help` both work.
- Clean-environment test run: 2991 / 2991 (`-W error`). The installed modules are byte-identical to the tested source (95/95).

**Real Anthropic investigation** `bb5fff86-8a52-4c95-b2b0-da047628a1b9`:
- run from the installed `chanakya` command with `--require-approval` and the out-of-repository workdir `D:\Chanakya-Data-Release-Smoke`;
- turn 1 `observe_local_host_environment` and turn 2 `list_listening_ports`: each exactly one `tool_use` block, Policy Gateway `require_approval`, approved, executed;
- turn 3 `report_findings`, then completed.

| Record | Count |
|---|---|
| Evidence (verified, screened) | 2 |
| Findings (each cites its evidence) | 7 |
| Risk assessments (`chanakya-risk-rules/1.0.0`) | 7 |
| Audit records (chain verified) | 36 |
| Review anomalies | 0 |

- The durable data stayed outside the repository.
- No credential appears in Evidence, Findings, audit records, terminal output or review output.
- Review was read-only: the workdir file count was unchanged.

## Documentation reports committed (`1f81635`)

- `FINAL-SECURITY-AUDIT-REPORT.md`
- `RELEASE-PREP-RP1-RP4-REPORT.md`
- `RELEASE-PREP-RP5-RP9-REPORT.md`
- `FINAL-RELEASE-VALIDATION-REPORT.md`
- `PHASE-21-ARCHITECTURE-READINESS-REPORT.md`
- `PHASE-21-ANTHROPIC-MULTI-TOOL-INVESTIGATION.md`

## Non-blocking findings

1. **No `--version` CLI option.** `chanakya --version` exits 2 with a usage error. The version is available through `python -c "import chanakya; print(chanakya.__version__)"`, which is documented. Not added, as instructed.
2. **The test suite imports the adjacent source tree** (`tests/conftest.py`). This was verified to be byte-identical to the installed wheel. Test infrastructure is unchanged, as instructed.
3. **An Anthropic HTTP 503 outage occurred during validation.** The first live attempt (`77f6860b-…`) failed closed: no retry, nothing executed, recorded, and its review is consistent. The next attempt completed.

Also noted:
- **Unsigned tag.** The tag is annotated but not GPG-signed, so `git tag -v` cannot verify a signature. If signed releases are wanted, a signing key must be configured and the tag re-created as signed, before publishing and with your approval.
- **Identity on push.** The commits and the tag carry the repository's configured Git identity (name and e-mail). Pushing publishes that identity.

## Confirmations

- **No security behavior changed** in this step, or since the validated commit `97cc108`. `1f81635` adds only the six documentation reports, and 0 files differ from `97cc108` in source, tests, dependencies, locks, packaging or documentation. No Policy Gateway, Runtime, capability, provider, threat-model, dependency, lock or test change was made. No `--version` was added.
- **GitHub push has NOT occurred.** There is no upstream, no remote-tracking ref, and no push command was run.

## Note on this report

This file is created after the tag, so it is not in `v1.0.0`. It is the only untracked file. Commit it separately after publication review, or keep it local; committing it now would move `main` ahead of `v1.0.0`.

---

**V1.0.0 LOCAL RELEASE — READY TO PUBLISH**
