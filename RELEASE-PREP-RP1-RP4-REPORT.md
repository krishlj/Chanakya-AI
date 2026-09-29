# Release Preparation — RP-1 through RP-4

Scope: RP-1 to RP-4 from `FINAL-SECURITY-AUDIT-REPORT.md`. This is release preparation, not a security phase. No security architecture, control or test was changed. Nothing was pushed, and no `v1.0.0` tag exists.

| Item | Status |
|---|---|
| RP-1 Dependency declaration and locking | **PASS** |
| RP-2 Python version | **PASS** |
| RP-3 Vulnerability scan | **PASS** (no findings) |
| RP-4 Packaging | **PASS**. It was blocked only on license selection; MIT was selected and added in `56481af` (§12) |

## 1. Baseline

| Check | Result |
|---|---|
| Branch / HEAD | `main` at `91dca31 Fix Anthropic parallel tool request compatibility` ✔ |
| Latest architectural tag | `v0.20.0-durable-data-placement-confinement` ✔ |
| Working tree | only `PHASE-21-ARCHITECTURE-READINESS-REPORT.md`, `PHASE-21-ANTHROPIC-MULTI-TOOL-INVESTIGATION.md` and `FINAL-SECURITY-AUDIT-REPORT.md` untracked ✔ (left untouched) |
| `pytest -q` | 2970 passed |
| `pytest -q -W error` | 2970 passed, 0 warnings |

## 2. Dependency Inventory

Taken from an AST scan of every `import` in the source, not from the old metadata:

| Where | Third-party modules imported |
|---|---|
| `chanakya/` (runtime) | `anthropic` (`providers/anthropic_provider.py`, `providers/transport.py`), `httpx2` (`providers/transport.py`), `truststore` (`providers/transport.py`) |
| `tests/` | `pytest`, `anthropic`, `httpx2`, `truststore`, `pydantic` (`test_anthropic_provider_sdk_security.py`), `tomllib`/`tomli` (new packaging test; stdlib on ≥3.11) |

Before this change, `pyproject.toml` declared only `anthropic>=1.7.0,<2.0`. `httpx2` and `truststore` were used only transitively, and no test dependency was declared.

## 3. Direct Runtime Dependencies

```toml
dependencies = [
    "anthropic>=1.7.0,<2",     # provider SDK
    "httpx2>=2.13.0,<3",       # explicitly built and verified provider transport
    "truststore>=0.10.4,<1",   # system trust store for provider TLS
]
```

- The ranges bound the compatible major versions, and the lower bounds are the tested versions.
- The reproducible release set is the lock (§5–§6).
- A test (`test_every_third_party_import_is_a_declared_runtime_dependency`) now fails if `chanakya/` imports anything undeclared.

## 4. Test/Development Dependencies

```toml
[project.optional-dependencies]
test = [
    "pytest>=9.1.1",
    "pydantic>=2.13.5,<3",
    "tomli>=2.4.1; python_version < '3.11'",
]
```

- These are never installed at run time.
- `pydantic` and `tomli` were already in the resolved set (through `anthropic` and `pytest`), so declaring them added no package.

Build tooling (uv 0.12.20, pip-audit 2.10.1, build 1.6.1) ran from a throwaway environment and is **not** a project dependency.

## 5. Locking Method

- **Tool:** `uv pip compile` (uv 0.12.20). It reads PEP 621 metadata from `pyproject.toml`.
- **Mode:** `--universal --python-version 3.10`. Environment markers are resolved for every platform and every Python ≥ 3.10, so one lock serves Windows, Linux and macOS installs.
- **Hashes:** `--generate-hashes`; each pin lists the sha256 of every published distribution of that version.
- **Pins:** constrained to the exact versions of the tested development environment, so nothing was upgraded or downgraded.
- **Files:**
  - `requirements.lock`: runtime, 17 packages.
  - `requirements-test.lock`: runtime + `test` extra, 24 packages.
  - Both headers carry the install and regeneration commands. No local paths are embedded.
- **Reproducibility:** regenerating with the committed test lock as the constraint (`-c requirements-test.lock`) produced **byte-identical** output for both files. Adding `tomli` to the test extra left both locks unchanged.
- **Distribution:** `MANIFEST.in` ships both locks in the sdist.

Install:

```
python -m pip install --require-hashes -r requirements.lock
python -m pip install --no-deps chanakya-1.0.0-py3-none-any.whl
```

## 6. Resolved Release Versions

| Package | Version | Marker | Runtime | Test |
|---|---|---|:-:|:-:|
| anthropic | 1.7.0 | | ✔ | ✔ |
| httpx2 | 2.13.0 | | ✔ | ✔ |
| httpcore2 | 2.13.0 | `sys_platform != 'emscripten'` | ✔ | ✔ |
| truststore | 0.10.4 | | ✔ | ✔ |
| h11 | 0.16.0 | `sys_platform != 'emscripten'` | ✔ | ✔ |
| anyio | 4.15.1 | | ✔ | ✔ |
| idna | 3.20 | | ✔ | ✔ |
| sniffio | 1.3.1 | | ✔ | ✔ |
| jiter | 0.17.0 | | ✔ | ✔ |
| docstring-parser | 0.18.0 | | ✔ | ✔ |
| pydantic | 2.13.5 | | ✔ | ✔ |
| pydantic-core | 2.46.5 | | ✔ | ✔ |
| annotated-types | 0.8.0 | | ✔ | ✔ |
| typing-inspection | 0.4.4 | | ✔ | ✔ |
| typing-extensions | 4.16.0 | | ✔ | ✔ |
| exceptiongroup | 1.3.1 | `python_full_version < '3.11'` | ✔ | ✔ |
| httpx2-jsfetch | 1.0 | `>= '3.12' and sys_platform == 'emscripten'` (never installed on supported platforms) | ✔ | ✔ |
| pytest | 9.1.1 | | | ✔ |
| pluggy | 1.6.0 | | | ✔ |
| packaging | 26.3 | | | ✔ |
| iniconfig | 2.3.0 | | | ✔ |
| pygments | 2.21.0 | | | ✔ |
| colorama | 0.4.6 | `sys_platform == 'win32'` | | ✔ |
| tomli | 2.4.1 | `python_full_version < '3.11'` | | ✔ |

- This is the development baseline the whole suite has been run against (anthropic 1.7.0 / httpx2 2.13.0), so nothing moved.
- The audit's observation that an unlocked install resolves anthropic 1.9.0 / httpx2 2.13.1 is now handled by the lock. The declared ranges still allow those versions for users who install without it.

## 7. Hash Verification

- Every entry in both locks is an exact `==` pin with at least one `--hash=sha256:` (checked by a script, and continuously by `test_lock_is_fully_pinned_and_hashed`).
- Hash totals: 269 lines in `requirements.lock`, 328 in `requirements-test.lock`. Binary packages carry hashes for all published wheels (e.g. `pydantic-core` for every platform/ABI).
- `pip install --require-hashes -r requirements.lock` succeeded in fresh venvs. pip verified every downloaded file against the lock.
- `uv pip install --require-hashes -r requirements-test.lock` succeeded for Python 3.10, 3.11, 3.12 and 3.13.
- `test_runtime_lock_is_the_runtime_part_of_the_test_lock` keeps the two locks from drifting apart.

## 8. Python Version Support

- `requires-python` changed from `>=3.9` to **`>=3.10`**, the floor of the dependency stack: `anthropic`, `httpx2`, `httpcore2` and `truststore` all declare `Requires-Python >=3.10`.
- Classifiers list only versions that were actually tested.

Full suite, `-W error`, dependencies installed from `requirements-test.lock`:

| Interpreter | Result |
|---|---|
| CPython 3.10.21 (uv-managed) | 2970 passed |
| CPython 3.11.16 (uv-managed) | 2970 passed |
| CPython 3.12.14 (uv-managed) | 2970 passed |
| CPython 3.13.1 (development) | 2970 passed |

The new packaging tests (11) were then added and pass on 3.10 (the `tomli` path) and 3.13. The package builds with the new floor (§13).

All runs were on Windows x86-64. Linux is exercised through the existing fixture tests only (audit item NB-10, unchanged).

## 9. Vulnerability Scan

**Tool:** pip-audit 2.10.1, run with `--require-hashes --disable-pip` against each lock, which audits exactly the pinned versions without resolving anything new.

**Databases:** PyPI Advisory (which also validates hashes) and OSV.

| Dependency set | PyPI | OSV |
|---|---|---|
| `requirements.lock` (runtime) | No known vulnerabilities | No known vulnerabilities |
| `requirements-test.lock` (runtime + test) | No known vulnerabilities (21 packages audited on this interpreter) | No known vulnerabilities |
| The 3 marker-conditional pins not installable on the scanning interpreter (`exceptiongroup 1.3.1`, `tomli 2.4.1`, `httpx2-jsfetch 1.0`), audited explicitly by version | 0 vulnerabilities | 0 vulnerabilities |

| Finding | Severity | Blocks v1.0.0 |
|---|---|---|
| none (24/24 locked packages clean in both databases) | — | **No** |

No dependency version had to change. Scans reflect the advisory databases on 2026-09-29. Re-run pip-audit on the lock immediately before tagging v1.0.0 (non-blocking; part of the §20 release sequence).

## 10. Packaging Changes

| Change | File |
|---|---|
| `[build-system]`: `requires = ["setuptools>=77"]`, `build-backend = "setuptools.build_meta"` | `pyproject.toml` |
| Version **1.0.0**, single source: `dynamic = ["version"]` read from `chanakya.__version__` | `pyproject.toml`, `chanakya/__init__.py` (only the version string changed; its outdated docstring is RP-8) |
| Direct runtime dependencies and `test` extra (§3–§4) | `pyproject.toml` |
| `requires-python = ">=3.10"` | `pyproject.toml` |
| Metadata: `readme = "README.md"`, author (`krishlj`, from the Git identity, no e-mail), keywords, classifiers (console, security, Python 3.10–3.13), `Repository` URL (the configured `origin`) | `pyproject.toml` |
| Package discovery limited to `chanakya*` | `pyproject.toml` |
| Console script (§11) | `pyproject.toml` |
| Locks shipped in the sdist | `MANIFEST.in` (new) |
| Hashed locks | `requirements.lock`, `requirements-test.lock` (new) |
| Packaging regression tests (11) | `tests/test_release_packaging.py` (new) |
| Stale "not-yet-implemented Phase 5.6" dependency comment | replaced |

License metadata was added in the follow-up commit `56481af` (§12). The build backend is not itself locked. Builds use PEP 517 isolation with `setuptools>=77`; the wheel is pure Python, and its contents do not depend on the setuptools version.

## 11. Console Script

```toml
[project.scripts]
chanakya = "chanakya.cli.main:main"
```

- It calls the existing `main()`; no CLI code was duplicated.
- The generated launcher exits with `main()`'s return code: exit 0 for `--help`, and exit 2 on a missing `ANTHROPIC_API_KEY`, as before.
- `python -m chanakya.cli` (`chanakya/cli/__main__.py`) is unchanged and works.
- Both paths print the same `usage: chanakya …`. `test_console_script_and_module_share_behavior` checks this.

## 12. License Status

**MIT, selected by the project owner. RP-4: PASS.**

*History:* the first pass found no licensing decision anywhere in the repository. The owner chose "Decide later", so RP-4 was reported **BLOCKED — LICENSE SELECTION REQUIRED**, and nothing was invented. The owner then selected the MIT License.

| Item | Result |
|---|---|
| License selected | MIT (owner decision) |
| `LICENSE` added | standard MIT text, `Copyright (c) 2026 krishlj`. The holder is the author already declared in `pyproject.toml` (`authors`) and the repository's Git identity |
| Package metadata | PEP 639, supported by the existing `setuptools>=77` backend: `license = "MIT"`, `license-files = ["LICENSE"]`. No `License ::` classifier, which would conflict with the SPDX expression. No deprecated `license = {text=…}` table |
| Built metadata | `Metadata-Version: 2.4`, `License-Expression: MIT`, `License-File: LICENSE` in the wheel `METADATA` and the sdist `PKG-INFO` |
| Wheel | contains `chanakya-1.0.0.dist-info/licenses/LICENSE`, byte-identical to the repository file |
| sdist | contains `chanakya-1.0.0/LICENSE` |
| Build warnings | none (no setuptools deprecation or license warnings) |
| Regression test | `test_license_is_mit_and_declared_once` pins the metadata, the holder line and the MIT warranty clause |

## 13. Clean Installation Test

Built from a clean copy of the committed tree in the session scratchpad (never the repository), with `python -m build`:

| Artifact | sha256 |
|---|---|
| `chanakya-1.0.0-py3-none-any.whl` | `68f70214a2c851c5ad8f3c717474e8bac22e003acddf805c25641c3d19738f0b` |
| `chanakya-1.0.0.tar.gz` (205 entries, includes `tests/`, `README.md`, both locks) | `0e7c21dda6a33d2b51a3d1b432a0b49a746a89256b8f7a8ee3cbc5b11f418e21` |

Wheel metadata: `Version: 1.0.0`, `Requires-Python: >=3.10`, `Requires-Dist` = the three runtime dependencies plus the `test` extra; `entry_points.txt` has `chanakya = chanakya.cli.main:main`; the only top-level package is `chanakya`.

Fresh venv, run from an empty directory outside the repository and the build tree:

| Step | Result |
|---|---|
| 1. Build wheel | ✔ |
| 2. Build sdist | ✔ |
| 3. Fresh virtual environment | ✔ |
| 4. Runtime dependencies from `requirements.lock` with `--require-hashes`, then the wheel with `--no-deps` | ✔ |
| `pip check` | ✔ No broken requirements |
| 5. `python -c "import chanakya"` | ✔ imported from the venv's `site-packages` |
| 6. `chanakya --help` | ✔ exit 0 |
| 7. `python -m chanakya.cli --help` | ✔ exit 0 |
| 8. Version | ✔ `chanakya.__version__ == importlib.metadata.version("chanakya") == "1.0.0"` |
| 9. Dependencies from the lock | ✔ anthropic 1.7.0, httpx2 2.13.0, httpcore2 2.13.0, truststore 0.10.4, pydantic 2.13.5 … exactly the lock |
| sdist installs in a second fresh venv and provides `chanakya` | ✔ |
| Missing API key | ✔ `error: environment variable ANTHROPIC_API_KEY is not set`, exit 2, nothing written |
| Installed `chanakya --review c6fd58a7-… --workdir D:/Chanakya-Data` (read-only) | ✔ completed; chain verified (41), consistent, 2 evidence records, 10 findings, 9 risk assessments, 0 anomalies |

**License follow-up (`56481af`), repeated from a clean copy of the new tree:**

| Artifact | sha256 |
|---|---|
| `chanakya-1.0.0-py3-none-any.whl` | `46990590c57b2fa7ff1e380f12c1172abf5a8ef9cc560dea207e518cde681c07` |
| `chanakya-1.0.0.tar.gz` | `a01cc2a17f031fd237648514e475408444f96d3dbec4208be31e1f6178b2da9a` |

| Check | Result |
|---|---|
| Wheel installs (runtime from `requirements.lock` with `--require-hashes`, wheel with `--no-deps`) | ✔ |
| `pip check` | ✔ No broken requirements |
| Version | ✔ `1.0.0` (`__version__` and distribution metadata) |
| `chanakya --help` / `python -m chanakya.cli --help` | ✔ exit 0 / ✔ exit 0 |
| License metadata of the installed distribution | ✔ `License-Expression: MIT`, `License-File: LICENSE` |
| LICENSE installed | ✔ `chanakya-1.0.0.dist-info/licenses/LICENSE` |
| Runtime dependencies | ✔ from the locked set: anthropic 1.7.0, httpx2 2.13.0, httpcore2 2.13.0, truststore 0.10.4, pydantic 2.13.5 |
| sdist installs in a second fresh venv | ✔ provides `chanakya`, and its metadata reports `License-Expression: MIT` |

No real Anthropic investigation was run from the clean environment; that is reserved for final release validation. The API key was not read or printed.

## 14. Security Regression

| Run | Result |
|---|---|
| `pytest -q` (repository, Python 3.13.1) | **2981 passed** (2970 + 11 new packaging tests), 0 failed, 0 skipped, 0 xfailed |
| `pytest -q -W error` | **2981 passed**, 0 warnings |
| 3.10 / 3.11 / 3.12 / 3.13 matrix from the hashed lock (`-W error`) | 2970 passed on each, before the 11 new tests were added |
| After the MIT license (`56481af`): `pytest -q` / `pytest -q -W error` | **2982 passed** (2981 + 1 license test) / **2982 passed, 0 warnings**; 0 failed, 0 skipped, 0 xfailed |
| Packaging tests after the license (`-W error`) | 12 passed on 3.13 and on 3.10 |

- No existing test was removed or changed, and no security assertion was touched.
- No file under `chanakya/` changed except the version string.

The whole existing suite passes unchanged on every interpreter, so these all remain intact:
- CT-INV-3 and `MULTIPLE_TOOL_USE_BLOCKS`;
- Policy Gateway enforcement and the Capability Envelope;
- output screening and Evidence integrity;
- finding grounding and the deterministic Risk Engine;
- the audit chain and read-only Review;
- provider transport isolation and logging protection;
- Phase 20 data placement.

## 15. Git Commit

- **Commit:** `69da3d1` (`69da3d12368ce75834abe0b824104ba0127ce7b2`) "Prepare v1.0.0 dependencies and packaging".
- **Contents (6 files):**
  - `pyproject.toml`
  - `chanakya/__init__.py`
  - `MANIFEST.in`
  - `requirements.lock`
  - `requirements-test.lock`
  - `tests/test_release_packaging.py`
- **License commit:** `56481af` (`56481afc632c854f30309f7deb937c824a23facc`) "Add MIT license for v1.0.0". Contents (3 files): `LICENSE` (new), `pyproject.toml` (`license`, `license-files`), `tests/test_release_packaging.py` (+1 test).
- **Not committed:** the three existing reports, and this report.
- **GitHub push:** NO.
- **`v1.0.0` tag:** NOT CREATED.
- **Working tree:** clean apart from the four untracked reports.

**Environment side effects outside the repository:**
- uv installed CPython 3.10.21, 3.11.16 and 3.12.14 under `%APPDATA%\uv\python`. Remove them with `uv python uninstall 3.10 3.11 3.12` if unwanted.
- Tooling, virtual environments and build artifacts are in the session scratchpad.

## 16. Remaining RP-5 through RP-9 Work

| ID | Remaining | Blocks v1.0.0 |
|---|---|---|
| RP-4 (residual) | ~~License selection~~: **done**, MIT in `56481af` | — |
| RP-5 | LICENSE file: **done** with RP-4 (`56481af`) | — |
| RP-6 | README: install from the lock (`--require-hashes`), `chanakya` command, Python ≥3.10, platforms (Windows/Linux; ports capability fails closed elsewhere), API key, usage, approval/review, read-only default-allow, one-tool-per-turn, free-form approver identity | **Yes** |
| RP-7 | Operator data disclosure (host telemetry and objective sent to Anthropic; storage location; not encrypted at rest; credentials not in Evidence) | **Yes** |
| RP-8 | `ARCHITECTURE.md` drift; `chanakya/__init__.py` docstring (still "Phase 2") | **Yes** |
| RP-9 | Consolidated threat register with final statuses | **Yes** |
| — | Re-run pip-audit on the lock just before tagging | No (release-day check) |
| NB-10 | Real-provider smoke test on Linux | No (recommended) |
