"""Release packaging: declared dependencies, Python support, version, console
script and the hashed locks stay consistent with the code (v1.0.0 release
preparation, RP-1 through RP-4)."""
from __future__ import annotations

import ast
import re
import sys
from pathlib import Path

import pytest

try:
    import tomllib
except ModuleNotFoundError:  # Python 3.10
    import tomli as tomllib

import chanakya
from chanakya.cli import main as cli_main

_REPO = Path(__file__).resolve().parent.parent
_PYPROJECT = tomllib.loads((_REPO / "pyproject.toml").read_text(encoding="utf-8"))
_PROJECT = _PYPROJECT["project"]
_LOCKS = ("requirements.lock", "requirements-test.lock")


def _name(requirement: str) -> str:
    return re.split(r"[\s;<>=!~\[(]", requirement, maxsplit=1)[0].lower().replace("_", "-")


def _third_party_imports() -> set:
    found = set()
    for path in (_REPO / "chanakya").rglob("*.py"):
        for node in ast.walk(ast.parse(path.read_text(encoding="utf-8"))):
            if isinstance(node, ast.Import):
                names = [alias.name for alias in node.names]
            elif isinstance(node, ast.ImportFrom) and node.level == 0 and node.module:
                names = [node.module]
            else:
                continue
            for name in names:
                top = name.split(".")[0]
                if top != "chanakya" and top not in sys.stdlib_module_names:
                    found.add(top.lower().replace("_", "-"))
    return found


def _lock(name: str) -> dict:
    """``{package: version}`` for one lock; every entry must be an exact pin
    carrying at least one sha256 hash."""
    text = (_REPO / name).read_text(encoding="utf-8")
    entries = {}
    for block in re.split(r"\n(?=[a-z0-9])", text):
        if block.startswith("#") or not block.strip():
            continue
        head = block.split("\\", 1)[0].strip()
        match = re.fullmatch(r"([a-z0-9][a-z0-9._-]*)==([0-9][^\s;]*)(\s*;.*)?", head)
        assert match, f"{name}: not an exact pin: {head!r}"
        assert "--hash=sha256:" in block, f"{name}: {match.group(1)} has no hash"
        entries[match.group(1)] = match.group(2)
    return entries


def test_every_third_party_import_is_a_declared_runtime_dependency():
    declared = {_name(r) for r in _PROJECT["dependencies"]}
    assert _third_party_imports() <= declared
    assert declared == {"anthropic", "httpx2", "truststore"}


def test_test_only_dependencies_are_an_extra_not_runtime():
    runtime = {_name(r) for r in _PROJECT["dependencies"]}
    test = {_name(r) for r in _PROJECT["optional-dependencies"]["test"]}
    assert "pytest" in test and "pytest" not in runtime
    assert not runtime & test


def test_python_support_matches_the_dependency_stack():
    assert _PROJECT["requires-python"] == ">=3.10"
    assert sys.version_info >= (3, 10)


def test_version_has_one_source_and_is_1_0_0():
    assert "version" not in _PROJECT and "version" in _PROJECT["dynamic"]
    assert _PYPROJECT["tool"]["setuptools"]["dynamic"]["version"] == {"attr": "chanakya.__version__"}
    assert chanakya.__version__ == "1.0.0"


def test_build_system_is_declared():
    assert _PYPROJECT["build-system"]["build-backend"] == "setuptools.build_meta"
    assert any(_name(r) == "setuptools" for r in _PYPROJECT["build-system"]["requires"])


def test_console_script_is_the_existing_cli_entry_point():
    assert _PROJECT["scripts"] == {"chanakya": "chanakya.cli.main:main"}
    assert callable(cli_main.main)


def test_console_script_and_module_share_behavior(capsys):
    with pytest.raises(SystemExit) as exit_info:
        cli_main.main(["--help"])
    assert exit_info.value.code == 0
    assert capsys.readouterr().out.startswith("usage: chanakya ")


@pytest.mark.parametrize("name", _LOCKS)
def test_lock_is_fully_pinned_and_hashed(name):
    entries = _lock(name)
    assert {"anthropic", "httpx2", "truststore"} <= set(entries)


def test_runtime_lock_is_the_runtime_part_of_the_test_lock():
    runtime, test = _lock("requirements.lock"), _lock("requirements-test.lock")
    assert set(runtime) <= set(test)
    assert all(test[package] == version for package, version in runtime.items())
    assert "pytest" in test and "pytest" not in runtime


def test_locks_ship_in_the_source_distribution():
    manifest = (_REPO / "MANIFEST.in").read_text(encoding="utf-8")
    assert "include requirements.lock requirements-test.lock" in manifest
