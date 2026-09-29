"""v1.0.0 release documentation stays consistent with the code (RP-5 to RP-9):
the README documents exactly the real capabilities, CLI options and refused
environment variables; ARCHITECTURE.md's package map matches the package; the
consolidated threat register covers every threat ID exactly once."""
from __future__ import annotations

import re
from pathlib import Path

import chanakya
from chanakya.cli.main import API_KEY_ENV_VAR, _parser
from chanakya.providers.anthropic_provider import FORBIDDEN_SDK_ENVIRONMENT, FORBIDDEN_TRANSPORT_ENVIRONMENT
from chanakya.registry.bootstrap import production_registry_entries

_REPO = Path(__file__).resolve().parent.parent
_README = (_REPO / "README.md").read_text(encoding="utf-8")
_ARCHITECTURE = (_REPO / "ARCHITECTURE.md").read_text(encoding="utf-8")
_THREAT_MODEL = (_REPO / "docs" / "THREAT-MODEL.md").read_text(encoding="utf-8")
_STATUSES = {"MITIGATED", "PARTIALLY MITIGATED", "RESIDUAL ACCEPTED", "FUTURE"}


def _capabilities() -> set:
    return {entry.capability for entry in production_registry_entries()}


def test_readme_capability_table_is_exactly_the_registered_set():
    section = _README.split("## Capabilities", 1)[1].split("\n## ", 1)[0]
    documented = set(re.findall(r"^\| `([a-z_]+)` \|", section, re.MULTILINE))
    assert documented == _capabilities() == {"observe_local_host_environment", "list_listening_ports"}


def test_readme_documents_every_cli_option_and_no_other():
    parser_options = {
        option for action in _parser()._actions for option in action.option_strings if option.startswith("--")
    }
    section = _README.split("## Command-line usage", 1)[1].split("\n## ", 1)[0]
    documented = set(re.findall(r"`(--[a-z-]+)", section))
    assert documented == parser_options


def test_readme_documented_commands_parse():
    parser = _parser()
    for block in re.findall(r"```\n(.*?)```", _README, re.DOTALL):
        for line in block.splitlines():
            if not line.startswith("chanakya ") or "[" in line or "--help" in line:
                continue
            argv = re.findall(r'"[^"]*"|\S+', line)[1:]
            args = parser.parse_args([a.strip('"') for a in argv])
            assert args.review is not None or args.objective


def test_readme_lists_every_refused_environment_variable():
    section = _README.split("## API key", 1)[1].split("\n## ", 1)[0]
    for name in FORBIDDEN_SDK_ENVIRONMENT + FORBIDDEN_TRANSPORT_ENVIRONMENT:
        if name.islower():
            assert "lower-case" in section
        else:
            assert f"`{name}`" in section, name
    assert f"`{API_KEY_ENV_VAR}`" in section


def test_readme_uses_only_a_placeholder_key():
    assert "YOUR_ANTHROPIC_API_KEY" in _README
    assert "sk-ant-" not in _README


def test_readme_states_one_tool_per_turn_and_the_disclosure():
    assert "at most one tool" in _README
    disclosure = _README.split("## Operator data disclosure", 1)[1].split("\n## ", 1)[0]
    for fact in ("hostname", "public IPv4/IPv6", "process id", "process executable name", "your objective",
                 "https://api.anthropic.com"):
        assert fact in disclosure, fact


def test_architecture_package_map_matches_the_package():
    section = _ARCHITECTURE.split("## Package map (v1.0.0)", 1)[1].split("\n## ", 1)[0]
    documented = set(re.findall(r"^  ([a-z_]+)/", section, re.MULTILINE))
    actual = {p.name for p in (_REPO / "chanakya").iterdir() if p.is_dir() and (p / "__init__.py").exists()}
    assert documented == actual
    assert "not started yet" not in _ARCHITECTURE


def test_consolidated_register_covers_every_threat_once():
    register = _THREAT_MODEL.split("### Consolidated threat register (v1.0.0)", 1)[1].split("\n## ", 1)[0]
    rows = re.findall(r"^\| (T-\d\d) \| [^|]+ \| ([A-Z ]+) \|", register, re.MULTILINE)
    assert [threat for threat, _ in rows] == [f"T-{n:02d}" for n in range(1, 66)]
    assert {status for _, status in rows} <= _STATUSES
    every_id_used = set(re.findall(r"\bT-(\d\d)\b", _THREAT_MODEL))
    assert every_id_used <= {f"{n:02d}" for n in range(1, 66)}


def test_package_docstring_describes_the_release():
    doc = chanakya.__doc__ or ""
    assert "Phase 2" not in doc and "Deliberately NOT implemented" not in doc
    for capability in _capabilities():
        assert capability in doc
