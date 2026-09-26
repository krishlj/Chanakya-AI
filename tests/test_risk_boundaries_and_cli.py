"""Phase 10 — CLI display (10.8), provider taxonomy hint (10.7), scoped
evidence verification, and static import boundaries (RA-INV-1, 2, 5, 11).
"""
from __future__ import annotations

import ast
import io
import json
from pathlib import Path

import pytest

import chanakya.cli.main as cli_main
from chanakya.capability.reserved import RESERVED_FINDING_TOOL
from chanakya.contracts.audit_event import AuditEventType
from chanakya.contracts.investigation_context import InvestigationStatus
from chanakya.contracts.risk_taxonomy import RISK_CATEGORY_IDS
from chanakya.evidence import EvidenceStore
from chanakya.evidence.store import CorruptEvidenceError, InvalidIdentifierError, UnknownEvidenceError
from chanakya.evidence.hashing import compute_content_hash
from chanakya.providers import mapping
from chanakya.runtime.agent_turn import AgentTurnOutput

from risk_factories import put_evidence
from test_anthropic_provider import _config
from test_findings import HOSTILE, Block, Response, assembled, cli_run, finding_dict
from test_anthropic_provider_sdk_security import SENTINEL_KEY  # noqa: F401
from test_anthropic_provider_sdk_security import _offline_guard  # noqa: F401 — autouse offline guard

E = AuditEventType
_REPO_ROOT = Path(__file__).resolve().parent.parent
_CHANAKYA = _REPO_ROOT / "chanakya"

# ===========================================================================
# CLI (real composition root, fake Anthropic HTTP; the fake model observes
# the host environment, so platform_configuration is the compatible category)
# ===========================================================================


def test_cli_rates_stores_audits_and_displays_a_rated_finding(tmp_path):
    runtime, context, shown, _ = cli_run(tmp_path, lambda ids: [finding_dict(ids, category="platform_configuration")])
    assert context.status == InvestigationStatus.COMPLETED
    (ra,) = runtime.risk_store.list_by_investigation(context.investigation_id)
    assert (tmp_path / "risk" / context.investigation_id / f"{ra.risk_assessment_id}.json").is_file()
    trail = [r.event.event_type for r in runtime.audit_log.list_by_investigation(context.investigation_id)]
    assert trail.index(E.FINDING_CREATED) < trail.index(E.RISK_ASSESSED) < trail.index(E.INVESTIGATION_COMPLETED)
    assert runtime.audit_log.verify(context.investigation_id)  # the durable chain stays valid
    assert cli_main._RISK_HEADER in shown
    assert 'rule-based risk ("chanakya-risk-rules/1.0.0"):' in shown
    assert 'severity: "low"' in shown and 'basis confidence: "medium"' in shown
    assert 'agent-reported confidence: "medium"' in shown and 'category: "platform_configuration"' in shown
    assert "rules: " in shown and '"ceiling.read_only"' in shown


@pytest.mark.parametrize(
    "category,reason",
    [("network_exposure", "evidence_incompatible"), ("exposure", "category_unrated"), (None, "category_unrated")],
)
def test_cli_shows_not_assessed_explicitly_and_never_as_safe(tmp_path, category, reason):
    extra = {"category": category} if category else {}
    build = (lambda ids: [finding_dict(ids, **extra)]) if category else (
        lambda ids: [{"title": "RDP exposed", "description": "d", "evidence_refs": ids}])
    runtime, context, shown, _ = cli_run(tmp_path, build)
    assert context.status == InvestigationStatus.COMPLETED
    assert f'rule-based risk: not assessed ("{reason}")' in shown
    assert runtime.risk_store.list_by_investigation(context.investigation_id) == ()
    lowered = shown.lower()
    for phrase in ("safe", "no risk", "low risk", "severity:"):
        assert phrase not in lowered, phrase


def test_cli_withholds_ratings_that_fail_verification(tmp_path):
    runtime, context, _, _ = cli_run(tmp_path, lambda ids: [finding_dict(ids, category="platform_configuration")])
    (ra,) = runtime.risk_store.list_by_investigation(context.investigation_id)
    path = tmp_path / "risk" / context.investigation_id / f"{ra.risk_assessment_id}.json"
    data = json.loads(path.read_text(encoding="utf-8"))
    data["risk_assessment"]["confidence"] = "high"  # contract-consistent forgery, rehashed
    data["risk_assessment"]["rule_ids"][-1] = "confidence.high"
    data["content_hash"] = compute_content_hash({k: data[k] for k in ("risk_assessment", "recorded_at")})
    path.write_text(json.dumps(data), encoding="utf-8")
    out = io.StringIO()
    cli_main._report_findings(out, runtime, context.investigation_id)
    shown = out.getvalue()
    assert "risk assessments: failed verification; not shown" in shown
    assert "rule-based risk: not shown (failed verification)" in shown
    assert "severity:" not in shown and "basis confidence" not in shown


def test_cli_withholds_ratings_when_the_risk_store_is_corrupt(tmp_path):
    runtime, context, _, _ = cli_run(tmp_path, lambda ids: [finding_dict(ids, category="platform_configuration")])
    (path,) = (tmp_path / "risk" / context.investigation_id).glob("*.json")
    path.write_text("{}", encoding="utf-8")
    out = io.StringIO()
    cli_main._report_findings(out, runtime, context.investigation_id)
    assert "failed verification; not shown" in out.getvalue() and "severity:" not in out.getvalue()


def test_cli_risk_output_is_escaped_with_hostile_finding_text(tmp_path):
    runtime, context, shown, _ = cli_run(
        tmp_path,
        lambda ids: [finding_dict(ids, category="platform_configuration", title="hostile", description=HOSTILE[0]),
                     finding_dict(ids, category="observation", title="ansi", description="x ‮ y " + HOSTILE[1])],
    )
    assert context.status == InvestigationStatus.COMPLETED
    assert all(ch == "\n" or 32 <= ord(ch) < 127 for ch in shown)
    assert len(runtime.risk_store.list_by_investigation(context.investigation_id)) == 2
    for path in (tmp_path / "risk").rglob("*.json"):
        text = path.read_text(encoding="utf-8")
        assert HOSTILE[0] not in text and HOSTILE[1] not in text


def test_cli_risk_files_never_contain_the_credential(tmp_path):
    _, _, shown, _ = cli_run(tmp_path, lambda ids: [finding_dict(ids, category="platform_configuration")])
    for path in (tmp_path / "risk").rglob("*.json"):
        assert SENTINEL_KEY not in path.read_text(encoding="utf-8")
    assert SENTINEL_KEY not in shown


def test_cli_adds_no_new_flags():
    # Phase 10 added no flags. Phase 12 adds exactly one, the approved,
    # read-only --review; nothing risk-related.
    options = {a.dest for a in cli_main._parser()._actions}
    assert options == {"help", "objective", "model", "workdir", "approver", "require_approval", "max_turns", "review"}


# ===========================================================================
# Provider taxonomy hint (C-4)
# ===========================================================================


def _finding_tool():
    kwargs = mapping.build_request_kwargs(assembled(), _config(findings_channel=True))
    (tool,) = [t for t in kwargs["tools"] if t["name"] == RESERVED_FINDING_TOOL]
    return tool, kwargs


def test_category_schema_is_the_taxonomy_enum():
    tool, _ = _finding_tool()
    category = tool["input_schema"]["properties"]["findings"]["items"]["properties"]["category"]
    assert category["enum"] == list(RISK_CATEGORY_IDS) and category["type"] == "string"
    assert "rule-based risk assessment" in category["description"]
    assert "do not rate severity" in category["description"]


def test_no_risk_channel_or_risk_fields_are_offered_to_the_model():
    tool, kwargs = _finding_tool()
    assert [t["name"] for t in kwargs["tools"]] == [RESERVED_FINDING_TOOL]
    item = tool["input_schema"]["properties"]["findings"]["items"]
    assert set(item["properties"]) == {"title", "description", "evidence_refs", "category", "confidence"}
    assert item["additionalProperties"] is False

    def keys(node):
        if isinstance(node, dict):
            for key, value in node.items():
                yield key
                yield from keys(value)
        elif isinstance(node, list):
            for value in node:
                yield from keys(value)

    def properties(node):
        if isinstance(node, dict):
            if isinstance(node.get("properties"), dict):
                yield from node["properties"]
            for value in node.values():
                yield from properties(value)

    names = set(properties(tool["input_schema"])) | set(keys(tool["input_schema"]))
    for word in ("severity", "risk", "risk_assessment", "scoring_method", "rule_ids", "rationale"):
        assert word not in names


def test_schema_is_deterministic():
    assert _finding_tool()[0] == _finding_tool()[0]


def test_schema_conformance_is_not_trusted_non_enum_category_still_maps():
    findings = [{"title": "t", "description": "d", "evidence_refs": ["tr-1"], "category": "made_up"}]
    response = Response(Block("tool_use", name=RESERVED_FINDING_TOOL, input={"findings": findings}))
    turn = mapping.response_to_turn_mapping_with_findings(response, investigation_id="inv-9")
    assert AgentTurnOutput.from_dict(turn).findings[0]["category"] == "made_up"  # rated later as category_unrated


def test_model_supplied_severity_on_a_finding_never_becomes_a_rating(tmp_path):
    runtime, context, shown, _ = cli_run(
        tmp_path, lambda ids: [finding_dict(ids, category="platform_configuration", severity="critical")])
    assert runtime.finding_store.list_by_investigation(context.investigation_id) == ()
    assert runtime.risk_store.list_by_investigation(context.investigation_id) == ()
    assert "malformed_turn" in shown


# ===========================================================================
# EvidenceStore.verify_in_investigation (scoped read used by the engine)
# ===========================================================================


def test_scoped_verification_returns_metadata_only(tmp_path):
    store = EvidenceStore(tmp_path)
    ev = put_evidence(store, "inv-a", "list_listening_ports")
    evidence = store.verify_in_investigation("inv-a", ev)
    assert evidence.evidence_id == ev and evidence.investigation_id == "inv-a"


def test_scoped_verification_does_not_search_other_investigations(tmp_path):
    store = EvidenceStore(tmp_path)
    ev = put_evidence(store, "inv-a", "list_listening_ports")
    with pytest.raises(UnknownEvidenceError):
        store.verify_in_investigation("inv-b", ev)


def test_scoped_verification_checks_the_payload(tmp_path):
    store = EvidenceStore(tmp_path)
    ev = put_evidence(store, "inv-a", "list_listening_ports")
    (tmp_path / "inv-a" / "payloads" / f"{ev}.json").write_text('{"output": 1}', encoding="utf-8")
    with pytest.raises(CorruptEvidenceError):
        store.verify_in_investigation("inv-a", ev)
    assert store.verify(ev) is False  # the existing API agrees


def test_scoped_verification_rejects_a_misfiled_record(tmp_path):
    store = EvidenceStore(tmp_path)
    ev = put_evidence(store, "inv-a", "list_listening_ports")
    (tmp_path / "inv-b").mkdir()
    (tmp_path / "inv-a" / f"{ev}.json").replace(tmp_path / "inv-b" / f"{ev}.json")
    with pytest.raises(CorruptEvidenceError):
        store.verify_in_investigation("inv-b", ev)


@pytest.mark.parametrize("bad", ["../x", "a/b", "CON", ""])
def test_scoped_verification_rejects_unsafe_identifiers(tmp_path, bad):
    with pytest.raises(InvalidIdentifierError):
        EvidenceStore(tmp_path).verify_in_investigation(bad, "ev-1")
    with pytest.raises(InvalidIdentifierError):
        EvidenceStore(tmp_path).verify_in_investigation("inv-a", bad)


def test_get_payload_behavior_is_unchanged(tmp_path):
    store = EvidenceStore(tmp_path)
    ev = put_evidence(store, "inv-a", "list_listening_ports", payload={"output": {"k": "v"}})
    assert store.get_payload(ev) == {"output": {"k": "v"}}


# ===========================================================================
# Static import boundaries
# ===========================================================================

_RISK_MODULES = ("chanakya.risk", "chanakya.contracts.risk_assessment", "chanakya.contracts.risk_taxonomy")


def _imports(path: Path) -> set:
    """Absolute module names imported by ``path`` (relative imports resolved)."""
    package = ".".join(path.relative_to(_REPO_ROOT).with_suffix("").parts[:-1])
    found = set()
    for node in ast.walk(ast.parse(path.read_text(encoding="utf-8"))):
        if isinstance(node, ast.ImportFrom):
            base = package.split(".")
            if node.level:
                base = base[: len(base) - node.level + 1]
                module = ".".join(base + ([node.module] if node.module else []))
            else:
                module = node.module or ""
            found.add(module)
            found.update(f"{module}.{alias.name}" for alias in node.names)
        elif isinstance(node, ast.Import):
            found.update(alias.name for alias in node.names)
    return found


def _package_files(package: str):
    return sorted((_CHANAKYA / package).rglob("*.py"))


@pytest.mark.parametrize("package", ["policy", "tools", "registry", "approval", "targets", "capability", "evidence", "findings", "audit"])
def test_authority_and_storage_packages_never_import_risk(package):
    for path in _package_files(package):
        assert not any(m.startswith(_RISK_MODULES) for m in _imports(path)), path


@pytest.mark.parametrize(
    "forbidden",
    ["chanakya.policy", "chanakya.runtime", "chanakya.providers", "chanakya.tools", "chanakya.registry",
     "chanakya.approval", "chanakya.audit", "chanakya.cli", "anthropic", "httpx", "subprocess", "socket"],
)
def test_risk_package_imports_nothing_forbidden(forbidden):
    for path in _package_files("risk"):
        for module in _imports(path):
            assert not (module == forbidden or module.startswith(forbidden + ".")), (path.name, module)


def test_risk_package_imports_only_contracts_evidence_findings_and_itself():
    allowed = ("chanakya.contracts", "chanakya.evidence", "chanakya.findings", "chanakya.risk", "__future__",
               "dataclasses", "typing", "json", "os", "tempfile", "datetime", "pathlib", "re")
    for path in _package_files("risk"):
        for module in _imports(path):
            assert module.startswith(allowed), (path.name, module)


def test_risk_contracts_import_only_contracts():
    for name in ("risk_assessment.py", "risk_taxonomy.py"):
        for module in _imports(_CHANAKYA / "contracts" / name):
            assert module.startswith(("chanakya.contracts", "__future__", "dataclasses", "typing", "types", "re", "uuid")), module


def test_runtime_never_imports_the_risk_package():
    for path in _package_files("runtime"):
        assert not any(m.startswith("chanakya.risk") for m in _imports(path)), path


def test_providers_import_only_the_taxonomy():
    for path in _package_files("providers"):
        risky = {m for m in _imports(path) if m.startswith(_RISK_MODULES)}
        assert risky <= {"chanakya.contracts.risk_taxonomy", "chanakya.contracts.risk_taxonomy.RISK_CATEGORY_IDS"}, path


def test_only_the_cli_composition_root_imports_the_risk_package():
    importers = {
        path.relative_to(_REPO_ROOT).as_posix()
        for path in _CHANAKYA.rglob("*.py")
        if "risk" not in path.relative_to(_CHANAKYA).parts[:1]
        and any(m.startswith("chanakya.risk") for m in _imports(path))
    }
    assert importers == {"chanakya/cli/main.py"}


def test_risk_code_has_no_execution_primitives():
    for path in list(_package_files("risk")) + [_CHANAKYA / "contracts" / "risk_assessment.py",
                                               _CHANAKYA / "contracts" / "risk_taxonomy.py"]:
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Name):
                assert node.func.id not in ("eval", "exec", "compile", "__import__"), path


def test_approval_request_risk_reference_is_never_set():
    for path in _CHANAKYA.rglob("*.py"):
        for node in ast.walk(ast.parse(path.read_text(encoding="utf-8"))):
            if isinstance(node, ast.Call):
                assert "risk_assessment_ref" not in {k.arg for k in node.keywords}, path
