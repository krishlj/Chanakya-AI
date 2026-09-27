"""Phase 12 — durable authorization record (additive AuditEvent.details).

A. Fact builders: D-1 objective, D-2 parameters, bounds, screening
B. Enriched events from real investigations (AR-INV-1..5)
C. Fail-closed: unsafe or oversized facts never let the action proceed
"""
from __future__ import annotations

import io
import json

import pytest

import chanakya.cli.main as cli_main
from chanakya.audit.log import AuditRecordTooLargeError, FilesystemAuditLog
from chanakya.contracts.audit_details import (
    MAX_OBJECTIVE_CHARS,
    MAX_PARAMETERS_BYTES,
    AuditFactError,
    envelope_summary,
    objective_fact,
    origin_details,
    parameters_fact,
    validate_details,
    verify_parameters,
)
from chanakya.contracts.audit_event import AuditEvent, AuditEventType
from chanakya.contracts.investigation_context import InvestigationStatus
from chanakya.capability.envelope import envelope_from_registry_entry
from chanakya.evidence.hashing import canonical_bytes, compute_content_hash
from chanakya.registry.bootstrap import make_observe_local_host_environment_entry
from chanakya.runtime.agent_loop import TurnOutcome

from review_factories import ENV, TARGET, Run

E = AuditEventType
SECRET = "hunter2-SECRET"


def details_of(run, kind):
    return [e.details for e in run.events() if e.event_type == kind]


# ===========================================================================
# A. Fact builders
# ===========================================================================


def test_objective_is_stored_as_bounded_text():
    assert objective_fact("Check open ports\nand OS version") == "Check open ports\nand OS version"
    assert len(objective_fact("x" * MAX_OBJECTIVE_CHARS)) == MAX_OBJECTIVE_CHARS


@pytest.mark.parametrize(
    "objective,code",
    [
        ("x" * (MAX_OBJECTIVE_CHARS + 1), "FACT_TOO_LARGE"),
        ("", "FACT_INVALID"),
        ("   ", "FACT_INVALID"),
        (None, "FACT_INVALID"),
        ("look \x1b[31m here", "FACT_UNSAFE_TEXT"),
        ("null \x00 byte", "FACT_UNSAFE_TEXT"),
        (f"login with password={SECRET}", "FACT_CREDENTIAL_SHAPED"),
        (f"the api_key: {SECRET}", "FACT_CREDENTIAL_SHAPED"),
        (f"fetch https://user:{SECRET}@host/", "FACT_CREDENTIAL_SHAPED"),
        ("-----BEGIN RSA PRIVATE KEY-----", "FACT_CREDENTIAL_SHAPED"),
    ],
    ids=["too_long", "empty", "blank", "none", "ansi", "nul", "password", "api_key", "userinfo", "pem"],
)
def test_unsafe_objectives_are_rejected_without_echo(objective, code):
    with pytest.raises(AuditFactError) as info:
        objective_fact(objective)
    assert info.value.code == code and SECRET not in str(info.value)


def test_parameters_are_canonical_json_with_integrity_hash():
    canonical, digest = parameters_fact({"b": [2, 1], "a": {"z": True, "y": None}})
    assert canonical == canonical_bytes({"a": {"y": None, "z": True}, "b": [2, 1]}).decode("ascii")
    assert digest == compute_content_hash({"b": [2, 1], "a": {"z": True, "y": None}})
    assert parameters_fact({"a": {"y": None, "z": True}, "b": [2, 1]}) == (canonical, digest)  # order-independent
    assert parameters_fact({}) == ("{}", compute_content_hash({}))
    assert verify_parameters(canonical, digest)


@pytest.mark.parametrize(
    "canonical,digest_of",
    [
        ('{"a":2}', {"a": 1}),              # value changed after hashing
        ('{"a": 1}', {"a": 1}),             # not canonical form
        ('[1]', [1]),                       # not an object
        ("not json", {"a": 1}),
    ],
    ids=["tampered", "non_canonical", "not_object", "not_json"],
)
def test_parameter_verification_detects_tampering(canonical, digest_of):
    digest = compute_content_hash(digest_of) if isinstance(digest_of, dict) else "sha256:" + "0" * 64
    assert not verify_parameters(canonical, digest)


@pytest.mark.parametrize(
    "parameters,code",
    [
        ({"password": "x"}, "FACT_CREDENTIAL_SHAPED"),
        ({"api_key": "x"}, "FACT_CREDENTIAL_SHAPED"),
        ({"note": f"token={SECRET}"}, "FACT_CREDENTIAL_SHAPED"),
        ({"nested": {"list": [f"secret: {SECRET}"]}}, "FACT_CREDENTIAL_SHAPED"),
        ({"url": f"https://u:{SECRET}@h"}, "FACT_CREDENTIAL_SHAPED"),
        ({"x": "a" * MAX_PARAMETERS_BYTES}, "FACT_TOO_LARGE"),
        ({"x": object()}, "FACT_NOT_SERIALIZABLE"),
        ({"x": float("nan")}, "FACT_NOT_SERIALIZABLE"),
        ({1: "int key"}, "FACT_NOT_SERIALIZABLE"),
        ("not-a-mapping", "FACT_INVALID"),
    ],
    ids=["password_key", "api_key", "token_value", "nested_secret", "userinfo", "too_large", "object", "nan",
         "int_key", "not_mapping"],
)
def test_unsafe_parameters_are_rejected_without_echo(parameters, code):
    with pytest.raises(AuditFactError) as info:
        parameters_fact(parameters)
    assert info.value.code == code and SECRET not in str(info.value)


def test_origin_details_bound_target_scope():
    base = dict(investigation_request_id="r", submitted_by="alice", submitted_at="t", objective="o")
    with pytest.raises(AuditFactError):
        origin_details(target_refs=[f"t{i}" for i in range(17)], **base)
    with pytest.raises(AuditFactError):
        origin_details(target_refs=[], **base)
    with pytest.raises(AuditFactError):
        origin_details(target_refs=["t"], **dict(base, submitted_by=f"x password={SECRET}"))


def test_envelope_summary_hashes_the_schema_instead_of_copying_it():
    env = envelope_from_registry_entry(make_observe_local_host_environment_entry())
    summary = envelope_summary(env)
    # Phase 15 (AuditEvent 1.2.0): plus the Registry-declared egress.
    assert set(summary) == {"capability", "timeout_seconds", "max_output_bytes", "output_schema_hash", "model_egress"}
    assert summary["model_egress"] == "allowed"
    assert summary["output_schema_hash"] == compute_content_hash(env.to_dict()["output_schema"])
    assert "properties" not in json.dumps(summary)


@pytest.mark.parametrize(
    "kind,details",
    [
        ("request_proposed", {"capability": "c", "target_ref": "t", "step_id": "s", "attempt_number": 1,
                              "parameters_canonical": "{}", "parameters_hash": compute_content_hash({}),
                              "injected": "x"}),
        ("policy_evaluated", {"verdict": "allow", "matched_rule": "r", "reason": "r"}),
        ("dispatch_started", None),
        ("investigation_started", {"objective": "o"}),
    ],
    ids=["extra_field", "missing_facts", "no_details", "partial_origin"],
)
def test_stored_details_are_validated_against_closed_shapes(kind, details):
    assert validate_details(kind, details)


# ===========================================================================
# B. Enriched events from real investigations
# ===========================================================================


def test_investigation_started_records_origin(tmp_path):
    """AR-INV-5."""
    run = Run(tmp_path).start("Assess exposed services\non this host")
    (origin,) = details_of(run, E.INVESTIGATION_STARTED)
    assert origin["objective"] == "Assess exposed services\non this host"
    assert origin["submitted_by"] == "alice" and origin["target_refs"] == [TARGET]
    assert origin["investigation_request_id"].startswith("req-") and origin["submitted_at"]
    assert validate_details("investigation_started", origin) == []


def test_request_and_policy_and_dispatch_are_recorded(tmp_path):
    """AR-INV-1, AR-INV-2, AR-INV-4."""
    run = Run(tmp_path).start()
    result = run.propose()
    assert result.outcome == TurnOutcome.STEP_COMPLETED
    (proposed,) = details_of(run, E.REQUEST_PROPOSED)
    assert proposed["capability"] == ENV and proposed["target_ref"] == TARGET
    assert proposed["step_id"] == result.step_record.step_id and proposed["attempt_number"] == 1
    assert (proposed["parameters_canonical"], proposed["parameters_hash"]) == parameters_fact({})
    (policy,) = details_of(run, E.POLICY_EVALUATED)
    envelope = envelope_from_registry_entry(run.runtime.registry.get_enabled(ENV))
    assert policy["capability"] == ENV and policy["target_ref"] == TARGET and policy["verdict"] == "allow"
    assert policy["classification"] == "read_only" and policy["risk_category"] == "informational"
    assert policy["envelope"] == envelope_summary(envelope)
    (dispatch,) = details_of(run, E.DISPATCH_STARTED)
    assert dispatch["capability"] == ENV and dispatch["target_ref"] == TARGET
    assert dispatch["resolved_timeout_seconds"] == min(envelope.timeout_seconds, 60)
    assert dispatch["max_output_bytes"] == envelope.max_output_bytes
    assert dispatch["step_id"] == result.step_record.step_id
    assert dispatch["policy_decision_id"] == result.step_record.policy_decision_id
    for kind in ("request_proposed", "policy_evaluated", "dispatch_started"):
        assert validate_details(kind, details_of(run, E(kind))[0]) == []


def test_denied_request_is_reconstructable(tmp_path):
    """AR-INV-1: a deny produces no Evidence, but capability/target/verdict are durable."""
    run = Run(tmp_path).start()
    assert run.propose("does_not_exist").outcome == TurnOutcome.STEP_DENIED
    (policy,) = details_of(run, E.POLICY_EVALUATED)
    assert (policy["capability"], policy["target_ref"], policy["verdict"], policy["envelope"]) == (
        "does_not_exist", TARGET, "deny", None)
    assert not details_of(run, E.DISPATCH_STARTED)


def test_non_empty_parameters_are_recorded_even_when_denied(tmp_path):
    """AR-INV-2: D-2 for future parameterized capabilities."""
    run = Run(tmp_path).start()
    assert run.propose(parameters={"b": 2, "a": [1, "x"]}).outcome == TurnOutcome.STEP_DENIED  # closed schema
    (proposed,) = details_of(run, E.REQUEST_PROPOSED)
    assert proposed["parameters_canonical"] == '{"a":[1,"x"],"b":2}'
    assert verify_parameters(proposed["parameters_canonical"], proposed["parameters_hash"])


def test_approval_request_records_what_was_shown(tmp_path):
    """AR-INV-3."""
    run = Run(tmp_path, require_approval=True, answer="approve").start()
    result = run.propose()
    assert result.outcome == TurnOutcome.STEP_COMPLETED
    (approval,) = details_of(run, E.APPROVAL_REQUESTED)
    assert approval["step_id"] == result.step_record.step_id and "expires_at" in approval
    assert approval["risk_context"]["capability"] == ENV and approval["risk_context"]["target_ref"] == TARGET
    assert approval["risk_context"]["parameters_canonical"] == "{}"
    assert validate_details("approval_requested", approval) == []
    (decided,) = details_of(run, E.APPROVAL_DECIDED)
    assert decided == {"outcome": "accept", "decided_by": "alice"}


def test_failed_investigations_are_marked_terminal(tmp_path):
    run = Run(tmp_path).start()
    run.runtime.manager.fail(run.inv, reason="test_failure")
    (error,) = [e for e in run.events() if e.event_type == E.ERROR]
    assert error.details == {"reason": "test_failure", "investigation_status": "failed"}


# ===========================================================================
# C. Fail closed
# ===========================================================================


def test_credential_shaped_objective_creates_no_investigation(tmp_path):
    run = Run(tmp_path)
    with pytest.raises(AuditFactError):
        run.start(f"check the server; password={SECRET}")
    assert not (tmp_path / "audit").exists() or not any((tmp_path / "audit").rglob("*.json"))
    assert len(run.runtime.manager._store) == 0


def test_oversized_objective_creates_no_investigation(tmp_path):
    with pytest.raises(AuditFactError):
        Run(tmp_path).start("x" * (MAX_OBJECTIVE_CHARS + 1))


def test_cli_rejects_unsafe_objective_without_echo(tmp_path, monkeypatch):
    out = io.StringIO()

    class NoProvider:
        def __init__(self, *a, **k):
            pass

    monkeypatch.setattr(cli_main, "AnthropicProvider", NoProvider)
    code = cli_main.main([f"password={SECRET}", "--workdir", str(tmp_path)], environ={"ANTHROPIC_API_KEY": "k"},
                         output=out)
    assert code == cli_main.EXIT_CONFIG_ERROR
    assert "FACT_CREDENTIAL_SHAPED" in out.getvalue() and SECRET not in out.getvalue()


@pytest.mark.parametrize(
    "parameters",
    [{"password": SECRET}, {"note": f"token={SECRET}"}, {"blob": "x" * (MAX_PARAMETERS_BYTES + 10)}],
    ids=["credential_key", "credential_value", "oversized"],
)
def test_unsafe_parameters_halt_before_policy_or_dispatch(tmp_path, parameters):
    run = Run(tmp_path).start()
    result = run.propose(parameters=parameters)
    assert result.outcome == TurnOutcome.HALTED
    assert run.context.status == InvestigationStatus.HALTED
    assert run.context.error_state["reason"] == "audit_sink_failure"
    kinds = [e.event_type for e in run.events()]
    assert E.REQUEST_PROPOSED not in kinds and E.POLICY_EVALUATED not in kinds and E.DISPATCH_STARTED not in kinds
    assert run.context.evidence_refs == ()
    for path in (tmp_path / "audit").rglob("*.json"):
        assert SECRET not in path.read_text(encoding="utf-8")


def test_audit_record_size_limit_still_fails_closed(tmp_path):
    log = FilesystemAuditLog(tmp_path)
    event = AuditEvent(audit_event_id="a", contract_version="1.0.0", event_type=E.POLICY_EVALUATED,
                       occurred_at="t", actor="system", investigation_id="inv-1",
                       details={"reason": "x" * 70000})
    with pytest.raises(AuditRecordTooLargeError):
        log.emit(event)
    assert not list(tmp_path.rglob("*.json"))


def test_no_secret_is_written_anywhere_in_a_normal_run(tmp_path):
    run = Run(tmp_path).start()
    run.propose()
    for path in tmp_path.rglob("*.json"):
        text = path.read_text(encoding="utf-8")
        assert "ANTHROPIC_API_KEY" not in text and "sk-" not in text
