"""Phase 12 — read-only Investigation Review.

I-L. Terminal states and crash points     N-R. Cross-store checks, orphans, cross-investigation refs
M.   Audit chain verification              S.   Tamper detection (consistent chain rewrites)
T-U. CLI --review and escaping             V-W. Boundaries and read-only guarantees (AR-INV-6, AR-INV-7)
"""
from __future__ import annotations

import ast
import dataclasses
import hashlib
import json
from pathlib import Path

import pytest

import chanakya.cli.main as cli_main
from chanakya.contracts.enums import RiskCategory
from chanakya.contracts.risk_assessment import derive_risk_assessment_id
from chanakya.review import InvestigationReview, ReviewStatus, reconstruct_investigation

from risk_factories import make_finding, make_ra, put_evidence
from review_factories import ENV, Run, codes, finding, load_stream, rewrite_events, truncate_after, write_stream

_REPO_ROOT = Path(__file__).resolve().parent.parent
_CHANAKYA = _REPO_ROOT / "chanakya"


def completed_run(tmp_path, category="platform_configuration") -> Run:
    run = Run(tmp_path).start()
    run.propose()
    run.conclude(lambda ids: [finding(ids, category=category)])
    return run


# ===========================================================================
# I-L. Terminal states
# ===========================================================================


def test_completed_investigation_reconstructs_fully(tmp_path):
    run = completed_run(tmp_path)
    review = run.review()
    assert review.status == ReviewStatus.COMPLETED and review.consistent, codes(review)
    assert review.origin.objective == "Assess this host for exposed services" and review.origin.submitted_by == "alice"
    (request,) = review.requests
    assert request.capability == ENV and request.policy.verdict == "allow"
    assert request.policy.envelope_timeout_seconds == 10 and request.dispatch.status == "success"
    assert request.evidence_id == review.evidence[0].evidence_id and review.evidence[0].verified
    assert len(review.findings) == 1 and review.risk_assessments[0].severity == "low"


def test_denied_and_approval_history_is_reconstructed(tmp_path):
    run = Run(tmp_path, require_approval=True, answer="deny").start()
    run.propose("does_not_exist")
    run.propose()
    run.conclude()
    review = run.review()
    assert review.status == ReviewStatus.COMPLETED and review.consistent, codes(review)
    denied, gated = review.requests
    assert denied.policy.verdict == "deny" and denied.dispatch is None
    assert gated.policy.verdict == "require_approval"
    assert gated.approval.outcome == "deny" and gated.approval.decided_by == "alice" and gated.dispatch is None


def test_accepted_approval_then_dispatch_is_consistent(tmp_path):
    run = Run(tmp_path, require_approval=True, answer="approve").start()
    run.propose()
    run.conclude()
    review = run.review()
    assert review.consistent, codes(review)
    assert review.requests[0].approval.outcome == "accept" and review.requests[0].dispatch.status == "success"


def test_halted_investigation(tmp_path):
    run = Run(tmp_path).start()
    run.propose()
    run.runtime.manager.cancel(run.inv, cancelled_by="alice")
    review = run.review()
    assert review.status == ReviewStatus.HALTED and review.terminal_reason == "cancelled_by_operator"
    assert review.consistent, codes(review)


def test_failed_investigation(tmp_path):
    run = Run(tmp_path).start()
    run.runtime.manager.fail(run.inv, reason="dispatch_precondition_violation")
    review = run.review()
    assert review.status == ReviewStatus.FAILED and review.terminal_reason == "dispatch_precondition_violation"


def test_backstop_error_alone_is_not_a_terminal_state(tmp_path):
    run = Run(tmp_path).start()
    run.runtime.audit.error(run.inv, reason="unhandled_runtime_exception")
    review = run.review()
    assert review.status == ReviewStatus.INCOMPLETE and "no_terminal_event" in codes(review)


@pytest.mark.parametrize(
    "event_type,occurrence,extra",
    [
        ("investigation_started", 1, []),
        ("request_proposed", 1, []),
        ("policy_evaluated", 1, []),
        ("dispatch_started", 1, ["dispatch_without_result"]),
        ("dispatch_completed", 1, ["orphan_evidence"]),
        ("evidence_recorded", 1, []),
        ("finding_created", 1, ["orphan_risk_assessment"]),
        ("risk_assessed", 1, []),
    ],
)
def test_crash_points_are_incomplete_never_completed(tmp_path, event_type, occurrence, extra):
    """AR-INV-7."""
    run = completed_run(tmp_path)
    truncate_after(run.stream_dir(), event_type, occurrence)
    review = run.review()
    assert review.status == ReviewStatus.INCOMPLETE and review.audit_verified
    assert "no_terminal_event" in codes(review)
    for code in extra:
        assert code in codes(review)


def test_crash_after_approval_requested(tmp_path):
    run = Run(tmp_path, require_approval=True, answer="approve").start()
    run.propose()
    truncate_after(run.stream_dir(), "approval_requested")
    review = run.review()
    assert review.status == ReviewStatus.INCOMPLETE and review.requests[0].approval.outcome is None


def test_removing_completion_is_incomplete_not_completed(tmp_path):
    """Adversarial break 9."""
    run = completed_run(tmp_path)
    rewrite_events(run.stream_dir(), lambda events: [e for e in events if e["event_type"] != "investigation_completed"])
    review = run.review()
    assert review.audit_verified and review.status == ReviewStatus.INCOMPLETE


def test_unknown_investigation_is_not_found(tmp_path):
    run = completed_run(tmp_path)
    review = run.review("00000000-0000-0000-0000-000000000000")
    assert review.status == ReviewStatus.NOT_FOUND and review.requests == () and review.origin is None
    assert codes(review) == ["no_audit_history"] and not review.consistent


@pytest.mark.parametrize("bad", ["../escape", "a/b", "CON", ""])
def test_unsafe_investigation_ids_are_unverifiable(tmp_path, bad):
    run = completed_run(tmp_path)
    review = run.review(bad)
    assert review.status == ReviewStatus.UNVERIFIABLE and codes(review) == ["invalid_investigation_id"]


# ===========================================================================
# M. Audit chain verification (fail closed)
# ===========================================================================


def _edit_record(path: Path, mutate) -> None:
    data = json.loads(path.read_text(encoding="utf-8"))
    mutate(data)
    path.write_text(json.dumps(data), encoding="utf-8")


@pytest.mark.parametrize(
    "mutate",
    [
        lambda d: d.__setitem__("record_hash", "sha256:" + "0" * 64),
        lambda d: d.__setitem__("previous_record_hash", "sha256:" + "1" * 64),
        lambda d: d["event"]["details"].__setitem__("objective", "rewritten"),
        lambda d: d.__setitem__("sequence", 7),
    ],
    ids=["record_hash", "previous_link", "event_edit", "sequence"],
)
def test_corrupt_audit_chain_is_unverifiable(tmp_path, mutate):
    """Adversarial breaks 10 and 11: nothing is reported as fact."""
    run = completed_run(tmp_path)
    _edit_record(sorted(run.stream_dir().glob("*.json"))[0], mutate)
    review = run.review()
    assert review.status == ReviewStatus.UNVERIFIABLE and codes(review) == ["audit_chain_invalid"]
    assert review.requests == () and review.origin is None and not review.consistent


def test_deleted_middle_record_is_unverifiable(tmp_path):
    run = completed_run(tmp_path)
    sorted(run.stream_dir().glob("*.json"))[2].unlink()
    assert run.review().status == ReviewStatus.UNVERIFIABLE


# ===========================================================================
# N-R. Cross-store consistency, orphans, cross-investigation references
# ===========================================================================


def test_finding_referencing_evidence_of_another_investigation(tmp_path):
    """Adversarial break 7."""
    run = completed_run(tmp_path)
    other = Run(tmp_path).start()
    other.propose()
    foreign = other.results[0].step_record.evidence_id
    run.runtime.finding_store.append(make_finding(investigation_id=run.inv, evidence_refs=(foreign,)))
    review = run.review()
    assert "finding_evidence_foreign_investigation" in codes(review) and "orphan_finding" in codes(review)
    assert not review.consistent


def test_finding_referencing_missing_evidence(tmp_path):
    run = completed_run(tmp_path)
    run.runtime.finding_store.append(make_finding(investigation_id=run.inv, evidence_refs=("ev-ghost",)))
    assert "finding_evidence_missing" in codes(run.review())


def test_risk_assessment_referencing_missing_finding(tmp_path):
    """Adversarial break 8."""
    run = completed_run(tmp_path)
    ev = run.review().evidence[0].evidence_id
    run.runtime.risk_store.append(make_ra(investigation_id=run.inv, finding_refs=("find-ghost",), evidence_refs=(ev,),
                                          rule_ids=("evidence.verified", "category.platform_configuration",
                                                    "compat.all", "ceiling.read_only", "confidence.medium"),
                                          severity=RiskCategory.LOW))
    review = run.review()
    assert "risk_missing_finding" in codes(review) and "orphan_risk_assessment" in codes(review)


def test_orphan_evidence_is_reported(tmp_path):
    run = completed_run(tmp_path)
    put_evidence(run.runtime.evidence_store, run.inv, ENV)
    assert "orphan_evidence" in codes(run.review())


def test_evidence_deleted_after_recording_is_missing(tmp_path):
    run = completed_run(tmp_path)
    ev = run.review().evidence[0].evidence_id
    (tmp_path / "evidence" / run.inv / f"{ev}.json").unlink()
    review = run.review()
    assert "evidence_missing" in codes(review) and "finding_evidence_missing" in codes(review)


def test_evidence_moved_to_another_investigation_is_foreign(tmp_path):
    run = completed_run(tmp_path)
    ev = run.review().evidence[0].evidence_id
    target = tmp_path / "evidence" / "inv-other"
    target.mkdir()
    (tmp_path / "evidence" / run.inv / f"{ev}.json").rename(target / f"{ev}.json")
    assert "evidence_foreign_investigation" in codes(run.review())


def test_tampered_evidence_payload_is_unverifiable(tmp_path):
    run = completed_run(tmp_path)
    ev = run.review().evidence[0].evidence_id
    (tmp_path / "evidence" / run.inv / "payloads" / f"{ev}.json").write_text('{"output": "forged"}', encoding="utf-8")
    review = run.review()
    assert "evidence_unverifiable" in codes(review) and "risk_recomputation_failed" in codes(review)


def test_deleted_finding_and_risk_are_missing(tmp_path):
    run = completed_run(tmp_path)
    for path in (tmp_path / "risk").rglob("*.json"):
        path.unlink()
    assert "risk_assessment_missing" in codes(run.review())
    for path in (tmp_path / "findings").rglob("*.json"):
        path.unlink()
    assert "finding_missing" in codes(run.review())


def test_corrupt_stores_are_reported_not_raised(tmp_path):
    run = completed_run(tmp_path)
    next((tmp_path / "findings").rglob("*.json")).write_text("{}", encoding="utf-8")
    next((tmp_path / "risk").rglob("*.json")).write_text("{}", encoding="utf-8")
    review = run.review()
    assert {"finding_store_unverifiable", "risk_store_unverifiable"} <= set(codes(review))


def test_risk_rewritten_and_rehashed_fails_recomputation(tmp_path):
    run = completed_run(tmp_path)
    path = next((tmp_path / "risk").rglob("*.json"))
    data = json.loads(path.read_text(encoding="utf-8"))
    data["risk_assessment"]["rationale"] = "Rated safe."
    from chanakya.evidence.hashing import compute_content_hash

    data["content_hash"] = compute_content_hash({k: data[k] for k in ("risk_assessment", "recorded_at")})
    path.write_text(json.dumps(data), encoding="utf-8")
    assert "risk_recomputation_mismatch" in codes(run.review())


# ===========================================================================
# S. Tamper detection with a consistently rewritten (valid) chain
# ===========================================================================


def _mutate_first(event_type, change):
    def mutate(events):
        for event in events:
            if event["event_type"] == event_type:
                change(event)
                break
        return events
    return mutate


@pytest.mark.parametrize(
    "event_type,change,expected",
    [
        ("policy_evaluated", lambda e: e["details"].pop("capability"), "details_shape_invalid"),
        ("policy_evaluated", lambda e: e["details"].pop("target_ref"), "details_shape_invalid"),
        ("request_proposed", lambda e: e["details"].__setitem__("parameters_canonical", '{"pid":1}'),
         "parameters_hash_mismatch"),
        ("request_proposed", lambda e: e["details"].__setitem__("injected", "x"), "details_shape_invalid"),
        ("policy_evaluated", lambda e: e["details"].__setitem__("capability", "other_capability"),
         "policy_request_mismatch"),
        ("policy_evaluated", lambda e: e["details"]["envelope"].__setitem__("output_schema_hash", "abc"),
         "envelope_summary_invalid"),
        ("dispatch_started", lambda e: e["details"].__setitem__("resolved_timeout_seconds", 999),
         "dispatch_envelope_mismatch"),
        ("dispatch_started", lambda e: e["details"].__setitem__("target_ref", "other-target"),
         "dispatch_request_mismatch"),
        ("investigation_started", lambda e: e["details"].__setitem__("objective", "\x1b[31mx"),
         "details_value_invalid"),
        ("finding_created", lambda e: e["details"].__setitem__("evidence_refs", ["ev-forged"]),
         "finding_audit_mismatch"),
    ],
    ids=["no_capability", "no_target_ref", "params_after_hash", "extra_field", "policy_mismatch",
         "bad_schema_hash", "looser_timeout", "dispatch_target", "unsafe_objective", "finding_refs"],
)
def test_rewritten_facts_are_detected(tmp_path, event_type, change, expected):
    """Adversarial breaks 1, 2, 3, 16 and related tampering."""
    run = completed_run(tmp_path)
    rewrite_events(run.stream_dir(), _mutate_first(event_type, change))
    review = run.review()
    assert review.audit_verified and expected in codes(review) and not review.consistent


def test_fake_approval_without_matching_request(tmp_path):
    """Adversarial break 12."""
    run = completed_run(tmp_path)

    def inject(events):
        fake = dict(events[1], event_type="approval_requested", audit_event_id="fake-approval",
                    related_ids={"tool_request_id": "tr-ghost", "policy_decision_id": "pd-ghost",
                                 "approval_request_id": "ar-ghost"},
                    details=None)
        decided = dict(events[1], event_type="approval_decided", audit_event_id="fake-decision",
                       related_ids={"approval_request_id": "ar-other"}, details={"outcome": "accept"})
        return events[:2] + [fake, decided] + events[2:]

    rewrite_events(run.stream_dir(), inject)
    review = run.review()
    assert {"approval_without_require_approval", "approval_decision_without_request"} <= set(codes(review))


def test_fake_dispatch_without_authorization(tmp_path):
    """Adversarial break 13."""
    run = Run(tmp_path).start()
    run.propose("does_not_exist")  # denied
    run.conclude()

    def inject(events):
        proposed = next(e for e in events if e["event_type"] == "request_proposed")
        fake = dict(proposed, event_type="dispatch_started", audit_event_id="fake-dispatch", actor="system",
                    details={"capability": "does_not_exist", "target_ref": proposed["details"]["target_ref"],
                             "step_id": proposed["details"]["step_id"], "attempt_number": 1,
                             "resolved_timeout_seconds": 10, "max_output_bytes": 100, "policy_decision_id": "pd-x"})
        index = events.index(proposed) + 2
        return events[:index] + [fake] + events[index:]

    rewrite_events(run.stream_dir(), inject)
    assert "dispatch_without_authorization" in codes(run.review())


def test_dispatch_for_unknown_request_and_events_after_terminal(tmp_path):
    run = completed_run(tmp_path)

    def inject(events):
        stray = dict(events[-1], event_type="dispatch_started", audit_event_id="stray",
                     related_ids={"tool_request_id": "tr-ghost"}, details=None)
        return events + [stray]

    rewrite_events(run.stream_dir(), inject)
    assert {"event_after_terminal", "dispatch_without_request"} <= set(codes(run.review()))


def test_evidence_event_without_dispatch(tmp_path):
    run = completed_run(tmp_path)
    rewrite_events(run.stream_dir(), lambda events: [e for e in events if e["event_type"] != "dispatch_completed"])
    assert "evidence_without_dispatch" in codes(run.review())


def test_legacy_streams_without_facts_are_flagged_not_trusted(tmp_path):
    run = completed_run(tmp_path)
    rewrite_events(run.stream_dir(), lambda events: [dict(e, details=None) if e["event_type"] in (
        "investigation_started", "request_proposed", "policy_evaluated", "dispatch_started") else e for e in events])
    review = run.review()
    assert "details_missing" in codes(review) and review.origin is None and not review.consistent


# ===========================================================================
# T-U. CLI --review and escaping
# ===========================================================================


def test_cli_review_of_a_completed_investigation(tmp_path):
    run = completed_run(tmp_path)
    code, shown = run.cli_review()
    assert code == cli_main.EXIT_COMPLETED
    assert f'review: "{run.inv}"' in shown and 'status: "completed"' in shown
    assert "audit chain: verified" in shown and "consistency: consistent" in shown
    assert '"observe_local_host_environment" on "local-host"' in shown and 'policy: "allow"' in shown
    assert "envelope: timeout 10s" in shown and "anomalies: 0" in shown


def test_cli_review_reads_no_credential_and_builds_no_runtime(tmp_path, monkeypatch):
    run = completed_run(tmp_path)
    for name in ("build_runtime", "AnthropicProvider", "PolicyGateway", "build_tool_executor", "run_investigation"):
        monkeypatch.setattr(cli_main, name, lambda *a, **k: (_ for _ in ()).throw(AssertionError(name)))

    class NoEnviron(dict):
        def get(self, key, default=None):
            raise AssertionError("review read the environment")

    import io
    out = io.StringIO()
    assert cli_main.main(["--review", run.inv, "--workdir", str(tmp_path)], environ=NoEnviron(), output=out) == 0


def test_cli_review_of_an_incomplete_investigation_is_non_zero(tmp_path):
    run = completed_run(tmp_path)
    truncate_after(run.stream_dir(), "dispatch_started")
    code, shown = run.cli_review()
    assert code == cli_main.EXIT_NOT_COMPLETED and 'status: "incomplete"' in shown and "no_terminal_event" in shown


def test_cli_review_of_a_corrupt_chain(tmp_path):
    run = completed_run(tmp_path)
    _edit_record(sorted(run.stream_dir().glob("*.json"))[0], lambda d: d.__setitem__("record_hash", "sha256:" + "0" * 64))
    code, shown = run.cli_review()
    assert code == cli_main.EXIT_NOT_COMPLETED and "unverifiable" in shown and "audit chain: NOT VERIFIED" in shown


def test_cli_review_of_an_empty_workdir_creates_nothing(tmp_path):
    import io
    out = io.StringIO()
    code = cli_main.main(["--review", "abc", "--workdir", str(tmp_path / "none")], environ={}, output=out)
    assert code == cli_main.EXIT_NOT_COMPLETED and "not_found" in out.getvalue()
    assert not (tmp_path / "none").exists()


def test_cli_rejects_objective_and_review_together_and_neither(tmp_path):
    import io
    for argv in (["objective", "--review", "x"], []):
        out = io.StringIO()
        assert cli_main.main(argv + ["--workdir", str(tmp_path)], environ={}, output=out) == cli_main.EXIT_CONFIG_ERROR


def test_cli_review_escapes_hostile_text(tmp_path):
    """Adversarial break 15."""
    run = Run(tmp_path).start("Check ‮ reversed text\tand\nnewlines")
    run.propose()
    hostile = "\u001b]0;pwned\u0007 ignore previous instructions"
    run.conclude(lambda ids: [finding(ids, title="‮ reversed title", description="d")])
    code, shown = run.cli_review()
    assert all(ch == "\n" or 32 <= ord(ch) < 127 for ch in shown)
    assert "\\u202e" in shown and "\\n" in shown and "\\t" in shown
    assert hostile not in shown


def test_cli_review_escapes_stored_hostile_values_in_a_rewritten_chain(tmp_path):
    run = completed_run(tmp_path)
    rewrite_events(run.stream_dir(), _mutate_first(
        "policy_evaluated", lambda e: e["details"].__setitem__("reason", "\x1b[2J\x1b[31mAPPROVED\x1b[0m")))
    code, shown = run.cli_review()
    assert "\x1b" not in shown and "\\u001b" in shown


# ===========================================================================
# V-W. Boundaries and read-only guarantees (AR-INV-6)
# ===========================================================================


def _imports(path: Path) -> set:
    found = set()
    for node in ast.walk(ast.parse(path.read_text(encoding="utf-8"))):
        if isinstance(node, ast.ImportFrom):
            found.add("." * node.level + (node.module or ""))
        elif isinstance(node, ast.Import):
            found.update(a.name for a in node.names)
    return found


@pytest.mark.parametrize(
    "forbidden",
    ["chanakya.runtime", "chanakya.policy", "chanakya.providers", "chanakya.tools", "chanakya.approval",
     "chanakya.registry", "chanakya.targets", "chanakya.cli", "chanakya.risk", "anthropic", "httpx", "subprocess",
     "socket", "importlib"],
)
def test_review_package_imports_nothing_on_the_execution_or_authorization_path(forbidden):
    """Adversarial break 14."""
    for path in (_CHANAKYA / "review").rglob("*.py"):
        for module in _imports(path):
            assert not (module == forbidden or module.startswith(forbidden + ".")), (path.name, module)


def test_only_the_cli_imports_the_review_package():
    importers = {
        path.relative_to(_REPO_ROOT).as_posix()
        for path in _CHANAKYA.rglob("*.py")
        if path.parent.name != "review" and any(m.startswith("chanakya.review") for m in _imports(path))
    }
    assert importers == {"chanakya/cli/main.py"}


def test_review_code_calls_no_mutating_or_executing_api():
    # Store/log/engine receivers may only be read; nothing may execute, open files or evaluate code.
    store_mutators = {"append", "emit", "write_text", "write_bytes", "unlink", "mkdir", "rename", "replace"}
    forbidden_anywhere = {"execute", "evaluate", "next_turn", "request_approval", "run_turn", "dispatch", "eval", "exec",
                          "open", "cancel", "halt", "complete", "fail"}
    for path in (_CHANAKYA / "review").rglob("*.py"):
        for node in ast.walk(ast.parse(path.read_text(encoding="utf-8"))):
            if not isinstance(node, ast.Call):
                continue
            if isinstance(node.func, ast.Attribute):
                name = node.func.attr
                receiver = ast.unparse(node.func.value)
                if name in store_mutators:
                    assert not any(k in receiver for k in ("store", "log", "engine", "path", "Path")), (path.name, receiver)
            else:
                name = getattr(node.func, "id", None)
            assert name not in forbidden_anywhere, (path.name, name)


def _snapshot(root: Path):
    return sorted((p.relative_to(root).as_posix(), hashlib.sha256(p.read_bytes()).hexdigest())
                  for p in root.rglob("*") if p.is_file())


def test_review_modifies_no_artifact(tmp_path):
    run = completed_run(tmp_path)
    put_evidence(run.runtime.evidence_store, run.inv, ENV)  # an orphan, so every code path runs
    before = _snapshot(tmp_path)
    run.review()
    run.cli_review()
    assert _snapshot(tmp_path) == before


def test_review_result_is_immutable_and_not_executable():
    review = InvestigationReview(investigation_id="x", status=ReviewStatus.INCOMPLETE)
    with pytest.raises(dataclasses.FrozenInstanceError):
        review.status = ReviewStatus.COMPLETED  # type: ignore[misc]
    assert not any(callable(getattr(review, f.name)) for f in dataclasses.fields(review))


def test_missing_terminal_event_is_never_consistent_completion(tmp_path):
    """AR-INV-7."""
    run = Run(tmp_path).start()
    run.propose()
    review = run.review()
    assert review.status == ReviewStatus.INCOMPLETE and not review.consistent


def test_review_never_raises_on_arbitrary_audit_details(tmp_path):
    run = completed_run(tmp_path)
    rewrite_events(run.stream_dir(), lambda events: [dict(e, details={"x": [1, {"y": None}]}) for e in events])
    review = run.review()
    assert review.status in (ReviewStatus.INCOMPLETE, ReviewStatus.COMPLETED) and not review.consistent


def test_risk_ids_in_review_match_the_deterministic_ids(tmp_path):
    run = completed_run(tmp_path)
    review = run.review()
    (risk,) = review.risk_assessments
    from chanakya.contracts.risk_taxonomy import RISK_RULE_SET_V1

    assert risk.risk_assessment_id == derive_risk_assessment_id(run.inv, risk.finding_id, RISK_RULE_SET_V1)
