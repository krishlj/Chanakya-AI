"""Phase 10 — RiskAssessmentStore (10.3): append-only, hash-verified,
investigation-partitioned, duplicate-resistant (RA-INV-8)."""
from __future__ import annotations

import dataclasses
import json
from pathlib import Path

import pytest

import chanakya.risk.store as store_module
from chanakya.contracts.risk_assessment import RiskAssessment
from chanakya.evidence.hashing import compute_content_hash
from chanakya.risk.store import (
    MAX_RECORD_BYTES,
    CorruptRiskAssessmentError,
    InvalidRiskAssessmentIdentifierError,
    RiskAssessmentIdCollisionError,
    RiskAssessmentRecordTooLargeError,
    RiskAssessmentStore,
)

from risk_factories import AUTHORITY_KEYS, make_ra


@pytest.fixture
def store(tmp_path):
    return RiskAssessmentStore(tmp_path / "risk")


def record_path(store: RiskAssessmentStore, ra: RiskAssessment) -> Path:
    return store.root / ra.investigation_id / f"{ra.risk_assessment_id}.json"


def rewrite(path: Path, mutate, *, rehash: bool) -> None:
    data = json.loads(path.read_text(encoding="utf-8"))
    mutate(data)
    if rehash:
        data["content_hash"] = compute_content_hash(
            {"risk_assessment": data["risk_assessment"], "recorded_at": data["recorded_at"]}
        )
    path.write_text(json.dumps(data), encoding="utf-8")


def test_append_list_verify(store):
    a, b = make_ra(finding_refs=("find-b",)), make_ra(finding_refs=("find-a",))
    store.append(a)
    store.append(b)
    assert store.list_by_investigation("inv-10") == (b, a)
    assert store.verify("inv-10")
    raw = json.loads(record_path(store, a).read_text(encoding="utf-8"))
    assert set(raw) == {"risk_assessment", "recorded_at", "content_hash"}
    assert raw["content_hash"].startswith("sha256:")
    assert raw["risk_assessment"] == a.to_dict()


def test_layout_is_investigation_then_id(store):
    ra = make_ra()
    store.append(ra)
    assert [p.relative_to(store.root).as_posix() for p in store.root.rglob("*.json")] == [
        f"inv-10/{ra.risk_assessment_id}.json"
    ]


def test_unknown_investigation_lists_nothing(store):
    assert store.list_by_investigation("inv-none") == ()
    assert store.verify("inv-none")


def test_store_survives_a_restart(store):
    ra = make_ra()
    store.append(ra)
    assert RiskAssessmentStore(store.root).list_by_investigation("inv-10") == (ra,)


def test_store_has_no_mutation_api():
    public = {n for n in dir(RiskAssessmentStore) if not n.startswith("_")}
    assert public == {"MAX_RECORD_BYTES", "append", "list_by_investigation", "root", "verify"}


def test_duplicate_assessment_collides_and_never_overwrites(store):
    ra = make_ra()
    store.append(ra)
    before = record_path(store, ra).read_bytes()
    again = dataclasses.replace(ra, assessed_at="2030-01-01T00:00:00Z")  # same finding, same rule set
    assert again.risk_assessment_id == ra.risk_assessment_id
    with pytest.raises(RiskAssessmentIdCollisionError):
        store.append(again)
    assert record_path(store, ra).read_bytes() == before
    assert store.list_by_investigation("inv-10") == (ra,)


def test_collision_raced_at_link_time_fails_closed(store, monkeypatch):
    ra = make_ra()

    def racing_link(src, dst):
        Path(dst).write_bytes(b"{}")
        raise FileExistsError(dst)

    monkeypatch.setattr(store_module.os, "link", racing_link)
    with pytest.raises(RiskAssessmentIdCollisionError):
        store.append(ra)
    assert not list(record_path(store, ra).parent.glob(".risk-tmp-*"))


@pytest.mark.parametrize("fail_at", ["fsync", "link"])
def test_write_failure_leaves_nothing_behind(store, monkeypatch, fail_at):
    def boom(*_a, **_k):
        raise OSError("disk full")

    monkeypatch.setattr(store_module.os, fail_at, boom)
    with pytest.raises(OSError):
        store.append(make_ra())
    directory = store.root / "inv-10"
    assert not directory.exists() or list(directory.iterdir()) == []


def test_non_contract_objects_are_refused(store):
    with pytest.raises(TypeError):
        store.append(make_ra().to_dict())  # type: ignore[arg-type]


@pytest.mark.parametrize(
    "tamper",
    [
        lambda d: d["risk_assessment"].__setitem__("severity", "high"),
        lambda d: d["risk_assessment"].__setitem__("evidence_refs", ["ev-forged"]),
        lambda d: d["risk_assessment"].__setitem__("rationale", "rewritten"),
        lambda d: d.__setitem__("content_hash", "sha256:" + "0" * 64),
        lambda d: d.__setitem__("recorded_at", "1999-01-01T00:00:00Z"),
        lambda d: d.__setitem__("approved", True),
    ],
    ids=["severity", "evidence_refs", "rationale", "hash", "recorded_at", "extra_key"],
)
def test_tampered_record_is_detected(store, tamper):
    ra = make_ra()
    store.append(ra)
    rewrite(record_path(store, ra), tamper, rehash=False)
    assert store.verify("inv-10") is False
    with pytest.raises(CorruptRiskAssessmentError):
        store.list_by_investigation("inv-10")


@pytest.mark.parametrize(
    "tamper",
    [
        lambda d: d["risk_assessment"].__setitem__("severity", "critical"),
        lambda d: d["risk_assessment"].__setitem__("severity", "high"),
        lambda d: d["risk_assessment"].__setitem__("scoring_method", "chanakya-risk-rules/9.0.0"),
        lambda d: d["risk_assessment"].__setitem__("assessed_by", "agent"),
        lambda d: d["risk_assessment"].__setitem__("finding_refs", ["find-other"]),
        lambda d: d["risk_assessment"].__setitem__("investigation_id", "inv-other"),
        lambda d: d["risk_assessment"].__setitem__("mitigations_suggested", ["kill it"]),
        lambda d: d["risk_assessment"].__setitem__("rule_ids", ["evidence.verified"]),
    ],
    ids=["critical", "severity", "unknown_method", "agent", "other_finding", "other_investigation",
         "mitigations", "rules"],
)
def test_tampered_and_rehashed_contract_violations_are_still_detected(store, tamper):
    ra = make_ra()
    store.append(ra)
    rewrite(record_path(store, ra), tamper, rehash=True)
    with pytest.raises(CorruptRiskAssessmentError):
        store.list_by_investigation("inv-10")


@pytest.mark.parametrize("key", AUTHORITY_KEYS)
def test_rehashed_authority_keys_are_rejected(store, key):
    ra = make_ra()
    store.append(ra)
    rewrite(record_path(store, ra), lambda d: d["risk_assessment"].__setitem__(key, True), rehash=True)
    assert store.verify("inv-10") is False


def test_record_copied_to_another_investigation_is_detected(store):
    ra = make_ra()
    store.append(ra)
    target = store.root / "inv-other" / record_path(store, ra).name
    target.parent.mkdir(parents=True)
    target.write_bytes(record_path(store, ra).read_bytes())
    assert store.verify("inv-other") is False


def test_record_renamed_is_detected(store):
    ra = make_ra()
    store.append(ra)
    path = record_path(store, ra)
    path.rename(path.with_name("00000000-0000-0000-0000-000000000000.json"))
    with pytest.raises(CorruptRiskAssessmentError):
        store.list_by_investigation("inv-10")


@pytest.mark.parametrize("content", [b"", b"not json", b"\xff\xfe", b"[]", b'{"risk_assessment": {}}'])
def test_garbage_records_fail_closed_without_partial_lists(store, content):
    good = make_ra(finding_refs=("find-good",))
    store.append(good)
    (store.root / "inv-10" / "zzzz.json").write_bytes(content)
    with pytest.raises(CorruptRiskAssessmentError):
        store.list_by_investigation("inv-10")


@pytest.mark.parametrize("bad", ["../escape", "a/b", "C:\\x", "CON", "inv\x00", "inv.id"])
def test_unsafe_investigation_ids_are_rejected(store, bad):
    with pytest.raises(InvalidRiskAssessmentIdentifierError):
        store.append(make_ra(investigation_id=bad))
    with pytest.raises(InvalidRiskAssessmentIdentifierError):
        store.list_by_investigation(bad)


def test_record_limit_is_8192_and_oversize_is_rejected(store, monkeypatch):
    assert MAX_RECORD_BYTES == 8192
    monkeypatch.setattr(store_module, "MAX_RECORD_BYTES", 200)
    with pytest.raises(RiskAssessmentRecordTooLargeError):
        store.append(make_ra())
    assert store.list_by_investigation("inv-10") == ()


def test_largest_valid_record_fits(store):
    refs = tuple(f"{i:02d}" + "e" * 34 for i in range(20))
    ra = make_ra(evidence_refs=refs, rationale="r" * 1000)
    store.append(ra)
    assert store.list_by_investigation("inv-10") == (ra,)
