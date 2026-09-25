"""Phase 6 — durable FilesystemAuditLog (6.1 foundation + 6.3 adversarial).

Unit-level: the log in isolation, against a per-test ``tmp_path``. Each
test names the AL-INV invariant(s) it exercises. Runtime integration is in
``tests/test_audit_log_runtime.py``.
"""
from __future__ import annotations

import ast
import json
import os
import threading
import uuid
from pathlib import Path
from typing import Any, Optional

import pytest

import chanakya.audit.log as audit_log_module
from chanakya.audit import (
    MAX_RECORD_BYTES,
    SYSTEM_STREAM,
    AuditLogError,
    AuditRecordTooLargeError,
    AuditSequenceCollisionError,
    CorruptAuditLogError,
    CredentialShapedAuditDataError,
    FilesystemAuditLog,
    InvalidAuditIdentifierError,
)
from chanakya.contracts.audit_event import AuditEvent, AuditEventType, AuditSeverity
from chanakya.evidence.hashing import compute_content_hash
from chanakya.runtime.audit import AuditEmitter, AuditSink
from chanakya.runtime.exceptions import AuditSinkError

_REPO_ROOT = Path(__file__).resolve().parent.parent
INV = "inv-audit-001"


def make_event(
    investigation_id: Optional[str] = INV,
    event_type: AuditEventType = AuditEventType.REQUEST_PROPOSED,
    details: Optional[dict] = None,
    **overrides: Any,
) -> AuditEvent:
    fields = dict(
        audit_event_id=str(uuid.uuid4()),
        contract_version="1.0.0",
        event_type=event_type,
        occurred_at="2026-09-25T00:00:00Z",
        actor="system",
        investigation_id=investigation_id,
        related_ids={"tool_request_id": "tr-1"},
        details=details,
        severity=None,
    )
    fields.update(overrides)
    return AuditEvent(**fields)


@pytest.fixture
def log(tmp_path) -> FilesystemAuditLog:
    return FilesystemAuditLog(tmp_path / "audit")


def stream_dir(log: FilesystemAuditLog, investigation_id: Optional[str] = INV) -> Path:
    return log.root / (SYSTEM_STREAM if investigation_id is None else investigation_id)


def record_path(log: FilesystemAuditLog, sequence: int, investigation_id: Optional[str] = INV) -> Path:
    return stream_dir(log, investigation_id) / f"{sequence:08d}.json"


def read_raw(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def write_raw(path: Path, data: dict) -> None:
    path.write_text(json.dumps(data), encoding="utf-8")


def rehash(data: dict) -> dict:
    """What a tamperer who knows the scheme would do to one record."""
    hashed = {k: data[k] for k in ("sequence", "previous_record_hash", "recorded_at", "event")}
    return dict(hashed, record_hash=compute_content_hash(hashed))


def emit_n(log: FilesystemAuditLog, n: int, investigation_id: Optional[str] = INV) -> None:
    for i in range(n):
        log.emit(make_event(investigation_id, details={"i": i}))


def entries(directory: Path) -> set:
    return {p.name for p in directory.iterdir()}


# ===========================================================================
# Storage, sink protocol, round trip
# ===========================================================================


def test_implements_the_existing_audit_sink_protocol(log):
    sink: AuditSink = log  # structural: emit(event) -> None
    assert callable(sink.emit)
    AuditEmitter(log).investigation_started(INV)
    assert [r.event.event_type for r in log.list_by_investigation(INV)] == [AuditEventType.INVESTIGATION_STARTED]


def test_layout_is_root_investigation_zero_padded_sequence(log):
    emit_n(log, 3)
    assert entries(stream_dir(log)) == {"00000001.json", "00000002.json", "00000003.json"}


def test_round_trip_preserves_every_event_field(log):
    event = make_event(
        details={"verdict": "allow", "nested": {"a": [1, 2, None]}, "unicode": "é"},
        severity=AuditSeverity.WARNING,
        event_type=AuditEventType.POLICY_EVALUATED,
    )
    log.emit(event)
    (record,) = log.list_by_investigation(INV)
    assert record.event == event


def test_system_events_use_a_separate_stream(log):
    log.emit(make_event(None, event_type=AuditEventType.ERROR))
    log.emit(make_event(INV))
    assert entries(log.root) == {SYSTEM_STREAM, INV}
    assert [r.event.investigation_id for r in log.list_by_investigation(None)] == [None]
    assert log.verify(None) and log.verify(INV)


def test_system_stream_name_can_never_be_an_investigation_id():
    with pytest.raises(InvalidAuditIdentifierError):
        audit_log_module._validate_identifier(SYSTEM_STREAM)


def test_empty_or_unknown_stream_lists_nothing_and_verifies(log):
    assert log.list_by_investigation("never-written") == ()
    assert log.verify("never-written") is True


# ===========================================================================
# AL-INV-1 — append-only
# ===========================================================================


def test_no_mutation_api_exists():
    public = {name for name in dir(FilesystemAuditLog) if not name.startswith("_")}
    assert public == {"MAX_RECORD_BYTES", "emit", "list_by_investigation", "root", "verify"}
    for forbidden in ("update", "delete", "replace", "overwrite", "remove", "truncate", "clear", "rewrite"):
        assert not hasattr(FilesystemAuditLog, forbidden)


def test_append_creates_the_next_sequence(log):
    emit_n(log, 2)
    log.emit(make_event(details={"third": True}))
    records = log.list_by_investigation(INV)
    assert [r.sequence for r in records] == [1, 2, 3]
    assert records[-1].event.details == {"third": True}


def test_existing_record_is_never_overwritten(log):
    emit_n(log, 1)
    before = record_path(log, 1).read_bytes()
    with pytest.raises(AuditSequenceCollisionError):
        FilesystemAuditLog._write_exclusive(record_path(log, 1), b"{}")
    assert record_path(log, 1).read_bytes() == before


def test_sequence_collision_during_append_fails_closed(log, monkeypatch):
    """A record appearing at the target name between head read and link
    (e.g. a second writer) makes the append fail; nothing is replaced."""
    emit_n(log, 1)
    real_link = os.link

    def racing_link(src, dst):
        Path(dst).write_bytes(b"RACED")
        return real_link(src, dst)

    monkeypatch.setattr(audit_log_module.os, "link", racing_link)
    with pytest.raises(AuditSequenceCollisionError):
        log.emit(make_event())
    assert record_path(log, 2).read_bytes() == b"RACED"
    assert not [p for p in stream_dir(log).iterdir() if p.name.startswith(".audit-tmp-")]


# ===========================================================================
# AL-INV-2 — store-owned integrity fields
# ===========================================================================


def test_store_owned_fields_are_present_and_computed(log):
    emit_n(log, 2)
    first, second = (read_raw(record_path(log, n)) for n in (1, 2))
    assert set(first) == {"sequence", "previous_record_hash", "recorded_at", "event", "record_hash"}
    assert first["sequence"] == 1 and first["previous_record_hash"] is None
    assert second["sequence"] == 2 and second["previous_record_hash"] == first["record_hash"]
    assert first["record_hash"] == rehash(first)["record_hash"]
    assert first["record_hash"].startswith("sha256:")


def test_audit_event_has_no_field_for_any_integrity_value():
    fields = set(AuditEvent.__dataclass_fields__)
    assert not fields & {"sequence", "previous_record_hash", "record_hash", "recorded_at"}


def test_caller_values_in_details_or_ids_never_become_envelope_fields(log):
    forged = {"sequence": 999, "previous_record_hash": "sha256:forged", "record_hash": "sha256:forged", "recorded_at": "1999"}
    log.emit(make_event(details=forged, related_ids={"sequence": "999", "record_hash": "sha256:forged"}))
    raw = read_raw(record_path(log, 1))
    assert raw["sequence"] == 1 and raw["previous_record_hash"] is None
    assert raw["record_hash"] != "sha256:forged" and raw["recorded_at"] != "1999"
    assert raw["event"]["details"] == forged  # stays inside the event, inert
    assert log.verify(INV)


def test_recorded_at_is_the_store_clock_not_occurred_at(log):
    log.emit(make_event(occurred_at="1970-01-01T00:00:00Z"))
    (record,) = log.list_by_investigation(INV)
    assert record.event.occurred_at == "1970-01-01T00:00:00Z"
    assert record.recorded_at != record.event.occurred_at and record.recorded_at.startswith("20")


# ===========================================================================
# AL-INV-3 — tamper detection (6.3)
# ===========================================================================


def _tamper_field(log, sequence, mutate, *, keep_hash_valid=False):
    path = record_path(log, sequence)
    data = read_raw(path)
    mutate(data)
    write_raw(path, rehash(data) if keep_hash_valid else data)


@pytest.mark.parametrize(
    "mutate",
    [
        lambda d: d["event"].__setitem__("actor", "attacker"),
        lambda d: d["event"].__setitem__("details", {"i": "changed"}),
        lambda d: d["event"].__setitem__("event_type", "investigation_completed"),
        lambda d: d.__setitem__("record_hash", "sha256:" + "0" * 64),
        lambda d: d.__setitem__("previous_record_hash", "sha256:" + "1" * 64),
        lambda d: d.__setitem__("recorded_at", "2000-01-01T00:00:00.000000Z"),
        lambda d: d.__setitem__("sequence", 7),
    ],
    ids=["event_actor", "event_details", "event_type", "record_hash", "previous_record_hash", "recorded_at", "sequence"],
)
def test_modified_middle_record_is_detected(log, mutate):
    emit_n(log, 3)
    _tamper_field(log, 2, mutate)
    assert log.verify(INV) is False
    with pytest.raises(CorruptAuditLogError):
        log.list_by_investigation(INV)


@pytest.mark.parametrize(
    "mutate",
    [
        lambda d: d["event"].__setitem__("actor", "attacker"),
        lambda d: d.__setitem__("recorded_at", "2000-01-01T00:00:00.000000Z"),
        lambda d: d.__setitem__("previous_record_hash", None),
    ],
    ids=["event", "recorded_at", "previous_record_hash"],
)
def test_rehashed_middle_record_still_breaks_the_chain(log, mutate):
    """Even with a correctly recomputed record_hash, the next record's
    previous_record_hash no longer matches."""
    emit_n(log, 3)
    _tamper_field(log, 2, mutate, keep_hash_valid=True)
    assert log.verify(INV) is False


def test_forged_sequence_with_valid_hash_is_detected(log):
    emit_n(log, 3)
    _tamper_field(log, 2, lambda d: d.__setitem__("sequence", 3), keep_hash_valid=True)
    assert log.verify(INV) is False


def test_forged_envelope_field_is_detected(log):
    emit_n(log, 2)
    _tamper_field(log, 1, lambda d: d.__setitem__("approved", True))
    assert log.verify(INV) is False
    _tamper_field(log, 1, lambda d: d.pop("approved"))
    assert log.verify(INV) is True
    _tamper_field(log, 1, lambda d: d.pop("recorded_at"))
    assert log.verify(INV) is False


def test_forged_event_shape_is_detected(log):
    emit_n(log, 2)
    _tamper_field(log, 1, lambda d: d["event"].__setitem__("verdict", "allow"), keep_hash_valid=True)
    assert log.verify(INV) is False


def test_deleted_middle_record_is_detected(log):
    emit_n(log, 3)
    record_path(log, 2).unlink()
    assert log.verify(INV) is False


def test_reordered_records_are_detected(log):
    emit_n(log, 3)
    one, two = record_path(log, 1), record_path(log, 2)
    a, b = one.read_bytes(), two.read_bytes()
    one.write_bytes(b)
    two.write_bytes(a)
    assert log.verify(INV) is False


def test_inserted_middle_record_is_detected(log):
    emit_n(log, 3)
    # Shift 2 -> 3 -> 4 and put a forged record at 2 (correctly hashed and
    # linked to 1): the shifted records' own sequence fields no longer match.
    for n in (3, 2):
        record_path(log, n).rename(record_path(log, n + 1))
    first = read_raw(record_path(log, 1))
    forged = rehash(
        {"sequence": 2, "previous_record_hash": first["record_hash"], "recorded_at": first["recorded_at"],
         "event": dict(first["event"], actor="attacker")}
    )
    write_raw(record_path(log, 2), forged)
    assert log.verify(INV) is False


def test_stray_record_like_file_is_detected(log):
    emit_n(log, 2)
    (stream_dir(log) / "00000002a.json").write_text("{}", encoding="utf-8")
    assert log.verify(INV) is False


def test_record_moved_between_investigations_is_detected(log):
    emit_n(log, 1, "inv-a")
    emit_n(log, 1, "inv-b")
    record_path(log, 1, "inv-b").write_bytes(record_path(log, 1, "inv-a").read_bytes())
    assert log.verify("inv-b") is False


@pytest.mark.parametrize(
    "content",
    [b"{not json", b"\xff\xfe\x00", b"[]", b'{"sequence": 1}', b""],
    ids=["broken_json", "not_utf8", "not_object", "missing_fields", "empty"],
)
def test_corrupted_record_is_detected(log, content):
    emit_n(log, 2)
    record_path(log, 1).write_bytes(content)
    assert log.verify(INV) is False
    with pytest.raises(CorruptAuditLogError):
        log.list_by_investigation(INV)


def test_append_refuses_to_extend_a_corrupted_head(log):
    emit_n(log, 2)
    _tamper_field(log, 2, lambda d: d["event"].__setitem__("actor", "attacker"))
    with pytest.raises(CorruptAuditLogError):
        log.emit(make_event())
    assert not record_path(log, 3).exists()


def test_append_refuses_to_extend_a_stream_with_a_gap(log):
    emit_n(log, 3)
    record_path(log, 2).unlink()
    with pytest.raises(CorruptAuditLogError):
        log.emit(make_event())


def test_verify_is_fail_closed_on_unexpected_errors(log, monkeypatch):
    emit_n(log, 1)
    monkeypatch.setattr(FilesystemAuditLog, "_load_stream", lambda self, stream: 1 / 0)
    assert log.verify(INV) is False


# -- documented limitation --------------------------------------------------


def test_limitation_tail_truncation_is_not_detected(log):
    """Known Phase 6 limitation: without an external anchor for the chain
    head, deleting the last records leaves a valid, shorter chain."""
    emit_n(log, 3)
    record_path(log, 3).unlink()
    assert log.verify(INV) is True
    assert [r.sequence for r in log.list_by_investigation(INV)] == [1, 2]


def test_limitation_rewritten_last_record_is_not_detected(log):
    """Same root cause: the hash is unkeyed and nothing commits to the head,
    so the last record can be rewritten and rehashed undetected."""
    emit_n(log, 3)
    _tamper_field(log, 3, lambda d: d["event"].__setitem__("actor", "attacker"), keep_hash_valid=True)
    assert log.verify(INV) is True


# ===========================================================================
# AL-INV-4 / AL-INV-5 — durability and fail-closed writes
# ===========================================================================


def test_record_is_on_disk_and_fsynced_before_emit_returns(log, monkeypatch):
    synced = []
    real_fsync = os.fsync
    monkeypatch.setattr(audit_log_module.os, "fsync", lambda fd: (synced.append(fd), real_fsync(fd)))
    log.emit(make_event())
    assert synced, "record data was not fsynced"
    # A brand-new instance (nothing in memory) sees the record immediately.
    assert len(FilesystemAuditLog(log.root).list_by_investigation(INV)) == 1


@pytest.mark.parametrize("fail_at", ["fsync", "link", "write"])
def test_atomic_write_failure_leaves_nothing_behind(log, monkeypatch, fail_at):
    emit_n(log, 1)
    before = entries(stream_dir(log))

    def boom(*_args, **_kwargs):
        raise OSError(f"simulated {fail_at} failure")

    if fail_at == "fsync":
        monkeypatch.setattr(audit_log_module.os, "fsync", boom)
    elif fail_at == "link":
        monkeypatch.setattr(audit_log_module.os, "link", boom)
    else:
        real_fdopen = os.fdopen

        class _FailingHandle:
            def __init__(self, fd, mode):
                self._h = real_fdopen(fd, mode)

            def __enter__(self):
                return self

            def __exit__(self, *exc):
                self._h.close()

            def write(self, data):
                raise OSError("simulated write failure")

        monkeypatch.setattr(audit_log_module.os, "fdopen", _FailingHandle)

    with pytest.raises(OSError):
        log.emit(make_event())
    assert entries(stream_dir(log)) == before  # no final record, no temp file
    assert log.verify(INV)


def test_write_failure_reaches_the_runtime_as_audit_sink_error(log, monkeypatch):
    monkeypatch.setattr(audit_log_module.os, "fsync", lambda fd: (_ for _ in ()).throw(OSError("disk full")))
    with pytest.raises(AuditSinkError):
        AuditEmitter(log).request_proposed(INV, "tr-1")
    assert log.list_by_investigation(INV) == ()


# ===========================================================================
# AL-INV-6 — identifiers
# ===========================================================================


@pytest.mark.parametrize(
    "bad_id",
    [
        "../escape", "..\\escape", "..", ".", "a/b", "a\\b", "/abs", "C:\\abs", "C:", "\\\\server\\share",
        "inv\x00id", "", " ", "inv id", "inv.id", "x" * 129, "CON", "nul", "Com1", "lpt9", "AUX", "PRN", SYSTEM_STREAM,
    ],
)
def test_unsafe_investigation_ids_are_rejected_before_any_io(log, bad_id):
    event = make_event(bad_id)
    with pytest.raises(InvalidAuditIdentifierError):
        log.emit(event)
    with pytest.raises(InvalidAuditIdentifierError):
        log.verify(bad_id)
    with pytest.raises(InvalidAuditIdentifierError):
        log.list_by_investigation(bad_id)
    assert not log.root.exists() or not any(log.root.iterdir())


@pytest.mark.parametrize("bad_id", [123, b"inv", ["inv"]])
def test_non_string_ids_are_rejected(log, bad_id):
    with pytest.raises(InvalidAuditIdentifierError):
        log.verify(bad_id)


def test_identifier_rule_is_the_evidence_store_rule():
    from chanakya.evidence.store import _validate_identifier as evidence_rule

    assert audit_log_module._validate_evidence_identifier is evidence_rule


# ===========================================================================
# AL-INV-8 — size and credential controls
# ===========================================================================


def test_record_at_the_size_limit_is_accepted_and_one_over_is_rejected(log):
    def size_for(padding: int) -> int:
        probe = FilesystemAuditLog(log.root.parent / f"probe-{padding}")
        probe.emit(make_event(details={"p": "x" * padding}))
        return len(record_path(probe, 1).read_bytes())

    base = size_for(0)
    exact = MAX_RECORD_BYTES - base
    assert size_for(exact) == MAX_RECORD_BYTES  # canonical bytes are what is measured and stored

    log.emit(make_event(details={"p": "x" * exact}))
    with pytest.raises(AuditRecordTooLargeError):
        log.emit(make_event(details={"p": "x" * (exact + 1)}))
    assert [r.sequence for r in log.list_by_investigation(INV)] == [1]
    assert not [p for p in stream_dir(log).iterdir() if p.name.startswith(".audit-tmp-")]


def test_oversized_record_is_rejected_not_truncated(log):
    with pytest.raises(AuditRecordTooLargeError):
        log.emit(make_event(details={"p": "x" * (MAX_RECORD_BYTES * 2)}))
    assert log.list_by_investigation(INV) == ()


@pytest.mark.parametrize(
    "details",
    [
        {"detail": "https://admin:hunter2@internal.example/path"},
        {"detail": "password=hunter2"},
        {"error_message": "request failed: url?token=abc123"},
        {"justification": "api_key=sk-live-123"},
        {"nested": {"deeper": ["ok", "client_secret=xyz"]}},
        {"password=hunter2": "key position"},
    ],
    ids=["url_userinfo", "password_pair", "token_param", "api_key", "nested_list", "in_key"],
)
def test_credential_shaped_details_are_rejected_and_not_persisted(log, details):
    with pytest.raises(CredentialShapedAuditDataError):
        log.emit(make_event(details=details))
    assert log.list_by_investigation(INV) == ()
    assert not stream_dir(log).exists() or not any(stream_dir(log).iterdir())


def test_credential_rejection_messages_never_echo_the_value(log):
    with pytest.raises(CredentialShapedAuditDataError) as excinfo:
        log.emit(make_event(details={"detail": "password=hunter2"}))
    assert "hunter2" not in str(excinfo.value)


@pytest.mark.parametrize(
    "details",
    [{"reason": "token budget exhausted"}, {"secret_marker": "none"}, {"matched_rule": "deny-passwords"}, {"url": "https://example.com/a?b=c"}],
)
def test_ordinary_details_are_not_over_blocked(log, details):
    log.emit(make_event(details=details))
    assert log.verify(INV)


def test_non_json_details_are_rejected_not_stringified(log):
    with pytest.raises(AuditLogError):
        log.emit(make_event(details={"obj": object()}))
    assert log.list_by_investigation(INV) == ()


def test_non_event_input_is_rejected(log):
    with pytest.raises(TypeError):
        log.emit({"event_type": "request_proposed"})


# ===========================================================================
# AL-INV-9 — restart continuation; isolation
# ===========================================================================


def test_chain_continues_across_a_process_restart(log):
    emit_n(log, 2)
    restarted = FilesystemAuditLog(log.root)  # fresh instance: no in-memory state
    restarted.emit(make_event(details={"after": "restart"}))
    records = restarted.list_by_investigation(INV)
    assert [r.sequence for r in records] == [1, 2, 3]
    assert records[2].previous_record_hash == records[1].record_hash
    assert restarted.verify(INV) and log.verify(INV)


def test_head_is_reread_from_disk_on_every_append(log):
    other = FilesystemAuditLog(log.root)
    log.emit(make_event())
    other.emit(make_event())  # sees log's record without any shared memory
    log.emit(make_event())
    assert [r.sequence for r in log.list_by_investigation(INV)] == [1, 2, 3]
    assert log.verify(INV)


def test_investigations_have_isolated_chains(log):
    for i in range(3):
        log.emit(make_event("inv-a", details={"i": i}))
        log.emit(make_event("inv-b", details={"i": i}))
    a, b = log.list_by_investigation("inv-a"), log.list_by_investigation("inv-b")
    assert [r.sequence for r in a] == [1, 2, 3] == [r.sequence for r in b]
    assert a[0].previous_record_hash is None and b[0].previous_record_hash is None
    assert {r.event.investigation_id for r in a} == {"inv-a"}
    record_path(log, 2, "inv-a").unlink()
    assert log.verify("inv-a") is False and log.verify("inv-b") is True


def test_concurrent_threads_across_investigations_stay_consistent(log):
    def writer(investigation_id):
        for i in range(20):
            log.emit(make_event(investigation_id, details={"i": i}))

    threads = [threading.Thread(target=writer, args=(f"inv-t{n}",)) for n in range(4)]
    threads += [threading.Thread(target=writer, args=("inv-shared",)) for _ in range(2)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    for n in range(4):
        assert log.verify(f"inv-t{n}") and len(log.list_by_investigation(f"inv-t{n}")) == 20
    assert log.verify("inv-shared") and len(log.list_by_investigation("inv-shared")) == 40


# ===========================================================================
# AL-INV-7 — never model input, never authorization input (static)
# ===========================================================================


def _imports(path: Path) -> set:
    tree = ast.parse(path.read_text(encoding="utf-8"))
    found = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom) and node.module:
            found.add(node.module)
        elif isinstance(node, ast.Import):
            found.update(alias.name for alias in node.names)
    return found


@pytest.mark.parametrize("package", ["policy", "runtime", "providers", "targets", "tools", "registry", "contracts", "evidence"])
def test_no_production_package_reads_the_audit_log(package):
    for path in (_REPO_ROOT / "chanakya" / package).rglob("*.py"):
        assert not any(m.startswith("chanakya.audit") for m in _imports(path)), path


def test_audit_package_has_no_authority_or_provider_dependency():
    for path in (_REPO_ROOT / "chanakya" / "audit").rglob("*.py"):
        for module in _imports(path):
            assert not module.startswith(
                ("chanakya.policy", "chanakya.runtime", "chanakya.providers", "chanakya.tools", "anthropic", "httpx")
            ), (path, module)
