"""Phase 6.2 — FilesystemAuditLog wired into the existing Runtime.

Real ``InvestigationManager``, ``AgentLoopController``, ``AuditEmitter``,
``PolicyGateway`` and ``FilesystemAuditLog``; one emitter shared by the
manager and the loop, exactly as a composition root would wire it. No
Runtime code is changed for this: the log is just an ``AuditSink``.
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import List, Optional

import pytest

import chanakya.audit.log as audit_log_module
from chanakya.audit import FilesystemAuditLog
from chanakya.contracts.approval import ApprovalDecisionValue
from chanakya.contracts.audit_event import AuditEventType
from chanakya.contracts.investigation_context import InvestigationStatus
from chanakya.providers.anthropic_provider import AnthropicProvider
from chanakya.runtime.agent_loop import AgentLoopController, TurnOutcome
from chanakya.runtime.audit import AuditEmitter
from chanakya.runtime.exceptions import AuditSinkError, InvestigationTerminatedError
from chanakya.runtime.investigation_manager import InvestigationManager

from runtime_factories import (
    FakeToolExecutor,
    ScriptedAgentProvider,
    ScriptedApprovalProvider,
    SpyPolicyEvaluator,
    make_agent_turn_conclude,
    make_agent_turn_propose,
    make_tool_result,
)
from test_anthropic_provider import RecordingTransport, _config, _conclude_response, _tool_use_response
from test_anthropic_provider_sdk_security import (  # noqa: F401 — autouse offline guard reused by name
    SENTINEL_KEY,
    _mock_client,
    _offline_guard,
)

TARGET = "target-local-host-01"
E = AuditEventType


def no_sleep(_seconds: float) -> None:
    return None


class FailOnEvent:
    """Delegates to the real durable log, but the write for one chosen
    ``event_type`` fails (``times`` times) before anything is persisted —
    a disk error at exactly that emission point."""

    def __init__(self, log: FilesystemAuditLog, event_type: AuditEventType, times: Optional[int] = 1) -> None:
        self.log = log
        self.event_type = event_type
        self.remaining = times

    def emit(self, event) -> None:
        if event.event_type == self.event_type and (self.remaining is None or self.remaining > 0):
            if self.remaining is not None:
                self.remaining -= 1
            raise OSError(f"simulated disk failure writing {event.event_type.value}")
        self.log.emit(event)


class Wiring:
    def __init__(self, target_registry, resource_governor, gateway, sink, *, executor=None, approval=None):
        self.audit = AuditEmitter(sink)
        self.manager = InvestigationManager(target_registry, resource_governor, audit=self.audit)
        self.executor = executor or FakeToolExecutor()
        self.spy = SpyPolicyEvaluator(gateway)
        self.controller = AgentLoopController(
            self.manager, resource_governor, self.spy, self.executor,
            approval_provider=approval, audit=self.audit, sleep=no_sleep,
        )

    def start(self, request):
        context = self.manager.create_investigation(request)
        self.manager.start(context.investigation_id)
        return context

    def propose(self, context, capability="list_listening_ports", parameters=None):
        return self.controller.run_turn(
            context.investigation_id,
            ScriptedAgentProvider([make_agent_turn_propose(context.investigation_id, capability, TARGET, parameters)]),
        )

    def conclude(self, context):
        return self.controller.run_turn(
            context.investigation_id, ScriptedAgentProvider([make_agent_turn_conclude(context.investigation_id)])
        )


@pytest.fixture
def log(tmp_path) -> FilesystemAuditLog:
    return FilesystemAuditLog(tmp_path / "audit")


def types(log: FilesystemAuditLog, investigation_id: str) -> List[AuditEventType]:
    return [r.event.event_type for r in log.list_by_investigation(investigation_id)]


def request_for(investigation_request, n: int):
    return type(investigation_request).from_dict(
        {
            "investigation_request_id": f"inv-req-audit-{n}",
            "contract_version": "1.0.0",
            "objective": f"audit runtime test {n}",
            "requested_targets": [TARGET],
            "submitted_by": "test-human",
            "submitted_at": investigation_request.submitted_at,
        }
    )


# ===========================================================================
# 1-2. Every Runtime event reaches durable storage, in order
# ===========================================================================


def test_every_runtime_event_is_persisted_in_order(target_registry, resource_governor, gateway, investigation_request, log):
    w = Wiring(target_registry, resource_governor, gateway, log, approval=ScriptedApprovalProvider(ApprovalDecisionValue.ACCEPT))
    context = w.start(investigation_request)
    assert w.propose(context).outcome == TurnOutcome.STEP_COMPLETED
    assert w.propose(context, "terminate_process", {"pid": 1}).outcome == TurnOutcome.STEP_COMPLETED
    assert w.conclude(context).outcome == TurnOutcome.CONCLUDED

    # Phase 14: every model turn is bracketed by its manifest and outcome.
    assert types(log, context.investigation_id) == [
        E.INVESTIGATION_STARTED,
        E.AGENT_TURN_REQUESTED, E.AGENT_TURN_RECEIVED,
        E.REQUEST_PROPOSED, E.POLICY_EVALUATED, E.DISPATCH_STARTED, E.DISPATCH_COMPLETED, E.EVIDENCE_RECORDED,
        E.AGENT_TURN_REQUESTED, E.AGENT_TURN_RECEIVED,
        E.REQUEST_PROPOSED, E.POLICY_EVALUATED, E.APPROVAL_REQUESTED, E.APPROVAL_DECIDED,
        E.DISPATCH_STARTED, E.DISPATCH_COMPLETED, E.EVIDENCE_RECORDED,
        E.AGENT_TURN_REQUESTED, E.AGENT_TURN_RECEIVED,
        E.INVESTIGATION_COMPLETED,
    ]
    assert log.verify(context.investigation_id)
    records = log.list_by_investigation(context.investigation_id)
    assert [r.sequence for r in records] == list(range(1, len(records) + 1))
    assert {r.event.investigation_id for r in records} == {context.investigation_id}


def test_durable_log_matches_what_the_emitter_produced(target_registry, resource_governor, gateway, investigation_request, log):
    produced = []

    class Tee:
        def emit(self, event):
            log.emit(event)
            produced.append(event)

    w = Wiring(target_registry, resource_governor, gateway, Tee())
    context = w.start(investigation_request)
    w.propose(context)
    w.conclude(context)
    assert [r.event for r in log.list_by_investigation(context.investigation_id)] == produced


def test_denial_is_persisted(target_registry, resource_governor, gateway, investigation_request, log):
    w = Wiring(target_registry, resource_governor, gateway, log)
    context = w.start(investigation_request)
    assert w.propose(context, "legacy_scan").outcome == TurnOutcome.STEP_DENIED
    records = log.list_by_investigation(context.investigation_id)
    policy = [r for r in records if r.event.event_type == E.POLICY_EVALUATED]
    assert policy and policy[-1].event.details["verdict"] == "deny"
    assert E.DISPATCH_STARTED not in types(log, context.investigation_id)


# ===========================================================================
# 3. dispatch_started is durable before the ToolExecutor runs
# ===========================================================================


def test_dispatch_started_is_durable_before_the_executor_runs(
    target_registry, resource_governor, gateway, investigation_request, log
):
    seen_on_disk = []

    def check_disk(instruction):
        # A fresh instance proves this is on disk, not in some buffer.
        records = FilesystemAuditLog(log.root).list_by_investigation(instruction.investigation_id)
        seen_on_disk.append(records[-1].event.event_type)
        return make_tool_result(instruction.tool_request_id, instruction.capability)

    w = Wiring(target_registry, resource_governor, gateway, log, executor=FakeToolExecutor(check_disk))
    context = w.start(investigation_request)
    assert w.propose(context).outcome == TurnOutcome.STEP_COMPLETED
    assert seen_on_disk == [E.DISPATCH_STARTED]


# ===========================================================================
# 4. Audit failure at dispatch_started: HALTED, executor never called
# ===========================================================================


def test_real_write_failure_at_dispatch_started_halts_before_execution(
    target_registry, resource_governor, gateway, investigation_request, log, monkeypatch
):
    """The real log's own fsync fails while writing dispatch_started."""
    w = Wiring(target_registry, resource_governor, gateway, log)
    context = w.start(investigation_request)

    real_emit = FilesystemAuditLog.emit

    def emit(self, event):
        if event.event_type == E.DISPATCH_STARTED:
            with monkeypatch.context() as m:
                m.setattr(audit_log_module.os, "fsync", lambda fd: (_ for _ in ()).throw(OSError("disk full")))
                return real_emit(self, event)
        return real_emit(self, event)

    monkeypatch.setattr(FilesystemAuditLog, "emit", emit)
    result = w.propose(context)

    assert result.outcome == TurnOutcome.HALTED
    assert context.status == InvestigationStatus.HALTED
    assert context.error_state["reason"] == "audit_sink_failure"
    assert w.executor.calls == []
    persisted = types(log, context.investigation_id)
    assert E.DISPATCH_STARTED not in persisted and E.DISPATCH_COMPLETED not in persisted
    assert persisted[-2:] == [E.ERROR, E.INVESTIGATION_HALTED]  # the halt itself is recorded
    assert log.verify(context.investigation_id)


# ===========================================================================
# 5. Audit failure at other emission points: HALTED, no continuation
# ===========================================================================


@pytest.mark.parametrize(
    "event_type, capability, executed",
    [
        (E.REQUEST_PROPOSED, "list_listening_ports", 0),
        (E.POLICY_EVALUATED, "list_listening_ports", 0),
        (E.DISPATCH_STARTED, "list_listening_ports", 0),
        (E.DISPATCH_COMPLETED, "list_listening_ports", 1),
        (E.EVIDENCE_RECORDED, "list_listening_ports", 1),
        (E.APPROVAL_REQUESTED, "terminate_process", 0),
        (E.APPROVAL_DECIDED, "terminate_process", 0),
    ],
)
def test_audit_failure_at_each_step_emission_point_halts(
    target_registry, resource_governor, gateway, investigation_request, log, event_type, capability, executed
):
    approval = ScriptedApprovalProvider(ApprovalDecisionValue.ACCEPT)
    w = Wiring(target_registry, resource_governor, gateway, FailOnEvent(log, event_type), approval=approval)
    context = w.start(investigation_request)
    result = w.propose(context, capability, {"pid": 1} if capability == "terminate_process" else None)

    assert result.outcome == TurnOutcome.HALTED
    assert context.status == InvestigationStatus.HALTED
    assert context.error_state["reason"] == "audit_sink_failure"
    assert len(w.executor.calls) == executed  # never dispatched after a pre-dispatch failure
    persisted = types(log, context.investigation_id)
    assert event_type not in persisted
    assert persisted[-2:] == [E.ERROR, E.INVESTIGATION_HALTED]
    assert log.verify(context.investigation_id)
    with pytest.raises(InvestigationTerminatedError):  # no successful continuation
        w.propose(context)
    assert len(w.executor.calls) == executed


def test_audit_failure_when_starting_an_investigation_surfaces_to_the_caller(
    target_registry, resource_governor, gateway, investigation_request, log
):
    w = Wiring(target_registry, resource_governor, gateway, FailOnEvent(log, E.INVESTIGATION_STARTED))
    with pytest.raises(AuditSinkError):
        w.manager.create_investigation(investigation_request)


def test_documented_existing_behavior_when_the_sink_stays_broken(
    target_registry, resource_governor, gateway, investigation_request, log
):
    """Existing Runtime behavior, recorded (not changed) by Phase 6: when
    every later write also fails, the backstop's own halt emission fails
    too. The investigation still ends HALTED and nothing runs, but the
    backstop reports TurnOutcome.FAILED, and no halt record exists."""
    w = Wiring(target_registry, resource_governor, gateway, log)
    context = w.start(investigation_request)
    w.audit._sink = FailOnEvent(log, E.REQUEST_PROPOSED, times=None)
    for later in (E.ERROR, E.INVESTIGATION_HALTED):
        w.audit._sink = _AlsoFail(w.audit._sink, later)
    result = w.propose(context)
    assert context.status == InvestigationStatus.HALTED
    assert result.outcome == TurnOutcome.FAILED
    assert w.executor.calls == []
    assert types(log, context.investigation_id) == [
        E.INVESTIGATION_STARTED, E.AGENT_TURN_REQUESTED, E.AGENT_TURN_RECEIVED  # Phase 14 turn records
    ]


class _AlsoFail:
    def __init__(self, inner, event_type):
        self.inner, self.event_type = inner, event_type

    def emit(self, event):
        if event.event_type == self.event_type:
            raise OSError("still broken")
        self.inner.emit(event)


def test_documented_existing_behavior_when_completion_cannot_be_audited(
    target_registry, resource_governor, gateway, investigation_request, log
):
    """Existing Runtime behavior, recorded: InvestigationManager.complete
    transitions before emitting, so a failed investigation_completed write
    leaves the investigation COMPLETED without a completion record. The
    turn is not reported as CONCLUDED, and the investigation is terminal,
    so nothing further can run."""
    w = Wiring(target_registry, resource_governor, gateway, FailOnEvent(log, E.INVESTIGATION_COMPLETED))
    context = w.start(investigation_request)
    result = w.conclude(context)
    assert result.outcome == TurnOutcome.FAILED
    assert context.status == InvestigationStatus.COMPLETED
    persisted = types(log, context.investigation_id)
    assert E.INVESTIGATION_COMPLETED not in persisted and persisted[-1] == E.ERROR


# ===========================================================================
# 6-7. Isolation and restart
# ===========================================================================


def test_investigations_have_isolated_chains(target_registry, resource_governor, gateway, investigation_request, log):
    w = Wiring(target_registry, resource_governor, gateway, log)
    a = w.start(request_for(investigation_request, 1))
    b = w.start(request_for(investigation_request, 2))
    w.propose(a)
    w.propose(b)
    w.propose(a)
    for context in (a, b):
        records = log.list_by_investigation(context.investigation_id)
        assert {r.event.investigation_id for r in records} == {context.investigation_id}
        assert records[0].previous_record_hash is None
        assert log.verify(context.investigation_id)
    assert len(log.list_by_investigation(a.investigation_id)) > len(log.list_by_investigation(b.investigation_id))
    assert (log.root / a.investigation_id).is_dir() and (log.root / b.investigation_id).is_dir()


def test_restarted_log_continues_the_existing_chain(target_registry, resource_governor, gateway, investigation_request, log):
    w = Wiring(target_registry, resource_governor, gateway, log)
    context = w.start(investigation_request)
    w.propose(context)
    before = len(log.list_by_investigation(context.investigation_id))

    restarted = FilesystemAuditLog(log.root)  # new instance, nothing carried in memory
    w.audit._sink = restarted
    w.propose(context)
    w.conclude(context)

    records = restarted.list_by_investigation(context.investigation_id)
    assert len(records) > before
    assert [r.sequence for r in records] == list(range(1, len(records) + 1))
    assert records[before].previous_record_hash == records[before - 1].record_hash
    assert restarted.verify(context.investigation_id)


# ===========================================================================
# 8-10. Provider integration; audit never reaches provider or Gateway
# ===========================================================================


def test_anthropic_provider_flow_with_durable_audit(
    target_registry, resource_governor, gateway, investigation_request, registry, log
):
    w = Wiring(target_registry, resource_governor, gateway, log)
    context = w.start(investigation_request)
    catalog = registry.catalog_view()

    transport = RecordingTransport(_tool_use_response("list_listening_ports", {"target_ref": TARGET}))
    provider = AnthropicProvider(_config(), SENTINEL_KEY, client=_mock_client(transport))
    result = w.controller.run_turn(context.investigation_id, provider, capability_catalog=catalog)
    assert result.outcome == TurnOutcome.STEP_COMPLETED

    transport2 = RecordingTransport(_conclude_response())
    provider2 = AnthropicProvider(_config(), SENTINEL_KEY, client=_mock_client(transport2))
    assert w.controller.run_turn(context.investigation_id, provider2, capability_catalog=catalog).outcome == TurnOutcome.CONCLUDED

    assert log.verify(context.investigation_id)
    assert types(log, context.investigation_id)[-1] == E.INVESTIGATION_COMPLETED

    # Audit data never enters provider context (AL-INV-7).
    records = log.list_by_investigation(context.investigation_id)
    for body in (transport.last_request_body, transport2.last_request_body):
        wire = json.dumps(body)
        for record in records:
            assert record.record_hash not in wire
            assert record.event.audit_event_id not in wire
        for marker in ("record_hash", "previous_record_hash", "recorded_at", "audit_event_id"):
            assert marker not in wire
    # The credential never reaches the audit log.
    for path in (log.root / context.investigation_id).iterdir():
        assert SENTINEL_KEY not in path.read_text(encoding="utf-8")


def test_audit_data_never_reaches_the_policy_gateway(target_registry, resource_governor, gateway, investigation_request, log):
    w = Wiring(target_registry, resource_governor, gateway, log)
    context = w.start(investigation_request)
    w.propose(context)
    w.propose(context)
    records = log.list_by_investigation(context.investigation_id)
    assert w.spy.call_count == 2
    for raw_request, evaluation_context in w.spy.calls:
        seen = repr(raw_request) + repr(evaluation_context)
        for record in records:
            assert record.record_hash not in seen and record.event.audit_event_id not in seen
        assert "record_hash" not in seen and "audit" not in repr(sorted(vars(evaluation_context)))


def test_gateway_verdicts_are_identical_with_and_without_the_durable_log(
    target_registry, resource_governor, gateway, investigation_request, log
):
    from chanakya.runtime.audit import InMemoryAuditSink

    outcomes = []
    for sink in (log, InMemoryAuditSink()):
        w = Wiring(target_registry, resource_governor, gateway, sink)
        context = w.start(investigation_request)
        outcomes.append(
            (
                w.propose(context).outcome,
                w.propose(context, "dump_environment_variables").outcome,
                w.propose(context, "terminate_process", {"pid": 1}).outcome,
            )
        )
    assert outcomes[0] == outcomes[1]
