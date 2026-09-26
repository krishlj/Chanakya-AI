"""Phase 12 test helpers: drive real investigations through the production
composition root with a scripted model, then inspect or tamper with the
durable artifacts."""
from __future__ import annotations

import io
import json
import uuid
from pathlib import Path
from typing import Callable, List, Optional

import chanakya.cli.main as cli_main
from chanakya.contracts.investigation_request import InvestigationRequest
from chanakya.evidence.hashing import compute_content_hash
from chanakya.review import reconstruct_investigation
from chanakya.runtime.clock import utcnow_iso

from runtime_factories import ScriptedAgentProvider, make_agent_turn_conclude, make_agent_turn_propose

ENV = "observe_local_host_environment"
TARGET = cli_main.LOCAL_TARGET_ID


class Run:
    def __init__(self, workdir: Path, *, require_approval: bool = False, answer: str = "approve") -> None:
        self.workdir = workdir
        self.out = io.StringIO()
        self.runtime = cli_main.build_runtime(
            workdir, approver="alice", require_approval=require_approval, input_fn=lambda _p: answer, output=self.out
        )
        self.context = None
        self.results: List = []

    def start(self, objective: str = "Assess this host for exposed services") -> "Run":
        request = InvestigationRequest.from_dict({
            "investigation_request_id": f"req-{uuid.uuid4()}", "contract_version": "1.0.0", "objective": objective,
            "requested_targets": [TARGET], "submitted_by": "alice", "submitted_at": utcnow_iso()})
        self.context = self.runtime.manager.create_investigation(request)
        self.runtime.manager.start(self.context.investigation_id)
        return self

    @property
    def inv(self) -> str:
        return self.context.investigation_id

    def propose(self, capability: str = ENV, target: str = TARGET, parameters=None):
        turn = make_agent_turn_propose(self.inv, capability, target, parameters or {})
        result = self.runtime.controller.run_turn(self.inv, ScriptedAgentProvider([turn]))
        self.results.append(result)
        return result

    def conclude(self, findings: Optional[Callable[[List[str]], list]] = None):
        turn = make_agent_turn_conclude(self.inv)
        if findings is not None:
            ids = [r.tool_result.tool_result_id for r in self.results if r.tool_result is not None]
            turn["findings"] = findings(ids)
        return self.runtime.controller.run_turn(self.inv, ScriptedAgentProvider([turn]))

    def review(self, investigation_id: Optional[str] = None):
        rt = self.runtime
        return reconstruct_investigation(
            self.inv if investigation_id is None else investigation_id, audit_log=rt.audit_log, evidence_store=rt.evidence_store,
            finding_store=rt.finding_store, risk_store=rt.risk_store, risk_engine=rt.risk_engine,
        )

    def stream_dir(self, investigation_id: Optional[str] = None) -> Path:
        return self.workdir / "audit" / (investigation_id or self.inv)

    def events(self, investigation_id: Optional[str] = None):
        return [r.event for r in self.runtime.audit_log.list_by_investigation(investigation_id or self.inv)]

    def cli_review(self, investigation_id: Optional[str] = None):
        out = io.StringIO()
        code = cli_main.main(["--review", investigation_id or self.inv, "--workdir", str(self.workdir)],
                             environ={}, output=out)
        return code, out.getvalue()


def finding(ids, **extra):
    return dict({"title": "Service exposure", "description": "Observed on this host.", "evidence_refs": list(ids),
                 "category": "platform_configuration", "confidence": "medium"}, **extra)


def load_stream(directory: Path) -> List[dict]:
    return [json.loads(p.read_text(encoding="utf-8")) for p in sorted(directory.glob("*.json"))]


def write_stream(directory: Path, records: List[dict]) -> None:
    """Rewrites a whole stream with a freshly recomputed, valid hash chain:
    what a local attacker able to rewrite every file could produce."""
    for path in directory.glob("*.json"):
        path.unlink()
    previous = None
    for sequence, record in enumerate(records, start=1):
        hashed = {"sequence": sequence, "previous_record_hash": previous, "recorded_at": record["recorded_at"],
                  "event": record["event"]}
        full = dict(hashed, record_hash=compute_content_hash(hashed))
        (directory / f"{sequence:08d}.json").write_text(json.dumps(full), encoding="utf-8")
        previous = full["record_hash"]


def rewrite_events(directory: Path, mutate: Callable[[List[dict]], List[dict]]) -> None:
    records = load_stream(directory)
    events = mutate([r["event"] for r in records])
    stamp = records[-1]["recorded_at"] if records else "2026-01-01T00:00:00.000000Z"
    rebuilt = [
        {"recorded_at": records[i]["recorded_at"] if i < len(records) else stamp, "event": e}
        for i, e in enumerate(events)
    ]
    write_stream(directory, rebuilt)


def truncate_after(directory: Path, event_type: str, occurrence: int = 1) -> None:
    """Simulates a crash: keeps the stream up to and including the n-th
    event of ``event_type`` and removes everything after it."""
    records = load_stream(directory)
    seen = 0
    for index, record in enumerate(records):
        if record["event"]["event_type"] == event_type:
            seen += 1
            if seen == occurrence:
                for path in sorted(directory.glob("*.json"))[index + 1:]:
                    path.unlink()
                return
    raise AssertionError(f"no {event_type} #{occurrence} in stream")


def codes(review) -> List[str]:
    return [a.code for a in review.anomalies]
