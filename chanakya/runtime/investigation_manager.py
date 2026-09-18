"""InvestigationManager — docs/AGENT-RUNTIME.md §1 (Investigation/session
lifecycle) and §17 (Cancellation).

Owns investigation creation and every top-level lifecycle transition:
creation, initialization/start, running, waiting (awaiting_approval),
completion, failure, cancellation, and termination. Delegates the actual
state-machine enforcement to ``InvestigationContext.transition_status``
(docs/CONTRACTS.md §2) and never bypasses it — this class adds the
cross-cutting concerns a bare ``InvestigationContext`` cannot enforce on
its own: validating ``requested_targets`` against a real target registry,
registering/releasing the Resource Governor's concurrency slot, and
giving cancellation an explicit, human-triggered entry point distinct
from anything the Agent can do.
"""
from __future__ import annotations

import uuid
from typing import Any, Mapping, Optional

from chanakya.contracts.investigation_context import InvestigationContext, InvestigationStatus
from chanakya.contracts.investigation_request import InvestigationRequest
from chanakya.targets.registry import TargetRegistry

from .audit import AuditEmitter
from .clock import utcnow_iso
from .exceptions import RuntimeInvariantError, UnknownTargetError
from .investigation_store import InvestigationStateStore
from .resource_governor import ResourceGovernor

_CONTRACT_VERSION = "1.0.0"


class InvestigationManager:
    def __init__(
        self,
        target_registry: TargetRegistry,
        resource_governor: ResourceGovernor,
        *,
        store: Optional[InvestigationStateStore] = None,
        clock=utcnow_iso,
        audit: Optional[AuditEmitter] = None,
    ) -> None:
        self._targets = target_registry
        self._governor = resource_governor
        self._store = store if store is not None else InvestigationStateStore()
        self._clock = clock
        self._audit = audit if audit is not None else AuditEmitter(clock=clock)

    # -- lifecycle --------------------------------------------------------

    def create_investigation(self, request: InvestigationRequest) -> InvestigationContext:
        """docs/CONTRACTS.md §1 validation requirement: every
        ``requested_targets`` entry must already be known to the Target
        Manager. A request naming an unregistered target never produces
        an ``InvestigationContext`` (mirrors ToolRequest Intake's "never
        repair, only reject" rule)."""
        for target_id in request.requested_targets:
            if self._targets.get(target_id) is None:
                raise UnknownTargetError(f"requested target is not registered: {target_id!r}")

        context = InvestigationContext(
            investigation_id=str(uuid.uuid4()),
            contract_version=_CONTRACT_VERSION,
            investigation_request_id=request.investigation_request_id,
            objective=request.objective,
            target_refs=tuple(request.requested_targets),
            created_at=self._clock(),
            clock=self._clock,
        )
        self._store.create(context)
        self._governor.register_investigation(context.investigation_id)
        self._audit.investigation_started(context.investigation_id)
        return context

    def start(self, investigation_id: str) -> None:
        """pending -> running."""
        self.get(investigation_id).transition_status(InvestigationStatus.RUNNING)

    def enter_awaiting_approval(self, investigation_id: str) -> None:
        """running -> awaiting_approval."""
        self.get(investigation_id).transition_status(InvestigationStatus.AWAITING_APPROVAL)

    def resume_running(self, investigation_id: str) -> None:
        """awaiting_approval -> running (fires on either an accepted or a
        denied/expired ApprovalDecision — the *step* concluded either
        way; the investigation itself continues, docs/AGENT-RUNTIME.md
        §15)."""
        self.get(investigation_id).transition_status(InvestigationStatus.RUNNING)

    def complete(self, investigation_id: str) -> None:
        """running -> completed."""
        context = self.get(investigation_id)
        context.transition_status(InvestigationStatus.COMPLETED)
        self._governor.release_investigation(investigation_id)
        self._audit.investigation_completed(investigation_id)

    def fail(self, investigation_id: str, *, reason: str, details: Optional[Mapping[str, Any]] = None) -> None:
        """running -> failed. Never used for a policy denial or a human
        approval denial — those are expected outcomes, not failures
        (docs/AGENT-RUNTIME.md §11); this is for fatal/unrecoverable
        Runtime conditions only. Emits ``event_type: error`` — the
        closed AuditEvent enum (docs/CONTRACTS.md §13) has no dedicated
        ``investigation_failed`` value, and ``error`` ("Internal Runtime
        error, fail-closed outcome") is the semantically correct match
        for exactly this transition."""
        context = self.get(investigation_id)
        error_state = {"reason": reason, **(dict(details) if details else {})}
        context.transition_status(InvestigationStatus.FAILED, error_state=error_state)
        self._governor.release_investigation(investigation_id)
        self._audit.error(investigation_id, reason=reason, details=details)

    def halt(self, investigation_id: str, *, reason: str, details: Optional[Mapping[str, Any]] = None) -> None:
        """running|awaiting_approval -> halted (governance stop: operator
        cancellation, timeout, or budget exhaustion)."""
        context = self.get(investigation_id)
        error_state = {"reason": reason, **(dict(details) if details else {})}
        context.transition_status(InvestigationStatus.HALTED, error_state=error_state)
        self._governor.release_investigation(investigation_id)
        self._audit.investigation_halted(investigation_id, reason=reason, details=details)

    def cancel(self, investigation_id: str, *, cancelled_by: str) -> None:
        """docs/AGENT-RUNTIME.md §17. Operator-initiated only; the Agent
        has no path to this method. Cooperative (RT-INV-9) — this only
        flips the investigation's status; it does not, and cannot, reach
        into an in-flight dispatch and interrupt it. Rejects cancellation
        of an investigation that is not currently running or awaiting
        approval (i.e. one that is pending or already terminal)."""
        context = self.get(investigation_id)
        if context.status not in (InvestigationStatus.RUNNING, InvestigationStatus.AWAITING_APPROVAL):
            raise RuntimeInvariantError(
                f"cannot cancel investigation {investigation_id!r} in status {context.status.value!r}"
            )
        self.halt(investigation_id, reason="cancelled_by_operator", details={"cancelled_by": cancelled_by})

    # -- accessors ----------------------------------------------------------

    def get(self, investigation_id: str) -> InvestigationContext:
        return self._store.get(investigation_id)

    @property
    def store(self) -> InvestigationStateStore:
        return self._store
