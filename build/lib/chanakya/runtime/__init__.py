"""Chanakya AI — Phase 3 Agent Runtime foundation (Step 3.4).

Implements, per docs/AGENT-RUNTIME.md:

- Investigation lifecycle management (``InvestigationManager``,
  ``InvestigationStateStore``) atop ``chanakya.contracts.
  investigation_context.InvestigationContext``.
- The Runtime-internal step state machine (``StepRecord``).
- Runtime execution limits and their enforcement (``RuntimeExecutionLimits``,
  ``ResourceGovernor``).
- The Agent turn envelope (``AgentTurnOutput``) and ToolRequest intake
  (``ToolRequestIntake``) — the two points untrusted Agent output is
  structurally validated before anything downstream treats it as
  meaningful.
- The Context Assembler, which keeps tool/target-originated content
  (``UntrustedData``) structurally separate from Runtime-authored
  instructions.
- The dispatch/execution boundary (``dispatch``), which cannot be called
  without a favorable ``PolicyDecision`` and, for a ``require_approval``
  verdict, an accepted, correctly-bound ``ApprovalDecision``.
- The Agent Loop Controller orchestration skeleton (``AgentLoopController``).

Each of the Runtime's collaborators is an explicit interface
(``Protocol``) implemented elsewhere: the provider (``chanakya.providers``),
the Tool Layer (``chanakya.tools``), the Target Manager (``chanakya.targets``),
the Evidence Store (``chanakya.evidence``), the Audit Log
(``chanakya.audit``), findings and risk. ``chanakya.cli.main.build_runtime``
wires the production set. There is no MCP integration.
"""
from .agent_loop import (
    AgentLoopController,
    AgentProvider,
    ApprovalProvider,
    PolicyEvaluator,
    TurnOutcome,
    TurnResult,
)
from .agent_turn import AgentTurnOutput, NextAction
from .audit import AuditEmitter, AuditSink, InMemoryAuditSink, NullAuditSink
from .context_assembler import AssembledContext, ContextAssembler, UntrustedData
from .dispatch import DispatchInstruction, ToolExecutor, dispatch
from .evidence import EvidenceRecorder, StubEvidenceRecorder
from .exceptions import (
    AuditSinkError,
    DispatchPreconditionError,
    InvalidStepTransitionError,
    InvestigationTerminatedError,
    MalformedAgentTurnOutputError,
    ResourceLimitExceededError,
    RuntimeInvariantError,
    UnknownInvestigationError,
    UnknownTargetError,
)
from .investigation_manager import InvestigationManager
from .investigation_store import InvestigationStateStore
from .limits import ApprovalExpiryAction, RuntimeExecutionLimits
from .resource_governor import ResourceGovernor
from .retry_controller import RetryController
from .step_record import ALLOWED_STEP_TRANSITIONS, TERMINAL_STEP_STATUSES, StepRecord, StepStatus
from .timeout_supervisor import TimeoutSupervisor, ToolExecutionTimedOut
from .tool_request_intake import ToolRequestIntake

__all__ = [
    "InvestigationManager",
    "InvestigationStateStore",
    "StepRecord",
    "StepStatus",
    "ALLOWED_STEP_TRANSITIONS",
    "TERMINAL_STEP_STATUSES",
    "RuntimeExecutionLimits",
    "ApprovalExpiryAction",
    "ResourceGovernor",
    "AgentTurnOutput",
    "NextAction",
    "ToolRequestIntake",
    "ContextAssembler",
    "AssembledContext",
    "UntrustedData",
    "DispatchInstruction",
    "ToolExecutor",
    "dispatch",
    "EvidenceRecorder",
    "StubEvidenceRecorder",
    "RetryController",
    "TimeoutSupervisor",
    "ToolExecutionTimedOut",
    "AuditEmitter",
    "AuditSink",
    "NullAuditSink",
    "InMemoryAuditSink",
    "AgentLoopController",
    "AgentProvider",
    "PolicyEvaluator",
    "ApprovalProvider",
    "TurnOutcome",
    "TurnResult",
    "RuntimeInvariantError",
    "InvalidStepTransitionError",
    "AuditSinkError",
    "DispatchPreconditionError",
    "ResourceLimitExceededError",
    "UnknownTargetError",
    "UnknownInvestigationError",
    "InvestigationTerminatedError",
    "MalformedAgentTurnOutputError",
]
