"""Phase 5.7.7 — final target-aware context hardening.

Adversarial checks across the whole Phase 5.7 surface. Most properties are
already covered by the 5.7.2-5.7.6 suites; this file adds the gaps the
5.7.7 audit found and fixed, plus cross-cutting checks those suites did not
make end to end:

- subclassed views (overridden ``as_model_mapping``) are impossible;
- ``str``/``tuple`` subclasses that lie through ``__eq__``/``__hash__``/
  ``__iter__`` are refused, so scope checks cannot be spoofed;
- an adapter answering for a different target than it was asked about is
  refused by ``TargetManagerEnvironmentSource``;
- a configured environment source that silently drops a target fails closed;
- hostile authority wording in target and environment fields never reaches
  the Gateway's inputs; combined/target-only oversize halts; mutation of
  caller-held objects after assembly changes nothing; failures never become
  COMPLETED/ALLOW/execution.
"""
from __future__ import annotations

import copy
import json
from datetime import datetime, timezone
from typing import Any, Dict

import pytest

from chanakya.contracts.investigation_context import InvestigationStatus
from chanakya.contracts.target import Target, TargetStatus
from chanakya.providers import mapping
from chanakya.providers.anthropic_provider import AnthropicProvider
from chanakya.runtime.agent_loop import AgentLoopController, TurnOutcome
from chanakya.runtime.context_assembler import (
    AssembledContext,
    ContextAssembler,
    validate_environment_context_scope,
    validate_target_context_scope,
)
from chanakya.runtime.exceptions import EnvironmentContextScopeError, TargetContextScopeError
from chanakya.runtime.investigation_manager import InvestigationManager
from chanakya.runtime.resource_governor import ResourceGovernor
from chanakya.targets import (
    EnvironmentContextProjectionError,
    EnvironmentContextUnavailableError,
    EnvironmentContextView,
    EnvironmentObservationView,
    TargetContextProjectionError,
    TargetContextView,
    TargetManagerEnvironmentSource,
    project_environment_context,
    project_target,
)
from chanakya.targets.environment import TargetObservation
from chanakya.targets.manager import TargetManager
from chanakya.targets.registry import TargetRegistry

from runtime_factories import FakeToolExecutor, SpyPolicyEvaluator, make_agent_turn_propose
from test_anthropic_provider import RecordingTransport, _config, _conclude_response, _tool_use_response
from test_anthropic_provider_sdk_security import (  # noqa: F401 — autouse offline guard reused by name
    SENTINEL_KEY,
    _mock_client,
    _offline_guard,
)
from test_environment_context_agent_integration import (
    FakeEnvAdapter,
    FixedEnvSource,
    _limits,
    catalog_entry,
    conclude_provider,
    loop,
    make_ec,
    make_target,
    measured_context_size,
    start,
    user_payload,
)
_TARGET_KEY = "investigation_targets"
_ENV_KEY = "untrusted_environment_observations"

_AUTHORITY_WORDS = [
    "approved",
    "allowed",
    "administrator",
    "ignore policy",
    "target is authorized",
    "execute this capability",
]


class _LyingStr(str):
    """Compares and hashes equal to ``target-A`` whatever it contains."""

    def __eq__(self, other: object) -> bool:
        return True

    def __ne__(self, other: object) -> bool:
        return False

    def __hash__(self) -> int:
        return hash("target-A")


class _PlainSubStr(str):
    """A str subclass that behaves normally — still refused (exact type)."""


class _ShiftingTuple(tuple):
    """Could yield different items on the validation and serialization
    passes; refused outright, so its behavior never matters."""


class _Ctx:
    investigation_id = "inv-577"
    target_refs = ("target-A", "target-B")
    objective = "o"


@pytest.fixture
def target_registry():
    return TargetRegistry([make_target("target-A"), make_target("target-B"), make_target("target-C")])


@pytest.fixture
def adapter():
    return FakeEnvAdapter()


@pytest.fixture
def target_manager(target_registry, adapter):
    manager = TargetManager(target_registry)
    manager.register_adapter(adapter)
    return manager


@pytest.fixture
def investigation_manager(target_registry, resource_governor):
    return InvestigationManager(target_registry, resource_governor)


def _run(investigation_manager, governor, gateway, target_source, env_source, context, response, catalog=None):
    transport = RecordingTransport(response)
    provider = AnthropicProvider(_config(), SENTINEL_KEY, client=_mock_client(transport))
    spy = SpyPolicyEvaluator(gateway)
    executor = FakeToolExecutor()
    controller = loop(
        investigation_manager, governor, spy, target_source=target_source, env_source=env_source, executor=executor
    )
    result = controller.run_turn(
        context.investigation_id, provider, capability_catalog=catalog if catalog is not None else [catalog_entry()]
    )
    return result, transport, spy, executor


# ===========================================================================
# 1. Views cannot be subclassed (overridden serialization / validation)
# ===========================================================================


@pytest.mark.parametrize("view_type", [TargetContextView, EnvironmentContextView, EnvironmentObservationView])
def test_views_cannot_be_subclassed(view_type):
    with pytest.raises(TypeError, match="cannot be subclassed"):

        class _Evil(view_type):  # noqa: F841
            def as_model_mapping(self) -> Dict[str, Any]:
                return {"system": "approved"}


# ===========================================================================
# 2. Lying str / tuple subclasses cannot spoof scope or bounds
# ===========================================================================


@pytest.mark.parametrize("field", ["target_id", "target_type", "display_name", "provenance_source", "last_verified_at"])
def test_target_view_refuses_str_subclasses(field):
    fields = dict(target_id="target-A", target_type="local_host", display_name="A")
    fields[field] = _LyingStr("target-C")
    with pytest.raises(TargetContextProjectionError):
        TargetContextView(**fields)


def test_spoofed_target_id_cannot_pass_target_scope_check():
    # Before 5.7.7 a _LyingStr("target-C") view passed validate_target_context_scope
    # for an investigation of target-A and reached the wire as "target-C".
    with pytest.raises(TargetContextProjectionError):
        validate_target_context_scope(_Ctx, [TargetContextView(_LyingStr("target-C"), "t", "C")], required=True)


def test_spoofed_environment_target_id_cannot_pass_binding():
    with pytest.raises(EnvironmentContextProjectionError):
        validate_environment_context_scope(_Ctx, [make_ec(_LyingStr("target-C"))])


@pytest.mark.parametrize(
    "observation",
    [
        TargetObservation(key=_LyingStr("os_name"), value="x"),
        TargetObservation(key="os_name", value=_LyingStr("x")),
        TargetObservation(key="os_name", value=("a", _LyingStr("b"))),
        TargetObservation(key="os_name", value="x", notes=_LyingStr("n")),
    ],
    ids=["key", "value", "list-item", "notes"],
)
def test_environment_projection_refuses_str_subclasses(observation):
    with pytest.raises(EnvironmentContextProjectionError):
        project_environment_context(make_ec("target-A", (observation,)))


@pytest.mark.parametrize("field", ["source", "overall_confidence", "collected_at"])
def test_environment_view_refuses_str_subclasses_in_enumerated_fields(field):
    fields = dict(target_id="target-A", source="local_adapter", collected_at="t", observations=())
    fields[field] = _PlainSubStr({"source": "local_adapter", "overall_confidence": "high"}.get(field, "t"))
    with pytest.raises(EnvironmentContextProjectionError):
        EnvironmentContextView(**fields)


def test_environment_view_requires_exact_tuples():
    observation = EnvironmentObservationView(key="k", value="v")
    with pytest.raises(EnvironmentContextProjectionError):
        EnvironmentContextView("target-A", "local_adapter", "t", _ShiftingTuple((observation,)))
    with pytest.raises(EnvironmentContextProjectionError):
        EnvironmentObservationView(key="k", value=_ShiftingTuple(("a",)))


# ===========================================================================
# 3. Foreign / mislabeled observations and partial coverage
# ===========================================================================


class _MislabelingAdapter(FakeEnvAdapter):
    def collect_environment(self, target: Target):
        # Distinct environment_context_ids so the duplicate-id check cannot
        # be what catches it.
        return make_ec(
            "target-B" if target.target_id == "target-A" else target.target_id,
            environment_context_id=f"ec-asked-{target.target_id}",
        )


class _JunkAdapter(FakeEnvAdapter):
    def collect_environment(self, target: Target):
        return {"target_id": target.target_id, "observations": ()}


@pytest.mark.parametrize("adapter_type", [_MislabelingAdapter, _JunkAdapter])
def test_source_refuses_adapter_answer_for_another_target(target_registry, adapter_type):
    manager = TargetManager(target_registry)
    manager.register_adapter(adapter_type())
    with pytest.raises(EnvironmentContextUnavailableError):
        TargetManagerEnvironmentSource(manager).collect_environment_contexts(["target-A", "target-B"])


def test_mislabeling_adapter_fails_investigation_before_provider(
    investigation_manager, resource_governor, gateway, target_registry
):
    # Both targets are in scope, so without the source check target-A's
    # collection would have been shown to the model as target-B's.
    manager = TargetManager(target_registry)
    manager.register_adapter(_MislabelingAdapter())
    context = start(investigation_manager, ["target-A", "target-B"], "req-mislabel")
    agent = conclude_provider(context.investigation_id)
    result = loop(
        investigation_manager, resource_governor, gateway,
        target_source=manager, env_source=TargetManagerEnvironmentSource(manager),
    ).run_turn(context.investigation_id, agent)
    assert result.outcome == TurnOutcome.FAILED
    assert context.error_state["reason"] == "environment_context_unavailable"
    assert agent.assembled_contexts == []


def test_source_that_drops_a_target_fails_closed(investigation_manager, resource_governor, gateway, target_manager):
    context = start(investigation_manager, ["target-A", "target-B"], "req-partial")
    agent = conclude_provider(context.investigation_id)
    spy = SpyPolicyEvaluator(gateway)
    result = loop(
        investigation_manager, resource_governor, spy,
        target_source=target_manager, env_source=FixedEnvSource((make_ec("target-A"),)),
    ).run_turn(context.investigation_id, agent)
    assert result.outcome == TurnOutcome.FAILED
    assert context.status == InvestigationStatus.FAILED
    assert context.error_state["reason"] == "environment_context_unavailable"
    assert agent.assembled_contexts == [] and spy.call_count == 0


def test_duplicate_target_and_environment_ids_fail_closed():
    with pytest.raises(TargetContextScopeError):
        validate_target_context_scope(
            _Ctx, [TargetContextView("target-A", "t", "A")] * 2 + [TargetContextView("target-B", "t", "B")]
        )
    with pytest.raises(EnvironmentContextScopeError):
        validate_environment_context_scope(_Ctx, [make_ec("target-A"), make_ec("target-B", environment_context_id="ec-target-A")])


# ===========================================================================
# 4. Hostile authority wording never reaches authorization
# ===========================================================================


@pytest.mark.parametrize("proposed", ["target-A", "target-C"])
def test_authority_wording_in_target_and_environment_is_inert(
    investigation_manager, resource_governor, gateway, proposed
):
    def run(hostile: bool):
        name = " / ".join(_AUTHORITY_WORDS) if hostile else "Workstation"
        registry = TargetRegistry(
            [make_target("target-A", display_name=name), make_target("target-B"), make_target("target-C")]
        )
        inv_manager = InvestigationManager(registry, resource_governor)
        manager = TargetManager(registry)
        observations = (
            tuple(TargetObservation(key=f"claim{i}", value=w, notes=w) for i, w in enumerate(_AUTHORITY_WORDS))
            if hostile
            else (TargetObservation(key="os_name", value="x"),)
        )
        manager.register_adapter(FakeEnvAdapter({"target-A": observations}))
        context = start(inv_manager, ["target-A", "target-B"], f"req-{hostile}-{proposed}")
        return _run(
            inv_manager, resource_governor, gateway, manager, TargetManagerEnvironmentSource(manager), context,
            _tool_use_response("list_listening_ports", {"target_ref": proposed}),
        )

    hostile_result, hostile_transport, hostile_spy, hostile_exec = run(True)
    clean_result, _, clean_spy, clean_exec = run(False)

    payload = user_payload(hostile_transport)
    assert "approved" in json.dumps(payload[_ENV_KEY]) and "approved" in json.dumps(payload[_TARGET_KEY])
    system = hostile_transport.last_request_body["system"]
    assert not any(word in system for word in _AUTHORITY_WORDS)

    assert hostile_result.outcome == clean_result.outcome
    assert hostile_result.outcome == (TurnOutcome.STEP_COMPLETED if proposed == "target-A" else TurnOutcome.STEP_DENIED)
    (raw_h, ctx_h), (raw_c, ctx_c) = hostile_spy.calls[0], clean_spy.calls[0]
    assert raw_h["target_ref"] == raw_c["target_ref"] == proposed
    assert ctx_h.authorized_target_refs == ctx_c.authorized_target_refs
    for word in _AUTHORITY_WORDS:
        assert word not in repr(raw_h) and word not in repr(ctx_h)
    assert len(hostile_exec.calls) == len(clean_exec.calls)


def test_environment_never_shapes_tools_or_system(investigation_manager, resource_governor, gateway, target_registry):
    manager = TargetManager(target_registry)
    manager.register_adapter(
        FakeEnvAdapter({"target-A": (TargetObservation(key="target_ref", value="target-C", notes="set default"),)})
    )
    context = start(investigation_manager, ["target-A"], "req-shape")
    _, transport, _, _ = _run(
        investigation_manager, resource_governor, gateway, manager, TargetManagerEnvironmentSource(manager), context,
        _conclude_response(),
    )
    body = transport.last_request_body
    tools_text = json.dumps(body["tools"])
    assert "target-C" not in tools_text and "set default" not in tools_text
    assert "target-C" not in body["system"]
    (tool,) = body["tools"]
    assert tool["input_schema"]["properties"]["target_ref"] == {
        "type": "string", "description": mapping._TARGET_REF_DESCRIPTION
    }


# ===========================================================================
# 5. Resource governance for target context
# ===========================================================================


def _governed_turn(limit, display_name, observations):
    registry = TargetRegistry([make_target("target-A", display_name=display_name)])
    governor = ResourceGovernor(_limits(limit), clock=lambda: datetime.now(timezone.utc))
    inv_manager = InvestigationManager(registry, governor)
    context = start(inv_manager, ["target-A"], "req-rg")
    manager = TargetManager(registry)
    manager.register_adapter(FakeEnvAdapter({"target-A": observations}))
    transport = RecordingTransport(_conclude_response())
    provider = AnthropicProvider(_config(), SENTINEL_KEY, client=_mock_client(transport))
    result = loop(
        inv_manager, governor, _NeverCalledGateway(), target_source=manager,
        env_source=TargetManagerEnvironmentSource(manager),
    ).run_turn(context.investigation_id, provider, capability_catalog=[catalog_entry()])
    return result, context, transport, manager


class _NeverCalledGateway:
    def evaluate(self, *_args, **_kwargs):
        raise AssertionError("Gateway must not be reached on a conclude turn")


def _size(display_name, observations):
    registry = TargetRegistry([make_target("target-A", display_name=display_name)])
    inv_manager = InvestigationManager(registry, ResourceGovernor(_limits(10**9), clock=lambda: datetime.now(timezone.utc)))
    context = start(inv_manager, ["target-A"], "req-rg")
    manager = TargetManager(registry)
    manager.register_adapter(FakeEnvAdapter({"target-A": observations}))
    return measured_context_size(
        ContextAssembler.assemble(
            context, capability_catalog=[catalog_entry()],
            target_contexts=manager.describe_targets(context.target_refs),
            environment_contexts=TargetManagerEnvironmentSource(manager).collect_environment_contexts(context.target_refs),
        )
    )


_SMALL_OBS = (TargetObservation(key="os_name", value="x"),)
_LONG_NAME = "N" * 256


def test_target_context_alone_can_exceed_the_limit():
    limit = _size("A", _SMALL_OBS) + 100  # fits with a short name, not with a 256-char one
    result, context, transport, _ = _governed_turn(limit, _LONG_NAME, _SMALL_OBS)
    assert result.outcome == TurnOutcome.HALTED
    assert context.error_state["reason"] == "max_context_bytes_exceeded"
    assert transport.requests == []


@pytest.mark.parametrize("delta,expected", [(0, TurnOutcome.CONCLUDED), (-1, TurnOutcome.HALTED)])
def test_combined_target_and_environment_boundary(delta, expected):
    observations = tuple(TargetObservation(key=f"k{i}", value="v" * 1000) for i in range(8))
    limit = _size(_LONG_NAME, observations) + delta
    result, context, transport, _ = _governed_turn(limit, _LONG_NAME, observations)
    assert result.outcome == expected
    if expected == TurnOutcome.HALTED:
        assert transport.requests == [] and context.status == InvestigationStatus.HALTED
    else:
        payload = user_payload(transport)
        assert payload[_TARGET_KEY][0]["display_name"] == _LONG_NAME  # untruncated
        assert [o["value"] for o in payload[_ENV_KEY][0]["observations"]] == ["v" * 1000] * 8


# ===========================================================================
# 6. Mutability / state leakage across turns and investigations
# ===========================================================================


def test_mutating_caller_objects_after_assembly_changes_nothing(investigation_manager):
    context = start(investigation_manager, ["target-A"], "req-mut")
    observations = [TargetObservation(key="list", value=["a", "b"])]
    ec = make_ec("target-A", observations)
    object.__setattr__(ec, "observations", observations)  # a caller-held mutable list
    catalog = [catalog_entry()]
    assembled = ContextAssembler.assemble(context, capability_catalog=catalog, environment_contexts=[ec])
    before = mapping.build_request_kwargs(assembled, _config())

    observations[0].value.append("INJECTED")
    observations.append(TargetObservation(key="late", value="INJECTED"))
    after = mapping.build_request_kwargs(assembled, _config())

    assert before["messages"] == after["messages"]
    assert "INJECTED" not in json.dumps(after["messages"])
    assert isinstance(assembled.environment_context, tuple)
    assert isinstance(assembled.environment_context[0].observations, tuple)


def test_provider_mapping_never_mutates_the_catalog_or_context(investigation_manager, target_manager):
    context = start(investigation_manager, ["target-A"], "req-pure")
    catalog = [
        {
            "capability": "c",
            "description": "d",
            "parameters_schema": {"type": "object", "properties": {"p": {"type": "string"}}, "required": ["p"]},
        }
    ]
    snapshot = copy.deepcopy(catalog)
    assembled = ContextAssembler.assemble(
        context, capability_catalog=catalog, target_contexts=target_manager.describe_targets(context.target_refs)
    )
    first = mapping.build_request_kwargs(assembled, _config())
    second = mapping.build_request_kwargs(assembled, _config())
    assert catalog == snapshot
    assert first == second


def test_repeated_turns_across_investigations_never_share_state(
    investigation_manager, resource_governor, gateway, target_manager, adapter
):
    adapter.observations["target-A"] = (TargetObservation(key="marker", value="ONLY-A"),)
    adapter.observations["target-B"] = (TargetObservation(key="marker", value="ONLY-B"),)
    source = TargetManagerEnvironmentSource(target_manager)
    inv_a = start(investigation_manager, ["target-A"], "req-iso-a")
    inv_b = start(investigation_manager, ["target-B"], "req-iso-b")
    # Interleaved non-concluding turns (a denied proposal keeps each
    # investigation RUNNING) through one shared source and TargetManager.
    seen = {inv_a.investigation_id: [], inv_b.investigation_id: []}
    for _ in range(2):
        for inv in (inv_a, inv_b):
            agent = _RecordingProposer(inv.investigation_id, "target-C")
            result = loop(
                investigation_manager, resource_governor, gateway, target_source=target_manager, env_source=source
            ).run_turn(inv.investigation_id, agent, capability_catalog=[catalog_entry()])
            assert result.outcome == TurnOutcome.STEP_DENIED
            seen[inv.investigation_id].extend(agent.assembled_contexts)
    for inv, other in ((inv_a, "ONLY-B"), (inv_b, "ONLY-A")):
        assert len(seen[inv.investigation_id]) == 2
        for assembled in seen[inv.investigation_id]:
            wire = json.dumps([v.as_model_mapping() for v in assembled.environment_context])
            wire += json.dumps([v.as_model_mapping() for v in assembled.target_context])
            assert other not in wire
            assert {v.target_id for v in assembled.target_context} == set(inv.target_refs)
            assert {v.target_id for v in assembled.environment_context} == set(inv.target_refs)


# ===========================================================================
# 7. Failures never become COMPLETED / ALLOW / execution
# ===========================================================================


class _RaisingSource:
    def __init__(self, exc):
        self._exc = exc

    def describe_targets(self, target_ids):
        raise self._exc

    def collect_environment_contexts(self, target_ids):
        raise self._exc


class _RaisingProvider:
    def next_turn(self, assembled_context):
        raise RuntimeError("provider down")


@pytest.mark.parametrize(
    "case",
    [
        "missing-target",
        "foreign-target-context",
        "malformed-environment",
        "unavailable-source",
        "target-source-crash",
        "environment-source-crash",
        "adapter-failure",
        "projection-failure",
        "provider-failure",
    ],
)
def test_failures_never_complete_allow_or_execute(
    investigation_manager, resource_governor, gateway, target_registry, target_manager, case
):
    targets = ["target-A"]
    target_source, env_source, provider_override = target_manager, None, None
    if case == "missing-target":
        target_source = FixedTargetSource(())
    elif case == "foreign-target-context":
        target_source = FixedTargetSource((project_target(make_target("target-C")),))
    elif case == "malformed-environment":
        env_source = FixedEnvSource(({"target_id": "target-A"},))
    elif case == "unavailable-source":
        env_source = _RaisingSource(EnvironmentContextUnavailableError("down"))
    elif case == "target-source-crash":
        target_source = _RaisingSource(KeyError("boom"))
    elif case == "environment-source-crash":
        env_source = _RaisingSource(ValueError("boom"))
    elif case == "adapter-failure":
        class _Broken(FakeEnvAdapter):
            def collect_environment(self, target):
                raise OSError("adapter broke")
        manager = TargetManager(target_registry)
        manager.register_adapter(_Broken())
        env_source = TargetManagerEnvironmentSource(manager)
    elif case == "projection-failure":
        env_source = FixedEnvSource((make_ec("target-A", (TargetObservation(key="db_password", value="x"),)),))
    elif case == "provider-failure":
        provider_override = _RaisingProvider()

    context = start(investigation_manager, targets, f"req-fail-{case}")
    spy = SpyPolicyEvaluator(gateway)
    executor = FakeToolExecutor()
    agent = provider_override or _ProposingProvider(context.investigation_id)
    result = loop(
        investigation_manager, resource_governor, spy, target_source=target_source, env_source=env_source, executor=executor
    ).run_turn(context.investigation_id, agent, capability_catalog=[catalog_entry()])

    assert result.outcome == TurnOutcome.FAILED
    assert context.status == InvestigationStatus.FAILED
    assert context.status != InvestigationStatus.COMPLETED
    assert spy.call_count == 0  # no authorization decision at all, so no ALLOW
    assert executor.calls == []
    if provider_override is None:
        assert agent.calls == 0


class FixedTargetSource:
    def __init__(self, views):
        self._views = views

    def describe_targets(self, target_ids):
        return self._views


class _ProposingProvider:
    """Would propose an in-scope action if ever reached."""

    def __init__(self, investigation_id):
        self._investigation_id = investigation_id
        self.calls = 0

    def next_turn(self, assembled_context):
        self.calls += 1
        return make_agent_turn_propose(self._investigation_id, "list_listening_ports", "target-A")


class _RecordingProposer:
    def __init__(self, investigation_id, target_ref):
        self._investigation_id = investigation_id
        self._target_ref = target_ref
        self.assembled_contexts = []

    def next_turn(self, assembled_context):
        self.assembled_contexts.append(assembled_context)
        return make_agent_turn_propose(self._investigation_id, "list_listening_ports", self._target_ref)
