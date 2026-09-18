"""ToolRequest Intake — docs/AGENT-RUNTIME.md §4. Malformed ToolRequests
must be rejected before the Runtime treats an LLM-generated request as
trusted, and never repaired on the Agent's behalf."""
from __future__ import annotations

import pytest

from chanakya.contracts.tool_request import MalformedRequestError, ToolRequest
from chanakya.runtime.tool_request_intake import ToolRequestIntake

from factories import make_request


def test_valid_request_is_accepted():
    raw = make_request("list_listening_ports", "target-local-host-01")
    result = ToolRequestIntake.intake(raw)
    assert isinstance(result, ToolRequest)
    assert result.capability == "list_listening_ports"


@pytest.mark.parametrize(
    "mutate",
    [
        lambda raw: raw.pop("capability"),
        lambda raw: raw.pop("target_ref"),
        lambda raw: raw.update(contract_version="9.9.9"),
        lambda raw: raw.update(proposed_by="system"),
        lambda raw: raw.update(parameters="not-an-object"),
    ],
)
def test_malformed_requests_are_rejected(mutate):
    raw = make_request("list_listening_ports", "target-local-host-01")
    mutate(raw)
    with pytest.raises(MalformedRequestError):
        ToolRequestIntake.intake(raw)


def test_malformed_request_never_produces_a_tool_request_object():
    raw = make_request("list_listening_ports", "target-local-host-01")
    del raw["capability"]
    try:
        ToolRequestIntake.intake(raw)
        produced = True
    except MalformedRequestError:
        produced = False
    assert not produced


def test_intake_does_not_mutate_the_raw_payload():
    raw = make_request("list_listening_ports", "target-local-host-01")
    snapshot = dict(raw)
    ToolRequestIntake.intake(raw)
    assert raw == snapshot
