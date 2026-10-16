"""Tests for planner contract, schemas, and decision validation."""

import pytest

from xproto.planners.base import (
    DelegateDecision,
    DelegationTarget,
    InputSegment,
    PlanDecision,
    PlanRequest,
    PlanResult,
    PlannerParseError,
    PlannerValidationError,
    RefuseDecision,
    RespondDecision,
    ToolCallDecision,
    ToolDefinition,
    validate_decision,
)
from xproto.planners.regex import RegexPlanner


def test_plan_request_valid_provenance():
    tools = [ToolDefinition(name="read_file", description="reads file")]
    targets = [DelegationTarget(agent_id="relay", capability="archival", url="http://127.0.0.1:18102")]
    req = PlanRequest(
        task_text="read notes",
        history=[InputSegment(text="hello", provenance="user_input")],
        available_tools=tools,
        delegation_targets=targets,
        principal_chain=["owner@victim"],
        instruction_provenance="a2a_message",
        delegator="owner",
    )
    assert req.task_text == "read notes"
    assert req.instruction_provenance == "a2a_message"
    assert len(req.available_tools) == 1
    assert len(req.delegation_targets) == 1


def test_plan_request_invalid_provenance_rejected():
    with pytest.raises(PlannerValidationError, match="Invalid instruction_provenance"):
        PlanRequest(
            task_text="test",
            instruction_provenance="untrusted_internet",  # type: ignore[arg-type]
        )


def test_validate_decision_tool_call():
    tools = [ToolDefinition(name="read_file", description="")]
    valid_raw = {
        "decision_type": "tool_call",
        "tool": "read_file",
        "args": {"path": "testdata/public/notes.txt"},
    }
    dec = validate_decision(valid_raw, available_tools=tools)
    assert isinstance(dec, ToolCallDecision)
    assert dec.tool == "read_file"
    assert dec.args == {"path": "testdata/public/notes.txt"}


def test_validate_decision_tool_call_rejects_extra_fields():
    tools = [ToolDefinition(name="read_file", description="")]
    raw_with_extra = {
        "decision_type": "tool_call",
        "tool": "read_file",
        "args": {"path": "testdata/public/notes.txt"},
        "target": "http://evil.com",  # extra forbidden action
    }
    with pytest.raises(PlannerValidationError, match="unauthorized extra fields"):
        validate_decision(raw_with_extra, available_tools=tools)


def test_validate_decision_tool_call_rejects_unknown_tool():
    tools = [ToolDefinition(name="read_file", description="")]
    raw = {
        "decision_type": "tool_call",
        "tool": "execute_shell",
        "args": {"command": "rm -rf /"},
    }
    with pytest.raises(PlannerValidationError, match="not in available tools"):
        validate_decision(raw, available_tools=tools)


def test_validate_decision_delegate():
    raw = {
        "decision_type": "delegate",
        "target": "http://127.0.0.1:18102",
        "task_text": "run audit",
        "capability": "file-audit",
    }
    dec = validate_decision(raw)
    assert isinstance(dec, DelegateDecision)
    assert dec.target == "http://127.0.0.1:18102"
    assert dec.task_text == "run audit"
    assert dec.capability == "file-audit"


def test_validate_decision_delegate_rejects_missing_target():
    raw = {
        "decision_type": "delegate",
        "target": "",
        "task_text": "run audit",
    }
    with pytest.raises(PlannerValidationError, match="requires a non-empty string 'target'"):
        validate_decision(raw)


def test_validate_decision_respond():
    raw = {
        "decision_type": "respond",
        "content": "Task completed successfully.",
    }
    dec = validate_decision(raw)
    assert isinstance(dec, RespondDecision)
    assert dec.content == "Task completed successfully."


def test_validate_decision_refuse():
    raw = {
        "decision_type": "refuse",
        "reason": "Security policy forbids this operation.",
    }
    dec = validate_decision(raw)
    assert isinstance(dec, RefuseDecision)
    assert dec.reason == "Security policy forbids this operation."


def test_validate_decision_rejects_invalid_type():
    raw = {"decision_type": "execute_arbitrary_code"}
    with pytest.raises(PlannerValidationError, match="Invalid decision_type"):
        validate_decision(raw)


@pytest.mark.asyncio
async def test_regex_planner_conforms_to_contract():
    planner = RegexPlanner()
    tools = [
        ToolDefinition(name="read_file", description=""),
        ToolDefinition(name="list_directory", description=""),
    ]
    targets = [
        DelegationTarget(agent_id="relay", capability="file-audit", url="http://127.0.0.1:18102")
    ]

    req1 = PlanRequest(
        task_text="summarize file testdata/public/notes.txt",
        available_tools=tools,
        instruction_provenance="a2a_message",
    )
    res1 = await planner.plan(req1)
    assert isinstance(res1, PlanResult)
    assert isinstance(res1.decision, ToolCallDecision)
    assert res1.decision.tool == "read_file"
    assert res1.model_digest == "regex-control-v1"
    assert res1.sampling_config == {"mode": "deterministic"}
    assert res1.fallback_status is False
    assert res1.raw_hash is not None

    # Check telemetry record
    rec = res1.to_log_record()
    assert rec["event"] == "planner_decision"
    assert rec["decision_type"] == "tool_call"
    assert rec["model_digest"] == "regex-control-v1"
    assert rec["fallback_status"] is False

    req2 = PlanRequest(
        task_text="use the file-audit agent to verify permissions",
        delegation_targets=targets,
        instruction_provenance="a2a_message",
    )
    res2 = await planner.plan(req2)
    assert isinstance(res2.decision, DelegateDecision)
    assert res2.decision.target == "http://127.0.0.1:18102"
    assert res2.decision.capability == "file-audit"
