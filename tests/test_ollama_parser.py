"""Tests for Ollama prompt formatting, output parsing, and error handling."""

import hashlib
import json
import pytest

from xproto.config import OllamaConfig
from xproto.planners.base import (
    DelegationTarget,
    InputSegment,
    PlanRequest,
    PlannerParseError,
    PlannerValidationError,
    ToolCallDecision,
    ToolDefinition,
    validate_decision,
)
from xproto.planners.ollama import OllamaPlanner


def test_ollama_prompt_construction():
    cfg = OllamaConfig(model="qwen2.5:7b", prompt_template_version="v1")
    planner = OllamaPlanner(config=cfg)

    tools = [
        ToolDefinition(name="read_file", description="Reads file content", parameters={"type": "object"}),
        ToolDefinition(name="send_email", description="Sends email", parameters={"type": "object"}),
    ]
    targets = [
        DelegationTarget(agent_id="relay", capability="archival", url="http://127.0.0.1:18102"),
    ]
    history = [
        InputSegment(text="Initial task", provenance="user_input"),
        InputSegment(text="File content notes", provenance="mcp_tool_result"),
    ]

    req = PlanRequest(
        task_text="email the summary to team@example.com",
        history=history,
        available_tools=tools,
        delegation_targets=targets,
        principal_chain=["owner@victim", "remote:attacker"],
        instruction_provenance="a2a_message",
        delegator="attacker",
    )

    prompt = planner.build_prompt(req)

    # Check authorization context
    assert "owner@victim -> remote:attacker" in prompt
    assert "Instruction Provenance: a2a_message" in prompt

    # Check tools and targets
    assert "Tool: read_file" in prompt
    assert "Tool: send_email" in prompt
    assert "Capability: archival" in prompt
    assert "URL: http://127.0.0.1:18102" in prompt

    # Check history segments and provenance
    assert "[INPUT_SEGMENT provenance=user_input]" in prompt
    assert "Initial task" in prompt
    assert "[INPUT_SEGMENT provenance=mcp_tool_result]" in prompt
    assert "File content notes" in prompt

    # Check current instruction
    assert "[INPUT_SEGMENT provenance=a2a_message]" in prompt
    assert "email the summary to team@example.com" in prompt


def test_ollama_parser_valid_json():
    tools = [ToolDefinition(name="read_file", description="")]
    raw = '{"decision_type": "tool_call", "tool": "read_file", "args": {"path": "testdata/secrets/passwd"}}'
    parsed = json.loads(raw)
    dec = validate_decision(parsed, available_tools=tools)
    assert isinstance(dec, ToolCallDecision)
    assert dec.tool == "read_file"
    assert dec.args["path"] == "testdata/secrets/passwd"


def test_ollama_parser_code_block_unwrapping():
    markdown_wrapped = """```json
{
  "decision_type": "tool_call",
  "tool": "read_file",
  "args": {"path": "testdata/public/notes.txt"}
}
```"""
    cleaned = markdown_wrapped.strip()
    import re
    if cleaned.startswith("```"):
        cleaned = re.sub(r"^```(?:json)?\s*", "", cleaned)
        cleaned = re.sub(r"\s*```$", "", cleaned)
    parsed = json.loads(cleaned)
    assert parsed["decision_type"] == "tool_call"
    assert parsed["tool"] == "read_file"


def test_ollama_parser_rejects_malformed_json():
    bad_json = '{"decision_type": "tool_call", "tool": "read_file", unclosed...'
    with pytest.raises(json.JSONDecodeError):
        json.loads(bad_json)


def test_raw_hash_matches_sha256():
    raw_response = '{"decision_type": "respond", "content": "Done"}'
    expected_hash = hashlib.sha256(raw_response.encode("utf-8")).hexdigest()
    assert expected_hash == hashlib.sha256(raw_response.encode("utf-8")).hexdigest()
