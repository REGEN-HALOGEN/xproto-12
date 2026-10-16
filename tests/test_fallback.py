"""Tests ensuring explicit fallback control and forbidding silent fallbacks."""

import pytest
from unittest.mock import AsyncMock, patch

from xproto.config import OllamaConfig
from xproto.planners.base import (
    PlanRequest,
    PlanResult,
    PlannerError,
    PlannerParseError,
    ToolCallDecision,
    ToolDefinition,
)
from xproto.planners.ollama import OllamaPlanner
from xproto.planners.regex import RegexPlanner


@pytest.mark.asyncio
async def test_no_silent_fallback_when_disabled():
    """When allow_fallback=False, any error MUST be raised, never silently routed to regex."""
    cfg = OllamaConfig(base_url="http://127.0.0.1:99999")  # Unreachable port
    fallback = RegexPlanner()
    planner = OllamaPlanner(config=cfg, fallback_planner=fallback, allow_fallback=False)

    req = PlanRequest(
        task_text="summarize file testdata/public/notes.txt",
        available_tools=[ToolDefinition(name="read_file", description="")],
        instruction_provenance="a2a_message",
    )

    with pytest.raises(PlannerError):
        await planner.plan(req)


@pytest.mark.asyncio
async def test_no_silent_fallback_on_parse_error():
    """Invalid LLM response syntax raises PlannerParseError when fallback is disabled."""
    cfg = OllamaConfig(base_url="http://127.0.0.1:11434")
    fallback = RegexPlanner()
    planner = OllamaPlanner(config=cfg, fallback_planner=fallback, allow_fallback=False)

    req = PlanRequest(
        task_text="summarize file testdata/public/notes.txt",
        available_tools=[ToolDefinition(name="read_file", description="")],
        instruction_provenance="a2a_message",
    )

    # Mock an invalid JSON response from Ollama
    mock_resp = AsyncMock()
    mock_resp.status_code = 200
    mock_resp.json = lambda: {"response": "Sorry, I cannot help with that (not JSON)"}

    with patch("httpx.AsyncClient.post", return_value=mock_resp):
        with pytest.raises(PlannerParseError, match="Failed to parse LLM JSON"):
            await planner.plan(req)


@pytest.mark.asyncio
async def test_explicit_fallback_when_enabled():
    """When allow_fallback=True is explicitly set, fallback occurs with explicit telemetry."""
    cfg = OllamaConfig(base_url="http://127.0.0.1:11434")
    fallback = RegexPlanner()
    planner = OllamaPlanner(config=cfg, fallback_planner=fallback, allow_fallback=True)

    req = PlanRequest(
        task_text="summarize file testdata/public/notes.txt",
        available_tools=[ToolDefinition(name="read_file", description="")],
        instruction_provenance="a2a_message",
    )

    mock_resp = AsyncMock()
    mock_resp.status_code = 200
    mock_resp.json = lambda: {"response": "Malformed non-JSON output"}

    with patch("httpx.AsyncClient.post", return_value=mock_resp):
        res = await planner.plan(req)

        assert isinstance(res, PlanResult)
        assert isinstance(res.decision, ToolCallDecision)
        assert res.decision.tool == "read_file"
        assert res.fallback_status is True
        assert res.parser_error is not None
        assert "PlannerParseError" in res.parser_error

        log_rec = res.to_log_record()
        assert log_rec["fallback_status"] is True
        assert log_rec["parser_error"] is not None
