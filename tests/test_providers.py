"""Unit tests for pluggable LLM provider adapters (Ollama, OpenAI-compatible, Anthropic).

All HTTP requests are strictly mocked with no live network calls.
Tests valid decisions, malformed JSON, HTTP error statuses, and timeouts for all adapters.
"""

from __future__ import annotations

import json
from unittest.mock import AsyncMock, patch

import httpx
import pytest

from xproto.config import OllamaConfig
from xproto.planners.base import (
    DelegateDecision,
    DelegationTarget,
    InputSegment,
    PlanRequest,
    PlanResult,
    PlannerError,
    PlannerParseError,
    PlannerValidationError,
    RefuseDecision,
    RespondDecision,
    ToolCallDecision,
    ToolDefinition,
)
from xproto.providers import (
    AnthropicConfig,
    AnthropicProvider,
    OllamaProvider,
    OpenAICompatibleConfig,
    OpenAICompatibleProvider,
    create_provider,
)


@pytest.fixture
def plan_request() -> PlanRequest:
    tools = [
        ToolDefinition(name="read_file", description="Reads file content", parameters={"type": "object"}),
        ToolDefinition(name="send_email", description="Sends email", parameters={"type": "object"}),
    ]
    targets = [
        DelegationTarget(agent_id="relay", capability="file-audit", url="http://127.0.0.1:18102"),
    ]
    history = [
        InputSegment(text="Hello", provenance="user_input"),
    ]
    return PlanRequest(
        task_text="summarize file testdata/public/notes.txt",
        history=history,
        available_tools=tools,
        delegation_targets=targets,
        principal_chain=["owner@victim"],
        instruction_provenance="a2a_message",
        delegator="owner",
    )


# ---------------------------------------------------------------------------
# 1. OllamaProvider Tests
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_ollama_provider_valid_tool_call(plan_request):
    provider = OllamaProvider(OllamaConfig(model="qwen2.5:7b"))
    mock_resp = AsyncMock()
    mock_resp.status_code = 200
    mock_resp.json = lambda: {
        "response": json.dumps({
            "decision_type": "tool_call",
            "tool": "read_file",
            "args": {"path": "testdata/public/notes.txt"},
        })
    }

    with patch("httpx.AsyncClient.post", return_value=mock_resp):
        result = await provider.generate_decision(plan_request)
        assert isinstance(result, PlanResult)
        assert isinstance(result.decision, ToolCallDecision)
        assert result.decision.tool == "read_file"
        assert result.decision.args == {"path": "testdata/public/notes.txt"}
        assert result.fallback_status is False
        assert result.parser_error is None


@pytest.mark.asyncio
async def test_ollama_provider_malformed_json(plan_request):
    provider = OllamaProvider(OllamaConfig(model="qwen2.5:7b"))
    mock_resp = AsyncMock()
    mock_resp.status_code = 200
    mock_resp.json = lambda: {"response": "This is definitely not JSON output."}

    with patch("httpx.AsyncClient.post", return_value=mock_resp):
        with pytest.raises(PlannerParseError, match="Failed to parse LLM JSON"):
            await provider.generate_decision(plan_request)


@pytest.mark.asyncio
async def test_ollama_provider_http_error(plan_request):
    provider = OllamaProvider(OllamaConfig(model="qwen2.5:7b"))
    mock_resp = AsyncMock()
    mock_resp.status_code = 500
    mock_resp.text = "Internal Server Error in model runner"

    with patch("httpx.AsyncClient.post", return_value=mock_resp):
        with pytest.raises(PlannerError, match="Ollama API returned HTTP 500"):
            await provider.generate_decision(plan_request)


@pytest.mark.asyncio
async def test_ollama_provider_timeout(plan_request):
    provider = OllamaProvider(OllamaConfig(model="qwen2.5:7b", timeout=5.0))

    with patch("httpx.AsyncClient.post", side_effect=httpx.TimeoutException("Timed out")):
        with pytest.raises(PlannerError, match="timed out"):
            await provider.generate_decision(plan_request)


# ---------------------------------------------------------------------------
# 2. OpenAICompatibleProvider Tests (OpenAI, Groq, Together, LM Studio, vLLM)
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_openai_compatible_provider_valid_delegate(plan_request):
    config = OpenAICompatibleConfig(
        base_url="https://api.openai.com/v1",
        api_key="sk-testkey123",
        model="gpt-4o",
    )
    provider = OpenAICompatibleProvider(config)

    mock_resp = AsyncMock()
    mock_resp.status_code = 200
    mock_resp.json = lambda: {
        "id": "chatcmpl-mock",
        "choices": [
            {
                "index": 0,
                "message": {
                    "role": "assistant",
                    "content": json.dumps({
                        "decision_type": "delegate",
                        "target": "http://127.0.0.1:18102",
                        "task_text": "run audit on directory",
                        "capability": "file-audit",
                    }),
                },
                "finish_reason": "stop",
            }
        ],
    }

    with patch("httpx.AsyncClient.post", return_value=mock_resp) as mock_post:
        result = await provider.generate_decision(plan_request)
        assert isinstance(result, PlanResult)
        assert isinstance(result.decision, DelegateDecision)
        assert result.decision.target == "http://127.0.0.1:18102"
        assert result.decision.capability == "file-audit"

        # Check call arguments
        call_kwargs = mock_post.call_args.kwargs
        assert "Authorization" in call_kwargs["headers"]
        assert call_kwargs["headers"]["Authorization"] == "Bearer sk-testkey123"
        payload = call_kwargs["json"]
        assert payload["model"] == "gpt-4o"
        assert len(payload["messages"]) == 2


@pytest.mark.asyncio
async def test_openai_compatible_provider_markdown_fenced_json(plan_request):
    config = OpenAICompatibleConfig(base_url="http://localhost:1234/v1", model="local-model")
    provider = OpenAICompatibleProvider(config)

    fenced_output = """```json
{
  "decision_type": "respond",
  "content": "Analysis completed successfully."
}
```"""
    mock_resp = AsyncMock()
    mock_resp.status_code = 200
    mock_resp.json = lambda: {
        "choices": [{"message": {"role": "assistant", "content": fenced_output}}]
    }

    with patch("httpx.AsyncClient.post", return_value=mock_resp):
        result = await provider.generate_decision(plan_request)
        assert isinstance(result.decision, RespondDecision)
        assert result.decision.content == "Analysis completed successfully."


@pytest.mark.asyncio
async def test_openai_compatible_provider_malformed_json(plan_request):
    config = OpenAICompatibleConfig(base_url="https://api.groq.com/openai/v1", api_key="gsk-test")
    provider = OpenAICompatibleProvider(config)

    mock_resp = AsyncMock()
    mock_resp.status_code = 200
    mock_resp.json = lambda: {
        "choices": [{"message": {"role": "assistant", "content": '{"decision_type": unclosed...'}}]
    }

    with patch("httpx.AsyncClient.post", return_value=mock_resp):
        with pytest.raises(PlannerParseError, match="Failed to parse LLM JSON"):
            await provider.generate_decision(plan_request)


@pytest.mark.asyncio
async def test_openai_compatible_provider_http_error(plan_request):
    config = OpenAICompatibleConfig(base_url="https://api.openai.com/v1", api_key="sk-bad")
    provider = OpenAICompatibleProvider(config)

    mock_resp = AsyncMock()
    mock_resp.status_code = 401
    mock_resp.text = "Incorrect API key provided"

    with patch("httpx.AsyncClient.post", return_value=mock_resp):
        with pytest.raises(PlannerError, match="OpenAI-compatible endpoint returned HTTP 401"):
            await provider.generate_decision(plan_request)


@pytest.mark.asyncio
async def test_openai_compatible_provider_timeout(plan_request):
    config = OpenAICompatibleConfig(base_url="https://api.together.xyz/v1", api_key="tok-123", timeout=3.0)
    provider = OpenAICompatibleProvider(config)

    with patch("httpx.AsyncClient.post", side_effect=httpx.TimeoutException("Read timeout")):
        with pytest.raises(PlannerError, match="timed out"):
            await provider.generate_decision(plan_request)


# ---------------------------------------------------------------------------
# 3. AnthropicProvider Tests
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_anthropic_provider_valid_refuse(plan_request):
    config = AnthropicConfig(
        api_key="sk-ant-test123",
        model="claude-3-5-sonnet-20241022",
    )
    provider = AnthropicProvider(config)

    mock_resp = AsyncMock()
    mock_resp.status_code = 200
    mock_resp.json = lambda: {
        "id": "msg_mock123",
        "type": "message",
        "role": "assistant",
        "content": [
            {
                "type": "text",
                "text": json.dumps({
                    "decision_type": "refuse",
                    "reason": "Security policy prevents reading confidential files.",
                }),
            }
        ],
    }

    with patch("httpx.AsyncClient.post", return_value=mock_resp) as mock_post:
        result = await provider.generate_decision(plan_request)
        assert isinstance(result, PlanResult)
        assert isinstance(result.decision, RefuseDecision)
        assert result.decision.reason == "Security policy prevents reading confidential files."

        call_kwargs = mock_post.call_args.kwargs
        assert call_kwargs["headers"]["x-api-key"] == "sk-ant-test123"
        assert call_kwargs["headers"]["anthropic-version"] == "2023-06-01"
        payload = call_kwargs["json"]
        assert payload["model"] == "claude-3-5-sonnet-20241022"
        assert "system" in payload
        assert isinstance(payload["messages"], list)


@pytest.mark.asyncio
async def test_anthropic_provider_malformed_json(plan_request):
    config = AnthropicConfig(api_key="sk-ant-test")
    provider = AnthropicProvider(config)

    mock_resp = AsyncMock()
    mock_resp.status_code = 200
    mock_resp.json = lambda: {
        "content": [{"type": "text", "text": "I will execute the task directly without structured json."}]
    }

    with patch("httpx.AsyncClient.post", return_value=mock_resp):
        with pytest.raises(PlannerParseError, match="Failed to parse LLM JSON"):
            await provider.generate_decision(plan_request)


@pytest.mark.asyncio
async def test_anthropic_provider_http_error(plan_request):
    config = AnthropicConfig(api_key="sk-ant-test")
    provider = AnthropicProvider(config)

    mock_resp = AsyncMock()
    mock_resp.status_code = 529
    mock_resp.text = "Anthropic API overloaded"

    with patch("httpx.AsyncClient.post", return_value=mock_resp):
        with pytest.raises(PlannerError, match="Anthropic endpoint returned HTTP 529"):
            await provider.generate_decision(plan_request)


@pytest.mark.asyncio
async def test_anthropic_provider_timeout(plan_request):
    config = AnthropicConfig(api_key="sk-ant-test", timeout=2.0)
    provider = AnthropicProvider(config)

    with patch("httpx.AsyncClient.post", side_effect=httpx.TimeoutException("Connection timed out")):
        with pytest.raises(PlannerError, match="timed out"):
            await provider.generate_decision(plan_request)


# ---------------------------------------------------------------------------
# 4. Factory and Configuration Tests
# ---------------------------------------------------------------------------

def test_create_provider_from_dict():
    # OpenAI compatible
    p1 = create_provider({
        "type": "openai",
        "base_url": "https://api.openai.com/v1",
        "api_key": "sk-123",
        "model": "gpt-4o",
    })
    assert isinstance(p1, OpenAICompatibleProvider)
    assert p1.config.model == "gpt-4o"
    assert p1.config.api_key == "sk-123"

    # Anthropic
    p2 = create_provider({
        "type": "anthropic",
        "api_key": "sk-ant-456",
        "model": "claude-3-haiku-20240307",
    })
    assert isinstance(p2, AnthropicProvider)
    assert p2.config.model == "claude-3-haiku-20240307"

    # Ollama
    p3 = create_provider({
        "type": "ollama",
        "base_url": "http://127.0.0.1:11434",
        "model": "llama3.1:8b",
    })
    assert isinstance(p3, OllamaProvider)
    assert p3.config.model == "llama3.1:8b"
