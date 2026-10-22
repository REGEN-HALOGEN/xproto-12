"""Base interface, prompt formatting, and decision parsing for pluggable LLM providers."""

from __future__ import annotations

import hashlib
import json
import re
import time
from abc import ABC, abstractmethod
from typing import Any

from xproto.planners.base import (
    DelegationTarget,
    InputSegment,
    PlanDecision,
    PlanRequest,
    PlanResult,
    Planner,
    PlannerError,
    PlannerParseError,
    PlannerValidationError,
    ToolDefinition,
    validate_decision,
)


def build_planning_prompt(request: PlanRequest) -> str:
    """Construct a complete planning prompt with provenance labeling and tool schemas."""
    tools_str = ""
    for t in request.available_tools:
        tools_str += f"- Tool: {t.name}\n  Description: {t.description}\n  Parameters: {json.dumps(t.parameters)}\n"

    delegation_str = ""
    for d in request.delegation_targets:
        delegation_str += f"- Capability: {d.capability}\n  Agent: {d.agent_id}\n  URL: {d.url}\n"

    history_str = ""
    for seg in request.history:
        history_str += f"[INPUT_SEGMENT provenance={seg.provenance}]\n{seg.text}\n"

    current_segment = (
        f"[INPUT_SEGMENT provenance={request.instruction_provenance}]\n{request.task_text}"
    )

    chain_str = " -> ".join(request.principal_chain) if request.principal_chain else "none"

    return f"""You are the planning engine for an autonomous agent.
Analyze the input segments, authority context, available tools, and delegation targets.
Then make ONE single decision.

[AUTHORIZATION CONTEXT]
Principal Chain: {chain_str}
Instruction Provenance: {request.instruction_provenance}

[AVAILABLE MCP TOOLS]
{tools_str or "None"}

[AVAILABLE A2A DELEGATION TARGETS]
{delegation_str or "None"}

[CONVERSATION HISTORY]
{history_str or "None"}

[CURRENT INSTRUCTION]
{current_segment}

[OUTPUT FORMAT]
You must respond ONLY with a single JSON object matching ONE of these 4 schema definitions:
1. Tool call:
   {{"decision_type": "tool_call", "tool": "<tool_name>", "args": {{<arguments>}}}}
2. Delegation:
   {{"decision_type": "delegate", "target": "<target_url>", "task_text": "<task_to_delegate>", "capability": "<optional_capability>"}}
3. Direct response:
   {{"decision_type": "respond", "content": "<response_text>"}}
4. Refusal:
   {{"decision_type": "refuse", "reason": "<refusal_reason>"}}

Do NOT provide extra text, explanations, or multiple actions. Return ONLY valid JSON.
"""


def build_chat_messages(request: PlanRequest) -> tuple[str, str]:
    """Return (system_prompt, user_prompt) pair for chat completion APIs."""
    system_prompt = (
        "You are the planning engine for an autonomous agent.\n"
        "Analyze the input segments, authority context, available tools, and delegation targets.\n"
        "Then make ONE single decision.\n\n"
        "You must respond ONLY with a single JSON object matching ONE of these 4 schema definitions:\n"
        '1. Tool call: {"decision_type": "tool_call", "tool": "<tool_name>", "args": {<arguments>}}\n'
        '2. Delegation: {"decision_type": "delegate", "target": "<target_url>", "task_text": "<task_to_delegate>", "capability": "<optional_capability>"}\n'
        '3. Direct response: {"decision_type": "respond", "content": "<response_text>"}\n'
        '4. Refusal: {"decision_type": "refuse", "reason": "<refusal_reason>"}\n\n'
        "Do NOT provide extra text, explanations, or multiple actions. Return ONLY valid JSON."
    )

    tools_str = ""
    for t in request.available_tools:
        tools_str += f"- Tool: {t.name}\n  Description: {t.description}\n  Parameters: {json.dumps(t.parameters)}\n"

    delegation_str = ""
    for d in request.delegation_targets:
        delegation_str += f"- Capability: {d.capability}\n  Agent: {d.agent_id}\n  URL: {d.url}\n"

    history_str = ""
    for seg in request.history:
        history_str += f"[INPUT_SEGMENT provenance={seg.provenance}]\n{seg.text}\n"

    current_segment = (
        f"[INPUT_SEGMENT provenance={request.instruction_provenance}]\n{request.task_text}"
    )

    chain_str = " -> ".join(request.principal_chain) if request.principal_chain else "none"

    user_prompt = f"""[AUTHORIZATION CONTEXT]
Principal Chain: {chain_str}
Instruction Provenance: {request.instruction_provenance}

[AVAILABLE MCP TOOLS]
{tools_str or "None"}

[AVAILABLE A2A DELEGATION TARGETS]
{delegation_str or "None"}

[CONVERSATION HISTORY]
{history_str or "None"}

[CURRENT INSTRUCTION]
{current_segment}
"""
    return system_prompt, user_prompt


def parse_and_validate_decision_json(
    raw_response: str,
    available_tools: list[ToolDefinition] | None = None,
    delegation_targets: list[DelegationTarget] | None = None,
) -> PlanDecision:
    """Extract and validate structured PlanDecision from raw LLM text.
    
    Unwraps markdown code fences if present.
    Raises PlannerParseError on malformed JSON.
    Raises PlannerValidationError on schema violations.
    """
    if raw_response is None:
        raise PlannerParseError("Raw LLM response is None")

    cleaned = raw_response.strip()

    # Unwrap markdown fences (e.g. ```json ... ``` or ``` ...)
    if cleaned.startswith("```"):
        cleaned = re.sub(r"^```(?:json)?\s*", "", cleaned)
        cleaned = re.sub(r"\s*```$", "", cleaned)
    elif "```" in cleaned:
        m = re.search(r"```(?:json)?\s*(\{.*?\})\s*```", cleaned, re.DOTALL)
        if m:
            cleaned = m.group(1).strip()

    try:
        parsed_json = json.loads(cleaned)
    except Exception as exc:
        raise PlannerParseError(
            f"Failed to parse LLM JSON: {exc} | Raw: {raw_response[:200]}"
        ) from exc

    return validate_decision(
        parsed_json,
        available_tools=available_tools,
        delegation_targets=delegation_targets,
    )


class LLMProvider(Planner, ABC):
    """Base interface for all LLM providers in XProto-12.
    
    Accepts chat completion context (PlanRequest with InputSegments, tools, targets)
    and outputs a structured, validated PlanResult.
    Zero silent fallback: surfaces all provider errors directly.
    """

    @abstractmethod
    async def generate_decision(self, request: PlanRequest) -> PlanResult:
        """Call the provider endpoint and return a validated PlanResult."""
        ...

    @abstractmethod
    async def get_model_digest(self) -> str:
        """Fetch or compute a deterministic model identifier for audit logging."""
        ...

    async def plan(self, request: PlanRequest) -> PlanResult:
        """Planner protocol entry point; routes to generate_decision."""
        return await self.generate_decision(request)
