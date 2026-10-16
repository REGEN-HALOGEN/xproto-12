"""Ollama LLM adapter for XProto-12 supporting Llama 3.1 8B, Qwen2.5 7B, and local variants."""

from __future__ import annotations

import hashlib
import json
import re
import time
from typing import Any

import httpx

from xproto.config import OllamaConfig
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


class OllamaPlanner(Planner):
    """Planner adapter calling an Ollama instance with structured outputs and telemetry."""

    def __init__(
        self,
        config: OllamaConfig | None = None,
        fallback_planner: Planner | None = None,
        allow_fallback: bool = False,
    ):
        self.config = config or OllamaConfig()
        self.fallback_planner = fallback_planner
        self.allow_fallback = allow_fallback
        self._cached_digest: str | None = self.config.model_digest

    async def get_model_digest(self) -> str:
        """Fetch the SHA256 digest of the running model from Ollama, or generate a deterministic identifier."""
        if self._cached_digest:
            return self._cached_digest
        try:
            async with httpx.AsyncClient(timeout=3.0) as client:
                r = await client.get(f"{self.config.base_url.rstrip('/')}/api/tags")
                if r.status_code == 200:
                    data = r.json()
                    models = data.get("models", [])
                    for m in models:
                        name = m.get("name", "")
                        model_id = m.get("model", "")
                        if self.config.model in (name, model_id) or name.startswith(self.config.model):
                            digest = m.get("digest")
                            if digest:
                                self._cached_digest = digest
                                return digest
        except Exception:  # noqa: BLE001
            pass
        # Fallback digest if offline or model unlisted
        fallback_digest = hashlib.sha256(
            f"{self.config.model}:{self.config.prompt_template_version}".encode("utf-8")
        ).hexdigest()
        self._cached_digest = fallback_digest
        return fallback_digest

    def build_prompt(self, request: PlanRequest) -> str:
        """Construct a structured prompt with explicit provenance labeling and tool schemas."""
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

    async def plan(self, request: PlanRequest) -> PlanResult:
        t0 = time.perf_counter()
        prompt = self.build_prompt(request)
        model_digest = await self.get_model_digest()
        sampling_config = {
            "model": self.config.model,
            "temperature": self.config.temperature,
            "top_p": self.config.top_p,
            "max_tokens": self.config.max_tokens,
            "prompt_template_version": self.config.prompt_template_version,
        }

        options: dict[str, Any] = {
            "temperature": self.config.temperature,
            "top_p": self.config.top_p,
            "num_predict": self.config.max_tokens,
        }
        if self.config.seed is not None:
            options["seed"] = self.config.seed

        payload = {
            "model": self.config.model,
            "prompt": prompt,
            "format": "json",
            "stream": False,
            "options": options,
        }

        raw_response: str | None = None
        parser_error: str | None = None

        try:
            async with httpx.AsyncClient(timeout=self.config.timeout) as client:
                resp = await client.post(
                    f"{self.config.base_url.rstrip('/')}/api/generate",
                    json=payload,
                )
                if resp.status_code != 200:
                    raise PlannerError(
                        f"Ollama API returned HTTP {resp.status_code}: {resp.text}"
                    )
                data = resp.json()
                raw_response = data.get("response", "")

            # Parse and validate JSON
            cleaned = raw_response.strip()
            # Strip markdown formatting if present
            if cleaned.startswith("```"):
                cleaned = re.sub(r"^```(?:json)?\s*", "", cleaned)
                cleaned = re.sub(r"\s*```$", "", cleaned)

            try:
                parsed_json = json.loads(cleaned)
            except Exception as exc:
                raise PlannerParseError(f"Failed to parse LLM JSON: {exc} | Raw: {raw_response[:200]}") from exc

            decision = validate_decision(
                parsed_json,
                available_tools=request.available_tools,
                delegation_targets=request.delegation_targets,
            )

            duration_ms = (time.perf_counter() - t0) * 1000
            return PlanResult(
                decision=decision,
                raw_response=raw_response,
                model_digest=model_digest,
                sampling_config=sampling_config,
                seed=self.config.seed,
                duration_ms=duration_ms,
                parser_error=None,
                fallback_status=False,
            )

        except Exception as exc:
            parser_error = f"{type(exc).__name__}: {exc}"
            duration_ms = (time.perf_counter() - t0) * 1000

            # Check explicit fallback rule
            if self.allow_fallback and self.fallback_planner is not None:
                fallback_result = await self.fallback_planner.plan(request)
                fallback_result.raw_response = raw_response
                fallback_result.raw_hash = (
                    hashlib.sha256(raw_response.encode("utf-8")).hexdigest()
                    if raw_response
                    else None
                )
                fallback_result.parser_error = parser_error
                fallback_result.fallback_status = True
                fallback_result.model_digest = model_digest
                fallback_result.sampling_config = sampling_config
                fallback_result.seed = self.config.seed
                fallback_result.duration_ms = duration_ms
                return fallback_result

            # If fallback is not explicitly allowed, re-raise without hiding the error
            if isinstance(exc, (PlannerParseError, PlannerValidationError, PlannerError)):
                raise
            raise PlannerError(f"Ollama planning failed: {exc}") from exc
