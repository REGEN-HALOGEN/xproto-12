"""Ollama LLM adapter for XProto-12 supporting Llama 3.1 8B, Qwen2.5 7B, and local variants."""

from __future__ import annotations

import hashlib
import time

from xproto.config import OllamaConfig
from xproto.planners.base import (
    PlanRequest,
    PlanResult,
    Planner,
    PlannerError,
    PlannerParseError,
    PlannerValidationError,
)
from xproto.providers.ollama import OllamaProvider


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
        self.provider = OllamaProvider(config=self.config)

    async def get_model_digest(self) -> str:
        """Fetch the SHA256 digest of the running model from Ollama, or generate a deterministic identifier."""
        return await self.provider.get_model_digest()

    def build_prompt(self, request: PlanRequest) -> str:
        """Construct a structured prompt with explicit provenance labeling and tool schemas."""
        return self.provider.build_prompt(request)

    async def plan(self, request: PlanRequest) -> PlanResult:
        t0 = time.perf_counter()
        raw_response: str | None = None
        parser_error: str | None = None
        model_digest = await self.get_model_digest()
        sampling_config = {
            "model": self.config.model,
            "temperature": self.config.temperature,
            "top_p": self.config.top_p,
            "max_tokens": self.config.max_tokens,
            "prompt_template_version": self.config.prompt_template_version,
        }

        try:
            return await self.provider.generate_decision(request)
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
