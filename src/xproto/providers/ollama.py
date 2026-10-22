"""Ollama LLM provider adapter for XProto-12."""

from __future__ import annotations

import hashlib
import time
from typing import Any

import httpx

from xproto.config import OllamaConfig
from xproto.planners.base import (
    PlanRequest,
    PlanResult,
    PlannerError,
    PlannerParseError,
    PlannerValidationError,
)
from xproto.providers.base import (
    LLMProvider,
    build_planning_prompt,
    parse_and_validate_decision_json,
)


class OllamaProvider(LLMProvider):
    """Adapter calling an Ollama instance with structured outputs and telemetry."""

    def __init__(self, config: OllamaConfig | None = None):
        self.config = config or OllamaConfig()
        self._cached_digest: str | None = self.config.model_digest

    def build_prompt(self, request: PlanRequest) -> str:
        """Construct structured prompt matching existing Ollama template."""
        return build_planning_prompt(request)

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

    async def generate_decision(self, request: PlanRequest) -> PlanResult:
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

            decision = parse_and_validate_decision_json(
                raw_response,
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
        except (PlannerParseError, PlannerValidationError, PlannerError):
            raise
        except httpx.TimeoutException as exc:
            raise PlannerError(f"Ollama request timed out after {self.config.timeout}s: {exc}") from exc
        except Exception as exc:
            raise PlannerError(f"Ollama planning failed: {exc}") from exc
