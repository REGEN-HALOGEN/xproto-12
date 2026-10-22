"""OpenAI-compatible LLM provider adapter for XProto-12.

Supports OpenAI, Groq, Together, LM Studio, vLLM, and any endpoint
implementing the OpenAI chat completions specification.
"""

from __future__ import annotations

import hashlib
import os
import time
from dataclasses import dataclass, field
from typing import Any

import httpx

from xproto.planners.base import (
    PlanRequest,
    PlanResult,
    PlannerError,
    PlannerParseError,
    PlannerValidationError,
)
from xproto.providers.base import (
    LLMProvider,
    build_chat_messages,
    parse_and_validate_decision_json,
)


def normalize_openai_endpoint(base_url: str) -> str:
    """Normalize base URL into a full /chat/completions endpoint URL."""
    url = base_url.strip().rstrip("/")
    if url.endswith("/chat/completions"):
        return url
    if url.endswith("/v1"):
        return f"{url}/chat/completions"
    return f"{url}/v1/chat/completions"


@dataclass
class OpenAICompatibleConfig:
    """Configuration for OpenAI-compatible providers."""
    base_url: str = field(
        default_factory=lambda: os.environ.get("XPROTO_OPENAI_BASE_URL", "https://api.openai.com/v1")
    )
    api_key: str | None = field(
        default_factory=lambda: os.environ.get("OPENAI_API_KEY", os.environ.get("XPROTO_OPENAI_API_KEY"))
    )
    model: str = field(
        default_factory=lambda: os.environ.get("XPROTO_OPENAI_MODEL", "gpt-4o")
    )
    temperature: float = 0.0
    max_tokens: int = 512
    timeout: float = 45.0
    model_digest: str | None = None

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> OpenAICompatibleConfig:
        return cls(
            base_url=data.get("base_url") or os.environ.get("XPROTO_OPENAI_BASE_URL", "https://api.openai.com/v1"),
            api_key=data.get("api_key") or os.environ.get("OPENAI_API_KEY", os.environ.get("XPROTO_OPENAI_API_KEY")),
            model=data.get("model") or os.environ.get("XPROTO_OPENAI_MODEL", "gpt-4o"),
            temperature=float(data.get("temperature", 0.0)),
            max_tokens=int(data.get("max_tokens", 512)),
            timeout=float(data.get("timeout", 45.0)),
            model_digest=data.get("model_digest"),
        )


class OpenAICompatibleProvider(LLMProvider):
    """Adapter for endpoints exposing the OpenAI /chat/completions API."""

    def __init__(self, config: OpenAICompatibleConfig | None = None):
        self.config = config or OpenAICompatibleConfig()
        self.endpoint_url = normalize_openai_endpoint(self.config.base_url)
        self._cached_digest: str | None = self.config.model_digest

    async def get_model_digest(self) -> str:
        """Deterministic model digest for telemetry."""
        if self._cached_digest:
            return self._cached_digest
        digest = hashlib.sha256(
            f"openai-compatible:{self.config.model}:{self.config.base_url}".encode("utf-8")
        ).hexdigest()
        self._cached_digest = digest
        return digest

    async def generate_decision(self, request: PlanRequest) -> PlanResult:
        t0 = time.perf_counter()
        system_prompt, user_prompt = build_chat_messages(request)
        model_digest = await self.get_model_digest()

        sampling_config = {
            "provider": "openai_compatible",
            "model": self.config.model,
            "base_url": self.config.base_url,
            "temperature": self.config.temperature,
            "max_tokens": self.config.max_tokens,
        }

        messages = [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": user_prompt},
        ]

        payload: dict[str, Any] = {
            "model": self.config.model,
            "messages": messages,
            "temperature": self.config.temperature,
            "max_tokens": self.config.max_tokens,
        }

        headers: dict[str, str] = {
            "Content-Type": "application/json",
        }
        if self.config.api_key:
            headers["Authorization"] = f"Bearer {self.config.api_key}"

        raw_response: str | None = None
        try:
            async with httpx.AsyncClient(timeout=self.config.timeout) as client:
                resp = await client.post(
                    self.endpoint_url,
                    json=payload,
                    headers=headers,
                )
                if resp.status_code != 200:
                    raise PlannerError(
                        f"OpenAI-compatible endpoint returned HTTP {resp.status_code}: {resp.text}"
                    )
                data = resp.json()
                choices = data.get("choices")
                if not choices or not isinstance(choices, list):
                    raise PlannerError(
                        f"OpenAI-compatible response missing choices list: {resp.text[:200]}"
                    )
                message = choices[0].get("message", {})
                raw_response = message.get("content", "")

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
                duration_ms=duration_ms,
                parser_error=None,
                fallback_status=False,
            )
        except (PlannerParseError, PlannerValidationError, PlannerError):
            raise
        except httpx.TimeoutException as exc:
            raise PlannerError(
                f"OpenAI-compatible request timed out after {self.config.timeout}s: {exc}"
            ) from exc
        except Exception as exc:
            raise PlannerError(f"OpenAI-compatible planning failed: {exc}") from exc
