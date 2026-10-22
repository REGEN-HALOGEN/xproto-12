"""Anthropic Claude LLM provider adapter for XProto-12."""

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


@dataclass
class AnthropicConfig:
    """Configuration for Anthropic Claude provider."""
    api_key: str | None = field(
        default_factory=lambda: os.environ.get("ANTHROPIC_API_KEY", os.environ.get("XPROTO_ANTHROPIC_API_KEY"))
    )
    model: str = field(
        default_factory=lambda: os.environ.get("XPROTO_ANTHROPIC_MODEL", "claude-3-5-sonnet-20241022")
    )
    base_url: str = "https://api.anthropic.com"
    anthropic_version: str = "2023-06-01"
    temperature: float = 0.0
    max_tokens: int = 512
    timeout: float = 45.0
    model_digest: str | None = None

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> AnthropicConfig:
        return cls(
            api_key=data.get("api_key") or os.environ.get("ANTHROPIC_API_KEY", os.environ.get("XPROTO_ANTHROPIC_API_KEY")),
            model=data.get("model") or os.environ.get("XPROTO_ANTHROPIC_MODEL", "claude-3-5-sonnet-20241022"),
            base_url=data.get("base_url") or "https://api.anthropic.com",
            anthropic_version=data.get("anthropic_version") or "2023-06-01",
            temperature=float(data.get("temperature", 0.0)),
            max_tokens=int(data.get("max_tokens", 512)),
            timeout=float(data.get("timeout", 45.0)),
            model_digest=data.get("model_digest"),
        )


class AnthropicProvider(LLMProvider):
    """Adapter calling Anthropic Messages API."""

    def __init__(self, config: AnthropicConfig | None = None):
        self.config = config or AnthropicConfig()
        self.endpoint_url = f"{self.config.base_url.rstrip('/')}/v1/messages"
        self._cached_digest: str | None = self.config.model_digest

    async def get_model_digest(self) -> str:
        """Deterministic model digest for telemetry."""
        if self._cached_digest:
            return self._cached_digest
        digest = hashlib.sha256(
            f"anthropic:{self.config.model}:{self.config.base_url}".encode("utf-8")
        ).hexdigest()
        self._cached_digest = digest
        return digest

    async def generate_decision(self, request: PlanRequest) -> PlanResult:
        t0 = time.perf_counter()
        system_prompt, user_prompt = build_chat_messages(request)
        model_digest = await self.get_model_digest()

        sampling_config = {
            "provider": "anthropic",
            "model": self.config.model,
            "temperature": self.config.temperature,
            "max_tokens": self.config.max_tokens,
            "anthropic_version": self.config.anthropic_version,
        }

        headers: dict[str, str] = {
            "Content-Type": "application/json",
            "anthropic-version": self.config.anthropic_version,
        }
        if self.config.api_key:
            headers["x-api-key"] = self.config.api_key

        payload: dict[str, Any] = {
            "model": self.config.model,
            "max_tokens": self.config.max_tokens,
            "temperature": self.config.temperature,
            "system": system_prompt,
            "messages": [
                {"role": "user", "content": user_prompt},
            ],
        }

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
                        f"Anthropic endpoint returned HTTP {resp.status_code}: {resp.text}"
                    )
                data = resp.json()
                content_blocks = data.get("content", [])
                raw_response = "".join(
                    b.get("text", "") for b in content_blocks if b.get("type") == "text"
                )

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
                f"Anthropic request timed out after {self.config.timeout}s: {exc}"
            ) from exc
        except Exception as exc:
            raise PlannerError(f"Anthropic planning failed: {exc}") from exc
