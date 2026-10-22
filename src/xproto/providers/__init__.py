"""Pluggable LLM provider layer for XProto-12."""

from __future__ import annotations

from typing import Any

from xproto.config import OllamaConfig
from xproto.providers.anthropic import AnthropicConfig, AnthropicProvider
from xproto.providers.base import (
    LLMProvider,
    build_chat_messages,
    build_planning_prompt,
    parse_and_validate_decision_json,
)
from xproto.providers.ollama import OllamaProvider
from xproto.providers.openai_compatible import (
    OpenAICompatibleConfig,
    OpenAICompatibleProvider,
)


def create_provider(config: dict[str, Any] | Any) -> LLMProvider:
    """Instantiate an LLMProvider from a dictionary or configuration object."""
    if isinstance(config, LLMProvider):
        return config

    if isinstance(config, OllamaConfig):
        return OllamaProvider(config=config)
    if isinstance(config, OpenAICompatibleConfig):
        return OpenAICompatibleProvider(config=config)
    if isinstance(config, AnthropicConfig):
        return AnthropicProvider(config=config)

    if isinstance(config, dict):
        provider_type = (config.get("type") or config.get("planner_type") or "openai").lower()
        if provider_type in ("ollama",):
            cfg = OllamaConfig(
                model=config.get("model", "qwen2.5:7b"),
                base_url=config.get("base_url", "http://127.0.0.1:11434"),
                temperature=float(config.get("temperature", 0.0)),
                timeout=float(config.get("timeout", 45.0)),
            )
            return OllamaProvider(config=cfg)
        if provider_type in ("anthropic", "claude"):
            cfg = AnthropicConfig.from_dict(config)
            return AnthropicProvider(config=cfg)
        # default to openai compatible (OpenAI, Groq, Together, LM Studio, vLLM)
        cfg = OpenAICompatibleConfig.from_dict(config)
        return OpenAICompatibleProvider(config=cfg)

    raise ValueError(f"Unsupported provider configuration: {type(config).__name__}")


__all__ = [
    "AnthropicConfig",
    "AnthropicProvider",
    "LLMProvider",
    "OllamaConfig",
    "OllamaProvider",
    "OpenAICompatibleConfig",
    "OpenAICompatibleProvider",
    "build_chat_messages",
    "build_planning_prompt",
    "create_provider",
    "parse_and_validate_decision_json",
]
