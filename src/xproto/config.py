"""Configuration management for XProto-12."""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from typing import Literal

PlannerType = Literal["regex", "ollama"]


def _default_ollama_model() -> str:
    if "XPROTO_OLLAMA_MODEL" in os.environ:
        return os.environ["XPROTO_OLLAMA_MODEL"]
    try:
        import httpx
        host = os.environ.get("XPROTO_OLLAMA_HOST", "http://127.0.0.1:11434")
        with httpx.Client(timeout=1.0) as client:
            r = client.get(f"{host.rstrip('/')}/api/tags")
            if r.status_code == 200:
                models = [m.get("name", "") for m in r.json().get("models", [])]
                for preferred in ("qwen2.5:7b", "llama3.1:8b", "qwen2.5:3b", "qwen2.5:latest"):
                    for m in models:
                        if preferred in m or m.startswith(preferred):
                            return m
                if models:
                    return models[0]
    except Exception:
        pass
    return "qwen2.5:7b"


@dataclass
class OllamaConfig:
    """Configuration for the Ollama LLM adapter."""
    model: str = field(default_factory=_default_ollama_model)
    base_url: str = field(
        default_factory=lambda: os.environ.get("XPROTO_OLLAMA_HOST", "http://127.0.0.1:11434")
    )
    temperature: float = field(
        default_factory=lambda: float(os.environ.get("XPROTO_OLLAMA_TEMPERATURE", "0.0"))
    )
    top_p: float = 0.9
    seed: int | None = field(
        default_factory=lambda: int(os.environ["XPROTO_OLLAMA_SEED"]) if "XPROTO_OLLAMA_SEED" in os.environ else None
    )
    timeout: float = 45.0
    max_tokens: int = 512
    prompt_template_version: str = "v1"
    model_digest: str | None = None


@dataclass
class PlannerConfig:
    """Planner configuration: regex control baseline or Ollama LLM planner."""
    planner_type: PlannerType = field(
        default_factory=lambda: os.environ.get("XPROTO_PLANNER", "regex")  # type: ignore[return-value]
    )
    ollama: OllamaConfig = field(default_factory=OllamaConfig)
    allow_fallback: bool = False  # NEVER silently fallback unless explicitly allowed


@dataclass
class VictimConfig:
    """Configuration for an A2A victim or peer agent."""
    agent_id: str = "victim"
    port: int = 18080
    honest_provenance: bool = False  # False = vulnerable (confused deputy)
    known_agents: dict[str, str] = field(default_factory=dict)  # capability -> url
    planner_config: PlannerConfig = field(default_factory=PlannerConfig)
