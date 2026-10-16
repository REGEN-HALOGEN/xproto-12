"""Planner protocol, structured schemas, validated decision types, and logging models."""

from __future__ import annotations

import hashlib
import json
from abc import ABC, abstractmethod
from dataclasses import asdict, dataclass, field
from typing import Any, Literal

ProvenanceType = Literal[
    "user_input",
    "a2a_message",
    "mcp_tool_result",
    "delegated_response",
]

VALID_PROVENANCE_TYPES: set[str] = {
    "user_input",
    "a2a_message",
    "mcp_tool_result",
    "delegated_response",
}


class PlannerError(Exception):
    """Base exception for planner operations."""


class PlannerParseError(PlannerError):
    """Raised when the LLM output cannot be parsed into valid JSON/structure."""


class PlannerValidationError(PlannerError):
    """Raised when the planner output violates decision constraints."""


@dataclass
class InputSegment:
    """A provenance-labeled input segment for planner reasoning."""
    text: str
    provenance: ProvenanceType
    source_id: str | None = None
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class ToolDefinition:
    """Schema for a tool available to the planner."""
    name: str
    description: str
    parameters: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class DelegationTarget:
    """An attested or configured delegation target."""
    agent_id: str
    capability: str
    url: str
    description: str = ""

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class PlanRequest:
    """Execution context provided to a planner."""
    task_text: str
    history: list[InputSegment] = field(default_factory=list)
    available_tools: list[ToolDefinition] = field(default_factory=list)
    delegation_targets: list[DelegationTarget] = field(default_factory=list)
    principal_chain: list[str] = field(default_factory=list)
    instruction_provenance: ProvenanceType = "a2a_message"
    delegator: str | None = None

    def __post_init__(self):
        if self.instruction_provenance not in VALID_PROVENANCE_TYPES:
            raise PlannerValidationError(
                f"Invalid instruction_provenance: {self.instruction_provenance}. "
                f"Must be one of {sorted(VALID_PROVENANCE_TYPES)}"
            )


@dataclass
class PlanDecision(ABC):
    """Base class for one validated planner decision."""
    decision_type: Literal["tool_call", "delegate", "respond", "refuse"]

    @abstractmethod
    def to_dict(self) -> dict[str, Any]:
        ...


@dataclass
class ToolCallDecision(PlanDecision):
    decision_type: Literal["tool_call"] = "tool_call"
    tool: str = ""
    args: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "decision_type": "tool_call",
            "tool": self.tool,
            "args": dict(self.args),
        }


@dataclass
class DelegateDecision(PlanDecision):
    decision_type: Literal["delegate"] = "delegate"
    target: str = ""
    task_text: str = ""
    capability: str = ""

    def to_dict(self) -> dict[str, Any]:
        out = {
            "decision_type": "delegate",
            "target": self.target,
            "task_text": self.task_text,
        }
        if self.capability:
            out["capability"] = self.capability
        return out


@dataclass
class RespondDecision(PlanDecision):
    decision_type: Literal["respond"] = "respond"
    content: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "decision_type": "respond",
            "content": self.content,
        }


@dataclass
class RefuseDecision(PlanDecision):
    decision_type: Literal["refuse"] = "refuse"
    reason: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "decision_type": "refuse",
            "reason": self.reason,
        }


def validate_decision(
    raw: dict[str, Any],
    available_tools: list[ToolDefinition] | None = None,
    delegation_targets: list[DelegationTarget] | None = None,
) -> PlanDecision:
    """Validate a raw dictionary decision and return a strictly typed PlanDecision.
    
    Rejects malformed, incomplete, or extra actions before execution.
    """
    if not isinstance(raw, dict):
        raise PlannerValidationError(f"Decision must be a JSON object, got {type(raw).__name__}")

    decision_type = raw.get("decision_type")
    if not decision_type:
        raise PlannerValidationError("Decision missing required 'decision_type' field")

    valid_types = {"tool_call", "delegate", "respond", "refuse"}
    if decision_type not in valid_types:
        raise PlannerValidationError(
            f"Invalid decision_type '{decision_type}'. Must be one of {sorted(valid_types)}"
        )

    # Reject unexpected multi-action combinations
    allowed_keys_map = {
        "tool_call": {"decision_type", "tool", "args"},
        "delegate": {"decision_type", "target", "task_text", "capability"},
        "respond": {"decision_type", "content"},
        "refuse": {"decision_type", "reason"},
    }
    allowed_keys = allowed_keys_map[decision_type]
    extra_keys = set(raw.keys()) - allowed_keys
    if extra_keys:
        raise PlannerValidationError(
            f"Decision of type '{decision_type}' contains unauthorized extra fields: {sorted(extra_keys)}"
        )

    if decision_type == "tool_call":
        tool = raw.get("tool")
        if not tool or not isinstance(tool, str):
            raise PlannerValidationError("tool_call decision requires a non-empty string 'tool'")
        args = raw.get("args")
        if args is None:
            args = {}
        if not isinstance(args, dict):
            raise PlannerValidationError("tool_call 'args' must be a JSON object/dict")

        if available_tools is not None:
            valid_tool_names = {t.name for t in available_tools}
            if tool not in valid_tool_names:
                raise PlannerValidationError(
                    f"Requested tool '{tool}' is not in available tools: {sorted(valid_tool_names)}"
                )
        return ToolCallDecision(tool=tool, args=args)

    if decision_type == "delegate":
        target = raw.get("target")
        if not target or not isinstance(target, str):
            raise PlannerValidationError("delegate decision requires a non-empty string 'target'")
        task_text = raw.get("task_text", "")
        if not isinstance(task_text, str):
            raise PlannerValidationError("delegate 'task_text' must be a string")
        capability = raw.get("capability", "")
        if not isinstance(capability, str):
            raise PlannerValidationError("delegate 'capability' must be a string")
        return DelegateDecision(target=target, task_text=task_text, capability=capability)

    if decision_type == "respond":
        content = raw.get("content")
        if content is None or not isinstance(content, str):
            raise PlannerValidationError("respond decision requires a string 'content'")
        return RespondDecision(content=content)

    if decision_type == "refuse":
        reason = raw.get("reason")
        if reason is None or not isinstance(reason, str):
            raise PlannerValidationError("refuse decision requires a string 'reason'")
        return RefuseDecision(reason=reason)

    raise PlannerValidationError(f"Unhandled decision_type: {decision_type}")


@dataclass
class PlanResult:
    """Outcome of a planner invocation with audit telemetry."""
    decision: PlanDecision
    raw_response: str | None = None
    raw_hash: str | None = None
    model_digest: str | None = None
    sampling_config: dict[str, Any] = field(default_factory=dict)
    seed: int | None = None
    duration_ms: float = 0.0
    parser_error: str | None = None
    fallback_status: bool = False

    def __post_init__(self):
        if self.raw_response is not None and self.raw_hash is None:
            self.raw_hash = hashlib.sha256(self.raw_response.encode("utf-8")).hexdigest()

    def to_log_record(self) -> dict[str, Any]:
        """Convert into audit log record for provenance/evidence."""
        return {
            "event": "planner_decision",
            "decision_type": self.decision.decision_type,
            "normalized_decision": self.decision.to_dict(),
            "raw_response_hash": self.raw_hash,
            "model_digest": self.model_digest,
            "sampling_config": self.sampling_config,
            "seed": self.seed,
            "duration_ms": round(self.duration_ms, 2),
            "parser_error": self.parser_error,
            "fallback_status": self.fallback_status,
        }


class Planner(ABC):
    """Abstract protocol for an XProto-12 agent planner."""

    @abstractmethod
    async def plan(self, request: PlanRequest) -> PlanResult:
        """Accept execution context and emit a single validated PlanDecision."""
