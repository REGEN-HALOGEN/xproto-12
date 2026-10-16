"""Shared helpers: logging, constants, proto message builders for XProto-12."""

from __future__ import annotations

import json
import os
import time
import uuid
from pathlib import Path

# Root of the project (~/workspace/xproto-12 when run from the repo).
PROJECT_ROOT = Path(__file__).resolve().parents[2]

# Per-trial log directory, set by eval.py. A plain module global (not a
# contextvar): server handler tasks are created before trials start, so a
# contextvar set per trial would not propagate to them. Trials run
# sequentially in one event loop, so a global is safe here.
_log_dir_override: Path | None = None


def set_log_dir(path: Path | str) -> None:
    global _log_dir_override
    _log_dir_override = Path(path)


def get_log_dir() -> Path:
    d = _log_dir_override
    if d is None:
        d = PROJECT_ROOT / "logs"
    d.mkdir(parents=True, exist_ok=True)
    return d


def log_event(filename: str, record: dict) -> None:
    """Append one JSON line to <log_dir>/<filename>."""
    record = dict(record)
    record.setdefault("ts", time.time())
    path = get_log_dir() / filename
    with path.open("a", encoding="utf-8") as fh:
        fh.write(json.dumps(record) + "\n")


def utc_now() -> float:
    return time.time()


def new_id(prefix: str = "id") -> str:
    return f"{prefix}-{uuid.uuid4().hex[:12]}"


# ---------------------------------------------------------------------------
# Sensitivity model
# ---------------------------------------------------------------------------
HIGH, MEDIUM, LOW, NONE = 3, 2, 1, 0
LEVEL_NAME = {3: "HIGH", 2: "MEDIUM", 1: "LOW", 0: "NONE"}

# Principal -> max authority level it may exercise.
PRINCIPAL_AUTHORITY: dict[str, int] = {
    "owner": HIGH,
    "tool-output": NONE,  # instructions smuggled in via tool results: no authority
}


def principal_authority(principal: str) -> int:
    """Authority of a principal. Remote (delegated) principals are LOW by default."""
    if principal in PRINCIPAL_AUTHORITY:
        return PRINCIPAL_AUTHORITY[principal]
    if principal.startswith("remote:"):
        return LOW
    if principal.startswith("owner@"):
        return HIGH
    return NONE


def chain_authority(chain: list[str]) -> int:
    """Authority of a delegation chain = weakest link."""
    if not chain:
        return NONE
    return min(principal_authority(p) for p in chain)


def is_high_sensitivity_path(path: str) -> bool:
    p = os.path.expanduser(path)
    return p.startswith("/etc/") or p == "/etc/passwd" or "/.ssh/" in p or p.endswith("/.ssh")


# ---------------------------------------------------------------------------
# A2A proto helpers (a2a-sdk 1.2.2 uses protobuf types)
# ---------------------------------------------------------------------------
def make_user_message(text: str, metadata: dict | None = None):
    from google.protobuf.struct_pb2 import Struct
    from a2a.types import a2a_pb2 as pb

    msg = pb.Message()
    msg.message_id = new_id("msg")
    msg.role = pb.Role.Value("ROLE_USER")
    part = msg.parts.add()
    part.text = text
    if metadata:
        s = Struct()
        s.update(metadata)
        msg.metadata.CopyFrom(s)
    return msg


def make_agent_text(text: str):
    from a2a.types import a2a_pb2 as pb

    msg = pb.Message()
    msg.message_id = new_id("msg")
    msg.role = pb.Role.Value("ROLE_AGENT")
    part = msg.parts.add()
    part.text = text
    return msg


def message_text(msg) -> str:
    return "\n".join(p.text for p in msg.parts if p.text)


async def enqueue_task_proto(event_queue, task_id: str, context_id: str,
                             state: str = "TASK_STATE_SUBMITTED"):
    """Enqueue the Task proto itself. The a2a 1.2.2 server requires the Task
    to be enqueued before any TaskStatusUpdateEvent (TaskUpdater only emits
    status events, so executors must call this first)."""
    from a2a.types import a2a_pb2 as pb

    task = pb.Task()
    task.id = task_id
    task.context_id = context_id
    task.status.state = pb.TaskState.Value(state)
    await event_queue.enqueue_event(task)


def build_agent_card(name: str, description: str, base_url: str, skills: list[dict]) -> object:
    """Build a proto AgentCard served at base_url/.well-known/agent-card.json."""
    from a2a.types import a2a_pb2 as pb

    card = pb.AgentCard()
    card.name = name
    card.description = description
    card.version = "1.0.0"
    iface = card.supported_interfaces.add()
    iface.url = base_url
    iface.protocol_binding = "JSONRPC"
    card.capabilities.streaming = False
    card.capabilities.push_notifications = False
    card.default_input_modes.append("text")
    card.default_output_modes.append("text")
    for sk in skills:
        s = card.skills.add()
        s.id = sk["id"]
        s.name = sk.get("name", sk["id"])
        s.description = sk.get("description", "")
        for tag in sk.get("tags", []):
            s.tags.append(tag)
    return card
