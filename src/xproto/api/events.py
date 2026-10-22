"""Event bus and streaming subsystem for XProto-12 runs.

Captures engine events live, assigns monotonically increasing sequence numbers,
buffers events for replay, and broadcasts to active WebSocket subscribers.
"""

from __future__ import annotations

import asyncio
import time
from collections import defaultdict
from typing import Any


class EventBus:
    """Publish-subscribe event bus with sequence ordering and history buffering."""

    def __init__(self):
        self._subscribers: dict[str, list[asyncio.Queue]] = defaultdict(list)
        self._buffers: dict[str, list[dict[str, Any]]] = defaultdict(list)
        self._seq_counters: dict[str, int] = defaultdict(int)
        self._active_run_id: str | None = None

    def set_active_run_id(self, run_id: str | None) -> None:
        self._active_run_id = run_id

    def get_active_run_id(self) -> str | None:
        return self._active_run_id

    def emit(self, run_id: str, event_type: str, data: dict[str, Any]) -> dict[str, Any]:
        """Record and broadcast an event with monotonic sequence number."""
        self._seq_counters[run_id] += 1
        seq = self._seq_counters[run_id]

        event_msg = {
            "seq": seq,
            "run_id": run_id,
            "event": event_type,
            "data": data,
            "ts": time.time(),
        }

        self._buffers[run_id].append(event_msg)

        # Notify any active subscriber queues
        queues = list(self._subscribers.get(run_id, []))
        for q in queues:
            try:
                q.put_nowait(event_msg)
            except Exception:
                pass

        return event_msg

    def subscribe(self, run_id: str) -> asyncio.Queue:
        """Subscribe to live events for a run."""
        q: asyncio.Queue = asyncio.Queue()
        self._subscribers[run_id].append(q)
        return q

    def unsubscribe(self, run_id: str, queue: asyncio.Queue) -> None:
        """Unsubscribe a queue from a run."""
        if run_id in self._subscribers and queue in self._subscribers[run_id]:
            self._subscribers[run_id].remove(queue)
            if not self._subscribers[run_id]:
                del self._subscribers[run_id]

    def get_events(self, run_id: str) -> list[dict[str, Any]]:
        """Return all buffered events for a run in sequence order."""
        return list(self._buffers.get(run_id, []))


# Global singleton event bus
GLOBAL_EVENT_BUS = EventBus()


def engine_log_hook(filename: str, record: dict[str, Any]) -> None:
    """Callback hook attached to common.log_event to capture engine activity."""
    run_id = GLOBAL_EVENT_BUS.get_active_run_id()
    if not run_id:
        return

    # 1. A2A messages
    if filename == "provenance.jsonl" and record.get("event") == "instruction_received":
        GLOBAL_EVENT_BUS.emit(run_id, "a2a_message", {
            "agent": record.get("agent", "victim"),
            "text": record.get("text", ""),
            "principal_chain": record.get("principal_chain", []),
            "delegator": record.get("delegator_claim"),
            "note": record.get("note", ""),
        })

    # 2. Tool calls and XGate decisions
    elif filename == "tool_calls.jsonl":
        allowed = bool(record.get("allowed", False))
        GLOBAL_EVENT_BUS.emit(run_id, "tool_call", {
            "agent": record.get("agent", "victim"),
            "tool": record.get("tool", ""),
            "args": record.get("args", {}),
            "principal_chain": record.get("principal_chain", []),
        })
        GLOBAL_EVENT_BUS.emit(run_id, "xgate_decision", {
            "allowed": allowed,
            "decision": "ALLOW" if allowed else "DENY",
            "reason": record.get("decision", ""),
            "chain_authority": record.get("chain_authority", "NONE"),
            "required_authority": record.get("sensitivity", "HIGH"),
            "tool": record.get("tool", ""),
            "principal_chain": record.get("principal_chain", []),
            "error": record.get("error"),
        })

    # 3. Delegations
    elif filename == "delegations.jsonl":
        GLOBAL_EVENT_BUS.emit(run_id, "delegation", {
            "agent": record.get("agent", "victim"),
            "target_url": record.get("target_url", ""),
            "capability": record.get("capability") or record.get("claimed_capability", ""),
            "principal_chain": record.get("principal_chain", []),
            "allowed": bool(record.get("allowed", True)),
            "reason": record.get("reason", "authorized"),
        })
