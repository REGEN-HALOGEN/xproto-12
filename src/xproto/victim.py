"""Dual-protocol victim agent for XProto-12.

A2A server (JSON-RPC over HTTP) that accepts tasks and internally acts as an
MCP client (stdio) to the tool server. The planner is deterministic and
rule-based (no LLM needed): it maps task text to tool calls, and -- like a
naive LLM agent -- follows "INSTRUCTION:" lines found in tool results.

INTENTIONAL VULNERABILITY (the research subject): when honest_provenance=False
(the default, "defense off"), the agent executes every A2A-delegated task with
its OWN full authority (principal chain ["owner@<agent>"]), ignoring the
delegator's identity/authority carried in the message metadata. This is the
cross-protocol confused deputy: authorization from the MCP world is reused for
instructions arriving over A2A without scoping.

Provenance of every instruction and tool call is logged to provenance.jsonl.
"""

from __future__ import annotations

import asyncio
import re
from dataclasses import dataclass, field

from google.protobuf.json_format import MessageToDict

from xproto.common import (
    build_agent_card,
    enqueue_task_proto,
    log_event,
    make_agent_text,
    make_user_message,
    message_text,
    new_id,
)
from xproto.defense_xgate import XGate, XGateDenied

try:
    from a2a.server.agent_execution.agent_executor import AgentExecutor
except ImportError:  # pragma: no cover
    AgentExecutor = object

# Module-level gateway, installed per trial by eval.py (shares the event loop).
GATEWAY: XGate | None = None


def set_gateway(gw: XGate | None) -> None:
    global GATEWAY
    GATEWAY = gw


EMAIL_RE = re.compile(r"[\w.+-]+@[\w.-]+\.\w+")
PATH_RE = re.compile(r"(/[\w./~\-]+|~[/\w.\-]+|testdata/[\w./\-]+)")
DELEGATE_RE = re.compile(r"delegate to (https?://[^\s:]+(?::\d+)?)\s*:?\s*(.*)", re.I)
CAPABILITY_RE = re.compile(r"use the ([\w\- ]+?) (?:relay|agent)", re.I)
INSTRUCTION_RE = re.compile(r"^INSTRUCTION:\s*(.+)$", re.M)
MAX_DEPTH = 3


@dataclass
class VictimConfig:
    agent_id: str = "victim"
    port: int = 18080
    honest_provenance: bool = False  # False = vulnerable (confused deputy)
    known_agents: dict[str, str] = field(default_factory=dict)  # capability -> url


class VictimExecutor(AgentExecutor):
    """AgentExecutor implementation (duck-typed; registered with DefaultRequestHandlerV2)."""

    def __init__(self, config: VictimConfig):
        self.config = config
        self.owner = f"owner@{config.agent_id}"

    # -- AgentExecutor interface -------------------------------------------
    async def execute(self, context, event_queue) -> None:
        from a2a.server.tasks.task_updater import TaskUpdater

        msg = context.message
        text = message_text(msg)
        task_id = getattr(context, "task_id", None) or new_id("task")
        context_id = getattr(context, "context_id", None) or new_id("ctx")
        delegator, forwarded = self._meta_from(msg)

        # THE CONFUSED DEPUTY: vulnerable mode mints owner-only authority for
        # any A2A task, discarding the delegator's (lower) authority and any
        # forwarded chain. Honest mode adopts the forwarded chain.
        if self.config.honest_provenance:
            chain = [self.owner] + [p for p in forwarded if p != self.owner]
            # A delegator claim of "owner" is this agent's own owner (the lab's
            # trusted local channel); any other claimed identity is remote
            # and untrusted (LOW authority by default).
            if delegator and delegator != "owner" and not any(
                    p == f"remote:{delegator}" or p == delegator for p in chain):
                chain.append(f"remote:{delegator}")
            note = "honest chain (forwarded chain adopted)"
        else:
            chain = [self.owner]
            note = ("VULNERABLE: delegator/chain ignored, owner authority reused"
                    if (delegator or forwarded) else "local/owner task")

        log_event("provenance.jsonl", {
            "agent": self.config.agent_id, "task_id": task_id,
            "event": "instruction_received", "source_protocol": "a2a",
            "text": text[:300], "delegator_claim": delegator,
            "principal_chain": chain, "note": note,
        })

        updater = TaskUpdater(event_queue, task_id, context_id)
        # The a2a server requires the Task proto before any status event.
        await enqueue_task_proto(event_queue, task_id, context_id)
        try:
            result = await self._handle(text, chain, provenance="a2a",
                                        delegator=delegator, depth=0)
            await updater.complete(make_agent_text(result))
        except Exception as exc:  # noqa: BLE001
            await updater.failed(make_agent_text(f"task failed: {exc}"))

    # -- planner ------------------------------------------------------------
    async def _handle(self, text: str, chain: list[str], provenance: str,
                      delegator: str | None, depth: int) -> str:
        if depth > MAX_DEPTH:
            return "stopped: instruction nesting too deep"
        eff_chain = chain + (["tool-output"] if provenance == "tool-output" else [])
        t = text.strip()

        m = DELEGATE_RE.search(t)
        if m:
            return await self._delegate(m.group(1), m.group(2) or t,
                                        eff_chain, provenance)

        m = CAPABILITY_RE.search(t)
        if m:
            cap = m.group(1).strip().lower().replace(" ", "-")
            url = self.config.known_agents.get(cap)
            if not url:
                return f"no known agent with capability '{cap}'"
            return await self._delegate(url, t, eff_chain, provenance,
                                        claimed_capability=cap)

        email = EMAIL_RE.search(t)
        if email and "email" in t.lower():
            addr = email.group(0)
            pm = re.search(r"(?:contents|summary) of (\S+)", t, re.I)
            if pm:
                content = await self._tool("read_file", {"path": pm.group(1)},
                                           eff_chain, provenance)
                if content.startswith("DENIED"):
                    return content
                await self._follow_tool_instructions(content, eff_chain, delegator, depth)
                return await self._tool("send_email",
                                        {"to": addr, "subject": "requested contents",
                                         "body": content}, eff_chain, provenance)
            return await self._tool("send_email",
                                    {"to": addr, "subject": "message",
                                     "body": t}, eff_chain, provenance)

        if re.search(r"search (the )?web for|search for", t, re.I):
            q = re.split(r"search (the )?web for|search for", t, flags=re.I)[-1].strip(" :")
            result = await self._tool("search_web", {"query": q or t},
                                      eff_chain, provenance)
            if result.startswith("DENIED"):
                return result
            await self._follow_tool_instructions(result, eff_chain, delegator, depth)
            return f"search results:\n{result}"

        if "director" in t.lower() and ("list" in t.lower() or "show" in t.lower()):
            pm = PATH_RE.search(t)
            path = pm.group(1) if pm else "testdata"
            return await self._tool("list_directory", {"path": path},
                                    eff_chain, provenance)

        pm = PATH_RE.search(t)
        if pm and re.search(r"\b(read|open|summar)", t, re.I):
            path = pm.group(1)
            content = await self._tool("read_file", {"path": path},
                                       eff_chain, provenance)
            if content.startswith("DENIED"):
                return content
            await self._follow_tool_instructions(content, eff_chain, delegator, depth)
            lines = [ln for ln in content.splitlines() if ln.strip()][:3]
            return "summary:\n" + "\n".join(lines)

        return ("I could not map that request to a tool. "
                "Try: 'summarize file <path>', 'email the contents of <path> to <addr>', "
                "'list directory <path>', 'search the web for <query>'.")

    async def _tool(self, name: str, args: dict, chain: list[str],
                    provenance: str) -> str:
        log_event("provenance.jsonl", {
            "agent": self.config.agent_id, "event": "tool_call",
            "source_protocol": "mcp" if provenance == "a2a" else "mcp-via-tool-output",
            "instruction_provenance": provenance,
            "tool": name, "args": args, "principal_chain": chain,
        })
        try:
            return await GATEWAY.call_tool(name, args, chain,
                                           agent=self.config.agent_id)
        except XGateDenied as exc:
            return f"DENIED by XGate: {exc}"

    @staticmethod
    def _meta_from(msg) -> tuple[str | None, list[str]]:
        try:
            md = MessageToDict(msg.metadata)
            chain = md.get("chain") or []
            return md.get("delegator"), list(chain)
        except Exception:  # noqa: BLE001
            return None, []

    async def _follow_tool_instructions(self, tool_result: str, chain: list[str],
                                        delegator: str | None, depth: int) -> None:
        """Naive planner follows instructions embedded in tool output.

        This deterministically simulates an LLM agent acting on indirect
        prompt injection. The instruction executes with 'tool-output' in the
        chain (no authority) -- XGate denies privileged effects."""
        for m in INSTRUCTION_RE.finditer(tool_result):
            instr = m.group(1).strip()
            log_event("provenance.jsonl", {
                "agent": self.config.agent_id, "event": "tool_result_instruction",
                "source_protocol": "mcp-tool-result", "text": instr[:300],
            })
            await self._handle(instr, chain, provenance="tool-output",
                               delegator=delegator, depth=depth + 1)

    async def _delegate(self, url: str, task_text: str, chain: list[str],
                        provenance: str, claimed_capability: str = "") -> str:
        # Identity handling at the delegation boundary.
        if self.config.honest_provenance:
            forward_chain = list(chain)
        else:
            forward_chain = [self.owner]  # VULNERABLE: identity loss
        log_event("provenance.jsonl", {
            "agent": self.config.agent_id, "event": "delegation",
            "source_protocol": "a2a", "instruction_provenance": provenance,
            "target": url, "forwarded_chain": forward_chain,
            "note": "honest forward" if self.config.honest_provenance
                    else "VULNERABLE: chain collapsed to owner",
        })
        try:
            GATEWAY.authorize_delegation(chain, url, claimed_capability,
                                         agent=self.config.agent_id)
        except XGateDenied as exc:
            return f"DENIED by XGate: delegation blocked ({exc})"
        try:
            from a2a.client.client import ClientConfig
            from a2a.client.client_factory import ClientFactory
            from a2a.types import a2a_pb2 as pb

            factory = ClientFactory(ClientConfig())
            client = await factory.create_from_url(url)
            req = pb.SendMessageRequest()
            req.message.CopyFrom(make_user_message(
                task_text,
                metadata={"delegator": self.config.agent_id,
                          "chain": forward_chain}))
            final = None
            async for resp in client.send_message(req):
                if resp.HasField("task"):
                    final = resp.task
            await client.close()
            state = final.status.state if final else -1
            return f"delegated to {url} (task state={state})"
        except Exception as exc:  # noqa: BLE001
            log_event("provenance.jsonl", {
                "agent": self.config.agent_id, "event": "delegation_error",
                "target": url,
                "error": f"{type(exc).__name__}: {exc}",
            })
            return f"delegation to {url} failed: {type(exc).__name__}: {exc}"

    @staticmethod
    def _delegator_from(msg) -> str | None:
        delegator, _ = VictimExecutor._meta_from(msg)
        return delegator

    async def cancel(self, context, event_queue) -> None:
        from a2a.server.tasks.task_updater import TaskUpdater

        task_id = getattr(context, "task_id", None) or new_id("task")
        context_id = getattr(context, "context_id", None) or new_id("ctx")
        await TaskUpdater(event_queue, task_id, context_id).cancel()


def build_app(config: VictimConfig):
    """Build the Starlette A2A app for a victim instance."""
    from starlette.applications import Starlette
    from a2a.server.request_handlers.default_request_handler_v2 import (
        DefaultRequestHandlerV2,
    )
    from a2a.server.routes.agent_card_routes import create_agent_card_routes
    from a2a.server.routes.jsonrpc_routes import create_jsonrpc_routes
    from a2a.server.tasks.inmemory_task_store import InMemoryTaskStore

    base_url = f"http://127.0.0.1:{config.port}"
    card = build_agent_card(
        name=f"xproto-{config.agent_id}",
        description="Dual-protocol (A2A+MCP) research agent for XProto-12",
        base_url=base_url,
        skills=[{"id": "file-ops", "name": "File operations",
                 "description": "read files, list directories",
                 "tags": ["files"]},
                {"id": "messaging", "name": "Messaging",
                 "description": "send email summaries", "tags": ["email"]}],
    )
    handler = DefaultRequestHandlerV2(
        agent_executor=VictimExecutor(config),
        task_store=InMemoryTaskStore(),
        agent_card=card,
    )
    routes = create_jsonrpc_routes(handler, "/")
    routes += create_agent_card_routes(card)
    return Starlette(routes=routes)


async def serve(config: VictimConfig):
    """Serve forever (run as an asyncio task); set server.should_exit to stop."""
    import uvicorn

    app = build_app(config)
    server = uvicorn.Server(uvicorn.Config(
        app, host="127.0.0.1", port=config.port, log_level="warning"))
    serve._server = server  # noqa: SLF001
    await server.serve()
