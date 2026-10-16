"""XGate: authorization proxy between the victim agent and the MCP tool server.

Every tool call must carry a delegation token: the ordered chain of principals
the current instruction passed through, e.g. ["owner@victim", "remote:attacker"].
XGate authorizes a call iff *every* principal in the chain has authority >= the
tool's sensitivity (weakest-link semantics). Tool-output-derived instructions
carry the "tool-output" principal (authority NONE) and can therefore never
authorize privileged calls.

XGate also authorizes cross-protocol delegation (victim -> another A2A agent):
  - denied if the instruction provenance is "tool-output" (laundering), or
  - denied if the target agent's card is unattested (not in the trust registry).

In permissive mode (defense off) everything is allowed and only logged, so the
same code path produces the vulnerable baseline.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field

from xproto.common import (
    HIGH,
    LEVEL_NAME,
    LOW,
    MEDIUM,
    chain_authority,
    is_high_sensitivity_path,
    log_event,
    new_id,
    principal_authority,
)


class XGateDenied(Exception):
    """Raised when XGate refuses a tool call or delegation."""


def tool_sensitivity(tool: str, args: dict) -> int:
    if tool == "read_file":
        return HIGH if is_high_sensitivity_path(args.get("path", "")) else LOW
    if tool == "send_email":
        return MEDIUM
    if tool in ("list_directory", "search_web"):
        return LOW
    return HIGH  # unknown tools default to most restrictive


@dataclass
class XGate:
    session: object  # mcp ClientSession (stdio)
    enforcing: bool = True
    attested_agents: set[str] = field(default_factory=set)
    agent_id: str = "xgate"

    async def call_tool(self, name: str, args: dict, chain: list[str],
                        agent: str | None = None) -> str:
        sens = tool_sensitivity(name, args)
        auth = chain_authority(chain)
        allowed = (not self.enforcing) or (auth >= sens)
        reason = (
            "permissive mode"
            if not self.enforcing
            else ("authorized" if allowed else
                  f"chain authority {LEVEL_NAME[auth]} < required {LEVEL_NAME[sens]}")
        )
        t0 = time.perf_counter()
        result_text = ""
        error = None
        if allowed:
            try:
                res = await self.session.call_tool(name, args)
                # mcp 2.x CallToolResult: .content list of TextContent
                parts = []
                for c in getattr(res, "content", []) or []:
                    parts.append(getattr(c, "text", str(c)))
                result_text = "\n".join(parts)
            except Exception as exc:  # noqa: BLE001
                error = f"{type(exc).__name__}: {exc}"
                result_text = f"ERROR: {error}"
        else:
            error = f"XGateDenied: {reason}"
            result_text = f"DENIED by XGate: {reason}"
        latency_ms = (time.perf_counter() - t0) * 1000
        log_event("tool_calls.jsonl", {
            "call_id": new_id("call"),
            "side": "gateway",
            "agent": agent or self.agent_id,
            "tool": name,
            "args": args,
            "sensitivity": LEVEL_NAME[sens],
            "principal_chain": chain,
            "chain_authority": LEVEL_NAME[auth],
            "allowed": allowed,
            "decision": reason,
            "latency_ms": round(latency_ms, 2),
            "error": error,
            "result_preview": result_text[:200],
        })
        if not allowed:
            raise XGateDenied(reason)
        return result_text

    def authorize_delegation(self, chain: list[str], target_url: str,
                             claimed_capability: str = "",
                             agent: str | None = None) -> None:
        """Decide whether the victim may delegate to target_url. Raises XGateDenied."""
        decision = "authorized"
        allowed = True
        if self.enforcing:
            if "tool-output" in chain:
                allowed, decision = False, "delegation instruction came from untrusted tool output (laundering)"
            elif target_url not in self.attested_agents:
                allowed, decision = False, f"target agent card unattested: {target_url}"
        log_event("delegations.jsonl", {
            "agent": agent or self.agent_id,
            "target_url": target_url,
            "claimed_capability": claimed_capability,
            "principal_chain": chain,
            "allowed": allowed,
            "decision": decision,
        })
        if not allowed:
            raise XGateDenied(decision)
