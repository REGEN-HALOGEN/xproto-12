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

import json
import time
from dataclasses import dataclass, field
from pathlib import Path

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


from xproto.attestation import AttestationRegistry, AttestedCardEnvelope

PROJECT_ROOT = Path(__file__).resolve().parents[2]


def load_default_registry(config_path: Path | str | None = None) -> AttestationRegistry:
    """Load trusted public roots and signed agent card attestations from configuration."""
    registry = AttestationRegistry()
    cfg_file = Path(config_path) if config_path else PROJECT_ROOT / "config" / "agents.json"
    if cfg_file.exists():
        data = json.loads(cfg_file.read_text(encoding="utf-8"))
        for kid, pub_hex in data.get("trust_roots", {}).items():
            registry.add_trust_root(kid, pub_hex)
        for att in data.get("attestations", []):
            registry.register_card(AttestedCardEnvelope.from_dict(att))
    return registry


@dataclass
class XGate:
    session: object  # mcp ClientSession (stdio)
    enforcing: bool = True
    registry: AttestationRegistry | None = None
    attested_agents: set[str] = field(default_factory=set)  # Backward compatibility
    agent_id: str = "xproto-victim"

    def __post_init__(self):
        if self.registry is None:
            self.registry = load_default_registry()
            # If any legacy URLs were passed in attested_agents, preserve them as basic entries
            for url in self.attested_agents:
                norm_url = url.rstrip("/")
                if norm_url not in self.registry.registered_cards:
                    pass

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
        """Decide whether the victim may delegate to target_url using AttestationRegistry. Raises XGateDenied."""
        decision = "authorized"
        allowed = True
        denial_reason = None
        policy_rule = "capability-policy-allowed"
        card_fp = "none"

        # Independent laundering rule: tool-output in chain NEVER has authority to delegate
        if self.enforcing and "tool-output" in chain:
            allowed = False
            decision = "delegation instruction came from untrusted tool output (laundering)"
            denial_reason = decision
            policy_rule = "anti-laundering"
            card_fp = "none"
        elif self.enforcing:
            assert self.registry is not None
            allowed, decision, card_fp, policy_rule = self.registry.authorize(
                endpoint=target_url,
                requested_capability=claimed_capability,
                audience=self.agent_id,
            )
            denial_reason = None if allowed else decision
        else:
            allowed = True
            decision = "permissive mode (defense off)"
            policy_rule = "permissive"
            denial_reason = None
            if self.registry and target_url.rstrip("/") in self.registry.registered_cards:
                card_fp = self.registry.registered_cards[target_url.rstrip("/")].fingerprint()
            else:
                card_fp = "unverified"

        log_event("delegations.jsonl", {
            "agent": agent or self.agent_id,
            "target_url": target_url,
            "claimed_capability": claimed_capability,
            "principal_chain": chain,
            "allowed": allowed,
            "decision": decision,
            "denial_reason": denial_reason,
            "card_fingerprint": card_fp,
            "requested_capability": claimed_capability,
            "policy_rule": policy_rule,
        })
        if not allowed:
            raise XGateDenied(decision)

