"""Multi-hop topology execution, cycle detection, and chain integrity verification for XProto-12."""

from __future__ import annotations

import time
from dataclasses import asdict, dataclass, field
from typing import Any

from xproto.attestation import (
    AttestationRegistry,
    AttestedCardEnvelope,
    generate_keypair,
    public_key_to_hex,
    sign_envelope,
)
from xproto.common import (
    HIGH,
    LEVEL_NAME,
    LOW,
    MEDIUM,
    NONE,
    chain_authority,
    principal_authority,
)
from xproto.provenance_token import ProvenanceTokenChain


@dataclass
class TopologyNode:
    """Agent or relay node participating in a multi-hop delegation topology."""

    node_id: str
    endpoint: str
    is_trusted: bool = True
    owner_identity: str = ""
    public_key_id: str = ""
    card: AttestedCardEnvelope | None = None

    def __post_init__(self):
        if not self.owner_identity:
            self.owner_identity = f"owner@{self.node_id}" if self.is_trusted else f"remote:{self.node_id}"
        if not self.public_key_id:
            self.public_key_id = f"key-{self.node_id}"


@dataclass
class HopRecord:
    """Telemetry recorded at each hop along the topology execution."""

    hop_index: int
    node_id: str
    endpoint: str
    input_chain: list[str]
    retained_chain: list[str]
    identity_retention_preserved: bool
    weakest_authority: str
    token_verified: bool
    authorized: bool
    status: str  # "FORWARDED", "TOOL_EXECUTED", "CYCLE_BLOCKED", "DEPTH_EXCEEDED", "OUTAGE", "DENIED"
    denial_reason: str | None = None
    latency_ms: float = 0.0

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class TopologyResult:
    """Comprehensive result of executing a multi-hop delegation topology."""

    topology_type: str  # "linear", "cycle", "repeated_principal", "mixed_trust", "outage"
    configured_chain_length: int
    hops_completed: int
    success: bool
    hop_records: list[HopRecord] = field(default_factory=list)
    final_authority: str = LEVEL_NAME[NONE]
    cycle_detected: bool = False
    depth_exceeded: bool = False
    outage_occurred: bool = False
    error: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "topology_type": self.topology_type,
            "configured_chain_length": self.configured_chain_length,
            "hops_completed": self.hops_completed,
            "success": self.success,
            "final_authority": self.final_authority,
            "cycle_detected": self.cycle_detected,
            "depth_exceeded": self.depth_exceeded,
            "outage_occurred": self.outage_occurred,
            "error": self.error,
            "hop_records": [h.to_dict() for h in self.hop_records],
        }


class TopologyExecutor:
    """Executes delegation flows through configured multi-hop topologies."""

    def __init__(
        self,
        max_depth: int = 10,
        allow_cycles: bool = False,
        registry: AttestationRegistry | None = None,
    ):
        self.max_depth = max_depth
        self.allow_cycles = allow_cycles
        self.registry = registry or AttestationRegistry()
        self.nodes: dict[str, TopologyNode] = {}
        self._private_keys: dict[str, Any] = {}

    def register_node(
        self,
        node_id: str,
        is_trusted: bool = True,
        capabilities: list[str] | None = None,
    ) -> TopologyNode:
        """Create and register a topology node with Ed25519 card and keypair."""
        priv, pub = generate_keypair()
        kid = f"key-{node_id}"
        endpoint = f"http://127.0.0.1:182{len(self.nodes):02d}"

        self.registry.add_trust_root(kid, pub)
        self._private_keys[node_id] = priv

        caps = capabilities or ["delegate", "summarize", "read_file"]
        card = AttestedCardEnvelope(
            agent_id=node_id,
            endpoint=endpoint,
            capabilities=caps,
            issuer="xproto-lab-ca",
            audience="*",
            valid_from=time.time() - 60,
            valid_until=time.time() + 3600,
            public_key_id=kid,
        )
        card = sign_envelope(card, priv)
        if is_trusted:
            self.registry.register_card(card, endpoint)

        node = TopologyNode(
            node_id=node_id,
            endpoint=endpoint,
            is_trusted=is_trusted,
            public_key_id=kid,
            card=card,
        )
        self.nodes[node_id] = node
        return node

    def execute_chain(
        self,
        chain_node_ids: list[str],
        task_text: str,
        initial_chain: list[str],
        honest_mode: bool = True,
        fail_at_hop: int | None = None,
        topology_type: str = "linear",
    ) -> TopologyResult:
        """Simulate and verify delegation through a sequence of nodes."""
        result = TopologyResult(
            topology_type=topology_type,
            configured_chain_length=len(chain_node_ids),
            hops_completed=0,
            success=False,
        )

        visited_nodes: list[str] = []
        current_chain = list(initial_chain)
        token_chain = ProvenanceTokenChain()

        for hop_idx, node_id in enumerate(chain_node_ids):
            t0 = time.perf_counter()

            # 1. Depth check
            if hop_idx >= self.max_depth:
                result.depth_exceeded = True
                result.error = f"Max delegation depth exceeded ({self.max_depth})"
                result.hop_records.append(
                    HopRecord(
                        hop_index=hop_idx,
                        node_id=node_id,
                        endpoint="",
                        input_chain=list(current_chain),
                        retained_chain=list(current_chain),
                        identity_retention_preserved=True,
                        weakest_authority=LEVEL_NAME[chain_authority(current_chain)],
                        token_verified=False,
                        authorized=False,
                        status="DEPTH_EXCEEDED",
                        denial_reason=result.error,
                    )
                )
                break

            # 2. Cycle detection check
            if not self.allow_cycles and node_id in visited_nodes:
                result.cycle_detected = True
                result.error = f"Delegation cycle detected: node '{node_id}' already visited in chain"
                result.hop_records.append(
                    HopRecord(
                        hop_index=hop_idx,
                        node_id=node_id,
                        endpoint="",
                        input_chain=list(current_chain),
                        retained_chain=list(current_chain),
                        identity_retention_preserved=True,
                        weakest_authority=LEVEL_NAME[chain_authority(current_chain)],
                        token_verified=False,
                        authorized=False,
                        status="CYCLE_BLOCKED",
                        denial_reason=result.error,
                    )
                )
                break

            # 3. Partial outage simulation
            if fail_at_hop is not None and hop_idx == fail_at_hop:
                result.outage_occurred = True
                result.error = f"Node '{node_id}' unavailable (simulated partial outage)"
                result.hop_records.append(
                    HopRecord(
                        hop_index=hop_idx,
                        node_id=node_id,
                        endpoint="",
                        input_chain=list(current_chain),
                        retained_chain=list(current_chain),
                        identity_retention_preserved=True,
                        weakest_authority=LEVEL_NAME[chain_authority(current_chain)],
                        token_verified=False,
                        authorized=False,
                        status="OUTAGE",
                        denial_reason=result.error,
                    )
                )
                break

            node = self.nodes.get(node_id)
            if not node:
                # Dynamically create if not pre-registered
                node = self.register_node(node_id, is_trusted=True)

            visited_nodes.append(node_id)

            # 4. Identity retention & chain computation
            # Honest mode: accumulates and preserves all prior principals.
            # Vulnerable mode: drops prior principals, only keeping the node's own owner.
            if honest_mode:
                if node.owner_identity not in current_chain:
                    next_chain = current_chain + [node.owner_identity]
                else:
                    next_chain = list(current_chain)
                retention_preserved = all(p in next_chain for p in current_chain)
            else:
                next_chain = [node.owner_identity]
                retention_preserved = False

            auth_val = chain_authority(next_chain)
            auth_name = LEVEL_NAME[auth_val]

            # 5. Token creation & verification
            priv = self._private_keys.get(node_id)
            token_verified = False
            if priv:
                target_aud = chain_node_ids[hop_idx + 1] if hop_idx + 1 < len(chain_node_ids) else "sink"
                token_chain.append_hop(
                    issuer=node_id,
                    audience=target_aud,
                    task_text=task_text,
                    content="{\"payload\": \"delegated\"}",
                    capability="delegate",
                    private_key=priv,
                    public_key_id=node.public_key_id,
                )
                try:
                    is_valid, _ = token_chain.verify(self.registry)
                    token_verified = is_valid
                except Exception:
                    token_verified = False

            # 6. Authorization decision
            # Defended: allows if node is trusted and chain authority >= required
            is_authorized = node.is_trusted and (auth_val >= LOW)
            status = "FORWARDED" if hop_idx + 1 < len(chain_node_ids) else "TOOL_EXECUTED"
            denial_reason = None
            if not is_authorized:
                status = "DENIED"
                denial_reason = "Untrusted node or insufficient chain authority"

            latency_ms = (time.perf_counter() - t0) * 1000.0

            result.hop_records.append(
                HopRecord(
                    hop_index=hop_idx,
                    node_id=node_id,
                    endpoint=node.endpoint,
                    input_chain=list(current_chain),
                    retained_chain=list(next_chain),
                    identity_retention_preserved=retention_preserved,
                    weakest_authority=auth_name,
                    token_verified=token_verified,
                    authorized=is_authorized,
                    status=status,
                    denial_reason=denial_reason,
                    latency_ms=round(latency_ms, 3),
                )
            )

            if not is_authorized:
                result.error = denial_reason
                break

            current_chain = next_chain
            result.hops_completed += 1

        result.final_authority = LEVEL_NAME[chain_authority(current_chain)]
        result.success = (
            result.hops_completed == len(chain_node_ids)
            and not result.cycle_detected
            and not result.depth_exceeded
            and not result.outage_occurred
        )
        return result


def generate_linear_chain(length: int) -> list[str]:
    """Generate linear delegation chain IDs for given length (1, 2, 3, 5, 8)."""
    return [f"agent-hop-{i}" for i in range(length)]
