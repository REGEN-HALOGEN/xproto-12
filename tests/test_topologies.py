"""Unit tests for Phase 7 multi-hop topologies, cycle detection, depth limits, and mixed trust."""

import pytest

from xproto.attestation import AttestationRegistry
from xproto.common import HIGH, LOW, NONE
from xproto.topology import (
    TopologyExecutor,
    generate_linear_chain,
)


@pytest.fixture
def topology_env():
    registry = AttestationRegistry()
    executor = TopologyExecutor(max_depth=10, allow_cycles=False, registry=registry)
    return executor


@pytest.mark.parametrize("length", [1, 2, 3, 5, 8])
def test_linear_chain_lengths_execute(topology_env, length):
    """Requirement 1: Generate chains of lengths 1, 2, 3, 5, and 8."""
    chain_nodes = generate_linear_chain(length)
    # Pre-register nodes
    for nid in chain_nodes:
        topology_env.register_node(nid, is_trusted=True)

    result = topology_env.execute_chain(
        chain_node_ids=chain_nodes,
        task_text=f"Process data over {length} hops",
        initial_chain=["owner@initiator"],
        honest_mode=True,
        topology_type="linear",
    )

    assert result.success is True
    assert result.hops_completed == length
    assert len(result.hop_records) == length
    # Check identity retention: each hop accumulated prior principals
    last_record = result.hop_records[-1]
    assert last_record.identity_retention_preserved is True
    assert "owner@initiator" in last_record.retained_chain


def test_max_delegation_depth_configurable(topology_env):
    """Test that max depth stops recursion at configured limit."""
    topology_env.max_depth = 4
    chain_nodes = generate_linear_chain(8)
    for nid in chain_nodes:
        topology_env.register_node(nid, is_trusted=True)

    result = topology_env.execute_chain(
        chain_node_ids=chain_nodes,
        task_text="Run deep delegation",
        initial_chain=["owner@root"],
        honest_mode=True,
    )

    assert result.success is False
    assert result.depth_exceeded is True
    assert result.hops_completed == 4
    assert result.hop_records[-1].status == "DEPTH_EXCEEDED"


def test_cycle_detection_blocks_infinite_loop(topology_env):
    """Requirement 2: Test cycles blocked cleanly."""
    cycle_chain = ["agent-A", "agent-B", "agent-C", "agent-A"]
    for nid in set(cycle_chain):
        topology_env.register_node(nid, is_trusted=True)

    result = topology_env.execute_chain(
        chain_node_ids=cycle_chain,
        task_text="Cycle test task",
        initial_chain=["owner@root"],
        honest_mode=True,
        topology_type="cycle",
    )

    assert result.success is False
    assert result.cycle_detected is True
    assert result.hops_completed == 3  # A, B, C succeeded, 4th hop (A again) blocked
    assert result.hop_records[-1].status == "CYCLE_BLOCKED"


def test_repeated_principals_with_allow_cycles():
    """Requirement 2: Repeated principals (e.g. A -> B -> C -> B -> D)."""
    registry = AttestationRegistry()
    executor = TopologyExecutor(max_depth=10, allow_cycles=True, registry=registry)
    repeated_chain = ["agent-A", "agent-B", "agent-C", "agent-B", "agent-D"]
    for nid in set(repeated_chain):
        executor.register_node(nid, is_trusted=True)

    result = executor.execute_chain(
        chain_node_ids=repeated_chain,
        task_text="Repeated principal task",
        initial_chain=["owner@root"],
        honest_mode=True,
        topology_type="repeated_principal",
    )

    assert result.success is True
    assert result.hops_completed == 5
    assert not result.cycle_detected


def test_mixed_trust_weakest_link_authority(topology_env):
    """Requirement 2: Mixed trusted and untrusted hops enforce weakest-link."""
    # agent-trusted-1 -> agent-untrusted -> agent-trusted-2
    topology_env.register_node("agent-trusted-1", is_trusted=True)
    topology_env.register_node("agent-untrusted", is_trusted=False)
    topology_env.register_node("agent-trusted-2", is_trusted=True)

    chain_nodes = ["agent-trusted-1", "agent-untrusted", "agent-trusted-2"]

    # When honest_mode is True, untrusted node's identity is retained
    result = topology_env.execute_chain(
        chain_node_ids=chain_nodes,
        task_text="Audit financial records",
        initial_chain=["owner@root"],
        honest_mode=True,
        topology_type="mixed_trust",
    )

    # Hop 1 succeeds, Hop 2 (untrusted node) is detected and denied
    assert result.success is False
    assert result.hops_completed == 1
    denied_hop = result.hop_records[1]
    assert denied_hop.authorized is False
    assert denied_hop.status == "DENIED"


def test_partial_outage_simulation(topology_env):
    """Requirement 2: Partial outage handling."""
    chain_nodes = generate_linear_chain(5)
    for nid in chain_nodes:
        topology_env.register_node(nid, is_trusted=True)

    result = topology_env.execute_chain(
        chain_node_ids=chain_nodes,
        task_text="Reliability test",
        initial_chain=["owner@root"],
        fail_at_hop=2,  # 3rd node experiences simulated outage
        topology_type="outage",
    )

    assert result.success is False
    assert result.outage_occurred is True
    assert result.hops_completed == 2
    assert result.hop_records[2].status == "OUTAGE"
