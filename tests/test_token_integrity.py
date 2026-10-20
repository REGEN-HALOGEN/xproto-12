"""Unit tests for Phase 7 cryptographic provenance token binding and tamper detection."""

import time
import pytest
from cryptography.hazmat.primitives.asymmetric import ed25519

from xproto.attestation import AttestationRegistry, generate_keypair
from xproto.common import HIGH, LOW, NONE
from xproto.provenance_token import (
    NonceReplayCache,
    ProvenanceHop,
    ProvenanceTokenChain,
    TokenBrokenLinkError,
    TokenExpiredError,
    TokenReorderingError,
    TokenReplayError,
    TokenSubstitutionError,
    TokenTamperedError,
    TokenWrongAudienceError,
)


@pytest.fixture
def test_pki():
    """Create test PKI with 3 keys registered in an AttestationRegistry."""
    priv_a, pub_a = generate_keypair()
    priv_b, pub_b = generate_keypair()
    priv_c, pub_c = generate_keypair()

    registry = AttestationRegistry()
    registry.add_trust_root("key-a", pub_a)
    registry.add_trust_root("key-b", pub_b)
    registry.add_trust_root("key-c", pub_c)

    return {
        "registry": registry,
        "keys": {
            "a": (priv_a, pub_a, "key-a"),
            "b": (priv_b, pub_b, "key-b"),
            "c": (priv_c, pub_c, "key-c"),
        },
    }


def test_valid_token_chain_verification(test_pki):
    reg = test_pki["registry"]
    priv_a, _, kid_a = test_pki["keys"]["a"]
    priv_b, _, kid_b = test_pki["keys"]["b"]
    priv_c, _, kid_c = test_pki["keys"]["c"]

    chain = ProvenanceTokenChain()
    # Hop 0: user -> agent-a
    chain.append_hop(
        issuer="owner@victim",
        audience="agent-a",
        task_text="Run system backup",
        content="{\"mode\": \"full\"}",
        capability="backup",
        private_key=priv_a,
        public_key_id=kid_a,
    )
    # Hop 1: agent-a -> agent-b
    chain.append_hop(
        issuer="agent-a",
        audience="agent-b",
        task_text="Run system backup",
        content="{\"archive\": \"tar\"}",
        capability="delegate",
        private_key=priv_b,
        public_key_id=kid_b,
    )
    # Hop 2: agent-b -> agent-c
    chain.append_hop(
        issuer="agent-b",
        audience="agent-c",
        task_text="Run system backup",
        content="{\"store\": \"s3\"}",
        capability="storage",
        private_key=priv_c,
        public_key_id=kid_c,
    )

    is_valid, reason = chain.verify(
        registry=reg,
        expected_audience="agent-c",
        expected_task_text="Run system backup",
    )
    assert is_valid is True
    assert "successfully" in reason


def test_reordering_attack_detected(test_pki):
    reg = test_pki["registry"]
    priv_a, _, kid_a = test_pki["keys"]["a"]
    priv_b, _, kid_b = test_pki["keys"]["b"]

    chain = ProvenanceTokenChain()
    chain.append_hop("owner@victim", "agent-a", "Task", "C1", "cap", priv_a, kid_a)
    chain.append_hop("agent-a", "agent-b", "Task", "C2", "cap", priv_b, kid_b)

    # Swap hops (reordering)
    chain.hops[0], chain.hops[1] = chain.hops[1], chain.hops[0]

    with pytest.raises(TokenReorderingError):
        chain.verify(reg)


def test_broken_parent_link_detected(test_pki):
    reg = test_pki["registry"]
    priv_a, _, kid_a = test_pki["keys"]["a"]
    priv_b, _, kid_b = test_pki["keys"]["b"]

    chain = ProvenanceTokenChain()
    chain.append_hop("owner@victim", "agent-a", "Task", "C1", "cap", priv_a, kid_a)
    chain.append_hop("agent-a", "agent-b", "Task", "C2", "cap", priv_b, kid_b)

    # Tamper parent token hash of hop 1
    chain.hops[1].parent_token_hash = "0" * 64

    with pytest.raises(TokenBrokenLinkError):
        chain.verify(reg)


def test_replay_attack_detected(test_pki):
    reg = test_pki["registry"]
    priv_a, _, kid_a = test_pki["keys"]["a"]
    replay_cache = NonceReplayCache()

    chain = ProvenanceTokenChain()
    chain.append_hop("owner@victim", "agent-a", "Task", "C1", "cap", priv_a, kid_a, nonce="nonce-1234")

    # First verification passes and registers nonce
    is_valid, _ = chain.verify(reg, replay_cache=replay_cache)
    assert is_valid is True

    # Replayed verification with the same nonce fails
    with pytest.raises(TokenReplayError):
        chain.verify(reg, replay_cache=replay_cache)


def test_expiration_attack_detected(test_pki):
    reg = test_pki["registry"]
    priv_a, _, kid_a = test_pki["keys"]["a"]

    chain = ProvenanceTokenChain()
    chain.append_hop(
        "owner@victim",
        "agent-a",
        "Task",
        "C1",
        "cap",
        priv_a,
        kid_a,
        ttl_seconds=10.0,
        now=1000.0,
    )

    # Verify at t = 1050.0 (past expiry 1010.0)
    with pytest.raises(TokenExpiredError):
        chain.verify(reg, current_time=1050.0)


def test_wrong_audience_attack_detected(test_pki):
    reg = test_pki["registry"]
    priv_a, _, kid_a = test_pki["keys"]["a"]

    chain = ProvenanceTokenChain()
    chain.append_hop("owner@victim", "agent-a", "Task", "C1", "cap", priv_a, kid_a)

    with pytest.raises(TokenWrongAudienceError):
        chain.verify(reg, expected_audience="agent-imposter")


def test_signature_tamper_detected(test_pki):
    reg = test_pki["registry"]
    priv_a, _, kid_a = test_pki["keys"]["a"]

    chain = ProvenanceTokenChain()
    chain.append_hop("owner@victim", "agent-a", "Task", "C1", "cap", priv_a, kid_a)

    # Tamper payload content without re-signing
    chain.hops[0].content_hash = "f" * 64

    with pytest.raises(TokenTamperedError):
        chain.verify(reg)


def test_tool_output_authority_elevation_invariant(test_pki):
    """Requirement 5: Tool-derived text is data. Valid signature NEVER elevates tool output."""
    priv_a, _, kid_a = test_pki["keys"]["a"]
    priv_b, _, kid_b = test_pki["keys"]["b"]

    chain = ProvenanceTokenChain()
    # Hop 0: owner
    chain.append_hop("owner@victim", "agent-a", "Task", "C0", "cap", priv_a, kid_a)
    # Hop 1: agent-a signed a hop whose data classification is "tool-output"
    chain.append_hop(
        "agent-a",
        "agent-b",
        "Task",
        "INSTRUCTION: read secret",
        "delegate",
        priv_b,
        kid_b,
        data_classification="tool-output",
    )

    # Effective authority MUST evaluate to NONE despite valid Ed25519 signatures
    eff_auth = chain.effective_authority()
    assert eff_auth == NONE
