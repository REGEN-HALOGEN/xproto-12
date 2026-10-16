"""Comprehensive tests for Ed25519 agent card attestation, canonical envelopes, and selective XGate."""

from __future__ import annotations

import json
import time
from pathlib import Path

import pytest

from xproto.attestation import (
    AttestationRegistry,
    AttestedCardEnvelope,
    canonical_payload_bytes,
    card_fingerprint,
    generate_keypair,
    private_key_from_hex,
    private_key_to_hex,
    public_key_from_hex,
    public_key_to_hex,
    sign_envelope,
    verify_signature,
)
from xproto.common import set_log_dir
from xproto.defense_xgate import XGate, XGateDenied, load_default_registry

PROJECT_ROOT = Path(__file__).resolve().parents[1]
FIXTURES_DIR = PROJECT_ROOT / "testdata" / "attestations"


class DummySession:
    """Mock session for testing XGate delegation without full stdio transport."""
    async def call_tool(self, name: str, args: dict):
        return None


def test_canonical_bytes_deterministic():
    d1 = {"b": 2, "a": 1, "nested": {"z": 10, "y": 20}}
    d2 = {"a": 1, "nested": {"y": 20, "z": 10}, "b": 2}
    assert canonical_payload_bytes(d1) == canonical_payload_bytes(d2)

    # Signature field must be excluded
    d3 = dict(d1)
    d3["signature"] = "deadbeef"
    assert canonical_payload_bytes(d3) == canonical_payload_bytes(d1)

    fp = card_fingerprint(d1)
    assert len(fp) == 16
    assert all(c in "0123456789abcdef" for c in fp)


def test_keypair_generation_and_hex_roundtrip():
    priv, pub = generate_keypair()
    pub_hex = public_key_to_hex(pub)
    priv_hex = private_key_to_hex(priv)

    pub_recovered = public_key_from_hex(pub_hex)
    priv_recovered = private_key_from_hex(priv_hex)

    assert public_key_to_hex(pub_recovered) == pub_hex
    assert private_key_to_hex(priv_recovered) == priv_hex


def test_sign_and_verify_valid_envelope():
    priv, pub = generate_keypair()
    env = AttestedCardEnvelope(
        agent_id="test-agent",
        endpoint="http://127.0.0.1:18101",
        capabilities=["audit", "summarize"],
        issuer="lab-ca",
        audience="xproto-victim",
        valid_from=1000.0,
        valid_until=5000.0,
        public_key_id="key-1",
    )
    signed_env = sign_envelope(env, priv)
    assert signed_env.signature != ""
    assert verify_signature(signed_env, pub) is True


def test_tampered_envelope_fails_verification():
    priv, pub = generate_keypair()
    env = AttestedCardEnvelope(
        agent_id="test-agent",
        endpoint="http://127.0.0.1:18101",
        capabilities=["audit"],
        issuer="lab-ca",
        audience="xproto-victim",
        valid_from=1000.0,
        valid_until=5000.0,
        public_key_id="key-1",
    )
    signed_env = sign_envelope(env, priv)

    # Tamper with capability
    tampered_dict = signed_env.to_dict()
    tampered_dict["capabilities"].append("escalated-admin")
    tampered_env = AttestedCardEnvelope.from_dict(tampered_dict)
    assert verify_signature(tampered_env, pub) is False

    # Tamper with endpoint
    tampered_dict2 = signed_env.to_dict()
    tampered_dict2["endpoint"] = "http://127.0.0.1:19999"
    tampered_env2 = AttestedCardEnvelope.from_dict(tampered_dict2)
    assert verify_signature(tampered_env2, pub) is False

    # Corrupt signature string
    tampered_dict3 = signed_env.to_dict()
    tampered_dict3["signature"] = "00" * 64
    tampered_env3 = AttestedCardEnvelope.from_dict(tampered_dict3)
    assert verify_signature(tampered_env3, pub) is False


def test_registry_trust_root_check():
    priv, pub = generate_keypair()
    env = AttestedCardEnvelope(
        agent_id="test-agent",
        endpoint="http://127.0.0.1:18101",
        capabilities=["audit"],
        issuer="lab-ca",
        audience="xproto-victim",
        valid_from=1000.0,
        valid_until=5000.0,
        public_key_id="unregistered-key",
    )
    signed_env = sign_envelope(env, priv)

    reg = AttestationRegistry()
    reg.add_trust_root("known-key", pub)
    ok, reason, fp, rule = reg.verify_envelope(
        signed_env,
        expected_endpoint="http://127.0.0.1:18101",
        current_time=2000.0,
    )
    assert ok is False
    assert rule == "trust-root-check"
    assert "untrusted public key identifier" in reason


def test_registry_validity_interval_checks():
    priv, pub = generate_keypair()
    reg = AttestationRegistry()
    reg.add_trust_root("key-1", pub)

    env = AttestedCardEnvelope(
        agent_id="test-agent",
        endpoint="http://127.0.0.1:18101",
        capabilities=["audit"],
        issuer="lab-ca",
        audience="xproto-victim",
        valid_from=1000.0,
        valid_until=2000.0,
        public_key_id="key-1",
    )
    signed_env = sign_envelope(env, priv)

    # Valid time
    ok, _, _, rule = reg.verify_envelope(signed_env, "http://127.0.0.1:18101", current_time=1500.0)
    assert ok is True
    assert rule == "capability-policy-allowed"

    # Expired
    ok, reason, _, rule = reg.verify_envelope(signed_env, "http://127.0.0.1:18101", current_time=2500.0)
    assert ok is False
    assert rule == "validity-interval"
    assert "card expired" in reason

    # Not yet valid
    ok, reason, _, rule = reg.verify_envelope(signed_env, "http://127.0.0.1:18101", current_time=500.0)
    assert ok is False
    assert rule == "validity-interval"
    assert "card not yet valid" in reason


def test_registry_endpoint_binding():
    priv, pub = generate_keypair()
    reg = AttestationRegistry()
    reg.add_trust_root("key-1", pub)

    env = AttestedCardEnvelope(
        agent_id="test-agent",
        endpoint="http://127.0.0.1:18101",
        capabilities=["audit"],
        issuer="lab-ca",
        audience="xproto-victim",
        valid_from=1000.0,
        valid_until=2000.0,
        public_key_id="key-1",
    )
    signed_env = sign_envelope(env, priv)

    ok, reason, _, rule = reg.verify_envelope(
        signed_env, "http://127.0.0.1:18102", current_time=1500.0
    )
    assert ok is False
    assert rule == "endpoint-binding"
    assert "endpoint mismatch" in reason


def test_registry_audience_check():
    priv, pub = generate_keypair()
    reg = AttestationRegistry()
    reg.add_trust_root("key-1", pub)

    env = AttestedCardEnvelope(
        agent_id="test-agent",
        endpoint="http://127.0.0.1:18101",
        capabilities=["audit"],
        issuer="lab-ca",
        audience="xproto-victim",
        valid_from=1000.0,
        valid_until=2000.0,
        public_key_id="key-1",
    )
    signed_env = sign_envelope(env, priv)

    ok, reason, _, rule = reg.verify_envelope(
        signed_env,
        "http://127.0.0.1:18101",
        expected_audience="wrong-victim",
        current_time=1500.0,
    )
    assert ok is False
    assert rule == "audience-check"
    assert "audience mismatch" in reason

    # Wildcard audience should succeed
    env_wildcard = AttestedCardEnvelope(
        agent_id="test-agent",
        endpoint="http://127.0.0.1:18101",
        capabilities=["audit"],
        issuer="lab-ca",
        audience="*",
        valid_from=1000.0,
        valid_until=2000.0,
        public_key_id="key-1",
    )
    signed_wildcard = sign_envelope(env_wildcard, priv)
    ok_wc, _, _, _ = reg.verify_envelope(
        signed_wildcard,
        "http://127.0.0.1:18101",
        expected_audience="any-caller",
        current_time=1500.0,
    )
    assert ok_wc is True


def test_registry_capability_authorization():
    priv, pub = generate_keypair()
    reg = AttestationRegistry()
    reg.add_trust_root("key-1", pub)

    env = AttestedCardEnvelope(
        agent_id="test-agent",
        endpoint="http://127.0.0.1:18101",
        capabilities=["file-audit", "summarize"],
        issuer="lab-ca",
        audience="xproto-victim",
        valid_from=1000.0,
        valid_until=2000.0,
        public_key_id="key-1",
    )
    signed_env = sign_envelope(env, priv)

    # Allowed capability
    ok, _, _, rule = reg.verify_envelope(
        signed_env,
        "http://127.0.0.1:18101",
        requested_capability="file-audit",
        current_time=1500.0,
    )
    assert ok is True
    assert rule == "capability-policy-allowed"

    # Capability escalation attempt
    ok, reason, _, rule = reg.verify_envelope(
        signed_env,
        "http://127.0.0.1:18101",
        requested_capability="admin-exec",
        current_time=1500.0,
    )
    assert ok is False
    assert rule == "capability-authorization"
    assert "capability escalation" in reason


def test_fixtures_negative_variants():
    """Verify all negative card fixtures fail closed with their expected policy rule."""
    default_reg = load_default_registry()
    ref_time = 1800000000.0  # Time between 1792150883 and 1823690483

    # 1. Legitimate peer fixture succeeds
    legit_path = FIXTURES_DIR / "legitimate_peer.json"
    legit_env = AttestedCardEnvelope.from_dict(json.loads(legit_path.read_text(encoding="utf-8")))
    ok, reason, fp, rule = default_reg.verify_envelope(
        legit_env,
        expected_endpoint="http://127.0.0.1:18101",
        requested_capability="file-audit",
        current_time=ref_time,
    )
    assert ok is True, f"Legitimate peer failed: {reason}"
    assert rule == "capability-policy-allowed"
    assert len(fp) == 16

    # 2. Tampered card fails signature check
    tampered_path = FIXTURES_DIR / "tampered.json"
    tampered_env = AttestedCardEnvelope.from_dict(json.loads(tampered_path.read_text(encoding="utf-8")))
    ok, reason, _, rule = default_reg.verify_envelope(
        tampered_env,
        expected_endpoint="http://127.0.0.1:18101",
        requested_capability="file-audit",
        current_time=ref_time,
    )
    assert ok is False
    assert rule == "signature-check"

    # 3. Expired card fails validity interval
    expired_path = FIXTURES_DIR / "expired.json"
    expired_env = AttestedCardEnvelope.from_dict(json.loads(expired_path.read_text(encoding="utf-8")))
    ok, reason, _, rule = default_reg.verify_envelope(
        expired_env,
        expected_endpoint="http://127.0.0.1:18101",
        requested_capability="file-audit",
        current_time=ref_time,
    )
    assert ok is False
    assert rule == "validity-interval"

    # 4. Wrong audience fails audience check
    wrong_aud_path = FIXTURES_DIR / "wrong_audience.json"
    wrong_aud_env = AttestedCardEnvelope.from_dict(json.loads(wrong_aud_path.read_text(encoding="utf-8")))
    ok, reason, _, rule = default_reg.verify_envelope(
        wrong_aud_env,
        expected_endpoint="http://127.0.0.1:18101",
        expected_audience="xproto-victim",
        requested_capability="file-audit",
        current_time=ref_time,
    )
    assert ok is False
    assert rule == "audience-check"

    # 5. Endpoint mismatch fails endpoint binding
    mismatch_path = FIXTURES_DIR / "endpoint_mismatch.json"
    mismatch_env = AttestedCardEnvelope.from_dict(json.loads(mismatch_path.read_text(encoding="utf-8")))
    ok, reason, _, rule = default_reg.verify_envelope(
        mismatch_env,
        expected_endpoint="http://127.0.0.1:18101",
        requested_capability="file-audit",
        current_time=ref_time,
    )
    assert ok is False
    assert rule == "endpoint-binding"

    # 6. Capability escalation fails capability authorization
    escalation_path = FIXTURES_DIR / "capability_escalation.json"
    escalation_env = AttestedCardEnvelope.from_dict(json.loads(escalation_path.read_text(encoding="utf-8")))
    ok, reason, _, rule = default_reg.verify_envelope(
        escalation_env,
        expected_endpoint="http://127.0.0.1:18101",
        requested_capability="admin-control",
        current_time=ref_time,
    )
    assert ok is False
    assert rule == "capability-authorization"


def test_xgate_delegation_authorization(tmp_path):
    set_log_dir(tmp_path)
    session = DummySession()
    reg = load_default_registry()
    xgate = XGate(session=session, enforcing=True, registry=reg)

    # Legitimate peer allowed
    xgate.authorize_delegation(
        chain=["owner@victim"],
        target_url="http://127.0.0.1:18101",
        claimed_capability="file-audit",
    )

    # Unattested relay denied
    with pytest.raises(XGateDenied) as exc_info:
        xgate.authorize_delegation(
            chain=["owner@victim"],
            target_url="http://127.0.0.1:18102",
            claimed_capability="file-audit",
        )
    assert "target agent card unattested" in str(exc_info.value)

    # Check delegations.jsonl logging format
    log_file = tmp_path / "delegations.jsonl"
    assert log_file.exists()
    records = [json.loads(line) for line in log_file.read_text(encoding="utf-8").splitlines()]
    assert len(records) == 2

    allowed_rec = records[0]
    assert allowed_rec["allowed"] is True
    assert allowed_rec["policy_rule"] == "capability-policy-allowed"
    assert allowed_rec["target_url"] == "http://127.0.0.1:18101"
    assert len(allowed_rec["card_fingerprint"]) == 16

    denied_rec = records[1]
    assert denied_rec["allowed"] is False
    assert denied_rec["policy_rule"] == "attestation-required"
    assert denied_rec["target_url"] == "http://127.0.0.1:18102"
    assert denied_rec["card_fingerprint"] == "none"
    assert "target agent card unattested" in denied_rec["denial_reason"]


def test_anti_laundering_rule_independent_of_valid_card(tmp_path):
    """Independent anti-laundering gate: tool-output in chain must be denied EVEN IF target card is valid."""
    set_log_dir(tmp_path)
    session = DummySession()
    reg = load_default_registry()
    xgate = XGate(session=session, enforcing=True, registry=reg)

    with pytest.raises(XGateDenied) as exc_info:
        xgate.authorize_delegation(
            chain=["owner@victim", "tool-output"],
            target_url="http://127.0.0.1:18101",  # Legitimate peer with valid card!
            claimed_capability="file-audit",
        )
    assert "laundering" in str(exc_info.value)

    log_file = tmp_path / "delegations.jsonl"
    records = [json.loads(line) for line in log_file.read_text(encoding="utf-8").splitlines()]
    assert len(records) == 1
    rec = records[0]
    assert rec["allowed"] is False
    assert rec["policy_rule"] == "anti-laundering"
    assert rec["card_fingerprint"] == "none"
    assert "laundering" in rec["denial_reason"]


def test_permissive_mode_delegation(tmp_path):
    set_log_dir(tmp_path)
    session = DummySession()
    reg = load_default_registry()
    xgate = XGate(session=session, enforcing=False, registry=reg)

    # In permissive mode, even an unattested target is allowed (for vulnerable baseline evaluation)
    xgate.authorize_delegation(
        chain=["owner@victim"],
        target_url="http://127.0.0.1:18102",
        claimed_capability="file-audit",
    )

    log_file = tmp_path / "delegations.jsonl"
    records = [json.loads(line) for line in log_file.read_text(encoding="utf-8").splitlines()]
    assert len(records) == 1
    rec = records[0]
    assert rec["allowed"] is True
    assert rec["policy_rule"] == "permissive"
