"""Ed25519 signed agent card attestation, canonical envelopes, and trust registry for XProto-12."""

from __future__ import annotations

import base64
import hashlib
import json
import time
from dataclasses import asdict, dataclass, field
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric import ed25519


def canonical_payload_bytes(payload: dict[str, Any]) -> bytes:
    """Deterministic UTF-8 JSON bytes for cryptographic signing and hashing."""
    data = {k: v for k, v in payload.items() if k != "signature"}
    return json.dumps(data, sort_keys=True, separators=(",", ":")).encode("utf-8")


def card_fingerprint(payload: dict[str, Any]) -> str:
    """Stable 16-character SHA256 hex fingerprint of a card envelope."""
    return hashlib.sha256(canonical_payload_bytes(payload)).hexdigest()[:16]


@dataclass
class AttestedCardEnvelope:
    """Canonical card envelope binding agent identity, endpoint, capabilities, and trust roots."""
    agent_id: str
    endpoint: str
    capabilities: list[str]
    issuer: str
    audience: str
    valid_from: float
    valid_until: float
    public_key_id: str
    signature: str = ""
    policy_scope: dict[str, Any] = field(default_factory=dict)

    def canonical_bytes(self) -> bytes:
        return canonical_payload_bytes(self.to_dict())

    def fingerprint(self) -> str:
        return card_fingerprint(self.to_dict())

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> AttestedCardEnvelope:
        return cls(
            agent_id=data["agent_id"],
            endpoint=data["endpoint"],
            capabilities=list(data.get("capabilities", [])),
            issuer=data["issuer"],
            audience=data["audience"],
            valid_from=float(data["valid_from"]),
            valid_until=float(data["valid_until"]),
            public_key_id=data["public_key_id"],
            signature=data.get("signature", ""),
            policy_scope=dict(data.get("policy_scope", {})),
        )


def generate_keypair() -> tuple[ed25519.Ed25519PrivateKey, ed25519.Ed25519PublicKey]:
    """Generate a fresh Ed25519 keypair."""
    priv = ed25519.Ed25519PrivateKey.generate()
    return priv, priv.public_key()


def public_key_to_hex(pub: ed25519.Ed25519PublicKey) -> str:
    from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
    raw = pub.public_bytes(Encoding.Raw, PublicFormat.Raw)
    return raw.hex()


def public_key_from_hex(hex_str: str) -> ed25519.Ed25519PublicKey:
    return ed25519.Ed25519PublicKey.from_public_bytes(bytes.fromhex(hex_str))


def private_key_to_hex(priv: ed25519.Ed25519PrivateKey) -> str:
    from cryptography.hazmat.primitives.serialization import Encoding, PrivateFormat, NoEncryption
    raw = priv.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption())
    return raw.hex()


def private_key_from_hex(hex_str: str) -> ed25519.Ed25519PrivateKey:
    return ed25519.Ed25519PrivateKey.from_private_bytes(bytes.fromhex(hex_str))


def sign_envelope(
    envelope: AttestedCardEnvelope | dict[str, Any],
    private_key: ed25519.Ed25519PrivateKey,
) -> AttestedCardEnvelope:
    """Sign an envelope's canonical bytes with an Ed25519 private key."""
    if isinstance(envelope, AttestedCardEnvelope):
        data = envelope.to_dict()
    else:
        data = dict(envelope)

    canonical = canonical_payload_bytes(data)
    sig_bytes = private_key.sign(canonical)
    data["signature"] = sig_bytes.hex()
    return AttestedCardEnvelope.from_dict(data)


def verify_signature(
    envelope: AttestedCardEnvelope,
    public_key: ed25519.Ed25519PublicKey,
) -> bool:
    """Verify Ed25519 signature over canonical envelope bytes."""
    if not envelope.signature:
        return False
    try:
        sig_bytes = bytes.fromhex(envelope.signature)
        canonical = envelope.canonical_bytes()
        public_key.verify(sig_bytes, canonical)
        return True
    except (InvalidSignature, ValueError):
        return False


class AttestationRegistry:
    """Verifiable registry of trusted public roots and signed agent card attestations."""

    def __init__(self):
        self.trust_roots: dict[str, ed25519.Ed25519PublicKey] = {}
        self.registered_cards: dict[str, AttestedCardEnvelope] = {}  # endpoint -> envelope

    def add_trust_root(self, key_id: str, public_key: ed25519.Ed25519PublicKey | str) -> None:
        if isinstance(public_key, str):
            public_key = public_key_from_hex(public_key)
        self.trust_roots[key_id] = public_key

    def register_card(self, envelope: AttestedCardEnvelope, endpoint: str | None = None) -> None:
        norm_endpoint = (endpoint or envelope.endpoint).rstrip("/")
        self.registered_cards[norm_endpoint] = envelope

    def verify_envelope(
        self,
        envelope: AttestedCardEnvelope,
        expected_endpoint: str,
        requested_capability: str = "",
        expected_audience: str = "xproto-victim",
        current_time: float | None = None,
    ) -> tuple[bool, str, str, str]:
        """Perform full selective verification on an envelope.
        
        Returns:
            (allowed: bool, reason: str, card_fingerprint: str, policy_rule: str)
        """
        fp = envelope.fingerprint()
        now = current_time if current_time is not None else time.time()

        # 1. Trust root check
        pub_key = self.trust_roots.get(envelope.public_key_id)
        if pub_key is None:
            return (
                False,
                f"untrusted public key identifier '{envelope.public_key_id}'",
                fp,
                "trust-root-check",
            )

        # 2. Cryptographic signature verification
        if not verify_signature(envelope, pub_key):
            return (
                False,
                "cryptographic signature verification failed (tampered envelope)",
                fp,
                "signature-check",
            )

        # 3. Validity interval (expiry and future-dating)
        if now < envelope.valid_from:
            return (
                False,
                f"card not yet valid (valid_from={envelope.valid_from}, now={round(now, 1)})",
                fp,
                "validity-interval",
            )
        if now > envelope.valid_until:
            return (
                False,
                f"card expired (valid_until={envelope.valid_until}, now={round(now, 1)})",
                fp,
                "validity-interval",
            )

        # 4. Endpoint binding
        if envelope.endpoint.rstrip("/") != expected_endpoint.rstrip("/"):
            return (
                False,
                f"endpoint mismatch: card bound to '{envelope.endpoint}', attempted '{expected_endpoint}'",
                fp,
                "endpoint-binding",
            )

        # 5. Audience restriction
        if envelope.audience not in (expected_audience, "*"):
            return (
                False,
                f"audience mismatch: card issued for '{envelope.audience}', caller is '{expected_audience}'",
                fp,
                "audience-check",
            )

        # 6. Capability authorization
        if requested_capability:
            norm_req = requested_capability.strip().lower().replace(" ", "-")
            norm_caps = [c.strip().lower().replace(" ", "-") for c in envelope.capabilities]
            if norm_req not in norm_caps:
                return (
                    False,
                    f"capability escalation: requested '{requested_capability}' not granted in card capabilities {envelope.capabilities}",
                    fp,
                    "capability-authorization",
                )

        return (True, "authorized by attestation registry", fp, "capability-policy-allowed")

    def authorize(
        self,
        endpoint: str,
        requested_capability: str = "",
        audience: str = "xproto-victim",
        current_time: float | None = None,
    ) -> tuple[bool, str, str, str]:
        """Authorize a delegation request against registered attested cards."""
        norm_endpoint = endpoint.rstrip("/")
        envelope = self.registered_cards.get(norm_endpoint)
        if envelope is None:
            return (
                False,
                f"target agent card unattested: {endpoint}",
                "none",
                "attestation-required",
            )

        return self.verify_envelope(
            envelope=envelope,
            expected_endpoint=endpoint,
            requested_capability=requested_capability,
            expected_audience=audience,
            current_time=current_time,
        )
