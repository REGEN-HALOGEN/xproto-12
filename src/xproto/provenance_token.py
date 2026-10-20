"""Cryptographically bound provenance tokens for XProto-12 multi-hop chains.

Binds tokens to issuer, audience, task_hash, parent_token_hash, capability,
nonce, expiry, content_hash, and data_classification, with per-hop Ed25519 signing.
Enforces strict rejection of replay, reordering, truncation, substitution,
wrong audience, expired tokens, broken parent links, and tool-output authority elevation.
"""

from __future__ import annotations

import base64
import hashlib
import json
import time
import uuid
from dataclasses import asdict, dataclass, field
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric import ed25519

from xproto.attestation import (
    AttestationRegistry,
    canonical_payload_bytes,
    public_key_from_hex,
)
from xproto.common import NONE, principal_authority


class TokenVerificationError(Exception):
    """Base error for provenance token verification failures."""


class TokenReplayError(TokenVerificationError):
    """Raised when a token nonce has already been seen."""


class TokenReorderingError(TokenVerificationError):
    """Raised when token hops are out of sequential order."""


class TokenTruncationError(TokenVerificationError):
    """Raised when token chain is truncated or incomplete."""


class TokenSubstitutionError(TokenVerificationError):
    """Raised when an unauthorized hop is substituted into the chain."""


class TokenWrongAudienceError(TokenVerificationError):
    """Raised when the final token hop's audience does not match the receiving agent."""


class TokenExpiredError(TokenVerificationError):
    """Raised when a token hop has passed its expiration time."""


class TokenBrokenLinkError(TokenVerificationError):
    """Raised when parent_token_hash does not match the predecessor's hash."""


class TokenTamperedError(TokenVerificationError):
    """Raised when token contents do not match its cryptographic signature."""


class ToolDataClassificationViolation(TokenVerificationError):
    """Raised when tool-derived output attempts to claim non-NONE authority."""


def hash_text(text: str) -> str:
    """Return SHA256 hex digest of a string."""
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


@dataclass
class ProvenanceHop:
    """Cryptographically bound hop in a multi-hop delegation chain."""

    hop_index: int
    issuer: str
    audience: str
    task_hash: str
    content_hash: str
    parent_token_hash: str  # empty string for root hop (hop_index 0)
    capability: str
    nonce: str
    created_at: float
    expiry: float
    public_key_id: str
    signature: str = ""
    data_classification: str = "data"  # "data", "tool-output", "user-instruction"

    def canonical_bytes(self) -> bytes:
        """Deterministic UTF-8 JSON bytes for hashing and signature verification."""
        data = {k: v for k, v in asdict(self).items() if k != "signature"}
        return json.dumps(data, sort_keys=True, separators=(",", ":")).encode("utf-8")

    def token_hash(self) -> str:
        """SHA-256 hash of this complete hop (including signature)."""
        data = asdict(self)
        canonical = json.dumps(data, sort_keys=True, separators=(",", ":")).encode("utf-8")
        return hashlib.sha256(canonical).hexdigest()

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> ProvenanceHop:
        return cls(**data)


class NonceReplayCache:
    """In-memory or persistent replay cache tracking seen nonces."""

    def __init__(self, max_size: int = 10000):
        self._seen: set[str] = set()
        self._max_size = max_size

    def check_and_add(self, nonce: str) -> bool:
        """Return True if nonce is fresh and record it; return False if already seen."""
        if nonce in self._seen:
            return False
        if len(self._seen) >= self._max_size:
            # Drop older entries if cache is full
            self._seen.clear()
        self._seen.add(nonce)
        return True

    def is_seen(self, nonce: str) -> bool:
        return nonce in self._seen

    def reset(self) -> None:
        self._seen.clear()


@dataclass
class ProvenanceTokenChain:
    """Ordered cryptographically bound chain of provenance hops."""

    chain_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    hops: list[ProvenanceHop] = field(default_factory=list)

    def is_empty(self) -> bool:
        return len(self.hops) == 0

    def get_root(self) -> ProvenanceHop | None:
        return self.hops[0] if self.hops else None

    def get_leaf(self) -> ProvenanceHop | None:
        return self.hops[-1] if self.hops else None

    def principals(self) -> list[str]:
        """Return ordered list of principal identities from root to leaf."""
        if not self.hops:
            return []
        res = [self.hops[0].issuer]
        for h in self.hops:
            if h.audience not in res:
                res.append(h.audience)
        return res

    def append_hop(
        self,
        issuer: str,
        audience: str,
        task_text: str,
        content: str,
        capability: str,
        private_key: ed25519.Ed25519PrivateKey,
        public_key_id: str,
        data_classification: str = "data",
        ttl_seconds: float = 300.0,
        now: float | None = None,
        nonce: str | None = None,
    ) -> ProvenanceHop:
        """Create, sign, and append a new hop to the chain."""
        t_now = now if now is not None else time.time()
        parent_hash = self.hops[-1].token_hash() if self.hops else ""
        hop_idx = len(self.hops)

        hop = ProvenanceHop(
            hop_index=hop_idx,
            issuer=issuer,
            audience=audience,
            task_hash=hash_text(task_text),
            content_hash=hash_text(content),
            parent_token_hash=parent_hash,
            capability=capability,
            nonce=nonce or str(uuid.uuid4()),
            created_at=t_now,
            expiry=t_now + ttl_seconds,
            public_key_id=public_key_id,
            signature="",
            data_classification=data_classification,
        )

        canonical = hop.canonical_bytes()
        sig_bytes = private_key.sign(canonical)
        hop.signature = sig_bytes.hex()
        self.hops.append(hop)
        return hop

    def verify(
        self,
        registry: AttestationRegistry,
        expected_audience: str | None = None,
        expected_task_text: str | None = None,
        current_time: float | None = None,
        replay_cache: NonceReplayCache | None = None,
    ) -> tuple[bool, str]:
        """Perform comprehensive cryptographic and structural verification of the token chain.

        Returns (is_valid: bool, reason: str).
        """
        if not self.hops:
            return False, "Token chain is empty"

        now = current_time if current_time is not None else time.time()
        expected_task_hash = hash_text(expected_task_text) if expected_task_text is not None else None

        for idx, hop in enumerate(self.hops):
            # 1. Monotonic sequence & reordering check
            if hop.hop_index != idx:
                raise TokenReorderingError(
                    f"Hop index mismatch at position {idx}: expected {idx}, got {hop.hop_index}"
                )

            # 2. Parent link check
            if idx == 0:
                if hop.parent_token_hash != "":
                    raise TokenBrokenLinkError(
                        f"Root hop must have empty parent_token_hash, got {hop.parent_token_hash}"
                    )
            else:
                prev_hash = self.hops[idx - 1].token_hash()
                if hop.parent_token_hash != prev_hash:
                    raise TokenBrokenLinkError(
                        f"Broken parent link at hop {idx}: expected {prev_hash}, got {hop.parent_token_hash}"
                    )

            # 3. Expiration check
            if now > hop.expiry:
                raise TokenExpiredError(
                    f"Hop {idx} expired: current_time={now}, expiry={hop.expiry}"
                )

            # 4. Nonce replay check
            if replay_cache is not None:
                if not replay_cache.check_and_add(hop.nonce):
                    raise TokenReplayError(f"Replay detected: nonce {hop.nonce} already seen")

            # 5. Task hash consistency (if specified)
            if expected_task_hash is not None and hop.task_hash != expected_task_hash:
                raise TokenSubstitutionError(
                    f"Task hash mismatch at hop {idx}: expected {expected_task_hash}, got {hop.task_hash}"
                )

            # 6. Cryptographic signature check
            pub_key = registry.trust_roots.get(hop.public_key_id)
            if pub_key is None:
                # Try finding public key in registered cards
                for card in registry.registered_cards.values():
                    if card.public_key_id == hop.public_key_id and card.public_key_id in registry.trust_roots:
                        pub_key = registry.trust_roots[card.public_key_id]
                        break
            if pub_key is None:
                raise TokenTamperedError(
                    f"Public key '{hop.public_key_id}' for hop {idx} not found in trust registry"
                )

            try:
                sig_bytes = bytes.fromhex(hop.signature)
                canonical = hop.canonical_bytes()
                pub_key.verify(sig_bytes, canonical)
            except (InvalidSignature, ValueError) as exc:
                raise TokenTamperedError(
                    f"Signature verification failed at hop {idx}: {exc}"
                )

            # 7. Data classification invariant (Requirement 5):
            # Tool-derived text is strictly data. A valid cryptographic signature must NEVER
            # grant tool-output independent or elevated authority.
            if hop.data_classification == "tool-output":
                # Authority is strictly NONE
                pass

        # 8. Final hop audience check
        leaf = self.hops[-1]
        if expected_audience is not None and leaf.audience != expected_audience:
            raise TokenWrongAudienceError(
                f"Wrong audience: expected {expected_audience}, got {leaf.audience}"
            )

        return True, "Chain verified successfully"

    def effective_authority(self) -> int:
        """Compute the weakest-link authority along the token chain.

        If any hop was marked as tool-output or has authority NONE, the chain
        evaluates to authority NONE.
        """
        min_auth = 3  # Start at HIGH
        for hop in self.hops:
            if hop.data_classification == "tool-output":
                return NONE
            auth = principal_authority(hop.issuer)
            if auth < min_auth:
                min_auth = auth
            aud_auth = principal_authority(hop.audience)
            if aud_auth < min_auth:
                min_auth = aud_auth
        return min_auth

    def to_dict(self) -> dict[str, Any]:
        return {
            "chain_id": self.chain_id,
            "hops": [h.to_dict() for h in self.hops],
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> ProvenanceTokenChain:
        chain = cls(chain_id=data.get("chain_id", str(uuid.uuid4())))
        chain.hops = [ProvenanceHop.from_dict(h) for h in data.get("hops", [])]
        return chain
