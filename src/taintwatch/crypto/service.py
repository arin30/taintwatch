"""Token signing, verification, and anti-replay protection service."""

from __future__ import annotations

import hmac
import time
from collections import OrderedDict
from typing import Final

from taintwatch.crypto.tokens import (
    MerkleProvenanceTree,
    TaintToken,
    TokenExpiredError,
    TokenReplayError,
    TokenTamperedError,
    TokenVerificationResult,
    sha256_hex,
)
from taintwatch.labels import Label


class ReplayCache:
    """Bounded LRU memory cache to detect and reject replayed token nonces."""

    def __init__(self, capacity: int = 10_000) -> None:
        self._capacity = capacity
        self._seen: OrderedDict[str, float] = OrderedDict()

    def check_and_add(self, token_id: str, expires_at: float) -> None:
        now = time.time()
        # Clean expired items if capacity is reached
        if token_id in self._seen:
            raise TokenReplayError(f"token {token_id!r} has already been used")

        if len(self._seen) >= self._capacity:
            # Pop expired or oldest
            while self._seen:
                oldest_id, exp = next(iter(self._seen.items()))
                if exp < now or len(self._seen) >= self._capacity:
                    self._seen.pop(oldest_id)
                else:
                    break

        self._seen[token_id] = expires_at


class TaintTokenSigner:
    """Generates cryptographic attestations for inter-agent taint flows."""

    def __init__(self, secret_key: bytes, agent_id: str) -> None:
        if len(secret_key) < 16:
            raise ValueError("secret key must be at least 16 bytes for security")
        self._secret_key = secret_key
        self._agent_id = agent_id

    @property
    def agent_id(self) -> str:
        return self._agent_id

    def issue(
        self,
        *,
        content: str,
        label: Label,
        recipient: str = "*",
        ttl_seconds: float = 300.0,
    ) -> TaintToken:
        tree = MerkleProvenanceTree.from_sources(label.sources)
        return TaintToken.create(
            secret_key=self._secret_key,
            sender=self._agent_id,
            recipient=recipient,
            content=content,
            label=label,
            merkle_root=tree.root,
            ttl_seconds=ttl_seconds,
        )


class TaintTokenVerifier:
    """Verifies cryptographic attestations, detecting tampering, forgery, and replay."""

    def __init__(
        self,
        key_ring: dict[str, bytes] | bytes,
        expected_recipient: str | None = None,
        replay_cache: ReplayCache | None = None,
        clock_skew_seconds: float = 5.0,
    ) -> None:
        if isinstance(key_ring, bytes):
            self._key_ring = {"*": key_ring}
        else:
            self._key_ring = key_ring
        self._recipient = expected_recipient
        self._replay_cache = replay_cache if replay_cache is not None else ReplayCache()
        self._clock_skew: Final[float] = clock_skew_seconds

    def verify(
        self,
        token: TaintToken,
        content: str,
        *,
        expected_sender: str | None = None,
    ) -> TokenVerificationResult:
        now = time.time()

        # 1. Check expiration
        if now > (token.expires_at + self._clock_skew):
            raise TokenExpiredError(
                f"token expired at {token.expires_at:.2f} (current time: {now:.2f})"
            )

        # 2. Check future timestamp abuse
        if (token.created_at - self._clock_skew) > now:
            raise TokenTamperedError("token creation timestamp is in the future")

        # 3. Check sender
        if expected_sender is not None and token.sender != expected_sender:
            raise TokenTamperedError(
                f"expected sender {expected_sender!r}, token sender is {token.sender!r}"
            )

        # 4. Check recipient
        if (
            self._recipient is not None
            and token.recipient != "*"
            and token.recipient != self._recipient
        ):
            raise TokenTamperedError(
                f"token recipient {token.recipient!r} does not match expected {self._recipient!r}"
            )

        # 5. Check content digest
        digest = sha256_hex(content)
        if not hmac.compare_digest(digest, token.content_digest):
            raise TokenTamperedError(
                f"content digest mismatch: expected {token.content_digest}, calculated {digest}"
            )

        # 6. Check signature
        key = self._key_ring.get(token.sender) or self._key_ring.get("*")
        if key is None:
            raise TokenTamperedError(f"no verification key registered for sender {token.sender!r}")

        canonical = TaintToken._canonical_bytes(
            token_id=token.token_id,
            sender=token.sender,
            recipient=token.recipient,
            content_digest=token.content_digest,
            integrity=token.integrity,
            confidentiality=token.confidentiality,
            sources=token.sources,
            merkle_root=token.merkle_root,
            created_at=token.created_at,
            expires_at=token.expires_at,
        )
        expected_sig = hmac.new(key, canonical, "sha256").hexdigest()
        if not hmac.compare_digest(expected_sig, token.signature):
            raise TokenTamperedError("token cryptographic signature is invalid")

        # 7. Check replay cache
        self._replay_cache.check_and_add(token.token_id, token.expires_at)

        label = token.to_label()
        return TokenVerificationResult(valid=True, token=token, label=label)
