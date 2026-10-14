"""Cryptographic tokens and Merkle structures for multi-agent information flow control."""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import time
import uuid
from dataclasses import asdict, dataclass

from taintwatch.errors import TaintwatchError
from taintwatch.labels import Confidentiality, Integrity, Label


class CryptoTaintError(TaintwatchError):
    """Base error for cryptographic taint operations."""


class TokenTamperedError(CryptoTaintError):
    """The token signature, content digest, or provenance chain was tampered with."""


class TokenExpiredError(CryptoTaintError):
    """The token has expired."""


class TokenReplayError(CryptoTaintError):
    """The token nonce has already been seen (replay attack detected)."""


def sha256_hex(data: bytes | str) -> str:
    if isinstance(data, str):
        data = data.encode("utf-8")
    return hashlib.sha256(data).hexdigest()


class MerkleProvenanceTree:
    """Computes a cryptographic Merkle root over a sequence of provenance node descriptions."""

    def __init__(self, leaves: list[str]) -> None:
        self._leaves = leaves
        self._root = self._compute_root(leaves)

    @property
    def root(self) -> str:
        return self._root

    @property
    def leaves(self) -> tuple[str, ...]:
        return tuple(self._leaves)

    @classmethod
    def from_sources(cls, sources: frozenset[str]) -> MerkleProvenanceTree:
        sorted_sources = sorted(sources)
        return cls([f"source:{s}" for s in sorted_sources])

    @staticmethod
    def _compute_root(items: list[str]) -> str:
        if not items:
            return sha256_hex(b"EMPTY_PROVENANCE_ROOT")
        current_hashes = [sha256_hex(item) for item in items]
        while len(current_hashes) > 1:
            next_level: list[str] = []
            for i in range(0, len(current_hashes), 2):
                left = current_hashes[i]
                right = current_hashes[i + 1] if i + 1 < len(current_hashes) else left
                combined = sha256_hex(left + right)
                next_level.append(combined)
            current_hashes = next_level
        return current_hashes[0]

    def verify_inclusion(self, item: str) -> bool:
        return item in self._leaves


@dataclass(frozen=True, slots=True)
class TaintToken:
    """Tamper-evident attestation of data integrity, confidentiality, and provenance."""

    token_id: str
    sender: str
    recipient: str
    content_digest: str
    integrity: int
    confidentiality: int
    sources: tuple[str, ...]
    merkle_root: str
    created_at: float
    expires_at: float
    signature: str

    @classmethod
    def create(
        cls,
        *,
        secret_key: bytes,
        sender: str,
        recipient: str,
        content: str,
        label: Label,
        merkle_root: str,
        ttl_seconds: float = 300.0,
    ) -> TaintToken:
        token_id = str(uuid.uuid4())
        now = time.time()
        expires_at = now + ttl_seconds
        content_digest = sha256_hex(content)
        sorted_sources = tuple(sorted(label.sources))

        payload_bytes = cls._canonical_bytes(
            token_id=token_id,
            sender=sender,
            recipient=recipient,
            content_digest=content_digest,
            integrity=int(label.integrity),
            confidentiality=int(label.confidentiality),
            sources=sorted_sources,
            merkle_root=merkle_root,
            created_at=now,
            expires_at=expires_at,
        )

        sig = hmac.new(secret_key, payload_bytes, hashlib.sha256).hexdigest()

        return cls(
            token_id=token_id,
            sender=sender,
            recipient=recipient,
            content_digest=content_digest,
            integrity=int(label.integrity),
            confidentiality=int(label.confidentiality),
            sources=sorted_sources,
            merkle_root=merkle_root,
            created_at=now,
            expires_at=expires_at,
            signature=sig,
        )

    @staticmethod
    def _canonical_bytes(
        *,
        token_id: str,
        sender: str,
        recipient: str,
        content_digest: str,
        integrity: int,
        confidentiality: int,
        sources: tuple[str, ...],
        merkle_root: str,
        created_at: float,
        expires_at: float,
    ) -> bytes:
        data = {
            "token_id": token_id,
            "sender": sender,
            "recipient": recipient,
            "content_digest": content_digest,
            "integrity": integrity,
            "confidentiality": confidentiality,
            "sources": list(sources),
            "merkle_root": merkle_root,
            "created_at": round(created_at, 3),
            "expires_at": round(expires_at, 3),
        }
        return json.dumps(data, sort_keys=True, separators=(",", ":")).encode("utf-8")

    def to_compact(self) -> str:
        """Serialize token to URL-safe base64 string."""
        raw = json.dumps(asdict(self)).encode("utf-8")
        return base64.urlsafe_b64encode(raw).decode("ascii")

    @classmethod
    def from_compact(cls, compact_str: str) -> TaintToken:
        try:
            raw = base64.urlsafe_b64decode(compact_str.encode("ascii"))
            data = json.loads(raw.decode("utf-8"))
            return cls(
                token_id=str(data["token_id"]),
                sender=str(data["sender"]),
                recipient=str(data["recipient"]),
                content_digest=str(data["content_digest"]),
                integrity=int(data["integrity"]),
                confidentiality=int(data["confidentiality"]),
                sources=tuple(str(s) for s in data["sources"]),
                merkle_root=str(data["merkle_root"]),
                created_at=float(data["created_at"]),
                expires_at=float(data["expires_at"]),
                signature=str(data["signature"]),
            )
        except Exception as exc:
            raise CryptoTaintError(f"invalid compact token encoding: {exc}") from exc

    def to_label(self) -> Label:
        return Label(
            integrity=Integrity(self.integrity),
            confidentiality=Confidentiality(self.confidentiality),
            sources=frozenset(self.sources),
        )


@dataclass(frozen=True, slots=True)
class TokenVerificationResult:
    valid: bool
    token: TaintToken
    label: Label
    reason: str = "valid"
