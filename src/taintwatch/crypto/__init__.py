"""Cryptographic taint tokens and zero-trust inter-agent information flow control."""

from __future__ import annotations

from taintwatch.crypto.service import ReplayCache, TaintTokenSigner, TaintTokenVerifier
from taintwatch.crypto.tokens import (
    CryptoTaintError,
    MerkleProvenanceTree,
    TaintToken,
    TokenExpiredError,
    TokenReplayError,
    TokenTamperedError,
    TokenVerificationResult,
)
from taintwatch.crypto.transport import inter_agent_pack, inter_agent_unpack

__all__ = [
    "CryptoTaintError",
    "MerkleProvenanceTree",
    "ReplayCache",
    "TaintToken",
    "TaintTokenSigner",
    "TaintTokenVerifier",
    "TokenExpiredError",
    "TokenReplayError",
    "TokenTamperedError",
    "TokenVerificationResult",
    "inter_agent_pack",
    "inter_agent_unpack",
]
