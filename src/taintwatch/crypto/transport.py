"""Transport integration: serialize and deserialize authenticated labeled messages across agents."""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from taintwatch.crypto.service import TaintTokenSigner, TaintTokenVerifier
from taintwatch.crypto.tokens import TaintToken
from taintwatch.guard import Guard
from taintwatch.spans.guard_ext import ingest_text
from taintwatch.spans.tstr import TStr
from taintwatch.tainted import Labeled


def inter_agent_pack(
    signer: TaintTokenSigner,
    labeled_val: Labeled[Any],
    *,
    recipient: str = "*",
    ttl_seconds: float = 300.0,
) -> dict[str, str]:
    """Cryptographically package labeled data for transmission to another agent."""
    text = str(labeled_val.value)
    token = signer.issue(
        content=text,
        label=labeled_val.label,
        recipient=recipient,
        ttl_seconds=ttl_seconds,
    )
    return {
        "content": text,
        "token": token.to_compact(),
    }


def inter_agent_unpack(
    verifier: TaintTokenVerifier,
    guard: Guard,
    message: Mapping[str, str],
    *,
    expected_sender: str | None = None,
) -> Labeled[TStr]:
    """Verify and ingest an incoming authenticated message into the recipient agent's Guard."""
    content = message.get("content", "")
    compact_token = message.get("token", "")
    token = TaintToken.from_compact(compact_token)

    result = verifier.verify(token, content, expected_sender=expected_sender)
    source_name = f"agent:{token.sender}"

    return ingest_text(
        guard,
        content,
        source=source_name,
        integrity=result.label.integrity,
        confidentiality=result.label.confidentiality,
    )
