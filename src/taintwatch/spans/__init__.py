"""Span-level taint tracking."""

from __future__ import annotations

from taintwatch.spans.analysis import Excerpt, redact_below, untrusted_excerpts
from taintwatch.spans.canonical import (
    EvasionReport,
    canonicalize_tstr,
    decode_base64_blocks,
    decode_hex_escapes,
    decode_html_entities,
    decode_url_percent,
    detect_evasion,
    normalize_homoglyphs,
    strip_invisible,
)
from taintwatch.spans.fast_index import FastSpanIndex
from taintwatch.spans.guard_ext import derive_text, ingest_text
from taintwatch.spans.structured import (
    Tagged,
    join_label,
    leaves,
    untrusted_paths,
    unwrap,
    wrap,
)
from taintwatch.spans.tstr import Segment, TStr, interpolate

__all__ = [
    "EvasionReport",
    "Excerpt",
    "FastSpanIndex",
    "Segment",
    "TStr",
    "Tagged",
    "canonicalize_tstr",
    "decode_base64_blocks",
    "decode_hex_escapes",
    "decode_html_entities",
    "decode_url_percent",
    "derive_text",
    "detect_evasion",
    "ingest_text",
    "interpolate",
    "join_label",
    "leaves",
    "normalize_homoglyphs",
    "redact_below",
    "strip_invisible",
    "untrusted_excerpts",
    "untrusted_paths",
    "unwrap",
    "wrap",
]
