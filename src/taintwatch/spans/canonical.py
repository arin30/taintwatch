"""Span-level canonicalization, anti-evasion normalization, and taint-preserving decoding.

When attackers attempt to evade taint detection or policy filters using:
- Zero-width or invisible Unicode characters (e.g., zero-width spaces, Trojan Source Bidi overrides)
- Cross-script Unicode homoglyphs (e.g., Cyrillic or Greek characters masquerading as Latin)
- Multi-layer encodings (URL percent-encoding, Hex escapes, HTML entities, Base64)

This module provides mathematically sound normalizers that transform strings into their
canonical forms while strictly preserving character-level taint labels and provenance.
"""

from __future__ import annotations

import base64
import binascii
import html
import re
import unicodedata
from dataclasses import dataclass
from typing import Final

from taintwatch.labels import Label
from taintwatch.spans.tstr import Piece, TStr, _build

# Invisible, formatting, and zero-width characters used for filter evasion and Trojan Source
ZERO_WIDTH_CHARS: Final[frozenset[str]] = frozenset(
    {
        "\u200b",  # Zero-width space
        "\u200c",  # Zero-width non-joiner
        "\u200d",  # Zero-width joiner
        "\ufeff",  # Zero-width no-break space (BOM)
        "\u2060",  # Word joiner
        "\u00ad",  # Soft hyphen
        "\u200e",  # Left-to-right mark
        "\u200f",  # Right-to-left mark
        "\u202a",  # Left-to-right embedding
        "\u202b",  # Right-to-left embedding
        "\u202c",  # Pop directional formatting
        "\u202d",  # Left-to-right override
        "\u202e",  # Right-to-left override
        "\u2066",  # Left-to-right isolate
        "\u2067",  # Right-to-left isolate
        "\u2068",  # First strong isolate
        "\u2069",  # Pop directional isolate
    }
)

# Common visual confusable homoglyphs mapped to ASCII equivalents
HOMOGLYPH_MAP: Final[dict[str, str]] = {
    # Cyrillic small letters
    "\u0430": "a",  # а
    "\u0441": "c",  # с
    "\u0434": "d",  # д (in some italics)
    "\u0435": "e",  # е
    "\u04bb": "h",  # һ
    "\u0456": "i",  # і
    "\u0458": "j",  # ј
    "\u043a": "k",  # к (in small caps)
    "\u043e": "o",  # о
    "\u0440": "p",  # р
    "\u0455": "s",  # ѕ
    "\u0445": "x",  # х
    "\u0443": "y",  # у
    # Cyrillic capital letters
    "\u0410": "A",  # А
    "\u0412": "B",  # В
    "\u0421": "C",  # С
    "\u0415": "E",  # Е
    "\u041d": "H",  # Н
    "\u0406": "I",  # І
    "\u0408": "J",  # Ј
    "\u041a": "K",  # К
    "\u041c": "M",  # М
    "\u041e": "O",  # О
    "\u0420": "P",  # Р
    "\u0422": "T",  # Т
    "\u0425": "X",  # Х
    "\u0423": "Y",  # У
    # Greek small letters
    "\u03b1": "a",  # α
    "\u03b2": "b",  # β
    "\u03b5": "e",  # ε
    "\u03b7": "n",  # η
    "\u03b9": "i",  # ι
    "\u03ba": "k",  # κ
    "\u03bf": "o",  # ο
    "\u03c1": "p",  # ρ
    "\u03c4": "t",  # τ
    "\u03c5": "u",  # υ
    "\u03c7": "x",  # χ
    # Greek capital letters
    "\u0391": "A",  # Α
    "\u0392": "B",  # Β
    "\u0395": "E",  # Ε
    "\u0397": "H",  # Η
    "\u0399": "I",  # Ι
    "\u039a": "K",  # Κ
    "\u039c": "M",  # Μ
    "\u039d": "N",  # Ν
    "\u039f": "O",  # Ο
    "\u03a1": "P",  # Ρ
    "\u03a4": "T",  # Τ
    "\u03a7": "X",  # Χ
    "\u03a5": "Y",  # Υ
    "\u0396": "Z",  # Ζ
}


@dataclass(frozen=True, slots=True)
class EvasionReport:
    """Report detailing detected evasion techniques and normalized canonical representation."""

    has_evasion: bool
    techniques: tuple[str, ...]
    score: float
    canonical: TStr


def strip_invisible(text: TStr) -> tuple[TStr, int]:
    """Strip zero-width and invisible control characters, preserving character labels.

    Returns the stripped TStr and the count of stripped characters.
    """
    pieces: list[Piece] = []
    stripped_count = 0
    for char_idx in range(len(text)):
        char = text.text[char_idx]
        if char in ZERO_WIDTH_CHARS:
            stripped_count += 1
            continue
        pieces.append((char, text.label_at(char_idx)))
    return _build(pieces), stripped_count


def normalize_homoglyphs(text: TStr) -> tuple[TStr, int]:
    """Normalize Unicode confusables and compatibility characters into canonical ASCII/NFKC form.

    Each character in the resulting TStr retains the label of its source character.
    Returns the normalized TStr and the count of replaced homoglyphs.
    """
    pieces: list[Piece] = []
    replaced_count = 0
    for char_idx in range(len(text)):
        char = text.text[char_idx]
        lbl = text.label_at(char_idx)
        if char in HOMOGLYPH_MAP:
            replaced_char = HOMOGLYPH_MAP[char]
            pieces.append((replaced_char, lbl))
            replaced_count += 1
            continue
        # Apply NFKC normalization for fullwidth, circled, or mathematical alphanumerics
        nfkc = unicodedata.normalize("NFKC", char)
        if nfkc != char:
            replaced_count += 1
            pieces.append((nfkc, lbl))
        else:
            pieces.append((char, lbl))
    return _build(pieces), replaced_count


_HEX_ESCAPE_RE = re.compile(r"\\x([0-9a-fA-F]{2})|0x([0-9a-fA-F]{2})")
_URL_ENCODED_RE = re.compile(r"(?:%[0-9a-fA-F]{2})+")
_HTML_ENTITY_RE = re.compile(r"&(#?[xX]?[0-9a-zA-Z]+);")
_BASE64_BLOCK_RE = re.compile(r"[A-Za-z0-9+/]{8,}={0,2}")


def decode_hex_escapes(text: TStr) -> tuple[TStr, int]:
    """Decode \\xHH and 0xHH hex escapes, propagating taint to the decoded characters."""
    pieces: list[Piece] = []
    pos = 0
    count = 0
    raw = text.text
    for m in _HEX_ESCAPE_RE.finditer(raw):
        start, end = m.span()
        if start > pos:
            for i in range(pos, start):
                pieces.append((raw[i], text.label_at(i)))
        hex_val = m.group(1) or m.group(2)
        try:
            byte_val = int(hex_val, 16)
            char = chr(byte_val)
            # Label of decoded character is the join of the escape sequence characters
            span_label = Label.join_all(text.label_at(i) for i in range(start, end))
            pieces.append((char, span_label))
            count += 1
        except ValueError:
            for i in range(start, end):
                pieces.append((raw[i], text.label_at(i)))
        pos = end
    if pos < len(raw):
        for i in range(pos, len(raw)):
            pieces.append((raw[i], text.label_at(i)))
    return _build(pieces), count


def decode_url_percent(text: TStr) -> tuple[TStr, int]:
    """Decode sequences of URL percent-encoded bytes, propagating taint to the decoded text."""
    pieces: list[Piece] = []
    pos = 0
    count = 0
    raw = text.text
    for m in _URL_ENCODED_RE.finditer(raw):
        start, end = m.span()
        if start > pos:
            for i in range(pos, start):
                pieces.append((raw[i], text.label_at(i)))
        encoded_str = raw[start:end]
        byte_chunks = [int(encoded_str[i + 1 : i + 3], 16) for i in range(0, len(encoded_str), 3)]
        try:
            decoded_text = bytes(byte_chunks).decode("utf-8")
            span_label = Label.join_all(text.label_at(i) for i in range(start, end))
            pieces.append((decoded_text, span_label))
            count += 1
        except UnicodeDecodeError:
            for i in range(start, end):
                pieces.append((raw[i], text.label_at(i)))
        pos = end
    if pos < len(raw):
        for i in range(pos, len(raw)):
            pieces.append((raw[i], text.label_at(i)))
    return _build(pieces), count


def decode_html_entities(text: TStr) -> tuple[TStr, int]:
    """Decode HTML named and numeric entities, preserving character-level taint."""
    pieces: list[Piece] = []
    pos = 0
    count = 0
    raw = text.text
    for m in _HTML_ENTITY_RE.finditer(raw):
        start, end = m.span()
        if start > pos:
            for i in range(pos, start):
                pieces.append((raw[i], text.label_at(i)))
        entity_str = m.group(0)
        decoded = html.unescape(entity_str)
        if decoded != entity_str:
            span_label = Label.join_all(text.label_at(i) for i in range(start, end))
            pieces.append((decoded, span_label))
            count += 1
        else:
            for i in range(start, end):
                pieces.append((raw[i], text.label_at(i)))
        pos = end
    if pos < len(raw):
        for i in range(pos, len(raw)):
            pieces.append((raw[i], text.label_at(i)))
    return _build(pieces), count


def decode_base64_blocks(text: TStr, min_length: int = 8) -> tuple[TStr, int]:
    """Detect and decode printable UTF-8 Base64 payload blocks, propagating taint."""
    pieces: list[Piece] = []
    pos = 0
    count = 0
    raw = text.text
    for m in _BASE64_BLOCK_RE.finditer(raw):
        start, end = m.span()
        candidate = raw[start:end]
        if len(candidate) < min_length or len(candidate) % 4 != 0:
            continue
        try:
            decoded_bytes = base64.b64decode(candidate, validate=True)
            # Only consider valid printable utf-8 text strings of sufficient length
            decoded_str = decoded_bytes.decode("utf-8")
            if not decoded_str.isprintable() or len(decoded_str.strip()) < 3:
                continue
            if start > pos:
                for i in range(pos, start):
                    pieces.append((raw[i], text.label_at(i)))
            span_label = Label.join_all(text.label_at(i) for i in range(start, end))
            pieces.append((decoded_str, span_label))
            count += 1
            pos = end
        except (binascii.Error, UnicodeDecodeError, ValueError):
            continue
    if pos < len(raw):
        for i in range(pos, len(raw)):
            pieces.append((raw[i], text.label_at(i)))
    return _build(pieces), count


def canonicalize_tstr(
    text: TStr,
    *,
    strip_invisibles: bool = True,
    normalize_glyphs: bool = True,
    decode_hex: bool = True,
    decode_url: bool = True,
    decode_html_entities_flag: bool = True,
    decode_base64: bool = False,
) -> tuple[TStr, tuple[str, ...]]:
    """Transform text into canonical representation while maintaining taint across all spans.

    Returns the canonicalized TStr and a tuple of transformation descriptions applied.
    """
    applied: list[str] = []
    current = text

    if strip_invisibles:
        current, count = strip_invisible(current)
        if count > 0:
            applied.append(f"stripped {count} invisible/zero-width character(s)")

    if normalize_glyphs:
        current, count = normalize_homoglyphs(current)
        if count > 0:
            applied.append(f"normalized {count} homoglyph/compatibility character(s)")

    if decode_url:
        current, count = decode_url_percent(current)
        if count > 0:
            applied.append(f"decoded {count} URL percent-encoded sequence(s)")

    if decode_hex:
        current, count = decode_hex_escapes(current)
        if count > 0:
            applied.append(f"decoded {count} hex escape(s)")

    if decode_html_entities_flag:
        current, count = decode_html_entities(current)
        if count > 0:
            applied.append(f"decoded {count} HTML entity(ies)")

    if decode_base64:
        current, count = decode_base64_blocks(current)
        if count > 0:
            applied.append(f"decoded {count} base64 block(s)")

    return current, tuple(applied)


def detect_evasion(text: TStr) -> EvasionReport:
    """Analyze text for obfuscation, Trojan Source tricks, and filter evasion attempts."""
    techniques: list[str] = []
    score = 0.0

    # 1. Zero-width / invisible characters check
    invisibles = sum(1 for c in text.text if c in ZERO_WIDTH_CHARS)
    if invisibles > 0:
        techniques.append(f"zero_width_chars({invisibles})")
        score += min(1.0, 0.4 + 0.1 * invisibles)

    # 2. Homoglyphs & mixed-script check
    homoglyphs = sum(1 for c in text.text if c in HOMOGLYPH_MAP)
    if homoglyphs > 0:
        techniques.append(f"homoglyph_confusables({homoglyphs})")
        score += min(1.0, 0.3 + 0.1 * homoglyphs)

    # 3. URL percent encoding
    url_matches = len(_URL_ENCODED_RE.findall(text.text))
    if url_matches > 0:
        techniques.append(f"url_percent_encoding({url_matches})")
        score += min(0.4, 0.15 * url_matches)

    # 4. Hex escape encoding
    hex_matches = len(_HEX_ESCAPE_RE.findall(text.text))
    if hex_matches > 0:
        techniques.append(f"hex_escapes({hex_matches})")
        score += min(0.5, 0.2 * hex_matches)

    # 5. HTML entities
    html_matches = len(_HTML_ENTITY_RE.findall(text.text))
    if html_matches > 0:
        techniques.append(f"html_entities({html_matches})")
        score += min(0.3, 0.1 * html_matches)

    # Build canonical version
    canonical, _ = canonicalize_tstr(
        text,
        strip_invisibles=True,
        normalize_glyphs=True,
        decode_hex=True,
        decode_url=True,
        decode_html_entities_flag=True,
        decode_base64=True,
    )

    final_score = min(1.0, score)
    return EvasionReport(
        has_evasion=final_score > 0.0,
        techniques=tuple(techniques),
        score=final_score,
        canonical=canonical,
    )
