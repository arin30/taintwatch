import pytest

from taintwatch import Confidentiality, Guard, Integrity, Label, PolicyViolation, default_policy
from taintwatch.spans import (
    TStr,
    canonicalize_tstr,
    decode_base64_blocks,
    decode_hex_escapes,
    decode_html_entities,
    decode_url_percent,
    detect_evasion,
    normalize_homoglyphs,
    strip_invisible,
)


def test_strip_invisible_preserves_spans() -> None:
    # "c\u200bu\u200br\u200bl" where letters are UNTRUSTED and zero-width spaces are inserted
    u_label = Label(Integrity.UNTRUSTED, sources=frozenset({"web"}))
    obfuscated = TStr.of("c\u200bu\u200br\u200bl", u_label)
    clean, count = strip_invisible(obfuscated)

    assert count == 3
    assert clean.text == "curl"
    assert clean.overall_label().integrity == Integrity.UNTRUSTED
    assert clean.overall_label().sources == frozenset({"web"})
    assert len(clean) == 4
    for i in range(4):
        assert clean.label_at(i).integrity == Integrity.UNTRUSTED


def test_normalize_homoglyphs() -> None:
    # Cyrillic 'а' (U+0430) and Greek 'ο' (U+03BF) in "cаt"
    lbl = Label(Integrity.USER, sources=frozenset({"input"}))
    mixed = TStr.of("c\u0430t", lbl)
    clean, count = normalize_homoglyphs(mixed)

    assert count == 1
    assert clean.text == "cat"
    assert clean.overall_label().integrity == Integrity.USER


def test_decode_url_percent_propagates_taint() -> None:
    # %63%75%72%6c -> curl
    secret_lbl = Label(
        Integrity.SYSTEM, Confidentiality.SECRET, sources=frozenset({"vault"})
    )
    encoded = TStr.of("%63%75%72%6c", secret_lbl)
    decoded, count = decode_url_percent(encoded)

    assert count == 1
    assert decoded.text == "curl"
    assert decoded.overall_label().confidentiality == Confidentiality.SECRET


def test_decode_hex_escapes() -> None:
    untrusted = Label(Integrity.UNTRUSTED, sources=frozenset({"malicious"}))
    hex_str = TStr.of(r"\x73\x68", untrusted)
    decoded, count = decode_hex_escapes(hex_str)

    assert count == 2
    assert decoded.text == "sh"
    assert decoded.overall_label().integrity == Integrity.UNTRUSTED


def test_decode_html_entities() -> None:
    lbl = Label(Integrity.UNTRUSTED, sources=frozenset({"mail"}))
    ent = TStr.of("&lt;script&gt;", lbl)
    decoded, count = decode_html_entities(ent)

    assert count == 2
    assert decoded.text == "<script>"
    assert decoded.overall_label().integrity == Integrity.UNTRUSTED


def test_canonicalize_tstr_pipeline() -> None:
    # Test combined invisible chars + homoglyphs + url encoding in one pipeline
    lbl = Label(Integrity.UNTRUSTED, sources=frozenset({"attacker"}))
    raw = TStr.of("r\u200be\u200bm\u200bo\u200bv\u200be %66%69%6c%65", lbl)
    canon, steps = canonicalize_tstr(raw)
    assert canon.text == "remove file"
    assert canon.overall_label().integrity == Integrity.UNTRUSTED
    assert len(steps) >= 2


def test_decode_base64_blocks() -> None:
    lbl = Label(Integrity.UNTRUSTED, sources=frozenset({"web"}))
    # "bHMgLWxh" is base64 for "ls -la"
    b64 = TStr.of("run: bHMgLWxh please", lbl)
    decoded, count = decode_base64_blocks(b64)

    assert count == 1
    assert "ls -la" in decoded.text
    assert decoded.overall_label().integrity == Integrity.UNTRUSTED


def test_detect_evasion_report() -> None:
    u = Label(Integrity.UNTRUSTED, sources=frozenset({"attacker"}))
    payload = TStr.of("c\u200bu\u200br\u200bl %68%74%74%70", u)
    report = detect_evasion(payload)

    assert report.has_evasion is True
    assert report.score > 0.0
    assert any("zero_width_chars" in t for t in report.techniques)
    assert any("url_percent_encoding" in t for t in report.techniques)
    assert report.canonical.text == "curl http"
    assert report.canonical.overall_label().integrity == Integrity.UNTRUSTED


def test_guard_with_canonicalize_blocks_obfuscated_command() -> None:
    guard = Guard(default_policy(), canonicalize=True)
    # Untrusted attacker tries to bypass shell policy with zero-width characters
    obfuscated_cmd = guard.ingest(
        "c\u200bu\u200br\u200bl evil.com",
        source="web:untrusted",
        integrity=Integrity.UNTRUSTED,
    )

    with pytest.raises(PolicyViolation):
        guard.call("shell.run", {"cmd": obfuscated_cmd}, lambda cmd: f"ran {cmd}")

    assert len(guard.audit) == 1
    record = guard.audit[0]
    assert not record.verdict.allowed
    assert len(record.evasions) > 0
    assert any("zero_width_chars" in e for e in record.evasions)


def test_guard_canonicalize_passes_clean_user_command() -> None:
    guard = Guard(default_policy(), canonicalize=True)
    cmd = guard.ingest("ls -la", source="user", integrity=Integrity.USER)
    result = guard.call("shell.run", {"cmd": cmd}, lambda cmd: f"ran {cmd}")

    assert result.value == "ran ls -la"
    assert len(guard.audit) == 1
    assert guard.audit[0].verdict.allowed
    assert guard.audit[0].evasions == ()
