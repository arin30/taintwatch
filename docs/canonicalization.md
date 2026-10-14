# Anti-Evasion Canonicalization and Taint-Preserving Decoding

When adversaries attempt to bypass security policies or filter rules in LLM agent systems,
they frequently leverage character-level and semantic evasion techniques:
- **Zero-width and invisible control characters**: Inserting `\u200b`, `\u200c`, `\u200d`,
  `\ufeff`, `\u2060`, or Trojan Source bidirectional override marks (`\u202a`–`\u202e`, `\u2066`–`\u2069`)
  inside sensitive keywords (e.g. `c\u200bu\u200br\u200bl` or `r\u200be\u200bm\u200bo\u200bv\u200be`).
- **Unicode Homoglyphs & Confusables**: Substituting Latin glyphs with identical-looking Cyrillic,
  Greek, or mathematical alphanumerics (e.g., Cyrillic `а` U+0430 inside `cat`).
- **Multi-layer Encodings**: Hiding payloads inside URL percent-encoding (`%63%75%72%6c`),
  hex escapes (`\x63\x75\x72\x6c`), HTML entities (`&lt;script&gt;`), or Base64 blocks.

In standard systems, either these payloads slip past keyword and policy checks, or decoding them
strips away security labels (taint laundering).

## The TaintWatch Invariant

`taintwatch.spans.canonical` provides **span-preserving transformations**:
Every transformed or decoded character mathematically inherits the least-upper-bound label
(`Label.join_all`) of its constituent encoded or obfuscated characters. Taint is never lost across
transformations.

## Core API

```python
from taintwatch.spans import (
    canonicalize_tstr,
    detect_evasion,
    strip_invisible,
    normalize_homoglyphs,
    decode_url_percent,
    decode_hex_escapes,
    decode_html_entities,
    decode_base64_blocks,
)

# Stripping invisible characters while preserving exact span integrity
clean, count = strip_invisible(obfuscated_tstr)

# Normalizing Cyrillic/Greek confusables
normalized, count = normalize_homoglyphs(mixed_tstr)

# Decoding multi-layer encodings with taint propagation
decoded, count = decode_url_percent(encoded_tstr)

# Analyzing evasion scores and techniques
report = detect_evasion(incoming_tstr)
if report.has_evasion:
    print(f"Detected evasion techniques: {report.techniques}, score={report.score}")
```

## Guard Integration

The runtime `Guard` supports automated anti-evasion canonicalization:

```python
guard = Guard(policy, canonicalize=True)
```

When `canonicalize=True`:
1. Every prospective tool argument is inspected for evasion attempts.
2. Canonical representations are derived and recorded in the provenance graph.
3. Policy checks evaluate against canonical values, preventing policy bypass.
4. Underlying tool functions execute clean, de-obfuscated arguments.
5. All detected evasion techniques are preserved in the immutable audit trail (`AuditRecord.evasions`).
