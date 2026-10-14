# Interactive Security Sandbox & Playground

TaintWatch includes a live interactive security sandbox in both the FastAPI backend
and the React + TypeScript frontend viewer.

## Features

1. **Interactive Anti-Evasion & Canonicalization Lab**:
   - Test adversarial strings containing zero-width spaces, Unicode homoglyphs, and nested encodings.
   - Computes live evasion scores and identifies exact evasion techniques.
   - Displays canonicalized strings with span-level taint labels preserved.
2. **Cryptographic Inter-Agent Taint Tokens**:
   - Issue HMAC-SHA256 authenticated taint tokens with bound SHA-256 content digests,
     security labels, Merkle roots, nonces, and expiration timestamps.
   - Live testing of tamper detection and anti-replay defense.
3. **Grammar-Bounded Declassification Sandboxes**:
   - Interactive testing of regular expression sanitizers against candidate values to verify
     that prompt injections and SQLi metacharacters fail while legitimate values are promoted.

## API Endpoints

- `POST /api/canonicalize`: Accepts `{ "text": string }`, returns canonical representation and evasion report.
- `POST /api/tokens/issue`: Accepts message content, sender, and security level; returns compact token.
- `POST /api/tokens/verify`: Accepts content and compact token; verifies signature and integrity.
- `POST /api/declassify/test`: Accepts `{ "pattern": string, "value": string }`, tests sanitizer grammar.
