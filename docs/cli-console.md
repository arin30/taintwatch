# Universal Terminal Console & CLI Reference

TaintWatch includes a full-featured, zero-dependency, cross-platform terminal console tool (`taintwatch`). It provides real-time information-flow inspection, sink policy evaluation, cryptographic token generation, and an interactive terminal REPL across any operating system (Linux, macOS, Windows PowerShell, CMD, or headless SSH containers).

---

## 🚀 Quick Command Reference

```bash
# 1. Inspect any string or file with live ANSI span highlighting
taintwatch inspect "SELECT * FROM users WHERE id = '1'; DROP TABLE users;"

# 2. Check whether a tool call violates an Information-Flow policy
taintwatch check bash "cat /etc/shadow" --min-integrity trusted --input-integrity untrusted

# 3. Issue a verifiable cryptographic taint token for inter-agent workflows
taintwatch token issue --payload "order_9812" --sender "agent-a" --recipient "agent-b"

# 4. Verify a received token envelope
taintwatch token verify --token-json "<COMPACT_TOKEN>" --payload "order_9812"

# 5. Launch interactive terminal console REPL
taintwatch console
```

---

## 🔍 Detailed Command Specifications

### 1. `taintwatch inspect <target>`
Analyzes a string or file path:
- Detects adversarial evasion tactics (zero-width characters, Cyrillic homoglyphs, Trojan Source bidi marks, Base64/Hex/URL encodings).
- Prints color-coded ANSI span highlighting directly in your terminal.
- Generates a structured ASCII/Unicode table showing span offsets, lengths, integrity, and confidentiality labels.

Options:
- `--source <tag>`: Provenance origin label (default: `cli:input`).
- `--integrity <trusted|suspicious|untrusted>`: Base integrity level.
- `--confidentiality <public|confidential|secret>`: Base confidentiality level.

### 2. `taintwatch check <tool> <payload>`
Simulates a guarded tool call through TaintWatch's policy engine:
- Evaluates whether the payload's integrity and confidentiality satisfy the sink's declared constraints.
- Emits exit code `0` on ALLOWED and `1` on BLOCKED with detailed rationale.

Options:
- `--min-integrity <level>`: Sink's minimum required integrity (default: `trusted`).
- `--max-confidentiality <level>`: Sink's maximum allowed confidentiality (default: `public`).
- `--input-integrity <level>`: Input argument's integrity (default: `untrusted`).

### 3. `taintwatch token <issue|verify>`
Cryptographic inter-agent token utilities:
- `issue`: Generates an HMAC-SHA256 authenticated envelope with a Merkle provenance tree.
- `verify`: Validates the signature, nonce freshness, and Merkle root inclusion.

### 4. `taintwatch console` (or `taintwatch repl`)
Launches an interactive, live terminal session. Type or paste adversarial payloads to watch real-time span highlighting, evasion detection, and policy decisions against configurable sinks (`:sink bash`, `:sink sql`).
