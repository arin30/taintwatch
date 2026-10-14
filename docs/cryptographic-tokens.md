# Cryptographic Taint Tokens and Inter-Agent IFC Protocol

In distributed or multi-agent architectures, agents interact across network boundaries, microservices,
and messaging buses. Without cryptographic provenance guarantees, downstream agents cannot trust security
labels claimed by upstream messages, creating vulnerabilities:
- **Taint Forgery**: A compromised or third-party agent can falsely label untrusted web data as `SYSTEM` or `USER`.
- **Payload Tampering**: In-transit modification of tool arguments or directives without invalidating labels.
- **Replay Attacks**: Resending previously signed high-privilege tokens to authorize unvetted actions.
- **Provenance Erasure**: Stripping originating sources (`web:evil.com`) from provenance metadata.

`taintwatch.crypto` establishes a zero-trust information-flow protocol using authenticated tokens,
Merkle provenance trees, and replay caches.

## Architecture

1. **`TaintToken`**:
   - URL-safe compact representation.
   - Binds payload SHA-256 content digest, security lattice level (`Integrity`, `Confidentiality`),
     sorted sources, Merkle root, timestamp, and unique nonce.
   - Sealed with an HMAC-SHA256 signature against an agent key ring.
2. **`MerkleProvenanceTree`**:
   - Summarizes deep provenance DAGs into a cryptographic Merkle root.
   - Allows downstream verification of source inclusion without leaking unnecessary conversation history.
3. **`ReplayCache`**:
   - Bounded LRU cache that detects and denies reused token nonces within their valid TTL window.
4. **`inter_agent_pack` & `inter_agent_unpack`**:
   - Seamless serialization and deserialization bridge that verifies token authenticity and registers
     the payload into the recipient agent's `Guard` with the verified security label.

## Example

```python
from taintwatch import Guard, Integrity, Label, default_policy
from taintwatch.crypto import TaintTokenSigner, TaintTokenVerifier, inter_agent_pack, inter_agent_unpack
from taintwatch.spans.guard_ext import ingest_text

key = b"super-secret-key-32-bytes-long!!!"
signer = TaintTokenSigner(key, agent_id="researcher")
verifier = TaintTokenVerifier(key, expected_recipient="executor")

# Sender side
guard_a = Guard(default_policy())
untrusted_web = ingest_text(guard_a, "malicious script", source="web", integrity=Integrity.UNTRUSTED)
packet = inter_agent_pack(signer, untrusted_web, recipient="executor")

# Receiver side
guard_b = Guard(default_policy())
verified_input = inter_agent_unpack(verifier, guard_b, packet, expected_sender="researcher")

# verified_input carries Integrity.UNTRUSTED; any attempt to route to a shell sink is blocked!
```
