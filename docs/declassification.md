# Policy-Enforced Taint Declassification Sandboxes

In production LLM agent architectures, agents must routinely ingest untrusted user text
(e.g., extracting an order ID, a GitHub handle, or a UUID) and pass validated portions to
sensitive tool sinks (e.g. database queries or APIs).

Without bounded declassification, engineers face a dilemma:
1. **Total Blockage**: Rejecting valid business workflows because the input text carries an
   untrusted label from an external webhook or inbound email.
2. **Policy Disabling**: Removing taint policies on sensitive tools, exposing the system to
   unrestricted SQL injection, prompt injection, and command injection.

`taintwatch` solves this through **Declarative Declassification Contracts**:
Formal, grammar-bounded sanitizers that safely promote integrity or lower confidentiality
under strict regular expression or schema constraints.

## Declarative Policy Syntax (TOML)

```toml
[[rule]]
name = "protect-database"
tool = "db.lookup"
arg = "id"
min_integrity = "user"
action = "block"

[[declassification]]
name = "safe-order-id"
tool = "db.lookup"
arg = "id"
target_integrity = "user"
pattern = "^[0-9]{1,10}$"
reason = "Pure numeric IDs cannot cause SQL injection or command injection."
```

## How It Works

1. **Grammar Enforcement**: When a tool call is evaluated, if an argument would violate a policy rule,
   the guard checks for an applicable `DeclassificationRule`.
2. **Strict Matching**: If the argument's runtime value matches the anchored `pattern` regex
   (e.g., `^[0-9]+$`), its integrity is safely promoted to the declared `target_integrity`.
3. **Exploit Prevention**: If an attacker attempts prompt injection or SQL injection
   (e.g., `10482; DROP TABLE users`), the value fails the sanitizer grammar. Declassification is
   refused, and the guard blocks the tool call with a `PolicyViolation`.
4. **Audit and Provenance**: Every declassification generates a `NodeKind.DERIVED` entry in the
   provenance graph (`"declassified via safe-order-id"`) with full traceability.

## Explicit API

```python
from taintwatch import Guard, Policy, DeclassificationRule, Integrity

guard = Guard(policy)
raw_input = guard.ingest("98421", source="webhook", integrity=Integrity.UNTRUSTED)

# Explicitly sanitize and declassify:
promoted = guard.declassify("db.lookup", "id", raw_input)
assert promoted.label.integrity == Integrity.USER
```
