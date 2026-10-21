<div align="center">

# 🛡️ TaintWatch

### Enterprise Runtime Information-Flow Control (IFC) & Zero-Trust Taint Tracking for LLM Agents

[![CI](https://github.com/eyadstein/taintwatch/actions/workflows/ci.yml/badge.svg)](https://github.com/eyadstein/taintwatch/actions/workflows/ci.yml)
[![PyPI version](https://img.shields.io/pypi/v/taintwatch.svg?color=blue)](https://pypi.org/project/taintwatch/)
[![Python 3.11+](https://img.shields.io/badge/python-3.11%20%7C%203.12%20%7C%203.13-blue.svg)](https://pypi.org/project/taintwatch/)
[![License: Apache-2.0](https://img.shields.io/badge/License-Apache_2.0-green.svg)](https://opensource.org/licenses/Apache-2.0)
[![Type Checked: Mypy Strict](https://img.shields.io/badge/mypy-strict%20100%25-blueviolet.svg)](https://mypy.readthedocs.io/)
[![Docker Ready](https://img.shields.io/badge/docker-ready-2496ED.svg?logo=docker&logoColor=white)](https://hub.docker.com/)
[![MCP Compatible](https://img.shields.io/badge/Model_Context_Protocol-MCP_Ready-orange.svg)](https://modelcontextprotocol.io/)
[![PRs Welcome](https://img.shields.io/badge/PRs-30+_Tasks_Open-brightgreen.svg)](docs/CONTRIBUTING_TASKS_30.md)

<p align="center">
  <a href="#-quickstart-in-30-seconds">Quickstart</a> •
  <a href="#-why-taintwatch">Why TaintWatch</a> •
  <a href="#-core-innovations">Core Innovations</a> •
  <a href="#-feature-comparison-matrix">Comparison Matrix</a> •
  <a href="#-enterprise-integrations-mcp-openai-langchain">Integrations</a> •
  <a href="#-docker--cloud-deployment">Deployment</a> •
  <a href="#-community--30-contributor-tasks">Contribute</a>
</p>

</div>

---

## 📌 Overview

**TaintWatch** is a high-performance runtime security engine that enforces **Information-Flow Control (IFC)** across LLM agents, tools, and multi-agent swarms. 

Unlike traditional LLM guardrails that rely on slow, brittle "LLM-as-a-judge" classifiers or simplistic keyword regexes, TaintWatch tracks **integrity**, **confidentiality**, and **cryptographic provenance** down to individual character spans ($O(\log N)$ query speed) at sub-millisecond latency.

When an LLM agent consumes untrusted text—such as an external web scrape, an email body, or an untrusted API response—TaintWatch guarantees that:
1. **Adversarial instructions cannot hijack privileged sinks** (e.g. `bash`, `sql_exec`, `file_write`).
2. **Confidential data cannot leak to untrusted sinks** (e.g. external network requests, public chat, logs).
3. **Implicit covert side-channels** (timing, counterfactual perturbation, branching leakage) are detected and halted.
4. **Inter-agent communications** are sealed with cryptographic Merkle tokens that prevent replay and forgery across distributed swarms.

```
+-----------------------------------------------------------------------------------------+
|                                    ADVERSARIAL WORLD                                    |
|   Untrusted Web Scrapes / Emails / Customer Prompts (Zero-width, Homoglyphs, Base64)    |
+-------------------------------------------+---------------------------------------------+
                                            |
                                            v
+-----------------------------------------------------------------------------------------+
|                               TAINTWATCH DEFENSE PIPELINE                               |
|                                                                                         |
|   [1] Anti-Evasion Canonicalizer (NFKC, Homoglyph normalization, recursive decoders)    |
|                                            |                                            |
|   [2] Span-Level IFC Engine (TStr + FastSpanIndex augmented interval tree: O(log N))    |
|                                            |                                            |
|   [3] Inter-Agent Cryptographic Tokens (HMAC-SHA256, Merkle Provenance, Anti-Replay)    |
|                                            |                                            |
|   [4] Differential Covert Channel Oracle (Shannon entropy budget & perturbation test)   |
|                                            |                                            |
|   [5] Declarative Policy Enforcement (Grammar declassification & sink authorization)   |
+-------------------------------------------+---------------------------------------------+
                                            |
                         +------------------+------------------+
                         |                                     |
                         v                                     v
                  [ POLICY ALLOW ]                      [ POLICY BLOCKED ]
                 Safe Tool Execution              Security Exception Raised
             (Deterministic & Audited)            (Attack Isolated & Logged)
```

---

## 🚀 Quickstart in 30 Seconds

### 1. Installation

```bash
# Core library
pip install taintwatch

# With production REST server & CLI
pip install "taintwatch[server]"
```

### 2. Guarding an LLM Agent Tool Call

```python
from taintwatch.guard import Guard, FlowPolicy, SinkConfig
from taintwatch.policy import Integrity, Confidentiality
from taintwatch.spans import TStr

# 1. Define your declarative security policy
policy = FlowPolicy(
    sinks={
        "bash": SinkConfig(min_integrity=Integrity.TRUSTED),
        "http_post": SinkConfig(max_confidentiality=Confidentiality.PUBLIC),
    }
)
guard = Guard(policy=policy)

# 2. Incoming untrusted data is tagged at the span level
user_input = TStr("Deploy to production && cat /etc/shadow", integrity=Integrity.UNTRUSTED)

# 3. Guard evaluates the flow before the tool executes
try:
    guard.check_call("bash", {"command": user_input})
except Exception as e:
    print(f"🚨 TaintWatch blocked attack: {e}")
    # Output: 🚨 TaintWatch blocked attack: Sink 'bash' requires min integrity TRUSTED, got UNTRUSTED
```

---

## ⚡ Why TaintWatch?

| Attack Vector | Traditional Guardrails (NeMo, Llama Guard) | Regex / Keyword Filters | TaintWatch |
|:---|:---:|:---:|:---:|
| **Indirect Prompt Injection** | ❌ Bypassable via rephrasing | ❌ Easily bypassed | 🛡️ **Guaranteed Blocked (IFC)** |
| **Base64 / Hex / URL Obfuscation** | ❌ Fails to decode context | ❌ Completely blind | 🛡️ **Taint-Preserving Decoding** |
| **Trojan Source & Homoglyphs** | ❌ Invisible to model | ❌ Misses unicode | 🛡️ **NFKC & Zero-Width Stripping** |
| **Multi-Hop Agent Poisoning** | ❌ Context lost across hops | ❌ No memory | 🛡️ **Merkle Cryptographic Tokens** |
| **Covert Side-Channel Exfiltration** | ❌ Cannot detect implicit flows | ❌ Completely blind | 🛡️ **Differential Perturbation Oracle** |
| **Performance Latency** | ⚠️ 500ms - 2000ms (LLM overhead) | ⚡ < 1ms | ⚡ **< 0.5ms (Deterministic)** |

---

## 🌟 Core Innovations

### 1. 🧬 FastSpanIndex: $O(\log N)$ Interval Tree Span Tracking
Standard string taint tracking is either coarse (all-or-nothing per variable) or computationally prohibitive. TaintWatch introduces `FastSpanIndex`, an augmented interval tree with subtree min-integrity bounding:
- Performs interval point and range queries in $O(\log N)$ time.
- Preserves exact source spans through string concatenations, slices, and regex extractions.
- Bounded subtree pruning enables instant validation across 100,000+ token context windows.
- *Read the specification: [`docs/fast-span-index.md`](docs/fast-span-index.md) and [`docs/span-tracking.md`](docs/span-tracking.md).*

### 2. 🛡️ Anti-Evasion Canonicalizer
Attackers obfuscate malicious commands using zero-width Unicode characters, Trojan Source bidirectional marks, Cyrillic homoglyphs, or multi-layer encodings. TaintWatch provides `taintwatch.spans.canonical`:
- Strips invisible unicode (`\u200b`, `\u200c`, `\u202e`, etc.) while mapping span offsets back to original source indices.
- Normalizes Cyrillic, Greek, and typographic homoglyphs via NFKC projection.
- Decodes Base64, Hexadecimal, URL percent-encoding, and HTML entities while **propagating taint tags to the decoded output**.
- *Read the specification: [`docs/canonicalization.md`](docs/canonicalization.md).*

### 3. 🔐 Cryptographic Inter-Agent Taint Tokens
In distributed multi-agent systems (e.g. CrewAI, AutoGen, LangGraph), an untrusted agent can spoof tainted parameters or strip metadata. TaintWatch introduces `taintwatch.crypto`:
- **HMAC-SHA256 Authenticated Tokens**: Every tainted payload passed between agents is signed with a verifiable cryptographic token.
- **Merkle Tree Provenance**: Audit trails record the exact chain of custody across agent handoffs with Merkle inclusion proofs.
- **Anti-Replay Protection**: Cryptographic nonces and TTL timestamps prevent replay attacks across agent swarms.
- *Read the specification: [`docs/cryptographic-tokens.md`](docs/cryptographic-tokens.md).*

### 4. 🕵️ Covert Channel & Differential Taint Defense
Explicit taint tracking can be bypassed if an agent converts secrets into implicit control-flow branches (e.g. branching on secret characters or leaking data via timing/choice entropy). TaintWatch introduces `taintwatch.covert`:
- **Counterfactual Secret Perturbation**: Perturbs the secret ($S \to S'$) and observes whether the agent's tool invocations diverge.
- **Shannon Entropy Budgets**: Measures channel capacity in bits and raises `ImplicitFlowViolation` when leakage limits are exceeded.
- *Read the specification: [`docs/covert-channels.md`](docs/covert-channels.md).*

### 5. 🚪 Policy-Enforced Declassification Sandboxes
Real-world systems must safely extract benign components (such as an order ID or numerical count) from untrusted data without admitting malicious payloads. TaintWatch introduces `DeclassificationRule`:
- Grammar-bounded sanitization contracts (e.g. strict regex `^[0-9]+$`).
- Declarative TOML configuration (`[[declassification]]`).
- Promotes verified safe values to trusted status while rejecting injection vectors.
- *Read the specification: [`docs/declassification.md`](docs/declassification.md).*

---

## 📊 Feature Comparison Matrix

| Capability | TaintWatch | NeMo Guardrails | Llama Guard 3 | Guardrails AI | LangChain / CrewAI |
|:---|:---:|:---:|:---:|:---:|:---:|
| **Character-Span Precision** | ✅ **Yes ($O(\log N)$)** | ❌ No | ❌ No | ❌ No | ❌ No |
| **Zero-Trust Crypto Tokens** | ✅ **HMAC + Merkle** | ❌ No | ❌ No | ❌ No | ❌ No |
| **Anti-Evasion De-obfuscation** | ✅ **4 Decoders + NFKC** | ⚠️ Partial | ❌ No | ⚠️ Partial | ❌ No |
| **Covert Channel / Entropy** | ✅ **Differential Oracle** | ❌ No | ❌ No | ❌ No | ❌ No |
| **Model Context Protocol (MCP)** | ✅ **Native Guard** | ❌ No | ❌ No | ❌ No | ❌ No |
| **Declassification Contracts** | ✅ **Grammar Sandboxes** | ❌ No | ❌ No | ⚠️ Validators | ❌ No |
| **Evaluation Benchmark** | ✅ **600+ Scenarios** | ⚠️ Partial | ⚠️ Partial | ⚠️ Custom | ❌ No |
| **Deterministic Latency** | ✅ **< 1 ms** | ❌ > 500 ms | ❌ > 300 ms | ⚠️ Mixed | ❌ N/A |

---

## 🔌 Enterprise Integrations: MCP, OpenAI, LangChain

TaintWatch includes native, zero-friction adapters for modern AI architectures:

### Model Context Protocol (MCP) Guard
```python
from taintwatch.integrations.mcp import MCPGuard
from taintwatch.guard import Guard

mcp_guard = MCPGuard(guard=Guard.default())

# Transparently inspects MCP tools/call requests
guarded_request = mcp_guard.protect_tool_call(
    server_name="filesystem",
    tool_name="write_file",
    arguments={"path": "/etc/hosts", "content": untrusted_payload}
)
```

### OpenAI Function Calling Interceptor
```python
from taintwatch.integrations.openai import OpenAIInterceptor
from taintwatch.guard import Guard

interceptor = OpenAIInterceptor(guard=Guard.default())
# Inspects function call completions before execution
interceptor.inspect_function_call(response.choices[0].message.tool_calls[0])
```

### LangChain Agent Callback Handler
```python
from taintwatch.integrations.langchain import TaintWatchCallbackHandler

handler = TaintWatchCallbackHandler(guard=Guard.default())
agent.run("Analyze this report", callbacks=[handler])
```
*Read the full integration guide: [`docs/integrations.md`](docs/integrations.md).*

---

## 🐳 Docker & Cloud Deployment

TaintWatch provides an enterprise-ready, hardened, multi-stage Docker container with non-root security execution (UID 10001).

### Run with Docker Compose
```bash
docker compose up -d
```
The REST API and interactive Security Playground will be live at:
- **Web UI & Security Playground**: `http://localhost:8000`
- **Interactive OpenAPI Docs**: `http://localhost:8000/docs`
- **Health Check Endpoint**: `http://localhost:8000/healthz`

### Interactive Security Playground
The included React + TypeScript playground allows you to interactively test:
- Adversarial evasion payloads (zero-width, Cyrillic, Base64).
- Cryptographic token issuance and verification.
- Policy-enforced declassification rules.
- Live inspection of benchmark traces and execution timelines.
*Read more: [`docs/interactive-sandbox.md`](docs/interactive-sandbox.md).*

---

## 🔬 Benchmark & Research Evaluation

TaintWatch includes a comprehensive benchmark suite generated from a deterministic seed, providing reproducible evaluation against 600+ multi-vector attack scenarios and 200 benign agent tasks.

```bash
# Run full benchmark evaluation across all baselines
python -m taintwatch.evaluation

# Run outside-sink evasion experiments
python -m taintwatch.evaluation.outside

# Run query-budget adversary evaluation
python -m taintwatch.adversary
```

Detailed research documentation:
- [`docs/benchmark.md`](docs/benchmark.md): Scenario generator and attack taxonomy.
- [`docs/baselines.md`](docs/baselines.md): Baseline defense models (keyword, heuristic, spotlighting).
- [`docs/evaluation.md`](docs/evaluation.md): Full evaluation methodology and metric calculations.
- [`docs/adversary.md`](docs/adversary.md): Query-budget adaptive adversary analysis.
- [`docs/outside.md`](docs/outside.md): Analysis of attacks targeting sinks beyond default policies.
- [`paper/README.md`](paper/README.md): Reproducible LaTeX research paper generator.

---

## 🤝 Community & 30+ Contributor Tasks

We are actively building the open-source community around TaintWatch! We have created a curated catalog of **30 concrete, actionable tasks** designed for developers of all experience levels:

👉 **[Explore the 30 Contributor Tasks Catalog (`docs/CONTRIBUTING_TASKS_30.md`)](docs/CONTRIBUTING_TASKS_30.md)**

Tasks are organized across 6 distinct categories:
- 🔌 **Integrations**: AutoGen, CrewAI, Semantic Kernel, LlamaIndex, Haystack.
- 🔤 **Parsers & Decoders**: ROT13, Morse code, Brainfuck, Unicode homoglyphs, JSON-in-URL.
- 🔍 **Detectors & Analyzers**: Regex leak detector, credit card validator, PII detectors.
- 💻 **CLI & Developer Tools**: Visual diff CLI, policy linter, export commands.
- 🌐 **Web UI & Visualizations**: DAG graph viewer, dark mode toggle, export trace to HAR.
- 📊 **Benchmarks & Testing**: Additional indirect prompt injection vectors.

Check out our [Contributing Guide](CONTRIBUTING.md) and [Code of Conduct](CODE_OF_CONDUCT.md) to get started!

---

## 📚 Complete Documentation Index

| Guide | Description |
|:---|:---|
| [`docs/fast-span-index.md`](docs/fast-span-index.md) | Augmented interval tree architecture & $O(\log N)$ span tracking |
| [`docs/span-tracking.md`](docs/span-tracking.md) | `TStr` primitives, slicing, concatenation, and taint propagation |
| [`docs/canonicalization.md`](docs/canonicalization.md) | Anti-evasion canonicalizer and taint-preserving decoders |
| [`docs/cryptographic-tokens.md`](docs/cryptographic-tokens.md) | Merkle provenance trees, HMAC tokens, and anti-replay cache |
| [`docs/covert-channels.md`](docs/covert-channels.md) | Differential taint testing & Shannon entropy budgets |
| [`docs/declassification.md`](docs/declassification.md) | Grammar-bounded declassification sandboxes |
| [`docs/integrations.md`](docs/integrations.md) | MCP, OpenAI, and LangChain integration architecture |
| [`docs/interactive-sandbox.md`](docs/interactive-sandbox.md) | Interactive security playground & REST endpoints |
| [`docs/policy-language.md`](docs/policy-language.md) | Declarative `.twp` policy language specification |
| [`docs/agent-runtime.md`](docs/agent-runtime.md) | Guarded tool execution runtime |
| [`docs/server.md`](docs/server.md) | REST API endpoints and SQLite persistence |
| [`docs/web.md`](docs/web.md) | React + TypeScript web interface architecture |
| [`docs/CONTRIBUTING_TASKS_30.md`](docs/CONTRIBUTING_TASKS_30.md) | Curated catalog of 30 open contributor issues |

---

## 📄 License

TaintWatch is licensed under the **[Apache License 2.0](LICENSE)**.
Commercial and non-commercial usage permitted. Contributions are warmly welcomed.
