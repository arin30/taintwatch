[![CI](https://github.com/eyadstein/taintwatch/actions/workflows/ci.yml/badge.svg)](https://github.com/eyadstein/taintwatch/actions/workflows/ci.yml)

# Taintwatch

Runtime information-flow control for LLM agents. Every piece of data carries an
integrity and confidentiality label plus a provenance trail. Tool calls are
checked against a declarative policy, so untrusted text (a web page, an inbound
email) cannot silently steer shell commands or leak secrets.

Status: early research prototype.

## Policy language

Policies can be written in a small purpose-built language with a static validator.
See `docs/policy-language.md` and `policies/default.twp`.

## Span-level tracking

`taintwatch.spans.TStr` labels character ranges instead of whole values.
See `docs/span-tracking.md`.

## Anti-evasion and canonicalization

`taintwatch.spans.canonical` provides zero-width stripping, Unicode homoglyph normalization,
and taint-preserving multi-layer decoding (Base64, URL percent, hex, HTML entities).
See `docs/canonicalization.md`.

## Cryptographic Inter-Agent Taint Tokens

`taintwatch.crypto` provides zero-trust HMAC-SHA256 attestations, Merkle provenance trees,
and anti-replay protection for distributed multi-agent workflows.
See `docs/cryptographic-tokens.md`.

## Differential Taint & Covert Channel Defense

`taintwatch.covert` detects implicit flows and side-channel leakage by evaluating counterfactual
action divergence and Shannon entropy budgets.
See `docs/covert-channels.md`.

## Policy-Enforced Declassification Sandboxes

Taintwatch supports declarative declassification contracts and grammar-bounded sanitizers
to safely promote validated values into privileged sinks without vulnerability.
See `docs/declassification.md`.

## Agent runtime

`taintwatch.agent` provides a tool registry, a simulated world and a runtime that routes
every tool call through the guard. See `docs/agent-runtime.md`.

## Benchmark

`taintwatch.bench` generates 600+ attack scenarios and 200 benign tasks from a seed.
See `docs/benchmark.md`. The generated dataset is in `data/scenarios.jsonl`.

## Baselines

`taintwatch.baselines` implements the defenses we compare against: keyword filter,
heuristic scorer, a spotlighting model and a coarse-taint ablation.
Try `python -m taintwatch.baselines`. See `docs/baselines.md`.

## Evaluation

`python -m taintwatch.evaluation` runs the benchmark under every defense and writes
`results/records.csv`, `results/summary.json` and `results/report.md`.
See `docs/evaluation.md`.

## Server

`python -m taintwatch.server` serves a REST API over the benchmark with a SQLite trace store.
Install with `pip install -e ".[dev,server]"`. See `docs/server.md`.

## Trace viewer & Security Sandbox

`web/` holds a React + TypeScript viewer for stored runs and an interactive security playground
for anti-evasion testing, token verification, and declassification contracts.
See `docs/web.md` and `docs/interactive-sandbox.md`.

## Analysis

`python -m taintwatch.analysis sweeps` writes parameter sweeps and `notebooks/` holds two
generated Jupyter notebooks. See `docs/analysis.md`.

## Outside the guarded sinks

`python -m taintwatch.evaluation.outside` runs four attack goals the default policy does not
cover, plus a stricter `taintwatch-strict` policy. See `docs/outside.md`.

## Query-budget attacker

`python -m taintwatch.adversary` measures how many retries an attacker needs against each
defense, using the full attack grid. See `docs/adversary.md`.
