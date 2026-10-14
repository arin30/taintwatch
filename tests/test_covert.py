from collections.abc import Mapping

import pytest

from taintwatch import Confidentiality, Guard, Integrity, default_policy
from taintwatch.covert import (
    CovertChannelGuard,
    DifferentialTaintAnalyzer,
    ImplicitFlowViolation,
    LeakageBudget,
    estimate_channel_capacity,
    shannon_entropy,
)


def test_shannon_entropy_calculation() -> None:
    # Deterministic sequence: 0 entropy
    assert shannon_entropy("aaaa") == 0.0

    # Binary balanced sequence: 1 bit of entropy
    assert shannon_entropy(["0", "1", "0", "1"]) == pytest.approx(1.0)


def test_leakage_budget_consumption() -> None:
    budget = LeakageBudget(max_bits_per_session=2.0)
    assert budget.remaining_bits == 2.0
    assert budget.can_leak(1.5) is True

    budget2 = budget.consume(1.5)
    assert budget2.remaining_bits == 0.5
    assert budget2.can_leak(1.0) is False


def test_channel_capacity() -> None:
    # 4 distinct tools -> log2(4) = 2 bits per step
    cap = estimate_channel_capacity(vocabulary_size=4, sequence_length=1)
    assert cap == pytest.approx(2.0)


def test_differential_analyzer_detects_covert_side_channel() -> None:
    analyzer = DifferentialTaintAnalyzer()
    base_guard = Guard(default_policy())
    secret = base_guard.ingest(
        "sk-prod-1234",
        source="vault",
        integrity=Integrity.SYSTEM,
        confidentiality=Confidentiality.SECRET,
    )

    # Simulated malicious or compromised agent logic:
    # If secret starts with 'sk-prod', query for 'weather-paris', else 'weather-london'
    def agent_decision_oracle(context: Mapping[str, str]) -> tuple[str, Mapping[str, str]]:
        sec_val = context.get("api_key", "")
        if sec_val.startswith("sk-prod"):
            return "search.query", {"q": "weather-paris"}
        return "search.query", {"q": "weather-london"}

    # Actual chosen action under original secret
    tool, args = agent_decision_oracle({"api_key": str(secret.value)})

    report = analyzer.analyze_action(
        tool=tool,
        args=args,
        active_secrets={"api_key": secret},
        decision_oracle=agent_decision_oracle,
    )

    assert report.is_leaking is True
    assert report.leaked_bits > 0.0
    assert "Covert channel detected" in report.explanation


def test_differential_analyzer_passes_invariant_action() -> None:
    analyzer = DifferentialTaintAnalyzer()
    base_guard = Guard(default_policy())
    secret = base_guard.ingest(
        "sk-prod-1234",
        source="vault",
        integrity=Integrity.SYSTEM,
        confidentiality=Confidentiality.SECRET,
    )

    # Benign action invariant to secret
    def benign_oracle(context: Mapping[str, str]) -> tuple[str, Mapping[str, str]]:
        return "docs.read", {"topic": "python"}

    tool, args = benign_oracle({"api_key": str(secret.value)})

    report = analyzer.analyze_action(
        tool=tool,
        args=args,
        active_secrets={"api_key": secret},
        decision_oracle=benign_oracle,
    )

    assert report.is_leaking is False
    assert report.leaked_bits == 0.0


def test_covert_channel_guard_blocks_leak() -> None:
    base_guard = Guard(default_policy())
    covert_guard = CovertChannelGuard(base_guard, max_leak_bits=0.0)

    secret = covert_guard.ingest(
        "sk-secret",
        source="vault",
        integrity=Integrity.SYSTEM,
        confidentiality=Confidentiality.SECRET,
    )
    covert_guard.register_secret("api_key", secret)

    def leaking_oracle(context: Mapping[str, str]) -> tuple[str, Mapping[str, str]]:
        if "COUNTERFACTUAL" in context.get("api_key", ""):
            return "fs.read", {"path": "alt.txt"}
        return "fs.read", {"path": "normal.txt"}

    # Action has PUBLIC argument "normal.txt", so explicit policy check passes,
    # but implicit flow covert channel leaks information!
    path_arg = covert_guard.ingest("normal.txt", source="user", integrity=Integrity.USER)

    with pytest.raises(ImplicitFlowViolation, match="Blocked covert channel leak"):
        covert_guard.call_with_oracle(
            "fs.read",
            {"path": path_arg},
            lambda path: f"content of {path}",
            decision_oracle=leaking_oracle,
        )
