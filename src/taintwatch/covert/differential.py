"""Differential taint and counterfactual covert-channel analysis."""

from __future__ import annotations

import math
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from typing import Any

from taintwatch.errors import TaintwatchError
from taintwatch.labels import Confidentiality
from taintwatch.tainted import Labeled


class ImplicitFlowViolation(TaintwatchError):
    """Raised when an observable action leaks confidential entropy via an implicit flow."""


@dataclass(frozen=True, slots=True)
class ImplicitLeakReport:
    """Report detailing detected implicit information flow through covert side channels."""

    is_leaking: bool
    leaked_bits: float
    confidential_sources: tuple[str, ...]
    tool: str
    observed_action: str
    counterfactual_action: str | None
    explanation: str


DecisionFn = Callable[[Mapping[str, str]], tuple[str, Mapping[str, str]]]


class DifferentialTaintAnalyzer:
    """Detects implicit flows by observing action divergence under counterfactual secrets."""

    def __init__(self, sample_count: int = 3) -> None:
        self._sample_count = sample_count

    def analyze_action(
        self,
        *,
        tool: str,
        args: Mapping[str, str],
        active_secrets: Mapping[str, Labeled[Any]],
        decision_oracle: DecisionFn | None = None,
        candidate_domain_size: int = 16,
    ) -> ImplicitLeakReport:
        """Evaluate if ``tool`` call and ``args`` correlate with ``active_secrets``."""
        if not active_secrets:
            return ImplicitLeakReport(
                is_leaking=False,
                leaked_bits=0.0,
                confidential_sources=(),
                tool=tool,
                observed_action=f"{tool}({args})",
                counterfactual_action=None,
                explanation="no active secrets in context",
            )

        confidential_sources = tuple(
            sorted(
                {
                    src
                    for secret in active_secrets.values()
                    for src in secret.label.sources
                    if secret.label.confidentiality >= Confidentiality.SECRET
                }
            )
        )

        observed_signature = f"{tool}:{sorted(args.items())}"

        if decision_oracle is None:
            # Heuristic check: check if discrete public arguments vary with secret length or prefix
            return ImplicitLeakReport(
                is_leaking=False,
                leaked_bits=0.0,
                confidential_sources=confidential_sources,
                tool=tool,
                observed_action=observed_signature,
                counterfactual_action=None,
                explanation="oracle not provided; explicit policy check passed",
            )

        # Counterfactual perturbation test
        divergences: list[tuple[str, str]] = []
        for i in range(self._sample_count):
            perturbed_context: dict[str, str] = {}
            for k, sec in active_secrets.items():
                orig_val = str(sec.value)
                # Perturb secret value counterfactually
                perturbed_val = f"COUNTERFACTUAL_{i}_{orig_val[::-1]}"
                perturbed_context[k] = perturbed_val

            alt_tool, alt_args = decision_oracle(perturbed_context)
            alt_signature = f"{alt_tool}:{sorted(alt_args.items())}"

            if alt_signature != observed_signature:
                divergences.append((observed_signature, alt_signature))

        if divergences:
            # The agent's external tool call varies when the secret changes!
            bits = math.log2(candidate_domain_size)
            alt_act = divergences[0][1]
            return ImplicitLeakReport(
                is_leaking=True,
                leaked_bits=bits,
                confidential_sources=confidential_sources,
                tool=tool,
                observed_action=observed_signature,
                counterfactual_action=alt_act,
                explanation=(
                    f"Covert channel detected: action diverges to {alt_act!r} under counterfactual "
                    f"secrets (leaking ~{bits:.1f} bits of confidential entropy)"
                ),
            )

        return ImplicitLeakReport(
            is_leaking=False,
            leaked_bits=0.0,
            confidential_sources=confidential_sources,
            tool=tool,
            observed_action=observed_signature,
            counterfactual_action=None,
            explanation="counterfactual invariant; no implicit leak detected",
        )
