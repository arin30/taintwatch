"""Covert channel and implicit flow protection extension for Guard."""

from __future__ import annotations

from collections.abc import Callable, Mapping
from typing import Any, TypeVar

from taintwatch.covert.differential import (
    DecisionFn,
    DifferentialTaintAnalyzer,
    ImplicitFlowViolation,
)
from taintwatch.covert.entropy import LeakageBudget
from taintwatch.guard import Guard, PolicyViolation
from taintwatch.labels import Confidentiality, Integrity
from taintwatch.policy import Action
from taintwatch.tainted import Labeled

R = TypeVar("R")


class CovertChannelGuard(Guard):
    """Guard extension that enforces explicit IFC and implicit covert-channel limits."""

    def __init__(
        self,
        guard: Guard,
        *,
        max_leak_bits: float = 0.0,
        decision_oracle: DecisionFn | None = None,
    ) -> None:
        super().__init__(
            policy=guard._policy,
            graph=guard._graph,
            confirm=guard._confirm,
            canonicalize=guard._canonicalize,
        )
        self._budget = LeakageBudget(max_bits_per_session=max_leak_bits)
        self._analyzer = DifferentialTaintAnalyzer()
        self._decision_oracle = decision_oracle
        self._secrets: dict[str, Labeled[Any]] = {}

    def register_secret(self, name: str, labeled: Labeled[Any]) -> None:
        """Register a secret currently in the agent's context memory."""
        if labeled.label.confidentiality >= Confidentiality.SECRET:
            self._secrets[name] = labeled

    def call_with_oracle(
        self,
        tool: str,
        args: Mapping[str, Labeled[Any]],
        fn: Callable[..., R],
        *,
        decision_oracle: DecisionFn | None = None,
        output_integrity: Integrity = Integrity.TOOL_OUTPUT,
    ) -> Labeled[R]:
        """Gating tool calls against explicit policies AND differential implicit flow leaks."""
        # 1. Run explicit check first
        verdict = self.check(tool, args)
        if verdict.action is Action.BLOCK:
            raise PolicyViolation(tool, verdict)

        # 2. Run implicit flow covert-channel check
        str_args = {k: str(v.value) for k, v in args.items()}
        oracle = decision_oracle if decision_oracle is not None else self._decision_oracle

        if self._secrets and oracle is not None:
            report = self._analyzer.analyze_action(
                tool=tool,
                args=str_args,
                active_secrets=self._secrets,
                decision_oracle=oracle,
            )
            if report.is_leaking:
                if not self._budget.can_leak(report.leaked_bits):
                    raise ImplicitFlowViolation(
                        f"Blocked covert channel leak on tool {tool!r}: {report.explanation}"
                    )
                self._budget = self._budget.consume(report.leaked_bits)

        # 3. Call underlying tool implementation
        return self.call(tool, args, fn, output_integrity=output_integrity)
