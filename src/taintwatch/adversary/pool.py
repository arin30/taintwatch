"""Per-goal attack pools: how many variants of each goal get through a defense."""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass

from taintwatch.baselines import Defense, run_defended
from taintwatch.bench import Scenario
from taintwatch.guard import ConfirmFn


@dataclass(frozen=True, slots=True)
class Pool:
    """``successes`` of ``size`` variants of one goal succeed against a defense."""

    goal: str
    size: int
    successes: int

    @property
    def rate(self) -> float:
        return self.successes / self.size if self.size else 0.0


def build_pools(
    defense: Defense,
    scenarios: Sequence[Scenario],
    *,
    seed: int = 7,
    confirm: ConfirmFn | None = None,
) -> dict[str, Pool]:
    """Run every attack once and group the outcomes by goal (sorted by goal name)."""
    counts: dict[str, list[int]] = {}
    for scenario in scenarios:
        if not scenario.is_attack:
            raise ValueError(f"scenario {scenario.id} is not an attack")
        outcome = run_defended(scenario, defense, seed=seed, confirm=confirm)
        entry = counts.setdefault(scenario.meta_value("goal"), [0, 0])
        entry[0] += 1
        entry[1] += int(outcome.attack_succeeded)
    return {goal: Pool(goal, n, s) for goal, (n, s) in sorted(counts.items())}
