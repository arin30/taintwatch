"""Run the query-budget analysis for several defenses and render the results."""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass

from taintwatch.adversary.pool import build_pools
from taintwatch.adversary.search import expected_queries, success_at
from taintwatch.baselines import build_defense
from taintwatch.bench import Scenario
from taintwatch.guard import ConfirmFn

DEFAULT_BUDGETS = (1, 2, 5, 10, 25, 50)
NOTES = (
    "Every variant of every goal is run once, so the rates are exact for this grid. They say "
    "nothing about variants the grid does not contain.",
    "success@k is the chance that an attacker trying k distinct variants in random order gets "
    "at least one through. Expected queries is (N+1)/(s+1) for s working variants of N.",
    "This is random search, not an attacker that learns from failures, so it understates a "
    "smarter adversary.",
    "No variant changes a data label or opens a new channel, so a defense that is flat at 0% "
    "has only been shown to resist this grid. The outside-the-sinks goals show attacks that do "
    "get through.",
    "Spotlight depends on an assumed resistance probability, not a measurement.",
)


@dataclass(frozen=True, slots=True)
class GoalResult:
    defense: str
    goal: str
    size: int
    successes: int
    curve: tuple[tuple[int, float], ...]
    expected_queries: float | None

    @property
    def rate(self) -> float:
        return self.successes / self.size if self.size else 0.0


def validate_budgets(budgets: Sequence[int]) -> tuple[int, ...]:
    if not budgets or any(k < 1 for k in budgets):
        raise ValueError("budgets must be a non-empty list of positive integers")
    return tuple(sorted(set(budgets)))


def analyze(
    specs: Sequence[str],
    scenarios: Sequence[Scenario],
    budgets: Sequence[int] = DEFAULT_BUDGETS,
    *,
    seed: int = 7,
    confirm: ConfirmFn | None = None,
) -> list[GoalResult]:
    """One result per (defense, goal), defenses in the order given."""
    ks = validate_budgets(budgets)
    results: list[GoalResult] = []
    for spec in specs:
        defense = build_defense(spec)
        for goal, pool in build_pools(defense, scenarios, seed=seed, confirm=confirm).items():
            curve = tuple((k, success_at(pool, k)) for k in ks)
            results.append(
                GoalResult(
                    defense.name, goal, pool.size, pool.successes, curve, expected_queries(pool)
                )
            )
    return results


def _pct(value: float) -> str:
    return f"{value:.1%}"


def _queries(value: float | None) -> str:
    return "never" if value is None else f"{value:.1f}"


def _table(headers: Sequence[str], rows: Sequence[Sequence[str]]) -> str:
    lines = ["| " + " | ".join(headers) + " |", "|" + "|".join("---" for _ in headers) + "|"]
    lines.extend("| " + " | ".join(row) + " |" for row in rows)
    return "\n".join(lines)


def worst_goals(results: Sequence[GoalResult]) -> list[GoalResult]:
    """For each defense, the goal with the most working variants (ties: first listed)."""
    best: dict[str, GoalResult] = {}
    for result in results:
        current = best.get(result.defense)
        if current is None or result.rate > current.rate:
            best[result.defense] = result
    return list(best.values())


def render_markdown(results: Sequence[GoalResult], budgets: Sequence[int]) -> str:
    ks = validate_budgets(budgets)
    parts = [
        "# Taintwatch: query-budget attacker",
        "",
        "How many tries does an attacker need? Each cell is the chance that k random variants "
        "of one goal include at least one that succeeds.",
        "",
        "## Attacker's best goal per defense",
        "",
    ]
    summary_headers = ["defense", "best goal", "variants that work", *(f"@{k}" for k in ks)]
    summary_headers.append("expected queries")
    summary_rows = [
        [
            r.defense,
            r.goal,
            f"{r.successes}/{r.size} ({_pct(r.rate)})",
            *(_pct(value) for _, value in r.curve),
            _queries(r.expected_queries),
        ]
        for r in worst_goals(results)
    ]
    parts.append(_table(summary_headers, summary_rows))
    parts += ["", "## By goal", ""]
    detail_headers = ["defense", "goal", "variants that work", *(f"@{k}" for k in ks)]
    detail_headers.append("expected queries")
    detail_rows = [
        [
            r.defense,
            r.goal,
            f"{r.successes}/{r.size}",
            *(_pct(value) for _, value in r.curve),
            _queries(r.expected_queries),
        ]
        for r in results
    ]
    parts.append(_table(detail_headers, detail_rows))
    parts += ["", "## Notes", ""]
    parts += [f"- {note}" for note in NOTES]
    return "\n".join(parts) + "\n"


def curves_csv(results: Sequence[GoalResult]) -> str:
    lines = ["defense,goal,size,successes,k,success_at"]
    for r in results:
        for k, value in r.curve:
            lines.append(f"{r.defense},{r.goal},{r.size},{r.successes},{k},{value:.6f}")
    return "\n".join(lines) + "\n"
