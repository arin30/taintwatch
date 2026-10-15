"""Query-budget attacker analysis."""

from __future__ import annotations

from taintwatch.adversary.analysis import (
    DEFAULT_BUDGETS,
    GoalResult,
    analyze,
    curves_csv,
    render_markdown,
    validate_budgets,
    worst_goals,
)
from taintwatch.adversary.pool import Pool, build_pools
from taintwatch.adversary.search import expected_queries, simulate, success_at

__all__ = [
    "DEFAULT_BUDGETS",
    "GoalResult",
    "Pool",
    "analyze",
    "build_pools",
    "curves_csv",
    "expected_queries",
    "render_markdown",
    "simulate",
    "success_at",
    "validate_budgets",
    "worst_goals",
]
