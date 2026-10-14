"""Covert channel analysis, entropy budget tracking, and implicit information flow defense."""

from __future__ import annotations

from taintwatch.covert.differential import (
    DecisionFn,
    DifferentialTaintAnalyzer,
    ImplicitFlowViolation,
    ImplicitLeakReport,
)
from taintwatch.covert.entropy import (
    LeakageBudget,
    estimate_channel_capacity,
    shannon_entropy,
)
from taintwatch.covert.guard_ext import CovertChannelGuard

__all__ = [
    "CovertChannelGuard",
    "DecisionFn",
    "DifferentialTaintAnalyzer",
    "ImplicitFlowViolation",
    "ImplicitLeakReport",
    "LeakageBudget",
    "estimate_channel_capacity",
    "shannon_entropy",
]
