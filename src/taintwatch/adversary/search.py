"""Success probability for an attacker who tries variants in random order, without repeats."""

from __future__ import annotations

import random
from math import comb

from taintwatch.adversary.pool import Pool
from taintwatch.evaluation import Rate


def success_at(pool: Pool, k: int) -> float:
    """Probability that at least one of ``k`` distinct random variants succeeds.

    ``1 - C(N-s, k) / C(N, k)`` for ``s`` working variants out of ``N``. ``k`` is capped at
    ``N``, because there are no more variants to try.
    """
    if k < 0:
        raise ValueError("k must not be negative")
    if pool.size <= 0:
        raise ValueError("pool is empty")
    tries = min(k, pool.size)
    if tries == 0 or pool.successes == 0:
        return 0.0
    failing = pool.size - pool.successes
    if tries > failing:
        return 1.0
    return 1.0 - comb(failing, tries) / comb(pool.size, tries)


def expected_queries(pool: Pool) -> float | None:
    """Expected number of tries until the first success, or ``None`` if none ever works."""
    if pool.size <= 0:
        raise ValueError("pool is empty")
    if pool.successes == 0:
        return None
    return (pool.size + 1) / (pool.successes + 1)


def simulate(pool: Pool, k: int, trials: int, seed: int = 0) -> Rate:
    """Monte Carlo estimate of ``success_at``, used to cross-check the closed form."""
    if trials < 1:
        raise ValueError("trials must be at least 1")
    tries = min(k, pool.size)
    rng = random.Random(seed)
    hits = 0
    for _ in range(trials):
        if any(i < pool.successes for i in rng.sample(range(pool.size), tries)):
            hits += 1
    return Rate(hits, trials)
