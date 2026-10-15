# Query-budget attacker

    python -m taintwatch.adversary
    python -m taintwatch.adversary --defenses none taintwatch-strict spotlight --budgets 1 10 100
    python -m taintwatch.adversary --confirm      # auto-approve confirm verdicts

Writes `results/adversary/report.md` and `results/adversary/curves.csv`.

Every variant of every goal is run once against each defense: the 1,080 main variants (five
goals) and the 864 outside-the-sinks variants (four goals), 216 per goal. For `s` working
variants out of `N`, an attacker who tries `k` distinct variants in random order succeeds with
probability `1 - C(N-s, k) / C(N, k)`, and needs `(N+1)/(s+1)` tries on average. Both are exact
for this grid; a Monte Carlo test cross-checks the formula.

A defense with a 9% per-variant leak rate looks fine on one try and leaks almost surely within
25. A defense with no working variant stays at 0% however many tries it is given.

## Limits

- Random search, not an attacker that learns from failures. A smarter adversary does at least
  as well.
- No variant changes a data label or opens a new channel, so a flat 0% means "no variant in
  this grid works", not "no attack works". See `docs/outside.md` for attacks that do.
- The rates are exact for the grid, with no sampling error, but the grid is a modelling choice.
- Spotlight uses an assumed resistance probability.
