"""Run the analysis: ``python -m taintwatch.adversary [--defenses SPEC ...]``."""

from __future__ import annotations

import argparse
import sys
from collections.abc import Sequence
from pathlib import Path

from taintwatch.adversary.analysis import DEFAULT_BUDGETS, analyze, curves_csv, render_markdown
from taintwatch.bench import (
    GRID_SIZE,
    OUTSIDE_GRID_SIZE,
    generate_attacks,
    generate_outside_attacks,
)
from taintwatch.guard import ConfirmFn
from taintwatch.policy import Verdict

DEFAULT_SPECS = (
    "none",
    "taintwatch",
    "taintwatch-coarse",
    "taintwatch-strict",
    "keyword",
    "scorer",
    "spotlight",
)


def _approve(tool: str, verdict: Verdict) -> bool:
    return True


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="python -m taintwatch.adversary",
        description="How many tries does an attacker need against each defense?",
    )
    parser.add_argument("--defenses", nargs="+", default=list(DEFAULT_SPECS))
    parser.add_argument("--budgets", nargs="+", type=int, default=list(DEFAULT_BUDGETS))
    parser.add_argument("--seed", type=int, default=7)
    parser.add_argument("--confirm", action="store_true", help="auto-approve confirm verdicts")
    parser.add_argument("--out", default="results/adversary")
    args = parser.parse_args(argv)
    confirm: ConfirmFn | None = _approve if args.confirm else None
    try:
        scenarios = [
            *generate_attacks(GRID_SIZE, args.seed),
            *generate_outside_attacks(OUTSIDE_GRID_SIZE, args.seed),
        ]
        results = analyze(
            args.defenses, scenarios, args.budgets, seed=args.seed, confirm=confirm
        )
    except ValueError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1

    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    markdown = render_markdown(results, args.budgets)
    (out / "report.md").write_text(markdown, encoding="utf-8")
    (out / "curves.csv").write_text(curves_csv(results), encoding="utf-8", newline="\n")
    print(markdown)
    print(f"wrote {len(results)} rows to {out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
