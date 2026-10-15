"""Generate the paper's tables: ``python -m taintwatch.paper [--results DIR] [--out DIR]``."""

from __future__ import annotations

import argparse
import sys
from collections.abc import Sequence

from taintwatch.paper.tables import write_all


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="python -m taintwatch.paper", description="Write LaTeX tables from the results."
    )
    parser.add_argument("--results", default="results")
    parser.add_argument("--out", default="paper/generated")
    args = parser.parse_args(argv)
    try:
        paths = write_all(args.results, args.out)
    except (OSError, ValueError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    for path in paths:
        print(f"wrote {path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
