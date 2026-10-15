"""LaTeX tables and number macros generated from the result files."""

from __future__ import annotations

import csv
from collections.abc import Sequence
from dataclasses import dataclass, field
from pathlib import Path

from taintwatch.evaluation import (
    RunRecord,
    attack_breakdown,
    benign_breakdown,
    read_records,
    summarize,
)
from taintwatch.evaluation.stats import Rate

_ESCAPES = {
    "\\": r"\textbackslash{}",
    "&": r"\&",
    "%": r"\%",
    "$": r"\$",
    "#": r"\#",
    "_": r"\_",
    "{": r"\{",
    "}": r"\}",
    "~": r"\textasciitilde{}",
    "^": r"\textasciicircum{}",
}
DEFAULT_BUDGETS = (1, 10, 25)


def escape(text: str) -> str:
    """Escape LaTeX special characters in data (defense names, goals, families)."""
    return "".join(_ESCAPES.get(ch, ch) for ch in text)


def _p(value: float) -> str:
    return f"{value * 100:.1f}\\%"


def _rate(rate: Rate) -> str:
    low, high = rate.interval()
    return f"{_p(rate.value)} [{low * 100:.1f}, {high * 100:.1f}]"


def _table(
    caption: str,
    label: str,
    headers: Sequence[str],
    rows: Sequence[Sequence[str]],
    align: str,
) -> str:
    lines = [
        r"\begin{table}[t]",
        r"\centering",
        r"\small",
        rf"\caption{{{caption}}}",
        rf"\label{{{label}}}",
        rf"\begin{{tabular}}{{{align}}}",
        r"\toprule",
        " & ".join(headers) + r" \\",
        r"\midrule",
        *(" & ".join(row) + r" \\" for row in rows),
        r"\bottomrule",
        r"\end{tabular}",
        r"\end{table}",
    ]
    return "\n".join(lines) + "\n"


def main_table(records: Sequence[RunRecord]) -> str:
    rows = [
        [
            escape(s.defense),
            _rate(s.attack_success),
            _p(s.benign_utility.value),
            _p(s.utility_under_attack.value),
        ]
        for s in summarize(records)
    ]
    caption = (
        r"Main benchmark: \NAttacks{} attacks and \NBenign{} benign tasks per defense. "
        r"Attack success is a percentage with its 95\% Wilson interval."
    )
    headers = ["Defense", r"Attack success [95\% CI]", "Benign utility", "Utility under attack"]
    return _table(caption, "tab:main", headers, rows, "lrrr")


def outside_table(records: Sequence[RunRecord]) -> str:
    names = [s.defense for s in summarize(records)]
    goals = sorted({r.tag("goal") for r in records if r.is_attack})
    rows = []
    for name in names:
        rates = attack_breakdown(records, name, "goal")
        cells = [_p(rates[g].value) if g in rates else "n/a" for g in goals]
        rows.append([escape(name), *cells])
    caption = r"Attack success (\%) on four goals outside the default policy's guarded sinks."
    headers = ["Defense", *(escape(g) for g in goals)]
    return _table(caption, "tab:outside", headers, rows, "l" + "r" * len(goals))


def ablation_table(
    records: Sequence[RunRecord], span: str = "taintwatch", coarse: str = "taintwatch-coarse"
) -> str:
    by_span = benign_breakdown(records, span)
    by_coarse = benign_breakdown(records, coarse)
    if not by_span or not by_coarse:
        raise ValueError("records lack the ablation defenses")
    rows = [
        [
            escape(family.split("/")[-1]),
            _p(rate.value),
            _p(by_coarse[family].value) if family in by_coarse else "n/a",
        ]
        for family, rate in by_span.items()
    ]
    caption = r"Benign utility (\%) with span-level versus whole-context labels."
    headers = ["Task family", "Span-level", "Whole-context"]
    return _table(caption, "tab:ablation", headers, rows, "lrr")


@dataclass
class Curve:
    """Retry curve for one (defense, goal): ``successes`` of ``size`` variants work."""

    defense: str
    goal: str
    size: int
    successes: int
    values: dict[int, float] = field(default_factory=dict)


def read_curves(path: str | Path) -> list[Curve]:
    found: dict[tuple[str, str], Curve] = {}
    with Path(path).open(encoding="utf-8", newline="") as handle:
        for row in csv.DictReader(handle):
            key = (row["defense"], row["goal"])
            curve = found.setdefault(
                key, Curve(row["defense"], row["goal"], int(row["size"]), int(row["successes"]))
            )
            curve.values[int(row["k"])] = float(row["success_at"])
    return list(found.values())


def adversary_table(curves: Sequence[Curve], budgets: Sequence[int] = DEFAULT_BUDGETS) -> str:
    best: dict[str, Curve] = {}
    for curve in curves:
        current = best.get(curve.defense)
        if current is None or curve.successes / curve.size > current.successes / current.size:
            best[curve.defense] = curve
    rows = []
    for curve in best.values():
        missing = [k for k in budgets if k not in curve.values]
        if missing:
            raise ValueError(f"no success@{missing[0]} data for {curve.defense}")
        rows.append(
            [escape(curve.defense), escape(curve.goal), *(_p(curve.values[k]) for k in budgets)]
        )
    caption = (
        r"Chance (\%) that $k$ random variants of the attacker's best goal include one that "
        r"succeeds."
    )
    headers = ["Defense", "Best goal", *(f"$k{{=}}{k}$" for k in budgets)]
    return _table(caption, "tab:adversary", headers, rows, "ll" + "r" * len(budgets))


def numbers_tex(main: Sequence[RunRecord], outside: Sequence[RunRecord]) -> str:
    """``\\newcommand`` macros for the figures quoted in the paper text."""
    primary = {s.defense: s for s in summarize(main)}
    secondary = {s.defense: s for s in summarize(outside)}
    for name in ("none", "taintwatch", "taintwatch-coarse"):
        if name not in primary:
            raise ValueError(f"defense {name!r} not found in the main records")
    for name in ("taintwatch", "taintwatch-strict"):
        if name not in secondary:
            raise ValueError(f"defense {name!r} not found in the outside records")
    reference = primary["none"]
    macros = {
        "NAttacks": str(reference.attack_success.total),
        "NBenign": str(reference.benign_utility.total),
        "TwAttackHi": _p(primary["taintwatch"].attack_success.interval()[1]),
        "TwBenign": _p(primary["taintwatch"].benign_utility.value),
        "CoarseBenign": _p(primary["taintwatch-coarse"].benign_utility.value),
        "OutNAttacks": str(secondary["taintwatch"].attack_success.total),
        "OutTwAttack": _p(secondary["taintwatch"].attack_success.value),
        "OutStrictAttack": _p(secondary["taintwatch-strict"].attack_success.value),
    }
    return "\n".join(rf"\newcommand{{\{k}}}{{{v}}}" for k, v in macros.items()) + "\n"


def write_all(results_dir: str | Path, out_dir: str | Path) -> list[Path]:
    """Read the result files and write every generated LaTeX file. Returns the paths."""
    base = Path(results_dir)
    main = read_records(base / "records.csv")
    outside = read_records(base / "outside" / "records.csv")
    curves = read_curves(base / "adversary" / "curves.csv")
    files = {
        "numbers.tex": numbers_tex(main, outside),
        "tab_main.tex": main_table(main),
        "tab_outside.tex": outside_table(outside),
        "tab_adversary.tex": adversary_table(curves),
        "tab_ablation.tex": ablation_table(main),
    }
    target = Path(out_dir)
    target.mkdir(parents=True, exist_ok=True)
    written: list[Path] = []
    for name, content in files.items():
        path = target / name
        path.write_bytes(content.encode("utf-8"))
        written.append(path)
    return written
