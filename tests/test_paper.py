from pathlib import Path

import pytest

from taintwatch.adversary import analyze, curves_csv
from taintwatch.baselines import build_defense
from taintwatch.bench import (
    build_suite,
    generate_attacks,
    generate_benign,
    generate_outside_attacks,
)
from taintwatch.evaluation import evaluate, read_records, write_csv
from taintwatch.paper import (
    ablation_table,
    adversary_table,
    escape,
    main_table,
    numbers_tex,
    outside_table,
    read_curves,
    write_all,
)
from taintwatch.paper.__main__ import main

ROOT = Path(__file__).resolve().parents[1]
FILES = {"numbers.tex", "tab_main.tex", "tab_outside.tex", "tab_adversary.tex", "tab_ablation.tex"}


@pytest.fixture(scope="module")
def results_dir(tmp_path_factory: pytest.TempPathFactory) -> Path:
    base = tmp_path_factory.mktemp("results")
    suite = build_suite(20, 14)
    main_defenses = [build_defense(s) for s in ("none", "taintwatch", "taintwatch-coarse")]
    write_csv(evaluate(suite.scenarios, main_defenses), base / "records.csv")
    outside = [*generate_outside_attacks(8), *generate_benign(7)]
    outside_defenses = [build_defense(s) for s in ("none", "taintwatch", "taintwatch-strict")]
    write_csv(evaluate(outside, outside_defenses), base / "outside" / "records.csv")
    attacks = [*generate_attacks(10), *generate_outside_attacks(8)]
    curves = analyze(["none", "taintwatch"], attacks, [1, 10, 25])
    (base / "adversary").mkdir()
    (base / "adversary" / "curves.csv").write_text(curves_csv(curves), encoding="utf-8")
    return base


def test_escape() -> None:
    assert escape("a_b & 50% #1") == r"a\_b \& 50\% \#1"
    assert escape("plain-text@2.5") == "plain-text@2.5"
    assert escape("{x}") == r"\{x\}"


def test_main_table(results_dir: Path) -> None:
    text = main_table(read_records(results_dir / "records.csv"))
    assert text.startswith(r"\begin{table}[t]")
    assert text.endswith("\\end{table}\n")
    assert r"\toprule" in text
    assert r"taintwatch & 0.0\% [0.0, 16.1] & 85.7\% & 100.0\% \\" in text
    assert r"none & 100.0\% [83.9, 100.0] & 100.0\% & 100.0\% \\" in text


def test_outside_table(results_dir: Path) -> None:
    text = outside_table(read_records(results_dir / "outside" / "records.csv"))
    assert r"answer\_poison & exfil\_get & exfil\_internal & exfil\_mislabeled" in text
    assert r"taintwatch-strict & 100.0\% & 0.0\% & 0.0\% & 100.0\% \\" in text
    assert r"taintwatch & 100.0\% & 100.0\% & 100.0\% & 100.0\% \\" in text


def test_ablation_table(results_dir: Path) -> None:
    records = read_records(results_dir / "records.csv")
    text = ablation_table(records)
    assert r"email\_summary & 100.0\% & 0.0\% \\" in text
    assert r"save\_notes & 0.0\% & 0.0\% \\" in text
    with pytest.raises(ValueError):
        ablation_table(records, coarse="missing")


def test_adversary_table(results_dir: Path) -> None:
    curves = read_curves(results_dir / "adversary" / "curves.csv")
    assert len(curves) == 18
    text = adversary_table(curves)
    assert r"none & answer\_poison & 100.0\% & 100.0\% & 100.0\% \\" in text
    assert "$k{=}25$" in text
    with pytest.raises(ValueError):
        adversary_table(curves, budgets=(1, 7))


def test_number_macros(results_dir: Path) -> None:
    main = read_records(results_dir / "records.csv")
    outside = read_records(results_dir / "outside" / "records.csv")
    text = numbers_tex(main, outside)
    assert r"\newcommand{\NAttacks}{20}" in text
    assert r"\newcommand{\NBenign}{14}" in text
    assert r"\newcommand{\TwAttackHi}{16.1\%}" in text
    assert r"\newcommand{\TwBenign}{85.7\%}" in text
    assert r"\newcommand{\CoarseBenign}{71.4\%}" in text
    assert r"\newcommand{\OutNAttacks}{8}" in text
    assert r"\newcommand{\OutTwAttack}{100.0\%}" in text
    assert r"\newcommand{\OutStrictAttack}{50.0\%}" in text
    with pytest.raises(ValueError):
        numbers_tex([r for r in main if r.defense == "none"], outside)


def test_cli(results_dir: Path, tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    out = tmp_path / "gen"
    assert main(["--results", str(results_dir), "--out", str(out)]) == 0
    assert {p.name for p in out.iterdir()} == FILES
    assert capsys.readouterr().out.count("wrote") == 5


def test_cli_reports_missing_results(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    assert main(["--results", str(tmp_path / "none"), "--out", str(tmp_path / "o")]) == 1
    assert "error" in capsys.readouterr().err


def test_paper_uses_only_generated_macros() -> None:
    tex = (ROOT / "paper" / "main.tex").read_text(encoding="utf-8")
    macros = (ROOT / "paper" / "generated" / "numbers.tex").read_text(encoding="utf-8")
    for name in ("NAttacks", "NBenign", "TwAttackHi", "TwBenign", "CoarseBenign",
                 "OutNAttacks", "OutTwAttack", "OutStrictAttack"):
        assert rf"\newcommand{{\{name}}}" in macros
        assert rf"\{name}{{}}" in tex
    for table in ("tab_main", "tab_outside", "tab_adversary", "tab_ablation"):
        assert rf"\input{{generated/{table}}}" in tex


def test_committed_tables_match_the_results(tmp_path: Path) -> None:
    for fresh in write_all(ROOT / "results", tmp_path / "gen"):
        committed = ROOT / "paper" / "generated" / fresh.name
        assert committed.exists(), f"missing {committed}"
        assert committed.read_bytes() == fresh.read_bytes(), f"{fresh.name} is stale"
