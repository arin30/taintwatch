from pathlib import Path

import pytest

from taintwatch.adversary import (
    DEFAULT_BUDGETS,
    Pool,
    analyze,
    build_pools,
    curves_csv,
    expected_queries,
    render_markdown,
    simulate,
    success_at,
    validate_budgets,
    worst_goals,
)
from taintwatch.adversary.__main__ import main
from taintwatch.baselines import build_defense
from taintwatch.bench import (
    GOALS,
    GRID_SIZE,
    OUTSIDE_GOALS,
    OUTSIDE_GRID_SIZE,
    Scenario,
    generate_attacks,
    generate_benign,
    generate_outside_attacks,
)

PER_GOAL = 216
MAIN = set(GOALS)
OUTSIDE = set(OUTSIDE_GOALS)


@pytest.fixture(scope="module")
def scenarios() -> list[Scenario]:
    return [*generate_attacks(GRID_SIZE), *generate_outside_attacks(OUTSIDE_GRID_SIZE)]


def pools(scenarios: list[Scenario], spec: str) -> dict[str, Pool]:
    return build_pools(build_defense(spec), scenarios)


def test_closed_form_on_a_small_pool() -> None:
    pool = Pool("g", 10, 2)
    assert success_at(pool, 0) == 0.0
    assert success_at(pool, 1) == pytest.approx(0.2)
    assert success_at(pool, 2) == pytest.approx(17 / 45)
    assert success_at(pool, 9) == 1.0
    assert success_at(pool, 500) == 1.0
    assert expected_queries(pool) == pytest.approx(11 / 3)


def test_edge_pools() -> None:
    assert success_at(Pool("g", 10, 0), 10) == 0.0
    assert expected_queries(Pool("g", 10, 0)) is None
    assert success_at(Pool("g", 10, 10), 1) == 1.0
    assert expected_queries(Pool("g", 10, 10)) == 1.0
    with pytest.raises(ValueError):
        success_at(Pool("g", 0, 0), 1)
    with pytest.raises(ValueError):
        success_at(Pool("g", 5, 1), -1)
    with pytest.raises(ValueError):
        expected_queries(Pool("g", 0, 0))


def test_success_grows_with_the_budget() -> None:
    pool = Pool("g", 216, 19)
    values = [success_at(pool, k) for k in (1, 2, 5, 10, 25, 50, 100)]
    assert values == sorted(values)
    assert values[0] == pytest.approx(19 / 216)
    assert values[-1] > 0.99


def test_monte_carlo_agrees_with_the_closed_form() -> None:
    pool = Pool("g", 100, 10)
    estimate = simulate(pool, 5, trials=20000, seed=3)
    assert estimate.value == pytest.approx(success_at(pool, 5), abs=0.02)
    with pytest.raises(ValueError):
        simulate(pool, 5, trials=0)


def test_expected_queries_matches_simulation() -> None:
    pool = Pool("g", 50, 4)
    first = [next(i for i, flag in enumerate(order) if flag) + 1 for order in _orders(pool)]
    assert sum(first) / len(first) == pytest.approx(expected_queries(pool), rel=0.05)


def _orders(pool: Pool) -> list[list[bool]]:
    import random

    rng = random.Random(5)
    flags = [True] * pool.successes + [False] * (pool.size - pool.successes)
    orders = []
    for _ in range(4000):
        shuffled = list(flags)
        rng.shuffle(shuffled)
        orders.append(shuffled)
    return orders


def test_build_pools_rejects_benign_scenarios() -> None:
    with pytest.raises(ValueError):
        build_pools(build_defense("none"), generate_benign(1))


def test_every_variant_works_without_a_defense(scenarios: list[Scenario]) -> None:
    result = pools(scenarios, "none")
    assert set(result) == MAIN | OUTSIDE
    assert all(p.size == PER_GOAL and p.successes == PER_GOAL for p in result.values())


def test_default_policy_stops_every_main_variant_and_no_outside_variant(
    scenarios: list[Scenario],
) -> None:
    result = pools(scenarios, "taintwatch")
    assert all(result[g].successes == 0 for g in MAIN)
    assert all(result[g].successes == PER_GOAL for g in OUTSIDE)
    assert success_at(result["shell_exec"], 1000) == 0.0
    assert expected_queries(result["shell_exec"]) is None


def test_strict_policy_closes_exactly_two_outside_goals(scenarios: list[Scenario]) -> None:
    result = pools(scenarios, "taintwatch-strict")
    assert all(result[g].successes == 0 for g in MAIN)
    assert result["exfil_get"].successes == 0
    assert result["exfil_internal"].successes == 0
    assert result["exfil_mislabeled"].successes == PER_GOAL
    assert result["answer_poison"].successes == PER_GOAL


def test_keyword_filter_falls_to_retries(scenarios: list[Scenario]) -> None:
    result = pools(scenarios, "keyword")
    assert result["shell_exec"].successes == 0
    exfil = result["exfil_http"]
    assert 0 < exfil.successes < exfil.size
    assert success_at(exfil, 1) < 0.9
    assert success_at(exfil, 25) > 0.999


def test_probabilistic_spotlight_falls_to_retries(scenarios: list[Scenario]) -> None:
    result = pools(scenarios, "spotlight")
    for goal, pool in result.items():
        assert 0 < pool.successes < pool.size / 3, goal
        assert success_at(pool, 25) > pool.rate


def test_analyze_and_render(scenarios: list[Scenario]) -> None:
    budgets = [5, 1, 5, 25]
    assert validate_budgets(budgets) == (1, 5, 25)
    results = analyze(["none", "taintwatch"], scenarios, budgets)
    assert [r.defense for r in results[:9]] == ["none"] * 9
    assert len(results) == 18
    worst = {r.defense: r for r in worst_goals(results)}
    assert worst["none"].rate == 1.0
    assert worst["taintwatch"].rate == 1.0
    assert worst["taintwatch"].goal in OUTSIDE
    text = render_markdown(results, budgets)
    assert text.isascii()
    for heading in ("## Attacker's best goal per defense", "## By goal", "## Notes"):
        assert heading in text
    assert "@25" in text
    assert "never" in text
    csv_text = curves_csv(results)
    assert csv_text.splitlines()[0] == "defense,goal,size,successes,k,success_at"
    assert len(csv_text.splitlines()) == 1 + 18 * 3


def test_default_budgets_are_valid() -> None:
    assert validate_budgets(DEFAULT_BUDGETS) == tuple(DEFAULT_BUDGETS)
    for bad in ([], [0], [3, -1]):
        with pytest.raises(ValueError):
            validate_budgets(bad)


def test_cli_writes_the_report(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    out = tmp_path / "adv"
    code = main(
        ["--defenses", "none", "taintwatch", "--budgets", "1", "10", "--out", str(out)]
    )
    assert code == 0
    assert "taintwatch" in (out / "report.md").read_text(encoding="utf-8")
    assert (out / "curves.csv").read_text(encoding="utf-8").startswith("defense,goal")
    assert "wrote 18 rows" in capsys.readouterr().out


def test_cli_rejects_bad_input(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    base = ["--out", str(tmp_path / "x")]
    assert main([*base, "--defenses", "bogus"]) == 1
    assert main([*base, "--defenses", "none", "--budgets", "0"]) == 1
    assert "error" in capsys.readouterr().err
