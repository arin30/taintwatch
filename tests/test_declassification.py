import pytest

from taintwatch import (
    DeclassificationError,
    DeclassificationRule,
    Guard,
    Integrity,
    Policy,
    PolicyViolation,
)


def test_declassification_rule_validates() -> None:
    rule = DeclassificationRule(
        name="numeric-id",
        tool="db.lookup",
        arg="id",
        target_integrity=Integrity.USER,
        pattern=r"^[0-9]{1,8}$",
    )

    assert rule.validates("12345") is True
    assert rule.validates("0") is True
    assert rule.validates("1234567890") is False  # too long
    assert rule.validates("123; DROP TABLE users;") is False  # SQLi attempt
    assert rule.validates("123\nrm -rf /") is False  # command injection attempt


def test_policy_from_toml_with_declassifications() -> None:
    toml_text = """
    [[rule]]
    name = "protect-db"
    tool = "db.lookup"
    arg = "id"
    min_integrity = "user"
    action = "block"

    [[declassification]]
    name = "safe-order-id"
    tool = "db.lookup"
    arg = "id"
    target_integrity = "user"
    pattern = "^[0-9]+$"
    reason = "Pure numeric IDs cannot cause injection"
    """
    policy = Policy.from_toml(toml_text)
    assert len(policy.rules) == 1
    assert len(policy.declassifications) == 1

    declass = policy.find_declassification("db.lookup", "id")
    assert declass is not None
    assert declass.name == "safe-order-id"
    assert declass.target_integrity == Integrity.USER


def test_auto_declassification_permits_safe_untrusted_input() -> None:
    toml_text = """
    [[rule]]
    name = "protect-db"
    tool = "db.lookup"
    arg = "id"
    min_integrity = "user"
    action = "block"

    [[declassification]]
    name = "safe-order-id"
    tool = "db.lookup"
    arg = "id"
    target_integrity = "user"
    pattern = "^[0-9]+$"
    """
    policy = Policy.from_toml(toml_text)
    guard = Guard(policy)

    # Untrusted data from external customer web webhook
    safe_order_id = guard.ingest(
        "98421",
        source="web:webhook",
        integrity=Integrity.UNTRUSTED,
    )

    # Policy allows this call because 98421 matches ^[0-9]+$ and satisfies
    # the declassification contract!
    result = guard.call(
        "db.lookup",
        {"id": safe_order_id},
        lambda id: f"fetched order {id}",
    )
    assert result.value == "fetched order 98421"


def test_auto_declassification_blocks_malicious_untrusted_input() -> None:
    toml_text = """
    [[rule]]
    name = "protect-db"
    tool = "db.lookup"
    arg = "id"
    min_integrity = "user"
    action = "block"

    [[declassification]]
    name = "safe-order-id"
    tool = "db.lookup"
    arg = "id"
    target_integrity = "user"
    pattern = "^[0-9]+$"
    """
    policy = Policy.from_toml(toml_text)
    guard = Guard(policy)

    # Untrusted attacker attempts SQLi
    malicious_id = guard.ingest(
        "100 OR 1=1",
        source="web:webhook",
        integrity=Integrity.UNTRUSTED,
    )

    # Fails the regex grammar, so integrity is NOT promoted, and rule blocks it!
    with pytest.raises(PolicyViolation):
        guard.call(
            "db.lookup",
            {"id": malicious_id},
            lambda id: f"fetched order {id}",
        )


def test_explicit_guard_declassify() -> None:
    declass_rule = DeclassificationRule(
        name="uuid-sanitizer",
        tool="records.get",
        arg="record_id",
        target_integrity=Integrity.USER,
        pattern=r"^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$",
    )
    policy = Policy(declassifications=[declass_rule])
    guard = Guard(policy)

    raw_input = guard.ingest(
        "123e4567-e89b-12d3-a456-426614174000",
        source="untrusted_partner",
        integrity=Integrity.UNTRUSTED,
    )

    promoted = guard.declassify("records.get", "record_id", raw_input)
    assert promoted.label.integrity == Integrity.USER
    assert "untrusted_partner" in promoted.label.sources

    # Check provenance DAG
    sources = guard.graph.sources_of(promoted.node_id)
    assert [n.description for n in sources] == ["untrusted_partner"]


def test_explicit_guard_declassify_fails_invalid_value() -> None:
    declass_rule = DeclassificationRule(
        name="uuid-sanitizer",
        tool="records.get",
        arg="record_id",
        target_integrity=Integrity.USER,
        pattern=r"^[0-9]+$",
    )
    policy = Policy(declassifications=[declass_rule])
    guard = Guard(policy)

    raw_input = guard.ingest(
        "not-a-number",
        source="partner",
        integrity=Integrity.UNTRUSTED,
    )

    with pytest.raises(DeclassificationError, match="failed sanitizer grammar"):
        guard.declassify("records.get", "record_id", raw_input)


def test_explicit_guard_declassify_fails_unregistered_tool() -> None:
    policy = Policy()
    guard = Guard(policy)

    raw_input = guard.ingest("abc", source="user", integrity=Integrity.USER)
    with pytest.raises(DeclassificationError, match="no declassification rule registered"):
        guard.declassify("unknown.tool", "arg", raw_input)
