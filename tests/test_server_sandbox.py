import pytest
from fastapi.testclient import TestClient

from taintwatch.bench import Suite
from taintwatch.server.app import create_app


@pytest.fixture
def client() -> TestClient:
    app = create_app(db_path=":memory:", suite=Suite((), (), 0))
    return TestClient(app)


def test_api_canonicalize_endpoint(client: TestClient) -> None:
    resp = client.post("/api/canonicalize", json={"text": "c\u200bu\u200br\u200bl"})
    assert resp.status_code == 200
    data = resp.json()
    assert data["canonical"] == "curl"
    assert data["has_evasion"] is True
    assert data["score"] > 0.0
    assert any("zero_width_chars" in t for t in data["techniques"])


def test_api_tokens_issue_and_verify(client: TestClient) -> None:
    key = "super-secret-key-32-bytes-long!!"
    issue_resp = client.post(
        "/api/tokens/issue",
        json={
            "sender": "planner-agent",
            "content": "fetch https://internal.corp",
            "integrity": "tool_output",
            "confidentiality": "internal",
            "secret_key": key,
        },
    )
    assert issue_resp.status_code == 200
    issued = issue_resp.json()
    assert "token" in issued

    verify_resp = client.post(
        "/api/tokens/verify",
        json={
            "content": "fetch https://internal.corp",
            "token": issued["token"],
            "secret_key": key,
        },
    )
    assert verify_resp.status_code == 200
    verified = verify_resp.json()
    assert verified["valid"] is True
    assert verified["label"]["integrity"] == "TOOL_OUTPUT"
    assert verified["label"]["confidentiality"] == "INTERNAL"


def test_api_tokens_verify_fails_tampered(client: TestClient) -> None:
    key = "super-secret-key-32-bytes-long!!"
    issue_resp = client.post(
        "/api/tokens/issue",
        json={"sender": "agent-1", "content": "original text", "secret_key": key},
    )
    token = issue_resp.json()["token"]

    verify_resp = client.post(
        "/api/tokens/verify",
        json={"content": "tampered text", "token": token, "secret_key": key},
    )
    assert verify_resp.status_code == 400
    assert "content digest mismatch" in verify_resp.json()["detail"]


def test_api_declassify_test(client: TestClient) -> None:
    resp1 = client.post(
        "/api/declassify/test",
        json={"pattern": "^[0-9]+$", "value": "12345"},
    )
    assert resp1.status_code == 200
    assert resp1.json()["matches"] is True

    resp2 = client.post(
        "/api/declassify/test",
        json={"pattern": "^[0-9]+$", "value": "12345; rm -rf /"},
    )
    assert resp2.status_code == 200
    assert resp2.json()["matches"] is False
