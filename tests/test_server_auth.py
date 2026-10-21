from fastapi.testclient import TestClient

from taintwatch.bench import build_suite
from taintwatch.server import create_app


def test_api_key_authentication_is_disabled_when_unconfigured(monkeypatch) -> None:
    monkeypatch.delenv("TAINTWATCH_API_KEY", raising=False)
    client = TestClient(create_app(":memory:", suite=build_suite(1, 1)))

    assert client.get("/api/health").status_code == 200


def test_api_key_authentication_rejects_missing_or_invalid_key(monkeypatch) -> None:
    monkeypatch.setenv("TAINTWATCH_API_KEY", "test-api-key")
    client = TestClient(create_app(":memory:", suite=build_suite(1, 1)))

    missing = client.get("/api/health")
    invalid = client.get("/api/health", headers={"X-API-Key": "wrong-key"})

    assert missing.status_code == 401
    assert missing.json() == {"detail": "invalid or missing API key"}
    assert invalid.status_code == 401
    assert invalid.json() == {"detail": "invalid or missing API key"}


def test_api_key_authentication_accepts_valid_key(monkeypatch) -> None:
    monkeypatch.setenv("TAINTWATCH_API_KEY", "test-api-key")
    client = TestClient(create_app(":memory:", suite=build_suite(1, 1)))

    response = client.get("/api/health", headers={"X-API-Key": "test-api-key"})

    assert response.status_code == 200
