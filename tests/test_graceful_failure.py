"""Graceful-failure pass (Next-20 #18): caller faults answer in the
fleet {error, code} shape naming the field, and no bare 500 ever
leaves the service.

The paid-path tests bypass the x402 middleware in-process (the
paywall contract itself is pinned by test_paywall.py: unpaid probes
of every shape still get the 402 first).
"""

import pytest
from fastapi.testclient import TestClient

import app.main as main


@pytest.fixture()
def client(monkeypatch):
    async def passthrough(request, call_next):
        return await call_next(request)

    monkeypatch.setattr(main, "_payment_middleware", passthrough)
    return TestClient(main.app, raise_server_exceptions=False)


def test_missing_field_is_named_in_fleet_shape(client):
    r = client.post("/v1/audit", json={})
    assert r.status_code == 422
    body = r.json()
    assert body["code"] == "validation_error"
    assert "'endpoint_url' is required" in body["error"]


def test_malformed_json_is_named_in_fleet_shape(client):
    r = client.post(
        "/v1/audit",
        content=b"{not-json",
        headers={"content-type": "application/json"},
    )
    assert r.status_code == 422
    body = r.json()
    assert body["code"] == "validation_error"
    assert "JSON" in body["error"]


def test_wrong_type_is_named_in_fleet_shape(client):
    r = client.post("/v1/audit", json={"endpoint_url": {"x": 1}})
    assert r.status_code == 422
    body = r.json()
    assert body["code"] == "validation_error"
    assert "'endpoint_url'" in body["error"]


def test_bad_mode_is_named_in_fleet_shape(client):
    r = client.post(
        "/v1/audit",
        json={"endpoint_url": "https://x.example/v1/y", "mode": "weird"},
    )
    assert r.status_code == 422
    body = r.json()
    assert body["code"] == "validation_error"
    assert "'mode'" in body["error"]


def test_unhandled_failure_is_fleet_shaped_502(client, monkeypatch):
    object.__setattr__(main.settings, "fleet_internal_secret", "test-secret")

    def boom():
        raise RuntimeError("store exploded")

    monkeypatch.setattr(main._nudge_store, "nudge_count", boom)
    r = client.post(
        "/v1/internal/nudges",
        json={},
        headers={"x-fleet-internal-secret": "test-secret"},
    )
    assert r.status_code == 502
    assert r.json() == {"error": "internal failure", "code": "internal_error"}
