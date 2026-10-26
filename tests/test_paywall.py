"""The paywall contract: unpaid calls to /v1/audit get a 402 whose
accepts carry LockSmith's exact terms ($0.50, USDC on Base, owner
payTo) and the full Bazaar discovery extension; free routes stay open;
oversized bodies are refused with 413 before anything else runs.

Offline: the middleware builds the challenge locally; no facilitator
settlement happens for an unpaid call.
"""

import base64
import json

import pytest
from fastapi.testclient import TestClient

import app.main as main

USDC = "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913"
OWNER = "0x097f9685D1e0752bF8B02d61E5Ce9be7eA0FBA7F"


@pytest.fixture(scope="module")
def client():
    return TestClient(main.app, raise_server_exceptions=False)


def _challenge(response):
    raw = response.headers.get("payment-required")
    assert raw, "402 response must carry a payment-required header"
    return json.loads(base64.b64decode(raw))


def test_unpaid_audit_is_paywalled_at_50_cents(client):
    r = client.post("/v1/audit", json={"endpoint_url": "https://target.example.com/v1/thing"})
    assert r.status_code == 402
    challenge = _challenge(r)
    assert challenge["x402Version"] == 2
    accepts = challenge["accepts"]
    assert len(accepts) == 1
    a = accepts[0]
    assert a["scheme"] == "exact"
    assert a["network"] == "eip155:8453"
    assert a["asset"] == USDC
    assert a["amount"] == "500000"  # $0.50 in USDC smallest units
    assert a["payTo"] == main.settings.pay_to == OWNER


def test_402_carries_full_bazaar_extension(client):
    r = client.post("/v1/audit", json={"endpoint_url": "https://target.example.com/v1/thing"})
    out = _challenge(r)["extensions"]["bazaar"]["info"]["output"]
    assert "schema" in out
    assert "verdict" in out["schema"]["properties"]
    assert "checks" in out["schema"]["properties"]
    # The shipped example is a real audit (of the fleet's Token Verdict).
    assert out["example"]["verdict"] in ("SECURE", "FINDINGS", "EXPOSED")
    assert len(out["example"]["checks"]) == 8


def test_free_routes_stay_open(client):
    assert client.get("/health").status_code == 200
    quote = client.get("/quote")
    assert quote.status_code == 200
    body = quote.json()
    assert body["endpoints"]["/v1/audit"]["price"] == "$0.50"
    assert body["payTo"] == OWNER
    assert client.get("/").status_code == 200
    assert client.get("/.well-known/x402").status_code == 200


def test_oversized_body_is_413(client):
    big = b'{"endpoint_url":"https://target.example.com/v1/thing","pad":"' + b"x" * (1100 * 1024) + b'"}'
    r = client.post("/v1/audit", content=big, headers={"content-type": "application/json"})
    assert r.status_code == 413
