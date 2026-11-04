"""Market402 compatibility (2026-11-04): the unpaid 402 response
carries the x402 challenge in the JSON BODY as well as in the
PAYMENT-REQUIRED header.

Market402's self-test parses the challenge from the body (v1
style) and reported every field missing when the body was the
SDK's empty {}. The middleware mirrors the header's own decoded
challenge into the body, so the two must be exactly equal — that
equality is what this test pins. The header stays the canonical
v2 surface; nothing about prices, payTo, or paid behaviour moves.
"""

import base64
import json

from fastapi.testclient import TestClient

from app import main


def test_402_body_mirrors_header_challenge():
    client = TestClient(main.app, raise_server_exceptions=False)
    r = client.post("/v1/audit", json={})
    assert r.status_code == 402, r.text
    header = r.headers.get("payment-required")
    assert header, "payment-required header missing"
    challenge = json.loads(base64.b64decode(header))
    body = r.json()
    assert body == challenge, "body does not mirror header"
    assert body["x402Version"] == challenge["x402Version"]
    accept = body["accepts"][0]
    for field in ("scheme", "network", "asset", "amount", "payTo"):
        assert accept[field] == challenge["accepts"][0][field]
