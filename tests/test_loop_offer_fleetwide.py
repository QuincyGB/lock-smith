"""Loop block delivery layer (Next-20 #1, 2026-11-03): the
verdict_row_loop block attaches at the x402 middleware delivery
layer, so EVERY successful paid delivery on this stall's priced
route carries it — per-call and Fleet-Pass funded alike. Error
responses and unpaid 402 challenges never carry it; the 402
amount is unchanged. (Next-20 #5 per-wallet memory is scoped to
StallRow / RouteVerdict / ListSmith; this stall's block is
static, so a repeat delivery carries the same block.)

The per-call tests bypass the payment middleware in-process with
a passthrough (the paywall contract itself is pinned by
test_paywall.py and the unpaid test below, which runs against
the real middleware)."""

import asyncio
import base64
import json
from types import SimpleNamespace

import httpx
from fastapi.responses import JSONResponse
from fastapi.testclient import TestClient

import app.main as main
from app import delivery_ledger as delivery_ledger_svc
from app.fleet_pass import LEDGER_URL

URL = "https://93.184.216.34/v1/thing"
OWNER = "0x097f9685D1e0752bF8B02d61E5Ce9be7eA0FBA7F"
AUDIT_UNITS = main.PRICE_UNITS["/v1/audit"]


async def _fake_audit(endpoint_url, timeout=None, mode="full"):
    return {"verdict": "SECURE", "endpoint_url": endpoint_url, "checks": []}


def _settled_client(monkeypatch):
    """TestClient whose payment middleware is a passthrough — a
    settled per-call delivery, in-process."""
    monkeypatch.setattr(main, "run_audit", _fake_audit)

    # Fleet delivery-ledger recording (2026-11-07) is stubbed like
    # the other delivery side effects in this harness; its own
    # behavior is pinned by tests/test_delivery_ledger_recording.py.
    async def _fake_record_delivery(payload):
        return {"recorded": True}

    monkeypatch.setattr(
        delivery_ledger_svc, "record_delivery", _fake_record_delivery
    )

    async def passthrough(request, call_next):
        return await call_next(request)

    monkeypatch.setattr(main, "_payment_middleware", passthrough)
    return TestClient(main.app, raise_server_exceptions=False)


def _assert_block(body):
    block = body["verdict_row_loop"]
    offers = {o["id"]: o for o in block["offers"]}
    assert offers["recheck_pack"]["price_usd"] == 1.0
    assert offers["fleet_pass"]["url"] == f"{LEDGER_URL}/v1/fleet-pass"
    # Static block only on this stall — no per-wallet section.
    assert "returning_payer" not in block
    return block


# --- (a) settled deliveries carry the block -------------------------------

def test_per_call_delivery_carries_block(monkeypatch):
    client = _settled_client(monkeypatch)
    r = client.post("/v1/audit", json={"endpoint_url": URL})
    assert r.status_code == 200, r.text
    assert r.json()["verdict"] == "SECURE"  # original fields untouched
    _assert_block(r.json())


def _install_ledger(monkeypatch):
    real = httpx.AsyncClient

    def handler(request):
        if request.url.path.endswith("/debit"):
            return httpx.Response(200, json={"debit_id": "fpd_abc"})
        return httpx.Response(200, json={"ok": True})

    def factory(*args, **kwargs):
        kwargs.pop("timeout", None)
        return real(transport=httpx.MockTransport(handler), timeout=10.0)

    monkeypatch.setattr(httpx, "AsyncClient", factory)


def test_fleet_pass_funded_delivery_carries_block(monkeypatch):
    monkeypatch.setattr(main, "run_audit", _fake_audit)
    _install_ledger(monkeypatch)
    client = TestClient(main.app, raise_server_exceptions=False)

    r = client.post(
        "/v1/audit", json={"endpoint_url": URL},
        headers={"X-Fleet-Pass": "fpass_ok"},
    )
    assert r.status_code == 200, r.text
    _assert_block(r.json())


def test_repeat_delivery_still_static_block(monkeypatch):
    """No per-wallet memory on this stall: a second settled
    delivery carries the identical static block."""
    client = _settled_client(monkeypatch)
    first = client.post("/v1/audit", json={"endpoint_url": URL})
    second = client.post("/v1/audit", json={"endpoint_url": URL})
    assert first.json()["verdict_row_loop"] == second.json()["verdict_row_loop"]


# --- (c) 402 challenges and error responses carry no block ---------------

def test_unpaid_challenge_carries_no_block():
    client = TestClient(main.app, raise_server_exceptions=False)
    r = client.post("/v1/audit", json={"endpoint_url": URL})
    assert r.status_code == 402, r.text
    assert "verdict_row_loop" not in r.text
    challenge = json.loads(base64.b64decode(r.headers["payment-required"]))
    accept = challenge["accepts"][0]
    assert accept["amount"] == str(AUDIT_UNITS) == "500000"
    assert accept["payTo"] == OWNER


def test_error_responses_carry_no_block(monkeypatch):
    client = _settled_client(monkeypatch)

    # Validation error on the priced route (settled passthrough).
    r = client.post("/v1/audit", json={})
    assert r.status_code == 422, r.text
    assert "verdict_row_loop" not in r.text

    # Handler failure (bad target): 422, nothing delivered.
    async def failing(endpoint_url, timeout=None, mode="full"):
        raise ValueError("endpoint_url must be an http(s) URL")

    monkeypatch.setattr(main, "run_audit", failing)
    r = client.post("/v1/audit", json={"endpoint_url": URL})
    assert r.status_code == 422, r.text
    assert "verdict_row_loop" not in r.text


def test_oversized_delivery_is_not_rewritten(monkeypatch):
    """The streaming guard: a JSON response advertising a body over
    the injection cap passes through untouched — no buffering, no
    block."""
    big = JSONResponse(
        {"dataset": "x"},
        headers={"content-length": str(main._LOOP_MAX_JSON_BYTES + 1)},
    )
    request = SimpleNamespace(
        method="POST",
        url=SimpleNamespace(path="/v1/audit"),
        state=SimpleNamespace(),
    )
    out = asyncio.run(main._attach_loop_offer(request, big))
    assert out is big


def test_price_units_derived_from_settings():
    assert AUDIT_UNITS == 500000
    assert main._price_units(main.settings.audit_price_usdc) == AUDIT_UNITS
