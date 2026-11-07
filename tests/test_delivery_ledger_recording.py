"""Fleet delivery ledger recording (2026-11-07): every paid
delivery is recorded in the fleet's ONE durable ledger (StallRow
hub) as part of the delivery flow — fail-closed. These tests drive
the x402 middleware directly with a passthrough payment layer (the
settled shape) and the ledger client stubbed at record_delivery:

  * a settled per-call delivery produces exactly one record whose
    payer / tx / network come from the settlement receipt — the
    identification the amount alone could never give;
  * a record failure RAISES out of the middleware (in production
    the catch-all shapes it as the fleet 502) — the delivery is
    never returned unrecorded, never silent;
  * an unpaid 402 records nothing.
"""

import asyncio
import base64
import json

import pytest
from starlette.requests import Request
from fastapi.responses import JSONResponse

import app.main as main
from app import delivery_ledger as delivery_ledger_svc

PATH = next(iter(main.PRICE_UNITS))
PAYER = "0x1111111111111111111111111111111111111111"
TX = "0x" + "ab" * 32


def _request(path=PATH):
    scope = {
        "type": "http",
        "method": "POST",
        "path": path,
        "headers": [],
        "query_string": b"",
        "server": ("test", 80),
        "scheme": "http",
        "client": ("test", 1),
        "root_path": "",
        "http_version": "1.1",
    }
    return Request(scope)


def _receipt_header():
    receipt = {
        "success": True,
        "payer": PAYER,
        "transaction": TX,
        "network": "eip155:8453",
    }
    return base64.b64encode(json.dumps(receipt).encode()).decode()


def _settled_middleware(monkeypatch, captured):
    async def passthrough(request, call_next):
        response = await call_next(request)
        response.headers["payment-response"] = _receipt_header()
        return response

    monkeypatch.setattr(main, "_payment_middleware", passthrough)

    async def fake_record(payload):
        captured.append(payload)
        return {"recorded": True}

    monkeypatch.setattr(delivery_ledger_svc, "record_delivery", fake_record)


async def _ok_handler(request):
    return JSONResponse({"delivered": True})


def test_settled_delivery_is_recorded_from_receipt(monkeypatch):
    captured = []
    _settled_middleware(monkeypatch, captured)
    out = asyncio.run(main.x402_middleware(_request(), _ok_handler))
    assert out.status_code == 200
    assert len(captured) == 1
    (payload,) = captured
    assert payload["service"] == main.settings.service_name
    assert payload["route"] == PATH
    assert payload["amount_units"] == main.PRICE_UNITS[PATH]
    assert payload["funding"] == "per_call"
    assert payload["payer"] == PAYER
    assert payload["tx"] == TX
    assert payload["network"] == "eip155:8453"


def test_record_failure_fails_the_delivery_loudly(monkeypatch):
    async def passthrough(request, call_next):
        response = await call_next(request)
        response.headers["payment-response"] = _receipt_header()
        return response

    monkeypatch.setattr(main, "_payment_middleware", passthrough)

    async def broken_record(payload):
        raise delivery_ledger_svc.DeliveryRecordError("hub unreachable")

    monkeypatch.setattr(delivery_ledger_svc, "record_delivery", broken_record)
    with pytest.raises(delivery_ledger_svc.DeliveryRecordError):
        asyncio.run(main.x402_middleware(_request(), _ok_handler))


def test_unpaid_challenge_records_nothing(monkeypatch):
    captured = []

    async def unpaid(request, call_next):
        return JSONResponse({"error": "payment required"}, status_code=402)

    monkeypatch.setattr(main, "_payment_middleware", unpaid)

    async def fake_record(payload):
        captured.append(payload)
        return {"recorded": True}

    monkeypatch.setattr(delivery_ledger_svc, "record_delivery", fake_record)
    out = asyncio.run(main.x402_middleware(_request(), _ok_handler))
    assert out.status_code == 402
    assert captured == []
