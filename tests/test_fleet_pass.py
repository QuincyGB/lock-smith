"""Fleet Pass client: no-header passthrough, table debit success,
ledger refusal passthrough, unreachable-ledger 502. Offline —
MockTransport plays StallRow's ledger."""

import asyncio
import json

import httpx
import pytest
from starlette.requests import Request

from app import fleet_pass

PAID = {"/v1/verdict"}


def _request(headers=None, path="/v1/verdict", method="POST"):
    scope = {
        "type": "http", "method": method, "path": path,
        "headers": [
            (k.lower().encode(), v.encode()) for k, v in (headers or {}).items()
        ],
        "query_string": b"", "server": ("test", 80), "scheme": "http",
        "client": ("test", 1), "root_path": "", "http_version": "1.1",
    }
    return Request(scope)


def _install(monkeypatch, handler):
    real = httpx.AsyncClient

    def factory(*args, **kwargs):
        kwargs.pop("timeout", None)
        return real(transport=httpx.MockTransport(handler), timeout=10.0)

    monkeypatch.setattr(httpx, "AsyncClient", factory)


def test_no_header_or_unpaid_path_is_passthrough():
    assert asyncio.run(fleet_pass.debit_for(_request(), "token-verdict", PAID)) is None
    req = _request({"X-Fleet-Pass": "fpass_x"}, path="/health")
    assert asyncio.run(fleet_pass.debit_for(req, "token-verdict", PAID)) is None


def test_successful_debit_returns_debit_id(monkeypatch):
    seen = {}

    def handler(request):
        seen.update(json.loads(request.content))
        return httpx.Response(200, json={"debit_id": "fpd_abc", "balance_units": 1})

    _install(monkeypatch, handler)
    req = _request({"X-Fleet-Pass": "fpass_ok"})
    out = asyncio.run(fleet_pass.debit_for(req, "token-verdict", PAID))
    assert out == "fpd_abc"
    assert seen == {
        "pass_id": "fpass_ok", "service": "token-verdict", "route": "/v1/verdict"
    }


def test_refusal_passes_through_status(monkeypatch):
    def handler(request):
        return httpx.Response(402, json={"error": "insufficient", "code": "pass_insufficient"})

    _install(monkeypatch, handler)
    req = _request({"X-Fleet-Pass": "fpass_low"})
    out = asyncio.run(fleet_pass.debit_for(req, "token-verdict", PAID))
    assert out.status_code == 402


def test_unreachable_ledger_is_502(monkeypatch):
    def handler(request):
        raise httpx.ConnectError("down", request=request)

    _install(monkeypatch, handler)
    req = _request({"X-Fleet-Pass": "fpass_ok"})
    out = asyncio.run(fleet_pass.debit_for(req, "token-verdict", PAID))
    assert out.status_code == 502
