"""Regression (2026-11-07): settled per-call deliveries reach the
loop layer as a PLAIN starlette Response — the x402 SDK buffers the
handler's body to settle, then rebuilds the response from those
bytes, and a plain Response carries no ``body_iterator`` (only
StreamingResponse does). The loop layer assumed a streaming shape
and raised AttributeError on every settled per-call delivery; the
catch-all handler turned that into a 502 AFTER the payment had
already settled on-chain. The TestClient suite never saw it because
the passthrough test harness reaches the layer in streaming shape.

Same defect class as stall-row fbf7c48 (2026-11-06), proven live
on token-verdict 2026-11-07 ($0.02 settled, HTTP 502 returned).
These tests call the layer directly with the production shape.
"""

import asyncio
import json
from types import SimpleNamespace

from fastapi.responses import JSONResponse

import app.main as main


def _request(path="/v1/audit"):
    return SimpleNamespace(method="POST", url=SimpleNamespace(path=path))


def test_attach_handles_plain_settled_response():
    response = JSONResponse({"risk": "low", "findings": []})
    assert getattr(response, "body_iterator", None) is None  # the shape
    out = asyncio.run(main._attach_loop_offer(_request(), response))
    assert out.status_code == 200
    body = json.loads(out.body)
    assert body["risk"] == "low"  # original fields untouched
    assert "verdict_row_loop" in body


def test_attach_handles_plain_error_body_without_block():
    response = JSONResponse({"error": "bad wallet", "code": "bad_wallet"})
    out = asyncio.run(main._attach_loop_offer(_request(), response))
    body = json.loads(out.body)
    assert body["error"] == "bad wallet"
    assert "verdict_row_loop" not in body
