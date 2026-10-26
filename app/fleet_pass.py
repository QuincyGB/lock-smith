"""Fleet Pass spend client: lets this service accept a buyer's
X-Fleet-Pass header instead of a per-call x402 payment.

The pass ledger lives in StallRow (POST /v1/fleet-pass/debit is the
single source of truth for balances AND prices — this client names
only the service + route, never an amount). The middleware debits
BEFORE the handler runs and refunds by debit_id when the response
is a failure, mirroring the pack discipline in StallRow: never a
charge for our failure, and no silent fallback — a refused pass
returns the ledger's refusal (402/404/410) to the buyer, who can
then pay per call explicitly, without the header.
"""

from __future__ import annotations

import os

import httpx
from fastapi.responses import JSONResponse

PASS_HEADER = "x-fleet-pass"
LEDGER_URL = os.environ.get(
    "FLEET_PASS_LEDGER_URL", "https://stall-row-production.up.railway.app"
).rstrip("/")


async def debit_for(request, service: str, paid_paths: set[str]):
    """Returns None (no pass in play — run the normal paywall), a
    JSONResponse (pass refused/unreachable — return it as-is), or a
    debit_id string (pass charged — run the handler)."""
    pass_id = (request.headers.get(PASS_HEADER) or "").strip()
    if (
        not pass_id
        or request.method != "POST"
        or request.url.path not in paid_paths
    ):
        return None
    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
            resp = await client.post(
                f"{LEDGER_URL}/v1/fleet-pass/debit",
                json={
                    "pass_id": pass_id,
                    "service": service,
                    "route": request.url.path,
                },
            )
    except httpx.HTTPError:
        return JSONResponse(
            {"error": "fleet pass ledger unreachable; pay per call instead"},
            status_code=502,
        )
    if resp.status_code != 200:
        try:
            body = resp.json()
        except ValueError:
            body = {"error": "fleet pass refused"}
        return JSONResponse(body, status_code=resp.status_code)
    return resp.json()["debit_id"]


async def refund(debit_id: str) -> None:
    """Best-effort re-credit after our handler failed. A failed
    refund call is logged by the ledger's audit trail reconciling
    debit rows; it must never mask the handler's own error."""
    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
            await client.post(
                f"{LEDGER_URL}/v1/fleet-pass/refund", json={"debit_id": debit_id}
            )
    except httpx.HTTPError:
        pass
