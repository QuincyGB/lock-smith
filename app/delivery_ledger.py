"""Fleet delivery ledger client (2026-11-07): record every paid
delivery in the fleet's ONE durable ledger on the StallRow hub
(POST /v1/delivery-ledger/record) so every settlement can be
identified by what it bought — never guessed from its amount.

Fail-closed by the owner's rule: the record is written as part of
the delivery flow, after settlement and before the delivery
response is released. If the hub cannot record it (unreachable,
rejected as unverifiable), record_for_delivery RAISES and the
delivery fails loudly (the fleet's catch-all 502; pass-funded
callers refund their debit first). A settled-but-unrecorded
delivery must never pass silently; the checker-side reconciliation
alarms on any on-chain transfer to payTo with no ledger record.

Vendored per service, like loop_offer.py; the hub side (store,
verification, endpoints) lives in stall-row
app/services/deliveryledger.py.
"""

from __future__ import annotations

import base64
import json
import os

import httpx

LEDGER_URL = os.environ.get(
    "DELIVERY_LEDGER_URL", "https://stall-row-production.up.railway.app"
).rstrip("/")


class DeliveryRecordError(Exception):
    """The delivery record could not be written — the delivery it
    belongs to must fail loudly, never pass unrecorded."""


def extract_receipt(response) -> dict | None:
    """Decode the base64 `payment-response` settlement receipt the
    x402 SDK sets on a settled response, if any."""
    raw = response.headers.get("payment-response")
    if not raw:
        return None
    try:
        return json.loads(base64.b64decode(raw).decode("utf-8"))
    except (ValueError, UnicodeDecodeError):
        return None


def build_payload(
    request,
    response,
    *,
    service: str,
    price_units: dict,
    credential: tuple[str, str] | None = None,
    debit_id: str | None = None,
) -> dict | None:
    """The delivery-record payload for a response, or None when the
    response is not a paid delivery (unpaid, error, unpriced path).
    Mirrors the loop-block eligibility: POST to a priced route with
    a 2xx JSON response."""
    if (
        request.method != "POST"
        or request.url.path not in price_units
        or not (200 <= response.status_code < 300)
    ):
        return None
    content_type = response.headers.get("content-type") or ""
    if "application/json" not in content_type:
        return None
    base = {
        "service": service,
        "route": request.url.path,
        "amount_units": int(price_units[request.url.path]),
    }
    if credential is not None:
        kind, ref = credential
        funding = {
            "fleet-pass": "fleet_pass",
            "recheck-pack": "recheck_pack",
            "toolkit-pack": "toolkit_pack",
        }.get(kind, kind)
        return {
            **base,
            "payer": f"{kind}:{ref}",
            "tx": None,
            "network": None,
            "funding": funding,
            "ref": debit_id or ref,
        }
    if debit_id is not None:
        # Pass-funded where the layer tracks the debit id rather
        # than a credential tuple: the payer identity is the pass
        # in the request header.
        pass_id = (request.headers.get("x-fleet-pass") or "").strip()
        return {
            **base,
            "payer": f"fleet-pass:{pass_id}",
            "tx": None,
            "network": None,
            "funding": "fleet_pass",
            "ref": debit_id,
        }
    receipt = extract_receipt(response)
    if receipt is None:
        # A settled per-call delivery MUST carry its receipt. Its
        # absence is exactly the silent gap this ledger exists to
        # kill — build a tx-less per-call payload so the hub
        # rejects it loudly instead of the delivery passing
        # unrecorded.
        return {**base, "payer": "", "tx": None, "network": None,
                "funding": "per_call", "ref": None}
    return {
        **base,
        "payer": receipt.get("payer") or "",
        "tx": receipt.get("transaction"),
        "network": receipt.get("network"),
        "funding": "per_call",
        "ref": None,
    }


async def record_delivery(payload: dict) -> dict:
    """POST one record to the hub ledger. Raises DeliveryRecordError
    on ANY failure — unreachable hub, rejection, bad reply."""
    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
            resp = await client.post(
                f"{LEDGER_URL}/v1/delivery-ledger/record", json=payload
            )
    except httpx.HTTPError as exc:
        raise DeliveryRecordError(
            f"delivery ledger unreachable ({LEDGER_URL}): {exc}"
        ) from exc
    if resp.status_code != 200:
        raise DeliveryRecordError(
            f"delivery ledger refused the record "
            f"(HTTP {resp.status_code}): {resp.text[:200]}"
        )
    try:
        return resp.json()
    except ValueError as exc:
        raise DeliveryRecordError(
            "delivery ledger returned a non-JSON reply"
        ) from exc


async def record_for_delivery(
    request,
    response,
    *,
    service: str,
    price_units: dict,
    credential: tuple[str, str] | None = None,
    debit_id: str | None = None,
) -> None:
    """Record this delivery, or raise DeliveryRecordError.
    Non-deliveries build no payload and return quietly."""
    payload = build_payload(
        request,
        response,
        service=service,
        price_units=price_units,
        credential=credential,
        debit_id=debit_id,
    )
    if payload is None:
        return
    await record_delivery(payload)
