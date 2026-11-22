"""Delivery extras for every LockSmith paid response (W2 build,
2026-11-22): a ``next_check`` follow-up suggestion and a standard
``evidence`` block.

- ``next_check``: one suggested follow-up route as a small
  machine-readable object {name, path, price_usd} — plus ``service``
  and absolute ``url`` when the suggestion lives on a sibling stall.
  Built in app/main.py from settings prices (this module only holds
  the cross-service mirror constant, pinned by tests).

- ``evidence``: {settlement_tx, input_hash, timestamp}.
  ``input_hash`` is the sha256 of the canonical request input
  (JSON, sorted keys, compact separators) computed by the handler;
  ``timestamp`` is the handler's UTC delivery time. ``settlement_tx``
  is NOT knowable at handler time — the x402 SDK settles after the
  handler returns and puts the receipt on the response — so the
  handler emits it as None and the delivery layer in app/main.py
  fills it from the settlement receipt (the same
  ``payment-response`` header app/delivery_ledger.py reads) before
  the delivery is released. For Fleet-Pass-funded deliveries there
  is no per-call settlement transaction, so it stays None — an
  explicit null, never a fabricated hash.
"""

from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone

# StallRow's /v1/counterparty-report price, mirrored from stall-row
# app/config.py PRICE_UNITS (100_000 units = $0.10, verified
# 2026-11-22). The approval check's suggested follow-up.
COUNTERPARTY_REPORT_PRICE_USD = 0.10
STALLROW_BASE_URL = "https://stall-row-production.up.railway.app"


def canonical_input_hash(canonical_input: dict) -> str:
    """sha256 hex of the canonical request input."""
    blob = json.dumps(
        canonical_input, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")
    return hashlib.sha256(blob).hexdigest()


def make_evidence(canonical_input: dict) -> dict:
    """The evidence block as the handler emits it (settlement_tx is
    filled by the delivery layer when a settlement receipt exists)."""
    return {
        "settlement_tx": None,
        "input_hash": canonical_input_hash(canonical_input),
        "timestamp": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
    }
