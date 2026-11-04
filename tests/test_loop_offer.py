"""Loop offer block (Play 1, extended fleet-wide by Next-20 #1,
2026-11-03): every paid /v1/audit delivery carries one additive
top-level ``verdict_row_loop`` field quoting the fleet's repeat
products exactly as StallRow's enforcing code states them — and
error responses never carry it."""

import app.main as main
from app import loop_offer
from app.fleet_pass import LEDGER_URL


def _offers_by_id(block):
    return {o["id"]: o for o in block["offers"]}


def test_block_terms_match_stallrow_enforcement():
    block = loop_offer.loop_offer()
    offers = _offers_by_id(block)
    assert block["discovery"] == "/.well-known/verdict-row.json"

    fpass = offers["fleet_pass"]
    assert fpass["url"] == f"{LEDGER_URL}/v1/fleet-pass"
    assert fpass["price_usd"] == 5.0
    assert fpass["terms"]["ttl_days"] == 90
    assert "$0.50" in fpass["what_it_is"]  # this stall's audit price

    fpass20 = offers["fleet_pass_20"]
    assert fpass20["url"] == f"{LEDGER_URL}/v1/fleet-pass-20"
    assert fpass20["price_usd"] == 20.0

    pack = offers["recheck_pack"]
    assert pack["url"] == f"{LEDGER_URL}/v1/recheck/pack"
    assert pack["price_usd"] == 1.0
    assert pack["terms"]["credits"] == 250
    assert pack["terms"]["ttl_days"] == 90
    assert pack["terms"]["per_check_usd"] == 1.0 / 250
    assert pack["terms"]["per_call_price_usd"] == 0.005

    hook = offers["recheck_change_webhook"]
    assert hook["url"] == f"{LEDGER_URL}/v1/recheck/webhooks"
    assert hook["price_usd"] == 0
    assert "pack_id" in hook["terms"]["gate"]
    assert hook["terms"]["registration_debited"] is False

    feed = offers["recheck_feed"]
    assert feed["url"] == f"{LEDGER_URL}/v1/recheck/feed"
    assert feed["price_usd"] == 0


def test_block_route_price_matches_settings():
    """The mirrored route-price constant must equal the price this
    stall's own config enforces (default under test env)."""
    assert loop_offer.AUDIT_PRICE_USD * 1_000_000 == main.PRICE_UNITS["/v1/audit"]


def test_attach_passes_non_dicts_through():
    sentinel = object()
    assert loop_offer.attach_loop_offer(sentinel) is sentinel
