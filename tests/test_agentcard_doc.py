"""The published agent card at /.well-known/agent-card.json.

The card is derived from the x402 manifest, so the invariants are
about the derivation: one skill per priced route, the amounts in
services[] identical to the manifest's Base accepts, the fleet payTo
in the x402 block, and no capability claimed that the service does
not have. The HTTP surface is a free 200 JSON document.
"""

from fastapi.testclient import TestClient

import app.main as main
from app.config import load_settings
from app.discovery import CARD_NAME, agent_card, x402_manifest

BASE = "https://stall.example"


def test_card_shape_and_provider():
    settings = load_settings()
    card = agent_card(settings, BASE)
    assert card["name"] == CARD_NAME
    assert card["url"] == BASE
    assert card["provider"]["organization"] == "Verdict Row"
    assert card["documentationUrl"] == f"{BASE}/llms.txt"
    assert card["capabilities"] == {
        "streaming": False,
        "pushNotifications": False,
        "stateTransitionHistory": False,
    }
    assert card["x402"]["payTo"] == settings.pay_to
    assert card["x402"]["discovery"] == f"{BASE}/.well-known/x402"


def test_card_skills_mirror_priced_routes():
    settings = load_settings()
    card = agent_card(settings, BASE)
    manifest = x402_manifest(settings, BASE)
    priced = [r for r in manifest["resources"] if r.get("method") == "POST"]
    assert len(priced) >= 1
    assert len(card["skills"]) == len(priced)
    assert len(card["services"]) == len(priced)
    by_endpoint = {s["endpoint"]: s for s in card["services"]}
    for r in priced:
        base_accept = next(
            a for a in r["accepts"] if a["network"] == settings.network
        )
        entry = by_endpoint[r["resource"]]
        # The amount a verifier compares against the live challenge.
        assert entry["amount"] == str(base_accept["amount"])
        assert base_accept["payTo"] == settings.pay_to


def test_card_http_surface_is_free_json():
    with TestClient(main.app) as client:
        resp = client.get("/.well-known/agent-card.json")
    assert resp.status_code == 200
    body = resp.json()
    assert body["name"] == CARD_NAME
    assert len(body["skills"]) >= 1
